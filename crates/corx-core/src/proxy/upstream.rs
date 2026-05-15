//! Upstream HTTP client with SSRF-aware DNS, connection pooling and manual
//! redirect handling.
//!
//! A single [`Upstream`] instance should be created at startup and shared
//! across all requests: it owns the connection pool and the TLS client
//! configuration. The hot path performs zero allocations beyond the ones
//! required by hyper itself.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::Request;
use http_body_util::{BodyExt as _, Empty};
use hyper::body::Incoming;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::connect::dns::Name;
use hyper_util::rt::TokioExecutor;
use tower::Service;

use crate::error::ProxyError;
use crate::proxy::redirect;
use crate::proxy::ssrf::SsrfGuard;

/// Client-side body type used by the upstream client.
///
/// `UnsyncBoxBody` is used (rather than `BoxBody`) because the inbound
/// [`axum::body::Body`] is itself not `Sync`; hyper's client only requires
/// `Send + 'static` on the body, so this relaxed bound is sufficient.
pub type UpstreamBody = http_body_util::combinators::UnsyncBoxBody<Bytes, ProxyError>;

type Connector = hyper_rustls::HttpsConnector<HttpConnector<GuardedResolver>>;
type HyperClient = Client<Connector, UpstreamBody>;

/// Tuning parameters for the upstream client.
#[derive(Debug, Clone)]
pub struct UpstreamConfig {
    /// Max idle connections retained per host.
    pub pool_max_idle_per_host: usize,
    /// Idle connection timeout.
    pub pool_idle_timeout: Duration,
    /// TCP connect timeout.
    pub connect_timeout: Duration,
    /// Maximum number of redirects to follow.
    pub max_redirects: u8,
    /// Default User-Agent.
    pub user_agent: String,
}

/// Upstream HTTP client.
#[derive(Clone)]
pub struct Upstream {
    client: HyperClient,
    guard: Arc<SsrfGuard>,
    config: Arc<UpstreamConfig>,
}

impl std::fmt::Debug for Upstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Upstream")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl Upstream {
    /// Constructs a new upstream client.
    ///
    /// The supplied [`SsrfGuard`] is consulted inside the DNS resolver used
    /// by this client: no upstream connection is made to an address that
    /// violates SSRF policy.
    ///
    /// # Errors
    ///
    /// Fails if the platform TLS verifier cannot be obtained.
    pub fn new(config: UpstreamConfig, guard: SsrfGuard) -> anyhow::Result<Self> {
        let guard = Arc::new(guard);

        let mut http = HttpConnector::new_with_resolver(GuardedResolver {
            guard: Arc::clone(&guard),
        });
        http.enforce_http(false);
        http.set_connect_timeout(Some(config.connect_timeout));
        http.set_nodelay(true);
        http.set_keepalive(Some(Duration::from_secs(30)));

        use rustls_platform_verifier::ConfigVerifierExt as _;
        let tls_config = rustls::ClientConfig::with_platform_verifier();

        let https = HttpsConnectorBuilder::new()
            .with_tls_config(tls_config)
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .wrap_connector(http);

        let client = Client::builder(TokioExecutor::new())
            .pool_max_idle_per_host(config.pool_max_idle_per_host)
            .pool_idle_timeout(config.pool_idle_timeout)
            .build::<_, UpstreamBody>(https);

        Ok(Self {
            client,
            guard,
            config: Arc::new(config),
        })
    }

    /// Executes a request against the upstream, following redirects up to
    /// the configured budget.
    ///
    /// # Errors
    ///
    /// Surfaces SSRF violations, DNS failures, upstream connection errors,
    /// TLS failures and redirect loops as [`ProxyError`] variants.
    pub async fn execute(
        &self,
        request: Request<UpstreamBody>,
    ) -> Result<hyper::Response<Incoming>, ProxyError> {
        let max_redirects = self.config.max_redirects;
        let (mut state, first_request) = split_initial(request);
        let mut hops: u8 = 0;
        let mut next_request = first_request;

        loop {
            let response = self
                .client
                .request(next_request)
                .await
                .map_err(|err| ProxyError::Upstream(Box::new(err)))?;

            if !redirect::is_redirect(response.status()) {
                return Ok(response);
            }
            if hops >= max_redirects {
                return Err(ProxyError::TooManyRedirects(max_redirects));
            }
            match redirect::prepare_next(&mut state, &response)? {
                Some(req) => {
                    next_request = req;
                    hops = hops.saturating_add(1);
                }
                None => return Ok(response),
            }
        }
    }

    /// Exposes the SSRF guard, used by handlers that validate IP literals
    /// prior to hitting the client.
    #[must_use]
    pub fn guard(&self) -> &SsrfGuard {
        self.guard.as_ref()
    }

    /// Returns the configured user-agent default.
    #[must_use]
    pub fn user_agent(&self) -> &str {
        &self.config.user_agent
    }
}

fn split_initial(
    request: Request<UpstreamBody>,
) -> (redirect::RedirectState, Request<UpstreamBody>) {
    let (parts, body) = request.into_parts();
    let state = redirect::RedirectState::from_initial(
        parts.method.clone(),
        parts.uri.clone(),
        parts.headers.clone(),
    );
    let rebuilt = Request::from_parts(parts, body);
    (state, rebuilt)
}

/// Produces an empty [`UpstreamBody`] suitable for requests synthesised
/// after a redirect hop where the original body cannot be replayed.
#[must_use]
pub fn empty_upstream_body() -> UpstreamBody {
    Empty::<Bytes>::new()
        .map_err(|never: std::convert::Infallible| -> ProxyError { match never {} })
        .boxed_unsync()
}

#[derive(Clone)]
struct GuardedResolver {
    guard: Arc<SsrfGuard>,
}

impl Service<Name> for GuardedResolver {
    type Response = GuardedAddrs;
    type Error = ProxyError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, name: Name) -> Self::Future {
        let guard = Arc::clone(&self.guard);
        Box::pin(async move {
            let host = name.as_str().to_owned();
            let addr = guard.resolve(&host, 0).await?;
            Ok(GuardedAddrs { addr: Some(addr) })
        })
    }
}

/// Iterator yielding a single, pre-validated [`SocketAddr`].
#[derive(Debug, Clone, Copy)]
pub struct GuardedAddrs {
    addr: Option<SocketAddr>,
}

impl Iterator for GuardedAddrs {
    type Item = SocketAddr;

    fn next(&mut self) -> Option<Self::Item> {
        self.addr.take()
    }
}
