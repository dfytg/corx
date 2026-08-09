//! Streaming body wrappers that update Prometheus counters as data flows
//! through the proxy.
//!
//! Wrapping the body (rather than buffering and counting on completion) is
//! critical: the proxy explicitly streams in both directions and a buffered
//! counter would defeat that property. Each wrapper is `pin_project_lite`
//! based so it stays `Unsync`-compatible with hyper's client body type.

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Buf;
use corx_core::error::ProxyError;
use corx_core::observability::BYTES_TRANSFERRED;
use http_body::{Body, Frame, SizeHint};
use pin_project_lite::pin_project;

pin_project! {
    /// Wraps a [`Body`] and increments the
    /// `corx_bytes_transferred_total{direction}` counter for every byte that
    /// flows through. `direction` is statically allocated so cardinality
    /// stays bounded.
    pub struct CountingBody<B> {
        #[pin]
        inner: B,
        direction: &'static str,
    }
}

impl<B> CountingBody<B> {
    /// Build a wrapper that attributes all bytes flowing through it to the
    /// supplied direction (e.g. `"request"` or `"response"`).
    pub const fn new(inner: B, direction: &'static str) -> Self {
        Self { inner, direction }
    }
}

impl<B> Body for CountingBody<B>
where
    B: Body,
    B::Data: Buf,
{
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.project();
        let direction = *this.direction;
        let polled = this.inner.poll_frame(cx);
        let Poll::Ready(Some(Ok(frame))) = polled else {
            return polled;
        };
        if let Some(data) = frame.data_ref() {
            let bytes = u64::try_from(data.remaining()).unwrap_or(u64::MAX);
            if bytes > 0 {
                metrics::counter!(BYTES_TRANSFERRED, "direction" => direction).increment(bytes);
            }
        }
        Poll::Ready(Some(Ok(frame)))
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

pin_project! {
    /// Caps total bytes read from an inner body. When the budget is exhausted
    /// the stream ends with [`ProxyError::PayloadTooLarge`].
    ///
    /// `max_bytes = 0` disables the cap (pass-through).
    pub struct LimitingBody<B> {
        #[pin]
        inner: B,
        max_bytes: u64,
        seen: u64,
    }
}

impl<B> LimitingBody<B> {
    /// Wrap `inner`, aborting after `max_bytes` of data frames.
    pub const fn new(inner: B, max_bytes: u64) -> Self {
        Self {
            inner,
            max_bytes,
            seen: 0,
        }
    }
}

impl<B> Body for LimitingBody<B>
where
    B: Body,
    B::Data: Buf,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    type Data = B::Data;
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.project();
        if over_budget(*this.max_bytes, *this.seen) {
            return Poll::Ready(Some(Err(Box::new(ProxyError::PayloadTooLarge))));
        }

        match this.inner.poll_frame(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(Box::new(err)))),
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    let n = u64::try_from(data.remaining()).unwrap_or(u64::MAX);
                    *this.seen = this.seen.saturating_add(n);
                }
                if over_budget(*this.max_bytes, *this.seen) {
                    return Poll::Ready(Some(Err(Box::new(ProxyError::PayloadTooLarge))));
                }
                Poll::Ready(Some(Ok(frame)))
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

const fn over_budget(max_bytes: u64, seen: u64) -> bool {
    max_bytes > 0 && seen > max_bytes
}
