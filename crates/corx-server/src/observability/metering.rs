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
