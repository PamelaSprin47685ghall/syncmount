//! Streaming bodies with backpressure.
//!
//! Two adapters, both deliberately small:
//!
//! * [`MpscBody`] turns a bounded channel into an [`http_body::Body`]. A
//!   writer that outruns the socket waits instead of growing memory, so the
//!   channel capacity is the only buffer in the path (42 §3.4 L2).
//! * [`BodyStream`] turns any [`http_body::Body`] into a pull-based byte
//!   source. It yields data frames only; trailers are skipped, because the
//!   frame protocol has its own end-of-frame accounting.
//!
//! Neither adapter buffers a whole body, and neither knows what a frame is:
//! HTTP chunk boundaries carry no protocol meaning (51 §3.3).

use std::pin::Pin;
use std::task::{Context, Poll};

use hyper::body::{Body, Bytes, Frame, SizeHint};
use tokio::sync::mpsc;

/// A body failure that is local to the streaming adapter.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BodyError {
    /// The writer closed the channel before the reader saw end-of-stream.
    #[error("body was closed by its writer")]
    Closed,
    /// The reader is gone, so nothing can be delivered.
    #[error("body reader is gone")]
    ReceiverGone,
    /// A bounded send could not make progress immediately.
    #[error("body channel is full")]
    Backpressure,
}

/// One item in the body channel. `Err` terminates the stream.
type Chunk = Result<Bytes, BodyError>;

/// Writer half of a bounded body.
///
/// `send` waits for capacity. `try_send` reports [`BodyError::Backpressure`]
/// instead of waiting, which is what a non-blocking producer wants.
#[derive(Debug)]
pub struct MpscSender {
    tx: Option<mpsc::Sender<Chunk>>,
}

impl MpscSender {
    /// Send one chunk, waiting while the reader catches up.
    pub async fn send(&self, chunk: Bytes) -> Result<(), BodyError> {
        match &self.tx {
            Some(tx) => tx
                .send(Ok(chunk))
                .await
                .map_err(|_| BodyError::ReceiverGone),
            None => Err(BodyError::Closed),
        }
    }

    /// Send without waiting.
    pub fn try_send(&self, chunk: Bytes) -> Result<(), BodyError> {
        match &self.tx {
            Some(tx) => match tx.try_send(Ok(chunk)) {
                Ok(()) => Ok(()),
                Err(mpsc::error::TrySendError::Full(_)) => Err(BodyError::Backpressure),
                Err(mpsc::error::TrySendError::Closed(_)) => Err(BodyError::ReceiverGone),
            },
            None => Err(BodyError::Closed),
        }
    }

    /// Finish the stream cleanly. Later sends fail with [`BodyError::Closed`].
    pub fn close(&mut self) {
        self.tx = None;
    }

    /// Whether the reader or a local close ended the stream.
    pub fn is_closed(&self) -> bool {
        self.tx.as_ref().is_none_or(mpsc::Sender::is_closed)
    }

    /// Resolve when the reader goes away.
    pub async fn closed(&self) {
        if let Some(tx) = &self.tx {
            tx.closed().await;
        }
    }

    /// Configured queue depth, in chunks.
    pub fn capacity(&self) -> usize {
        self.tx.as_ref().map_or(0, mpsc::Sender::max_capacity)
    }
}

/// Reader half of a bounded body, usable directly as a hyper body.
#[derive(Debug)]
pub struct MpscBody {
    rx: mpsc::Receiver<Chunk>,
    finished: bool,
}

impl MpscBody {
    /// Create a channel with a queue depth of at least one chunk.
    ///
    /// The depth is a chunk count, not a byte count; callers size it so that
    /// `depth * largest_frame` stays inside their memory budget.
    pub fn channel(depth: usize) -> (MpscSender, Self) {
        let (tx, rx) = mpsc::channel(depth.max(1));
        (
            MpscSender { tx: Some(tx) },
            Self {
                rx,
                finished: false,
            },
        )
    }
}

impl Body for MpscBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if this.finished {
            return Poll::Ready(None);
        }
        match this.rx.poll_recv(cx) {
            Poll::Ready(Some(Ok(data))) => Poll::Ready(Some(Ok(Frame::data(data)))),
            Poll::Ready(Some(Err(error))) => {
                this.finished = true;
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                this.finished = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.finished
    }

    fn size_hint(&self) -> SizeHint {
        // Unknown length: HTTP/1.1 must use chunked transfer encoding.
        SizeHint::default()
    }
}

/// Pull-based byte source over any body.
///
/// The inner body is boxed and pinned once, so `BodyStream` works with
/// `!Unpin` bodies without unsafe code.
#[derive(Debug)]
pub struct BodyStream<B> {
    inner: Pin<Box<B>>,
}

impl<B> BodyStream<B> {
    /// Wrap a body.
    pub fn new(inner: B) -> Self {
        Self {
            inner: Box::pin(inner),
        }
    }
}

impl<B: Body> BodyStream<B> {
    /// Next data chunk, or `None` at end of stream.
    ///
    /// Trailers are skipped. An error terminates the stream and is returned
    /// exactly once; callers must not poll again after it.
    pub async fn next_bytes(&mut self) -> Result<Option<B::Data>, B::Error> {
        loop {
            let frame = std::future::poll_fn(|cx| self.inner.as_mut().poll_frame(cx)).await;
            match frame {
                None => return Ok(None),
                Some(Err(error)) => return Err(error),
                Some(Ok(frame)) => match frame.into_data() {
                    Ok(data) => return Ok(Some(data)),
                    Err(_trailers) => continue,
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn u_mpsc_body_streams_and_ends() {
        let (sender, body) = MpscBody::channel(4);
        assert!(sender.send(Bytes::from_static(b"one")).await.is_ok());
        assert!(sender.send(Bytes::from_static(b"two")).await.is_ok());

        let mut stream = BodyStream::new(body);
        assert_eq!(
            stream.next_bytes().await,
            Ok(Some(Bytes::from_static(b"one")))
        );
        assert_eq!(
            stream.next_bytes().await,
            Ok(Some(Bytes::from_static(b"two")))
        );

        let mut sender = sender;
        sender.close();
        assert_eq!(stream.next_bytes().await, Ok(None));
        assert_eq!(
            sender.send(Bytes::from_static(b"late")).await,
            Err(BodyError::Closed)
        );
    }

    #[tokio::test]
    async fn u_mpsc_body_applies_backpressure() {
        let (sender, body) = MpscBody::channel(1);
        assert!(sender.try_send(Bytes::from_static(b"first")).is_ok());
        assert_eq!(
            sender.try_send(Bytes::from_static(b"second")),
            Err(BodyError::Backpressure)
        );

        // A waiting send cannot complete until the reader drains the queue.
        assert!(
            tokio::time::timeout(
                Duration::from_millis(50),
                sender.send(Bytes::from_static(b"second"))
            )
            .await
            .is_err()
        );

        let mut stream = BodyStream::new(body);
        assert_eq!(
            stream.next_bytes().await,
            Ok(Some(Bytes::from_static(b"first")))
        );
        assert!(sender.send(Bytes::from_static(b"second")).await.is_ok());
        assert_eq!(
            stream.next_bytes().await,
            Ok(Some(Bytes::from_static(b"second")))
        );
    }

    #[tokio::test]
    async fn u_mpsc_body_reports_unknown_length() {
        let (_sender, body) = MpscBody::channel(2);
        assert_eq!(body.size_hint().exact(), None);
        assert!(!body.is_end_stream());
    }
}
