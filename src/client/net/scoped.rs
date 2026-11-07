//! JOINING-scoped RPC writer: one owner, clean handoff.
//!
//! Owner: client transport.
//!
//! # Why a second writer exists
//!
//! During JOINING the steady-state [`UplinkTask`] does not exist yet: the
//! JOIN proof writes through [`ConnParts::uplink`] directly, and the
//! manifest/block exchange needs the same stream before the write gate
//! opens. [`ScopedUplink`] owns the [`Uplink`] for exactly that window:
//!
//! * it is the only writer while it runs (the [`Uplink`] is moved into its
//!   task, so two writers cannot coexist);
//! * it writes only frames handed to it: a JOINING client sends no
//!   keepalive, because the connection itself proves liveness;
//! * [`ScopedUplink::handoff`] stops the task, drains queued frames and
//!   returns the [`Uplink`] for
//!   [`UplinkTask::new`](crate::client::net::uplink::UplinkTask::new).
//!
//! The steady-state task then receives the relay link through
//! [`RelaySyncLink::rebind`](crate::client::sync_link::RelaySyncLink::rebind) with
//! its control queue as the sink. Order matters: handoff first, then
//! rebind, then start the task, so no frame is ever queued for a writer that
//! will not run.
//!
//! [`UplinkTask`]: super::uplink::UplinkTask
//! [`ConnParts::uplink`]: super::conn::ConnParts

use std::fmt;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::protocol::FrameBuf;

use super::conn::{Uplink, UplinkError};
use crate::client::sync_link::{FrameSink, RelayError};

/// Depth of the JOINING writer queue.
///
/// The relay link applies backpressure through this bound; a full queue
/// makes the requester wait, it never drops a frame silently.
pub const SCOPED_QUEUE_DEPTH: usize = 16;

/// A writer the scoped task can own.
///
/// The production implementation is [`Uplink`]; tests use a recorder.
pub trait FrameWriter: Send + 'static {
    /// Write one complete frame.
    fn write_frame<'a>(
        &'a mut self,
        frame: &'a FrameBuf,
    ) -> crate::sync::BoxFut<'a, Result<(), UplinkError>>;
}

impl FrameWriter for Uplink {
    fn write_frame<'a>(
        &'a mut self,
        frame: &'a FrameBuf,
    ) -> crate::sync::BoxFut<'a, Result<(), UplinkError>> {
        Box::pin(async move { self.send(frame).await })
    }
}

/// JOINING writer failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ScopedError {
    /// The task or queue is gone.
    #[error("scoped uplink is closed")]
    Closed,
    /// The underlying writer failed.
    #[error("uplink: {0}")]
    Uplink(String),
    /// The writer task panicked or was cancelled.
    #[error("scoped uplink task: {0}")]
    Task(String),
}

enum ScopedCommand {
    Frame {
        frame: FrameBuf,
        ack: oneshot::Sender<Result<(), ScopedError>>,
    },
    Shutdown {
        ack: oneshot::Sender<()>,
    },
}

/// What the writer task returns.
struct ScopedExit<W> {
    writer: Option<W>,
    error: Option<ScopedError>,
}

/// The owning half; exactly one exists per [`Uplink`].
pub struct ScopedUplink<W: FrameWriter> {
    commands: Option<mpsc::Sender<ScopedCommand>>,
    task: Option<JoinHandle<ScopedExit<W>>>,
}

impl<W: FrameWriter> fmt::Debug for ScopedUplink<W> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScopedUplink")
            .field("running", &self.task.is_some())
            .finish_non_exhaustive()
    }
}

impl<W: FrameWriter> ScopedUplink<W> {
    /// Start the JOINING writer.
    pub fn start(writer: W) -> (Self, ScopedHandle) {
        let (commands, receiver) = mpsc::channel(SCOPED_QUEUE_DEPTH);
        let task = tokio::spawn(run(writer, receiver));
        (
            Self {
                commands: Some(commands.clone()),
                task: Some(task),
            },
            ScopedHandle { commands },
        )
    }

    /// Stop writing, drain the queue and return the [`Uplink`].
    ///
    /// The returned writer is the only one: the task is joined before this
    /// method returns, so a caller can immediately build the steady-state
    /// [`UplinkTask`](super::uplink::UplinkTask) without a second writer.
    ///
    /// # Errors
    ///
    /// [`ScopedError::Uplink`] when a queued frame failed to write,
    /// [`ScopedError::Closed`] when the task already stopped.
    pub async fn handoff(mut self) -> Result<W, ScopedError> {
        let Some(commands) = self.commands.take() else {
            return Err(ScopedError::Closed);
        };
        let (ack, receiver) = oneshot::channel();
        let sent = commands.send(ScopedCommand::Shutdown { ack }).await.is_ok();
        drop(commands);
        if sent {
            // The ack is sent just before the task returns; awaiting it
            // guarantees no write can start after `handoff` observes it.
            let _ = receiver.await;
        }
        let Some(task) = self.task.take() else {
            return Err(ScopedError::Closed);
        };
        match task.await {
            Err(error) => Err(ScopedError::Task(error.to_string())),
            Ok(exit) => {
                if let Some(error) = exit.error {
                    return Err(error);
                }
                exit.writer.ok_or(ScopedError::Closed)
            }
        }
    }
}

/// The sending half; cloneable and safe to share with the relay link.
#[derive(Clone)]
pub struct ScopedHandle {
    commands: mpsc::Sender<ScopedCommand>,
}

impl fmt::Debug for ScopedHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScopedHandle")
            .field("closed", &self.commands.is_closed())
            .finish()
    }
}

impl ScopedHandle {
    /// Write one sealed `RELAY` frame.
    ///
    /// Alias for [`FrameSink::send_frame`], named for the JOINING caller.
    pub fn send_relay(&self, frame: FrameBuf) -> crate::sync::BoxFut<'_, Result<(), RelayError>> {
        self.send_frame(frame)
    }
}

impl FrameSink for ScopedHandle {
    fn send_frame(&self, frame: FrameBuf) -> crate::sync::BoxFut<'_, Result<(), RelayError>> {
        Box::pin(async move {
            let (ack, receiver) = oneshot::channel();
            self.commands
                .send(ScopedCommand::Frame { frame, ack })
                .await
                .map_err(|_| RelayError::Closed)?;
            match receiver.await {
                Ok(Ok(())) => Ok(()),
                Ok(Err(error)) => Err(RelayError::Uplink(error.to_string())),
                Err(_) => Err(RelayError::Closed),
            }
        })
    }
}

async fn run<W: FrameWriter>(
    mut writer: W,
    mut commands: mpsc::Receiver<ScopedCommand>,
) -> ScopedExit<W> {
    loop {
        match commands.recv().await {
            Some(ScopedCommand::Frame { frame, ack }) => match writer.write_frame(&frame).await {
                Ok(()) => {
                    let _ = ack.send(Ok(()));
                }
                Err(error) => {
                    let text = error.to_string();
                    let _ = ack.send(Err(ScopedError::Uplink(text.clone())));
                    return ScopedExit {
                        writer: Some(writer),
                        error: Some(ScopedError::Uplink(text)),
                    };
                }
            },
            Some(ScopedCommand::Shutdown { ack }) => {
                let _ = ack.send(());
                return ScopedExit {
                    writer: Some(writer),
                    error: None,
                };
            }
            None => {
                return ScopedExit {
                    writer: Some(writer),
                    error: None,
                };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use super::*;
    use crate::protocol::MsgType;
    use crate::sync::BoxFut;

    struct FakeWriter {
        frames: Arc<Mutex<Vec<FrameBuf>>>,
        writes: Arc<AtomicUsize>,
    }

    impl FrameWriter for FakeWriter {
        fn write_frame<'a>(
            &'a mut self,
            frame: &'a FrameBuf,
        ) -> BoxFut<'a, Result<(), UplinkError>> {
            Box::pin(async move {
                self.writes.fetch_add(1, Ordering::Relaxed);
                self.frames
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(frame.clone());
                Ok(())
            })
        }
    }

    /// The JOINING writer sends nothing on its own: a silent client stays
    /// silent, and only queued frames reach the wire.
    #[tokio::test]
    async fn u_scoped_uplink_sends_no_unsolicited_frames() {
        let frames = Arc::new(Mutex::new(Vec::new()));
        let writes = Arc::new(AtomicUsize::new(0));
        let writer = FakeWriter {
            frames: Arc::clone(&frames),
            writes: Arc::clone(&writes),
        };
        let (scoped, _handle) = ScopedUplink::start(writer);
        tokio::time::sleep(Duration::from_millis(75)).await;
        let _writer = scoped.handoff().await.expect("handoff");
        assert_eq!(writes.load(Ordering::Relaxed), 0);
        assert!(
            frames
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_empty()
        );
    }

    #[tokio::test]
    async fn u_scoped_uplink_handoff_drains_and_closes() {
        let frames = Arc::new(Mutex::new(Vec::new()));
        let writes = Arc::new(AtomicUsize::new(0));
        let writer = FakeWriter {
            frames: Arc::clone(&frames),
            writes: Arc::clone(&writes),
        };
        let (scoped, handle) = ScopedUplink::start(writer);
        let body = crate::protocol::Flow { grant_bytes: 9 }
            .encode()
            .expect("flow");
        let mut header = crate::protocol::FrameHeader::new(
            MsgType::FLOW,
            crate::protocol::Flags::ROUTED,
            0,
            crate::protocol::Seq::UNSEQUENCED,
        );
        header.len = (crate::protocol::RoutePrefix::ENCODED_LEN + body.len()) as u32;
        let frame = FrameBuf::new(
            header,
            crate::protocol::Prefix::Route(crate::protocol::RoutePrefix::new(
                crate::protocol::SessionId::new(1),
                crate::protocol::StreamId::CTRL,
                0,
                0,
            )),
            body,
        );
        for _ in 0..3 {
            handle.send_frame(frame.clone()).await.expect("send");
        }
        let _writer = scoped.handoff().await.expect("handoff");
        assert_eq!(writes.load(Ordering::Relaxed), 3);
        assert_eq!(
            frames
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .len(),
            3
        );
        assert!(matches!(
            handle.send_frame(frame).await,
            Err(RelayError::Closed)
        ));
    }
}
