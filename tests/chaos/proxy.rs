//! Fault proxies for the chaos matrix.
//!
//! [`FrameProxy`] is the message-level proxy: it sits between a server outbox
//! and a client, or between a test writer and the sequencer, and applies
//! [`testkit::faults`] decisions to whole frames. It is deterministic and
//! never touches the HTTP envelope.
//!
//! [`TcpProxy`] is the byte-level proxy used for the faults that only make
//! sense on a real connection: FIN/RST and a silent half-open link. It forwards
//! bytes until the test flips it into `Close` or `Blackhole`.

#![allow(dead_code)]

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use syncmount::protocol::{FrameHeader, HEADER_LEN, MsgType};
use syncmount::testkit::{
    AppliedFault, Direction, FaultAction as Action, FaultEngine, FaultRule, FaultScript, FrameMeta,
    Selector,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

/// What a frame-level fault means for the caller's forwarding loop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyStop {
    /// Keep forwarding.
    None,
    /// Close the logical connection.
    Close,
    /// Stop forwarding without closing (half-open).
    Blackhole,
}

/// One direction of a frame-aware proxy.
pub struct FrameProxy {
    pub engine: FaultEngine,
    dir: Direction,
    reorder: VecDeque<Bytes>,
    window: usize,
}

impl FrameProxy {
    pub fn new(dir: Direction, script: FaultScript) -> Self {
        Self {
            engine: FaultEngine::new(script),
            dir,
            reorder: VecDeque::new(),
            window: 0,
        }
    }

    /// Number of frames the engine actually mutated.
    pub fn applied(&self) -> usize {
        self.engine.trace().applied_count()
    }

    /// Feed one frame through the proxy.
    ///
    /// `out` receives zero or more frames. A `Delay` blocks this loop, which
    /// is the head-of-line behaviour a real proxy has.
    pub async fn pass(&mut self, frame: Bytes, out: &mpsc::Sender<Bytes>) -> ProxyStop {
        // A reorder window keeps every following frame until it is full; the
        // rule only decides when the window opens.
        if !self.reorder.is_empty() && self.reorder.len() < self.window {
            self.reorder.push_back(frame);
            if self.reorder.len() >= self.window {
                while let Some(buffered) = self.reorder.pop_back() {
                    if out.send(buffered).await.is_err() {
                        return ProxyStop::Close;
                    }
                }
            }
            return ProxyStop::None;
        }
        let header = FrameHeader::decode(&frame[..HEADER_LEN]).unwrap();
        let meta = FrameMeta::new(self.dir, header.msg_type.get(), 0, header.seq.get());
        let Some(AppliedFault { action, .. }) = self.engine.decide(meta) else {
            let _ = out.send(frame).await;
            return ProxyStop::None;
        };
        match action {
            Action::Drop => ProxyStop::None,
            Action::Duplicate(copies) => {
                for _ in 0..=copies {
                    if out.send(frame.clone()).await.is_err() {
                        return ProxyStop::Close;
                    }
                }
                ProxyStop::None
            }
            Action::Delay(delay) => {
                tokio::time::sleep(delay).await;
                let _ = out.send(frame).await;
                ProxyStop::None
            }
            Action::Reorder(window) => {
                self.window = usize::from(window).max(2);
                self.reorder.push_back(frame);
                if self.reorder.len() >= self.window {
                    while let Some(buffered) = self.reorder.pop_back() {
                        if out.send(buffered).await.is_err() {
                            return ProxyStop::Close;
                        }
                    }
                }
                ProxyStop::None
            }
            Action::Corrupt { byte, xor } => {
                let mut bytes = frame.to_vec();
                if !bytes.is_empty() {
                    let at = byte % bytes.len();
                    bytes[at] ^= xor;
                }
                let _ = out.send(Bytes::from(bytes)).await;
                ProxyStop::None
            }
            Action::TamperTag => {
                let mut bytes = frame.to_vec();
                if let Some(last) = bytes.last_mut() {
                    *last ^= 0xff;
                }
                let _ = out.send(Bytes::from(bytes)).await;
                ProxyStop::None
            }
            Action::Truncate { bytes } => {
                let mut wire = frame.to_vec();
                wire.truncate(bytes.min(wire.len()));
                let _ = out.send(Bytes::from(wire)).await;
                ProxyStop::None
            }
            Action::UnknownType(raw) => {
                let mut bytes = frame.to_vec();
                if bytes.len() > 2 {
                    bytes[2] = raw;
                }
                let _ = out.send(Bytes::from(bytes)).await;
                ProxyStop::None
            }
            Action::Close => ProxyStop::Close,
            Action::Blackhole(_) => ProxyStop::Blackhole,
        }
    }

    /// Flush a partial reorder buffer at end of stream.
    pub async fn flush(&mut self, out: &mpsc::Sender<Bytes>) {
        while let Some(frame) = self.reorder.pop_front() {
            let _ = out.send(frame).await;
        }
    }
}

/// Common scripts. Each returns a fresh engine, so tests own the trace.
pub fn drop_nth(dir: Direction, n: usize) -> FaultScript {
    FaultScript::new(0x51a7).with_rule(FaultRule::new(dir, Selector::Nth(n), Action::Drop))
}

pub fn duplicate_nth(dir: Direction, n: usize, copies: u8) -> FaultScript {
    FaultScript::new(0x51a8).with_rule(FaultRule::new(
        dir,
        Selector::Nth(n),
        Action::Duplicate(copies),
    ))
}

pub fn reorder_first(dir: Direction, window: u16) -> FaultScript {
    FaultScript::new(0x51a9).with_rule(FaultRule::new(
        dir,
        Selector::Nth(0),
        Action::Reorder(window),
    ))
}

pub fn delay_nth(dir: Direction, n: usize, delay: Duration) -> FaultScript {
    FaultScript::new(0x51aa).with_rule(FaultRule::new(dir, Selector::Nth(n), Action::Delay(delay)))
}

pub fn corrupt_nth(dir: Direction, n: usize, byte: usize) -> FaultScript {
    FaultScript::new(0x51ab).with_rule(FaultRule::new(
        dir,
        Selector::Nth(n),
        Action::Corrupt { byte, xor: 0xa5 },
    ))
}

pub fn tamper_tag_nth(dir: Direction, n: usize) -> FaultScript {
    FaultScript::new(0x51ac).with_rule(FaultRule::new(dir, Selector::Nth(n), Action::TamperTag))
}

pub fn unknown_type_nth(dir: Direction, n: usize, raw: u8) -> FaultScript {
    FaultScript::new(0x51ad).with_rule(FaultRule::new(
        dir,
        Selector::Nth(n),
        Action::UnknownType(raw),
    ))
}

/// Assert a frame header decodes (used by tests to fail early).
pub fn frame_type(frame: &[u8]) -> MsgType {
    FrameHeader::decode(&frame[..HEADER_LEN]).unwrap().msg_type
}

// ---------------------------------------------------------------------------
// TCP proxy
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyMode {
    Pass,
    Blackhole,
    Close,
}

/// A loopback TCP proxy with one shared mode switch.
pub struct TcpProxy {
    pub addr: SocketAddr,
    mode: watch::Sender<ProxyMode>,
    task: JoinHandle<()>,
}

impl TcpProxy {
    pub async fn start(target: SocketAddr) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (mode, rx) = watch::channel(ProxyMode::Pass);
        let task = tokio::spawn(async move {
            loop {
                let Ok((inbound, _)) = listener.accept().await else {
                    break;
                };
                if *rx.borrow() == ProxyMode::Close {
                    drop(inbound);
                    continue;
                }
                let Ok(outbound) = TcpStream::connect(target).await else {
                    continue;
                };
                let rx = rx.clone();
                tokio::spawn(async move {
                    let (mut in_read, mut in_write) = inbound.into_split();
                    let (mut out_read, mut out_write) = outbound.into_split();
                    let upstream = pump(&mut in_read, &mut out_write, rx.clone());
                    let downstream = pump(&mut out_read, &mut in_write, rx);
                    tokio::join!(upstream, downstream);
                });
            }
        });
        Self { addr, mode, task }
    }

    pub fn set(&self, mode: ProxyMode) {
        self.mode.send_replace(mode);
    }
}

impl Drop for TcpProxy {
    fn drop(&mut self) {
        self.set(ProxyMode::Close);
        self.task.abort();
    }
}

async fn pump(
    read: &mut tokio::net::tcp::OwnedReadHalf,
    write: &mut tokio::net::tcp::OwnedWriteHalf,
    mut mode: watch::Receiver<ProxyMode>,
) {
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let state = { *mode.borrow() };
        match state {
            ProxyMode::Close => {
                let _ = write.shutdown().await;
                return;
            }
            ProxyMode::Blackhole => {
                if mode.changed().await.is_err() {
                    return;
                }
                continue;
            }
            ProxyMode::Pass => {}
        }
        tokio::select! {
            result = read.read(&mut buffer) => {
                match result {
                    Ok(0) | Err(_) => {
                        let _ = write.shutdown().await;
                        return;
                    }
                    Ok(count) => {
                        if write.write_all(&buffer[..count]).await.is_err() {
                            return;
                        }
                    }
                }
            }
            _ = mode.changed() => {}
        }
    }
}
