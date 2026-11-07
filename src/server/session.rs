//! Per-connection tasks: uplink reader, downlink writer, handshake pairing.
//!
//! One session is two independent HTTP requests (42 §7). This module owns the
//! four tasks that make them one logical session:
//!
//! ```text
//! rpc    read body → FrameDecoder → SeqCmd::{Ordered,Watermark,Leave,...}
//! events park the downlink under X-SM-Nonce (the actor binds it)
//! writer select ctrl first, then data; KICK is deferred until data drains
//! detach one SeqCmd::Detach, exactly once, from the uplink task
//! ```
//!
//! No task reads `enc_body`: a `FrameBuf` is moved, never inspected. The only
//! header field the server touches is `seq` (42 I4/I6).

use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use hyper::body::Incoming;
use tokio::sync::{mpsc, oneshot};

use crate::protocol::{
    ClientId, ErrorMessage, FrameBuf, FrameDecoder, HEADER_LEN, MAGIC, Message, MsgType, Prefix,
    PrefixKind, ProtoVersion, Seq, TrnReason, decode_plain, negotiate,
};
use crate::transport::{AcceptedHttp, BodyStream, MpscSender, PeerId};

use super::config::ServeConfig;
use super::online::{Outbox, QueueStats};
use super::sequencer::{
    DetachCause, HelloReply, HelloRequest, Sequencer, WatermarkReport, encode_control, server_caps,
};

/// Shared handles for every connection task.
#[derive(Clone, Debug)]
pub(crate) struct SessionContext {
    /// Actor handle.
    pub sequencer: Sequencer,
    /// Server configuration.
    pub config: Arc<ServeConfig>,
}

/// Spawn the task that owns one accepted HTTP half.
pub(crate) fn spawn(accepted: AcceptedHttp, context: SessionContext) {
    match accepted {
        AcceptedHttp::Rpc {
            peer,
            nonce,
            client_id,
            body,
            end,
        } => {
            tokio::spawn(run_rpc(context, peer, nonce, client_id, body, end));
        }
        AcceptedHttp::Events { nonce, out, .. } => {
            tokio::spawn(run_events(context, nonce, out));
        }
    }
}

async fn run_events(context: SessionContext, nonce: u64, out: MpscSender) {
    // The actor keeps `out`; this task has nothing left to own. A rejection
    // drops `out`, which closes the HTTP response body.
    let _ = context.sequencer.events(nonce, out).await;
}

/// What the uplink task learned about the session.
struct RpcSession {
    client_id: ClientId,
    generation: u64,
    ctrl_tx: mpsc::Sender<Bytes>,
    detach: DetachCause,
}

/// Whether the reader loop continues.
enum Flow {
    Continue,
    Close,
}

async fn run_rpc(
    context: SessionContext,
    peer: PeerId,
    nonce: u64,
    claimed: Option<[u8; 16]>,
    mut body: BodyStream<Incoming>,
    end: oneshot::Sender<()>,
) {
    let mut decoder = FrameDecoder::new(context.config.limits);
    let mut session: Option<RpcSession> = None;
    let mut writer_closed: Option<oneshot::Receiver<()>> = None;

    'session: loop {
        let next = match writer_closed.as_mut() {
            Some(closed) => {
                tokio::select! {
                    biased;
                    _ = closed => break 'session,
                    chunk = body.next_bytes() => chunk,
                }
            }
            None => body.next_bytes().await,
        };
        match next {
            Ok(Some(chunk)) => {
                if let Err(error) = decoder.push(&chunk) {
                    let reason = error.to_wire().unwrap_or(TrnReason::BadFrame);
                    send_error(session.as_ref(), reason);
                    break 'session;
                }
                loop {
                    match decoder.next_frame_owned() {
                        Ok(Some(frame)) => {
                            if session.is_none() {
                                match start_session(&context, peer, nonce, claimed, frame).await {
                                    Ok((established, closed)) => {
                                        session = Some(established);
                                        writer_closed = Some(closed);
                                    }
                                    Err(_) => break 'session,
                                }
                            } else if let Some(active) = session.as_mut() {
                                match handle_frame(&context, active, frame).await {
                                    Flow::Continue => {}
                                    Flow::Close => break 'session,
                                }
                            }
                        }
                        Ok(None) => break,
                        Err(error) => {
                            let reason = error.to_wire().unwrap_or(TrnReason::BadFrame);
                            send_error(session.as_ref(), reason);
                            break 'session;
                        }
                    }
                }
            }
            Ok(None) => break 'session,
            Err(_) => break 'session,
        }
    }

    if let Some(active) = session {
        let _ = context
            .sequencer
            .detach(active.client_id, active.generation, active.detach)
            .await;
    }
    let _ = end.send(());
}

/// Why the uplink could not be established.
#[derive(Debug)]
enum StartError {
    Protocol,
    Version,
    Rejected,
    NoDownlink,
}

async fn start_session(
    context: &SessionContext,
    peer: PeerId,
    nonce: u64,
    claimed: Option<[u8; 16]>,
    frame: FrameBuf,
) -> Result<(RpcSession, oneshot::Receiver<()>), StartError> {
    if frame.header.msg_type != MsgType::HELLO || frame.header.seq != Seq::UNSEQUENCED {
        return Err(StartError::Protocol);
    }
    let ctrl = frame.prefix.as_ctrl().ok_or(StartError::Protocol)?;
    ctrl.validate().map_err(|_| StartError::Protocol)?;
    let Message::Hello(hello) = decode_plain(MsgType::HELLO, &frame.body, &context.config.limits)
        .map_err(|_| StartError::Protocol)?
    else {
        return Err(StartError::Protocol);
    };
    let _ = negotiate(
        ProtoVersion::CURRENT,
        hello.proto,
        server_caps(),
        hello.caps,
    )
    .map_err(|_| StartError::Version)?;
    // The HTTP header is a declaration, never a credential. When present it
    // must agree with the plaintext HELLO, or the two halves disagree about
    // who is joining.
    if let Some(claimed) = claimed {
        if ClientId::from_bytes(claimed) != hello.client_id {
            return Err(StartError::Protocol);
        }
    }

    let (outbox, data, ctrl_rx) = Outbox::new(&context.config.outbox);
    let request = HelloRequest {
        nonce,
        client_id: hello.client_id,
        epoch_seen: ctrl.epoch_seen,
        applied_seq: ctrl.applied_seq,
        peer,
        outbox,
        data,
        ctrl: ctrl_rx,
    };
    let mut reply = context
        .sequencer
        .hello_with_caps(request, hello.caps)
        .await
        .map_err(|_| StartError::Rejected)?;
    let generation = reply.generation;
    let events = match reply.events.take() {
        Some(out) => out,
        None => {
            let wait = reply.wait.take().ok_or(StartError::Protocol)?;
            match tokio::time::timeout(context.config.hello_timeout, wait).await {
                Ok(Ok(out)) => out,
                _ => {
                    // The actor already attached this session. Without this
                    // detach it would sit in `AwaitingDownstream` forever.
                    let _ = context
                        .sequencer
                        .detach(hello.client_id, generation, DetachCause::Disconnected)
                        .await;
                    return Err(StartError::NoDownlink);
                }
            }
        }
    };
    let client_id = reply.client_id;
    let HelloReply {
        data,
        ctrl,
        ctrl_tx,
        queued,
        ..
    } = reply;
    let (closed_tx, closed_rx) = oneshot::channel();
    tokio::spawn(run_writer(events, data, ctrl, queued, closed_tx));
    Ok((
        RpcSession {
            client_id,
            generation,
            ctrl_tx,
            detach: DetachCause::Disconnected,
        },
        closed_rx,
    ))
}

async fn handle_frame(context: &SessionContext, session: &mut RpcSession, frame: FrameBuf) -> Flow {
    if frame.header.seq != Seq::UNSEQUENCED {
        send_error(Some(session), TrnReason::Protocol);
        session.detach = DetachCause::Protocol;
        return Flow::Close;
    }
    let msg_type = frame.header.msg_type;
    if msg_type == MsgType::ORDERED {
        if frame.prefix.kind() != PrefixKind::None {
            send_error(Some(session), TrnReason::Protocol);
            session.detach = DetachCause::Protocol;
            return Flow::Close;
        }
        return match context.sequencer.ordered(session.client_id, frame).await {
            Ok(()) => Flow::Continue,
            Err(_) => Flow::Close,
        };
    }
    if msg_type == MsgType::PING {
        let Some(ctrl) = frame.prefix.as_ctrl() else {
            send_error(Some(session), TrnReason::Protocol);
            session.detach = DetachCause::Protocol;
            return Flow::Close;
        };
        if ctrl.validate().is_err() {
            send_error(Some(session), TrnReason::Protocol);
            session.detach = DetachCause::Protocol;
            return Flow::Close;
        }
        let report = WatermarkReport {
            client: session.client_id,
            applied_seq: ctrl.applied_seq,
            epoch_seen: ctrl.epoch_seen,
            rtt_ms: None,
            at: Instant::now(),
        };
        return match context.sequencer.watermark(report).await {
            Ok(()) => Flow::Continue,
            Err(_) => Flow::Close,
        };
    }
    if msg_type == MsgType::LEAVE {
        if frame.prefix.kind() != PrefixKind::None {
            send_error(Some(session), TrnReason::Protocol);
            session.detach = DetachCause::Protocol;
            return Flow::Close;
        }
        let _ = context
            .sequencer
            .leave(session.client_id, Some(frame))
            .await;
        session.detach = DetachCause::ClientLeft;
        return Flow::Close;
    }
    if msg_type == MsgType::ACK || msg_type == MsgType::RESPONSE {
        // No replay window and no per-frame acknowledgement in v1: both are
        // counted as liveness only, never sequenced (42 §7.2). The actor
        // records the arrival so the diagnostic timestamp stays current.
        return match context.sequencer.seen(session.client_id).await {
            Ok(()) => Flow::Continue,
            Err(_) => Flow::Close,
        };
    }
    if msg_type == MsgType::RELAY
        || msg_type == MsgType::FLOW
        || msg_type == MsgType::SYNC_END
        || msg_type == MsgType::STREAM_DATA
    {
        if frame.prefix.kind() != PrefixKind::Route {
            send_error(Some(session), TrnReason::Protocol);
            session.detach = DetachCause::Protocol;
            return Flow::Close;
        }
        return match context.sequencer.relay(session.client_id, frame).await {
            Ok(()) => Flow::Continue,
            Err(_) => Flow::Close,
        };
    }
    send_error(Some(session), TrnReason::Protocol);
    session.detach = DetachCause::Protocol;
    Flow::Close
}

fn send_error(session: Option<&RpcSession>, reason: TrnReason) {
    let Some(session) = session else {
        return;
    };
    let Ok(body) = (ErrorMessage {
        reason,
        detail: &[],
        session_id: None,
    })
    .encode() else {
        return;
    };
    if let Ok(frame) = encode_control(MsgType::ERROR, Prefix::None, &body, Seq::UNSEQUENCED) {
        let _ = session.ctrl_tx.try_send(frame);
    }
}

/// Write queued frames to the HTTP response body.
///
/// Control frames go first, but a `KICK` is deferred until every already
/// queued data frame has been written: the client must not observe a kick
/// sequence before the frames that precede it (42 I9). The sender halves are
/// dropped by the actor when it detaches, so both channels end and the task
/// exits.
async fn run_writer(
    out: MpscSender,
    mut data: mpsc::Receiver<Bytes>,
    mut ctrl: mpsc::Receiver<Bytes>,
    queued: Arc<QueueStats>,
    closed: oneshot::Sender<()>,
) {
    let mut deferred_kick: Option<Bytes> = None;
    loop {
        tokio::select! {
            biased;
            Some(frame) = ctrl.recv(), if deferred_kick.is_none() => {
                if is_kick(&frame) {
                    deferred_kick = Some(frame);
                    continue;
                }
                if out.send(frame).await.is_err() {
                    break;
                }
            }
            Some(frame) = data.recv() => {
                let len = frame.len();
                if out.send(frame).await.is_err() {
                    break;
                }
                queued.sub(len);
            }
            else => break,
        }
    }
    if let Some(kick) = deferred_kick {
        let _ = out.send(kick).await;
    }
    let _ = closed.send(());
}

fn is_kick(frame: &Bytes) -> bool {
    frame.len() >= HEADER_LEN && frame[0] == MAGIC && frame[2] == MsgType::KICK.get()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn server_kick_detection_reads_only_the_plaintext_header() {
        let kick = encode_control(MsgType::KICK, Prefix::None, &[0; 5], Seq::UNSEQUENCED).unwrap();
        assert!(is_kick(&kick));
        let ordered = encode_control(MsgType::ORDERED, Prefix::None, &[0; 30], Seq(1)).unwrap();
        assert!(!is_kick(&ordered));
        assert!(!is_kick(&Bytes::from_static(b"short")));
    }
}
