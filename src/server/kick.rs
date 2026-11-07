//! Kick and teardown, with the one order that keeps the stream honest.
//!
//! ```text
//! 1. remove the session from the online table   (out of fan-out)
//! 2. build KICK{reason, seq = last_good_seq}
//! 3. deliver KICK to the control queue
//! 4. drop the relay slots held by the client
//! 5. inject LEAVE when the reason means "locks are gone"
//! 6. drop the session (both sender halves), closing the HTTP streams
//! ```
//!
//! Step 1 before step 3 is I9: no `ORDERED` frame may follow the `KICK`.
//! Step 3 before step 6 makes delivery best-effort but ordered. The session
//! value returned by [`KickPlan::deliver`] keeps the queues alive until the
//! caller has injected `LEAVE`; dropping it closes both channels.
//!
//! `KICK` carries `seq = last_good_seq`, never a new sequence: it is a
//! diagnostic fence, not an event (42 §6.3). `LEAVE` is a real event and is
//! stamped by the actor.

use std::time::Instant;

use bytes::Bytes;

use crate::protocol::{
    ClientId, ErrorMessage, Kick as KickMessage, KickReason, MsgType, Prefix, Seq, TrnReason,
};

use super::online::{OnlineTable, Session};
use super::relay::{RelayHub, RelaySession};
use super::sequencer::encode_control;

/// Whether this reason also releases the client's locks through `LEAVE`.
///
/// A shutdown or an epoch change does not mean the client's locks vanished;
/// every other reason does (42 §6.4).
pub const fn injects_leave(reason: KickReason) -> bool {
    !matches!(
        reason,
        KickReason::ServerShutdown | KickReason::EpochMismatch
    )
}

/// One prepared teardown.
#[derive(Debug)]
pub struct KickPlan {
    /// Removed session; dropping it closes both queues.
    pub session: Session,
    /// Reason carried in the frame.
    pub reason: KickReason,
    /// Encoded `KICK`, if encoding succeeded.
    pub frame: Option<Bytes>,
    /// Whether the actor must broadcast a `LEAVE` pseudo-operation.
    pub inject_leave: bool,
    /// Relay slots released by this teardown.
    pub dropped_relay: Vec<RelaySession>,
}

impl KickPlan {
    /// Build the plan: remove from fan-out, encode `KICK`, release relay.
    ///
    /// Returns `None` when the identity is not attached, which makes a
    /// duplicate kick a no-op rather than a second frame.
    pub fn prepare(
        online: &mut OnlineTable,
        relay: &mut RelayHub,
        client: ClientId,
        reason: KickReason,
        now: Instant,
    ) -> Option<Self> {
        // 1. Out of the broadcast set before any frame is queued.
        let session = online.remove(&client)?;
        // 2. Encode the fence with the last sequence the client may have.
        let frame = encode_kick(reason, session.last_good_seq);
        // 4. The client's route slots die with it.
        let dropped_relay = relay.drop_by_client(client, now);
        Some(Self {
            session,
            reason,
            frame,
            inject_leave: injects_leave(reason),
            dropped_relay,
        })
    }

    /// 3. Enqueue `KICK`, then hand the session back to the caller.
    ///
    /// The caller injects `LEAVE` (if requested) and then drops the returned
    /// session, which closes the writer. No frame can be enqueued after the
    /// `KICK` because the session is already out of the online table.
    pub fn deliver(self) -> (Session, bool) {
        if let Some(frame) = self.frame {
            let _ = self.session.outbox.try_push_ctrl(frame);
        }
        (self.session, self.inject_leave)
    }

    /// The relay slots released by this plan, for survivor notification.
    pub fn dropped_relay(&self) -> &[RelaySession] {
        &self.dropped_relay
    }
}

/// Encode a plain `KICK` frame.
pub fn encode_kick(reason: KickReason, last_good: Seq) -> Option<Bytes> {
    let body = (KickMessage { reason }).encode().ok()?;
    encode_control(MsgType::KICK, Prefix::None, &body, last_good).ok()
}

/// Encode a plain `ERROR` frame for a routed failure.
pub fn encode_error(
    reason: TrnReason,
    session: Option<crate::protocol::SessionId>,
) -> Option<Bytes> {
    let body = (ErrorMessage {
        reason,
        detail: &[],
        session_id: session,
    })
    .encode()
    .ok()?;
    encode_control(MsgType::ERROR, Prefix::None, &body, Seq::UNSEQUENCED).ok()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::protocol::{
        Flags, FrameBuf, FrameDecoder, Limits, Message, RoutePrefix, SessionId, StreamId,
        decode_plain,
    };
    use crate::server::config::OutboxConfig;
    use crate::server::online::{Outbox, SessionInit, SessionState};
    use crate::transport::PeerId;

    fn client(byte: u8) -> ClientId {
        ClientId::from_bytes([byte; 16])
    }

    fn session(id: ClientId, nonce: u64, now: Instant) -> Session {
        let (outbox, _data, _ctrl) = Outbox::new(&OutboxConfig::default());
        let mut session = Session::new(SessionInit {
            client_id: id,
            nonce,
            peer: PeerId::from_serial(nonce),
            outbox,
            epoch: 1,
            epoch_seen: 1,
            applied_seq: Seq::UNSEQUENCED,
            current_seq: Seq(9),
            now,
        });
        session.state = SessionState::Online;
        session
    }

    fn session_with_ctrl(
        id: ClientId,
        nonce: u64,
        now: Instant,
    ) -> (
        Session,
        tokio::sync::mpsc::Receiver<Bytes>,
        tokio::sync::mpsc::Receiver<Bytes>,
    ) {
        let (outbox, data, ctrl) = Outbox::new(&OutboxConfig::default());
        let mut session = Session::new(SessionInit {
            client_id: id,
            nonce,
            peer: PeerId::from_serial(nonce),
            outbox,
            epoch: 1,
            epoch_seen: 1,
            applied_seq: Seq::UNSEQUENCED,
            current_seq: Seq(9),
            now,
        });
        session.state = SessionState::Online;
        (session, data, ctrl)
    }

    fn decode(bytes: &Bytes) -> FrameBuf {
        let mut decoder = FrameDecoder::new(Limits::default());
        decoder.push(bytes).unwrap();
        decoder.next_frame_owned().unwrap().unwrap()
    }

    #[test]
    fn server_kick_removes_from_fanout_before_enqueue_and_closes_after() {
        let now = Instant::now();
        let a = client(1);
        let mut online = OnlineTable::new();
        let (session, _data, mut ctrl) = session_with_ctrl(a, 1, now);
        online.insert(session);
        let mut relay = RelayHub::new(super::super::relay::RelayLimits::default());

        let plan = KickPlan::prepare(&mut online, &mut relay, a, KickReason::Stalled, now).unwrap();
        assert!(!online.contains(&a), "step 1: out of the fan-out set");
        assert!(plan.frame.is_some());
        assert_eq!(
            ctrl.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        );
        let (session, inject) = plan.deliver();
        assert!(inject, "STALLED releases locks");
        let frame = decode(&ctrl.try_recv().unwrap());
        assert_eq!(frame.header.msg_type, MsgType::KICK);
        assert_eq!(frame.header.seq, Seq(9), "KICK carries last_good_seq");
        match decode_plain(MsgType::KICK, &frame.body, &Limits::default()).unwrap() {
            Message::Kick(kick) => assert_eq!(kick.reason, KickReason::Stalled),
            other => panic!("expected KICK, got {other:?}"),
        }
        drop(session);
        assert!(
            ctrl.is_closed(),
            "step 6: dropping the session closes the writer"
        );
    }

    #[test]
    fn server_kick_shutdown_does_not_inject_leave() {
        let now = Instant::now();
        let a = client(2);
        let mut online = OnlineTable::new();
        online.insert(session(a, 2, now));
        let mut relay = RelayHub::new(super::super::relay::RelayLimits::default());
        let plan =
            KickPlan::prepare(&mut online, &mut relay, a, KickReason::ServerShutdown, now).unwrap();
        assert!(!plan.inject_leave);
        assert!(!injects_leave(KickReason::EpochMismatch));
        assert!(injects_leave(KickReason::HeartbeatTimeout));
    }

    #[test]
    fn server_kick_drops_relay_slots_and_reports_survivors() {
        let now = Instant::now();
        let a = client(3);
        let b = client(4);
        let mut online = OnlineTable::new();
        let (session_a, _data_a, _ctrl_a) = session_with_ctrl(a, 3, now);
        let (session_b, _data_b, _ctrl_b) = session_with_ctrl(b, 4, now);
        online.insert(session_a);
        online.insert(session_b);
        let mut relay = RelayHub::new(super::super::relay::RelayLimits::default());
        let action = relay.route(
            a,
            MsgType::RELAY,
            Flags::ENC.with(Flags::ROUTED),
            &RoutePrefix::new(SessionId(5), StreamId::CTRL, 0, 0),
            16,
            &online,
            now,
        );
        assert!(matches!(
            action,
            super::super::relay::RouteAction::Open { .. }
        ));
        let plan =
            KickPlan::prepare(&mut online, &mut relay, b, KickReason::QueueOverflow, now).unwrap();
        assert_eq!(plan.dropped_relay().len(), 1);
        assert_eq!(plan.dropped_relay()[0].survivor(b), Some(a));
        assert_eq!(relay.session_count(), 0);
    }

    #[test]
    fn server_kick_duplicate_is_a_no_op() {
        let now = Instant::now();
        let a = client(5);
        let mut online = OnlineTable::new();
        online.insert(session(a, 5, now));
        let mut relay = RelayHub::new(super::super::relay::RelayLimits::default());
        assert!(KickPlan::prepare(&mut online, &mut relay, a, KickReason::Stalled, now).is_some());
        assert!(KickPlan::prepare(&mut online, &mut relay, a, KickReason::Stalled, now).is_none());
    }
}
