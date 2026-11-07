//! Relay routing: session table, ciphertext forwarding, flow windows, peers.
//!
//! # What this module is allowed to do
//!
//! A routed frame carries a plaintext 25-byte [`RoutePrefix`]; every other
//! byte is opaque. Routing therefore performs exactly three operations:
//!
//! 1. look the session up (or create it on an explicit `RELAY` control
//!    opening),
//! 2. account the frame against one directional window,
//! 3. return the destination identity.
//!
//! It never parses, rewrites, buffers, reorders or retries a body. The
//! actor re-encodes the same header, prefix and body and hands one `Bytes`
//! clone to the destination outbox (42 I11).
//!
//! # Session opening
//!
//! 42 D6 proposed `flags.bit7 = SESSION_OPEN`. The frozen frame layout
//! reserves bits 6 and 7 and the decoder rejects them (44 INV-02), so that
//! bit cannot reach this module. The equivalent, observable trigger is an
//! unknown `session_id` on a `RELAY` frame whose route prefix is
//! `CTRL/0/0`: the initiator's first frame. Every other unknown id is
//! `TRN_SESSION_UNKNOWN`, which keeps a stale id from silently pairing with
//! a random peer.
//!
//! # Flow control
//!
//! One [`Window`] per direction, 8 MiB hard cap (42 §5.4). A frame that does
//! not fit is dropped and answered with `TRN_BACKPRESSURE`; the hub never
//! queues content. `FLOW` releases credit on the opposite direction and is
//! forwarded unchanged.
//!
//! # Peer selection
//!
//! Uniform random over sessions that are `Online`, have both outbox
//! channels alive, are not the requester, serve fewer than
//! `max_source_sessions` sessions, and are not cooling down after a failure
//! (42 §5.5). The selector observes only server-visible failures: disconnect
//! and a new session id from an origin whose old session is still open. An
//! idle slot is released without penalty; a dead source is caught by TCP
//! keepalive. An origin may change source at most three times; the fourth
//! attempt gets `TRN_NO_PEER`.
//!
//! # Directed opening
//!
//! A `WELCOME` may carry a view-source token minted by
//! [`super::view_registry`]. The joiner's first `RELAY{CTRL,0,0}` names that
//! token as its session id; when the token is valid and belongs to the
//! sender, [`RelayHub::open_to`] inserts the slot without consulting the
//! random selector; the token is retired only after the slot exists, so a
//! failed attempt leaves the retry on the same holder. A foreign sender is
//! answered with `TRN_PROTOCOL`, and a token that is unknown or expired
//! falls back to the selector. The hub owns
//! the route table because redemption happens on the relay path; the
//! sequencer reaches it through [`RelayHub::views_mut`].

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::protocol::{
    CHUNK_PLAIN, ClientId, ENV_OVERHEAD, Flags, HEADER_LEN, MsgType, ROUTE_PREFIX_LEN, RoutePrefix,
    SessionId, StreamId, TrnReason,
};

use super::online::{OnlineTable, SessionState};
use super::view_registry::{ViewLookup, ViewRegistry};

/// Hard byte ceiling per direction (42 §5.4).
pub const RELAY_WINDOW_BYTES: u64 = 8 * 1024 * 1024;

/// Concurrent relay sessions across the process (42 §5.2).
pub const RELAY_MAX_SESSIONS: usize = 32;

/// Sessions one client may serve at the same time (42 §5.5).
///
/// Two joiners may pull from the same holder at once; a third waits for a
/// slot to free.
pub const RELAY_MAX_SOURCE_SESSIONS: u32 = 2;

/// Idle time after which a route slot is released (42 §5.2).
///
/// The window stays above the kernel keepalive interval (~90 s), so a slow
/// but live transfer never loses its slot while TCP is still probing.
pub const RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// Absolute session lifetime; content volume is unknown to the server.
pub const RELAY_SESSION_TTL: Duration = Duration::from_secs(30 * 60);

/// Largest routed frame accepted by the relay path (42 §5).
///
/// The cap covers the whole encoded frame, not just its plaintext. A
/// `STREAM_DATA` frame carries one full [`CHUNK_PLAIN`] fragment plus the
/// sealed envelope, the route prefix and the frame header; a bare 64 KiB cap
/// would reject the largest legal fragment and answer `TRN_BAD_FRAME`.
pub const RELAY_FRAME_BYTES: u64 =
    (HEADER_LEN + ROUTE_PREFIX_LEN + ENV_OVERHEAD as usize + CHUNK_PLAIN) as u64;

/// How long a failed source stays out of the candidate set (42 §5.5).
pub const RELAY_COOLDOWN: Duration = Duration::from_secs(60);

/// Maximum consecutive source changes per origin (42 §5.5).
pub const RELAY_MAX_RETRIES: u8 = 3;

/// Relay tunables.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelayLimits {
    /// Concurrent sessions.
    pub max_sessions: usize,
    /// Sessions one client may serve.
    pub max_source_sessions: u32,
    /// Per-direction byte window.
    pub window_bytes: u64,
    /// Largest routed frame.
    pub frame_bytes: u64,
    /// Idle release.
    pub idle_timeout: Duration,
    /// Absolute lifetime.
    pub session_ttl: Duration,
    /// Source cooldown after a failure.
    pub cooldown: Duration,
    /// Source changes allowed per origin.
    pub max_retries: u8,
}

impl Default for RelayLimits {
    fn default() -> Self {
        Self {
            max_sessions: RELAY_MAX_SESSIONS,
            max_source_sessions: RELAY_MAX_SOURCE_SESSIONS,
            window_bytes: RELAY_WINDOW_BYTES,
            frame_bytes: RELAY_FRAME_BYTES,
            idle_timeout: RELAY_IDLE_TIMEOUT,
            session_ttl: RELAY_SESSION_TTL,
            cooldown: RELAY_COOLDOWN,
            max_retries: RELAY_MAX_RETRIES,
        }
    }
}

/// One directional credit window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Window {
    /// Absolute credit ceiling.
    pub granted: u64,
    /// Bytes forwarded but not yet released by the receiver.
    pub inflight: u64,
    /// Hard cap, independent of any `FLOW` grant.
    pub cap: u64,
}

impl Window {
    /// A fresh window at the hard cap.
    pub const fn new(cap: u64) -> Self {
        Self {
            granted: cap,
            inflight: 0,
            cap,
        }
    }

    /// Bytes still sendable.
    pub const fn available(&self) -> u64 {
        self.granted.saturating_sub(self.inflight)
    }

    /// Reserve `len` bytes, or refuse without changing state.
    pub fn reserve(&mut self, len: u64) -> bool {
        if self.inflight.saturating_add(len) > self.granted {
            return false;
        }
        self.inflight += len;
        true
    }

    /// Release credit acknowledged by the opposite direction.
    ///
    /// Saturation matters: a duplicate or hostile `FLOW` must not wrap the
    /// counter below zero and create credit from nothing.
    pub fn release(&mut self, bytes: u64) {
        self.inflight = self.inflight.saturating_sub(bytes);
    }
}

/// Lifecycle of one routed session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayState {
    /// Slot created; no data frame forwarded yet.
    Open,
    /// Data has flowed.
    Streaming,
    /// `SYNC_END` seen or the slot is being released.
    Draining,
}

/// One routed session.
#[derive(Clone, Debug)]
pub struct RelaySession {
    /// Client-generated identifier; never rewritten.
    pub id: SessionId,
    /// Initiator (pull side).
    pub origin: ClientId,
    /// Selected source.
    pub peer: ClientId,
    /// Lifecycle.
    pub state: RelayState,
    /// Creation instant.
    pub created_at: Instant,
    /// Last forwarded frame.
    pub last_frame_at: Instant,
    /// Absolute deadline.
    pub deadline: Instant,
    /// Origin-to-peer window.
    pub o2p: Window,
    /// Peer-to-origin window.
    pub p2o: Window,
    /// Bytes forwarded per direction: `[origin→peer, peer→origin]`.
    pub bytes: [u64; 2],
}

impl RelaySession {
    /// The endpoint that is not `from`, or `None` when `from` is an
    /// intruder.
    pub fn target(&self, from: ClientId) -> Option<ClientId> {
        if from.as_bytes() == self.origin.as_bytes() {
            Some(self.peer)
        } else if from.as_bytes() == self.peer.as_bytes() {
            Some(self.origin)
        } else {
            None
        }
    }

    /// The endpoint that survives when `gone` disconnects.
    pub fn survivor(&self, gone: ClientId) -> Option<ClientId> {
        if gone.as_bytes() == self.origin.as_bytes() {
            Some(self.peer)
        } else if gone.as_bytes() == self.peer.as_bytes() {
            Some(self.origin)
        } else {
            None
        }
    }
}

/// Session table plus the reverse index used by disconnect cleanup.
#[derive(Debug, Default)]
pub struct SessionRouter {
    sessions: HashMap<SessionId, RelaySession>,
    by_client: HashMap<ClientId, Vec<SessionId>>,
}

impl SessionRouter {
    /// Empty router.
    pub fn new() -> Self {
        Self::default()
    }

    /// Borrow one session.
    pub fn get(&self, id: &SessionId) -> Option<&RelaySession> {
        self.sessions.get(id)
    }

    /// Mutably borrow one session.
    pub fn get_mut(&mut self, id: &SessionId) -> Option<&mut RelaySession> {
        self.sessions.get_mut(id)
    }

    /// Number of live slots.
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Whether no slot exists.
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// Sessions in which `client` is either endpoint.
    pub fn sessions_of(&self, client: ClientId) -> Vec<SessionId> {
        self.by_client.get(&client).cloned().unwrap_or_default()
    }

    /// Sessions initiated by `origin`.
    ///
    /// A client can be a source for someone else at the same time as it
    /// pulls its own snapshot; only the latter says "my previous source was
    /// bad" (42 §5.5).
    pub fn originated_by(&self, origin: ClientId) -> Vec<SessionId> {
        self.sessions
            .values()
            .filter(|session| session.origin.as_bytes() == origin.as_bytes())
            .map(|session| session.id)
            .collect()
    }

    /// Sessions served by `peer` and not already draining.
    pub fn source_count(&self, peer: ClientId) -> u32 {
        self.by_client
            .get(&peer)
            .map(|ids| {
                ids.iter()
                    .filter(|id| {
                        self.sessions.get(*id).is_some_and(|session| {
                            session.peer.as_bytes() == peer.as_bytes()
                                && session.state != RelayState::Draining
                        })
                    })
                    .count() as u32
            })
            .unwrap_or(0)
    }

    /// Insert a fresh slot. The caller guarantees the id is unknown.
    pub fn insert(&mut self, session: RelaySession) {
        self.by_client
            .entry(session.origin)
            .or_default()
            .push(session.id);
        self.by_client
            .entry(session.peer)
            .or_default()
            .push(session.id);
        self.sessions.insert(session.id, session);
    }

    /// Remove one slot and both reverse-index entries.
    pub fn remove(&mut self, id: &SessionId) -> Option<RelaySession> {
        let session = self.sessions.remove(id)?;
        self.unindex(session.origin, *id);
        self.unindex(session.peer, *id);
        Some(session)
    }

    fn unindex(&mut self, client: ClientId, id: SessionId) {
        if let Some(ids) = self.by_client.get_mut(&client) {
            ids.retain(|candidate| *candidate != id);
            if ids.is_empty() {
                self.by_client.remove(&client);
            }
        }
    }
}

/// Source cooldowns and consecutive-change counters.
#[derive(Debug, Default)]
pub struct PeerSelector {
    cooldown: HashMap<ClientId, Instant>,
    retries: HashMap<ClientId, u8>,
}

impl PeerSelector {
    /// Empty selector.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether `peer` failed recently enough to be excluded.
    pub fn is_cooling(&self, peer: ClientId, now: Instant) -> bool {
        self.cooldown.get(&peer).is_some_and(|until| *until > now)
    }

    /// Record one visible failure.
    pub fn note_failure(&mut self, peer: ClientId, now: Instant, cooldown: Duration) {
        self.cooldown.insert(peer, now + cooldown);
    }

    /// Count one source change for `origin`.
    ///
    /// Returns `false` once the frozen retry budget is exhausted; the caller
    /// then answers `TRN_NO_PEER` instead of opening another slot.
    pub fn count_retry(&mut self, origin: ClientId, max: u8) -> bool {
        let count = self.retries.get(&origin).copied().unwrap_or(0);
        if count >= max {
            return false;
        }
        self.retries.insert(origin, count + 1);
        true
    }

    /// Forget an origin's failures after a clean `SYNC_END`.
    pub fn reset(&mut self, origin: ClientId) {
        self.retries.remove(&origin);
    }

    /// Consecutive source changes observed for `origin`.
    pub fn retries(&self, origin: ClientId) -> u8 {
        self.retries.get(&origin).copied().unwrap_or(0)
    }
}

/// What the actor must do with one routed frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteAction {
    /// Forward unchanged to `to`.
    Forward {
        /// Destination.
        to: ClientId,
    },
    /// A first frame created a slot; forward to the selected peer.
    Open {
        /// Selected source.
        to: ClientId,
        /// Client-generated id, echoed for diagnostics only.
        id: SessionId,
    },
    /// Answer the origin with `ERROR{reason}`.
    Reject {
        /// Origin.
        to: ClientId,
        /// Transport reason.
        reason: TrnReason,
    },
    /// No receiver exists; the origin may still be told why.
    Drop {
        /// Reason.
        reason: TrnReason,
    },
}

/// The relay hub: router, peer policy and windows.
#[derive(Debug)]
pub struct RelayHub {
    router: SessionRouter,
    peers: PeerSelector,
    views: ViewRegistry,
    limits: RelayLimits,
}

impl RelayHub {
    /// Build a hub with explicit limits.
    pub fn new(limits: RelayLimits) -> Self {
        Self {
            router: SessionRouter::new(),
            peers: PeerSelector::new(),
            views: ViewRegistry::new(),
            limits,
        }
    }

    /// Borrow the configured limits.
    pub const fn limits(&self) -> &RelayLimits {
        &self.limits
    }

    /// Borrow the view-source routes.
    pub fn views(&self) -> &ViewRegistry {
        &self.views
    }

    /// Mutably borrow the view-source routes.
    pub fn views_mut(&mut self) -> &mut ViewRegistry {
        &mut self.views
    }

    /// Live slots.
    pub fn session_count(&self) -> usize {
        self.router.len()
    }

    /// Borrow one slot.
    pub fn session(&self, id: &SessionId) -> Option<&RelaySession> {
        self.router.get(id)
    }

    /// Route one data frame (`RELAY` or `STREAM_DATA`).
    #[allow(clippy::too_many_arguments)]
    pub fn route(
        &mut self,
        from: ClientId,
        kind: MsgType,
        flags: Flags,
        prefix: &RoutePrefix,
        len: usize,
        online: &OnlineTable,
        now: Instant,
    ) -> RouteAction {
        if flags.has_reserved_bits() {
            return RouteAction::Reject {
                to: from,
                reason: TrnReason::Protocol,
            };
        }
        if len as u64 > self.limits.frame_bytes {
            return RouteAction::Reject {
                to: from,
                reason: TrnReason::BadFrame,
            };
        }
        if !valid_shape(kind, prefix) {
            return RouteAction::Reject {
                to: from,
                reason: TrnReason::Protocol,
            };
        }
        if self.router.get(&prefix.session_id).is_some() {
            return self.route_existing(from, kind, prefix, len, online, now);
        }
        self.open(from, kind, prefix, online, now)
    }

    fn route_existing(
        &mut self,
        from: ClientId,
        kind: MsgType,
        prefix: &RoutePrefix,
        len: usize,
        online: &OnlineTable,
        now: Instant,
    ) -> RouteAction {
        let id = prefix.session_id;
        let Some(session) = self.router.get(&id) else {
            return RouteAction::Reject {
                to: from,
                reason: TrnReason::SessionUnknown,
            };
        };
        let Some(to) = session.target(from) else {
            return RouteAction::Reject {
                to: from,
                reason: TrnReason::Protocol,
            };
        };
        if kind == MsgType::FLOW {
            return RouteAction::Reject {
                to: from,
                reason: TrnReason::Protocol,
            };
        }
        let origin = session.origin;
        if !self.receiver_alive(online, to) {
            self.router.remove(&id);
            self.peers.note_failure(to, now, self.limits.cooldown);
            self.peers.count_retry(origin, self.limits.max_retries);
            return RouteAction::Reject {
                to: from,
                reason: TrnReason::NoPeer,
            };
        }
        let Some(session) = self.router.get_mut(&id) else {
            return RouteAction::Reject {
                to: from,
                reason: TrnReason::SessionUnknown,
            };
        };
        if kind == MsgType::SYNC_END {
            session.state = RelayState::Draining;
            session.last_frame_at = now;
            self.router.remove(&id);
            self.peers.reset(origin);
            return RouteAction::Forward { to };
        }
        let (window, index) = if from.as_bytes() == session.origin.as_bytes() {
            (&mut session.o2p, 0)
        } else {
            (&mut session.p2o, 1)
        };
        if !window.reserve(len as u64) {
            return RouteAction::Reject {
                to: from,
                reason: TrnReason::Backpressure,
            };
        }
        session.bytes[index] = session.bytes[index].saturating_add(len as u64);
        session.last_frame_at = now;
        session.state = RelayState::Streaming;
        RouteAction::Forward { to }
    }

    /// Account one `FLOW` frame and return where to forward it.
    pub fn on_flow(
        &mut self,
        from: ClientId,
        prefix: &RoutePrefix,
        grant_bytes: u32,
        online: &OnlineTable,
        now: Instant,
    ) -> RouteAction {
        if !valid_shape(MsgType::FLOW, prefix) {
            return RouteAction::Reject {
                to: from,
                reason: TrnReason::Protocol,
            };
        }
        let id = prefix.session_id;
        let Some(session) = self.router.get(&id) else {
            return RouteAction::Reject {
                to: from,
                reason: TrnReason::SessionUnknown,
            };
        };
        let Some(to) = session.target(from) else {
            return RouteAction::Reject {
                to: from,
                reason: TrnReason::Protocol,
            };
        };
        let origin = session.origin;
        if !self.receiver_alive(online, to) {
            self.router.remove(&id);
            self.peers.note_failure(to, now, self.limits.cooldown);
            self.peers.count_retry(origin, self.limits.max_retries);
            return RouteAction::Reject {
                to: from,
                reason: TrnReason::NoPeer,
            };
        }
        let Some(session) = self.router.get_mut(&id) else {
            return RouteAction::Reject {
                to: from,
                reason: TrnReason::SessionUnknown,
            };
        };
        // A FLOW from the peer acknowledges bytes the origin sent, and
        // vice versa (42 §5.4).
        let released = if from.as_bytes() == session.peer.as_bytes() {
            &mut session.o2p
        } else {
            &mut session.p2o
        };
        released.release(u64::from(grant_bytes));
        session.last_frame_at = now;
        session.state = RelayState::Streaming;
        RouteAction::Forward { to }
    }

    fn open(
        &mut self,
        from: ClientId,
        kind: MsgType,
        prefix: &RoutePrefix,
        online: &OnlineTable,
        now: Instant,
    ) -> RouteAction {
        let is_opening = kind == MsgType::RELAY
            && prefix.stream == StreamId::CTRL
            && prefix.chunk_index == 0
            && prefix.total_chunks == 0;
        if !is_opening {
            return RouteAction::Reject {
                to: from,
                reason: TrnReason::SessionUnknown,
            };
        }
        // A token from `WELCOME` names the holder directly. A foreign sender
        // is refused rather than silently rerouted; unknown and expired
        // tokens fall through to the normal selector.
        match self.views.resolve(from, prefix.session_id, now) {
            ViewLookup::Hit(holder) => {
                return match self.open_to(from, prefix.session_id, holder, online, now) {
                    Ok(()) => {
                        self.views.spend(prefix.session_id);
                        RouteAction::Open {
                            to: holder,
                            id: prefix.session_id,
                        }
                    }
                    Err(reason) => RouteAction::Reject { to: from, reason },
                };
            }
            ViewLookup::Mismatch => {
                return RouteAction::Reject {
                    to: from,
                    reason: TrnReason::Protocol,
                };
            }
            ViewLookup::Expired | ViewLookup::Unknown => {}
        }
        if self.peers.retries(from) >= self.limits.max_retries {
            return RouteAction::Reject {
                to: from,
                reason: TrnReason::NoPeer,
            };
        }
        if self.router.len() >= self.limits.max_sessions {
            return RouteAction::Reject {
                to: from,
                reason: TrnReason::SessionFull,
            };
        }
        // A second session id while the first is still open is the client's
        // only visible way to say "this source is bad" (42 §5.5).
        let existing = self.router.originated_by(from);
        if !existing.is_empty() {
            let mut old_peers = Vec::with_capacity(existing.len());
            for id in existing {
                if let Some(old) = self.router.remove(&id) {
                    old_peers.push(old.peer);
                }
            }
            for peer in old_peers {
                self.peers.note_failure(peer, now, self.limits.cooldown);
            }
            if !self.peers.count_retry(from, self.limits.max_retries) {
                return RouteAction::Reject {
                    to: from,
                    reason: TrnReason::NoPeer,
                };
            }
        }
        let Some(peer) = self.pick_peer(online, from, now) else {
            return RouteAction::Reject {
                to: from,
                reason: TrnReason::NoPeer,
            };
        };
        self.router.insert(RelaySession {
            id: prefix.session_id,
            origin: from,
            peer,
            state: RelayState::Open,
            created_at: now,
            last_frame_at: now,
            deadline: now + self.limits.session_ttl,
            o2p: Window::new(self.limits.window_bytes),
            p2o: Window::new(self.limits.window_bytes),
            bytes: [0, 0],
        });
        RouteAction::Open {
            to: peer,
            id: prefix.session_id,
        }
    }

    /// Open a slot directly against `target`, skipping peer selection.
    ///
    /// This is the redemption path for a view-source token. The checks are
    /// the same ones the selector applies: the target must be online, keep
    /// both writer halves, receive broadcasts, serve fewer than
    /// `max_source_sessions` sessions, and not be cooling down. A full router
    /// still answers `TRN_SESSION_FULL`.
    ///
    /// The caller guarantees `session` is unknown; a duplicate is a protocol
    /// error rather than a silent overwrite.
    pub fn open_to(
        &mut self,
        from: ClientId,
        session: SessionId,
        target: ClientId,
        online: &OnlineTable,
        now: Instant,
    ) -> Result<(), TrnReason> {
        if from.as_bytes() == target.as_bytes() {
            return Err(TrnReason::Protocol);
        }
        if self.router.get(&session).is_some() {
            return Err(TrnReason::Protocol);
        }
        if !self.receiver_alive(online, target) {
            return Err(TrnReason::NoPeer);
        }
        if self.peers.is_cooling(target, now) {
            return Err(TrnReason::NoPeer);
        }
        if self.router.source_count(target) >= self.limits.max_source_sessions {
            return Err(TrnReason::NoPeer);
        }
        if self.router.len() >= self.limits.max_sessions {
            return Err(TrnReason::SessionFull);
        }
        self.router.insert(RelaySession {
            id: session,
            origin: from,
            peer: target,
            state: RelayState::Open,
            created_at: now,
            last_frame_at: now,
            deadline: now + self.limits.session_ttl,
            o2p: Window::new(self.limits.window_bytes),
            p2o: Window::new(self.limits.window_bytes),
            bytes: [0, 0],
        });
        Ok(())
    }

    fn receiver_alive(&self, online: &OnlineTable, client: ClientId) -> bool {
        online.get(&client).is_some_and(|session| {
            session.state.receives_broadcast()
                && !session.outbox.data.is_closed()
                && !session.outbox.ctrl.is_closed()
        })
    }

    /// Uniform random over eligible sources.
    fn pick_peer(&self, online: &OnlineTable, exclude: ClientId, now: Instant) -> Option<ClientId> {
        let mut candidates = Vec::new();
        for (client, session) in online.iter() {
            if client.as_bytes() == exclude.as_bytes() {
                continue;
            }
            if session.state != SessionState::Online {
                continue;
            }
            if session.outbox.data.is_closed() || session.outbox.ctrl.is_closed() {
                continue;
            }
            if self.router.source_count(*client) >= self.limits.max_source_sessions {
                continue;
            }
            if self.peers.is_cooling(*client, now) {
                continue;
            }
            candidates.push(*client);
        }
        if candidates.is_empty() {
            return None;
        }
        Some(candidates[rand::random_range(0..candidates.len())])
    }

    /// Release slots that exceeded idle or absolute limits.
    ///
    /// Returns the removed sessions so the actor can answer the surviving
    /// endpoint with `TRN_NO_PEER`.
    ///
    /// Expiry records no failure: a slow transfer is not a bad peer. A really
    /// dead peer is detected by TCP keepalive and removed through
    /// [`RelayHub::drop_by_client`], and the origin's own JOIN retry policy
    /// handles the resulting `TRN_NO_PEER`.
    pub fn reap(&mut self, now: Instant) -> Vec<RelaySession> {
        let expired: Vec<SessionId> = self
            .router
            .sessions
            .iter()
            .filter(|(_, session)| {
                now.saturating_duration_since(session.last_frame_at) > self.limits.idle_timeout
                    || now >= session.deadline
            })
            .map(|(id, _)| *id)
            .collect();
        let mut removed = Vec::with_capacity(expired.len());
        for id in expired {
            let Some(session) = self.router.remove(&id) else {
                continue;
            };
            removed.push(session);
        }
        removed
    }

    /// Release every slot held by a disconnecting client.
    pub fn drop_by_client(&mut self, client: ClientId, now: Instant) -> Vec<RelaySession> {
        let ids = self.router.sessions_of(client);
        let mut removed = Vec::with_capacity(ids.len());
        for id in ids {
            let Some(session) = self.router.remove(&id) else {
                continue;
            };
            if client.as_bytes() == session.peer.as_bytes() {
                self.peers.note_failure(client, now, self.limits.cooldown);
                self.peers
                    .count_retry(session.origin, self.limits.max_retries);
            }
            removed.push(session);
        }
        removed
    }
}

/// Whether the route prefix has the shape frozen for this frame kind.
///
/// `FLOW` is a control frame with zero chunk bookkeeping; `SYNC_END` is the
/// only explicit release and carries zero chunks. Data frames keep whatever
/// the sender wrote (44 §3.4).
fn valid_shape(kind: MsgType, prefix: &RoutePrefix) -> bool {
    match kind {
        MsgType::FLOW => {
            prefix.stream == StreamId::CTRL && prefix.chunk_index == 0 && prefix.total_chunks == 0
        }
        MsgType::SYNC_END => prefix.chunk_index == 0 && prefix.total_chunks == 0,
        MsgType::RELAY | MsgType::STREAM_DATA => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::server::config::OutboxConfig;
    use crate::server::online::{Outbox, SessionInit};
    use crate::transport::PeerId;
    use std::ops::Deref;
    use std::time::Duration;

    fn client(byte: u8) -> ClientId {
        ClientId::from_bytes([byte; 16])
    }

    /// The table plus the writer halves, so `is_closed()` stays false.
    struct Online {
        table: OnlineTable,
        _data: Vec<tokio::sync::mpsc::Receiver<bytes::Bytes>>,
        _ctrl: Vec<tokio::sync::mpsc::Receiver<bytes::Bytes>>,
    }

    impl Deref for Online {
        type Target = OnlineTable;

        fn deref(&self) -> &Self::Target {
            &self.table
        }
    }

    fn online(ids: &[ClientId]) -> Online {
        let entries: Vec<(ClientId, Seq)> = ids.iter().map(|id| (*id, Seq::UNSEQUENCED)).collect();
        online_at(&entries)
    }

    /// Like [`online`], but each session reports the given applied sequence.
    fn online_at(entries: &[(ClientId, Seq)]) -> Online {
        let mut table = OnlineTable::new();
        let mut data_keep = Vec::new();
        let mut ctrl_keep = Vec::new();
        for (index, (id, applied)) in entries.iter().enumerate() {
            let nonce = index as u64 + 1;
            let (outbox, data, ctrl) = Outbox::new(&OutboxConfig::default());
            let mut session = crate::server::online::Session::new(SessionInit {
                client_id: *id,
                nonce,
                peer: PeerId::from_serial(nonce),
                outbox,
                epoch: 1,
                epoch_seen: 1,
                applied_seq: *applied,
                current_seq: *applied,
                now: Instant::now(),
            });
            session.state = SessionState::Online;
            table.insert(session);
            data_keep.push(data);
            ctrl_keep.push(ctrl);
        }
        Online {
            table,
            _data: data_keep,
            _ctrl: ctrl_keep,
        }
    }

    #[test]
    fn server_relay_view_token_targets_the_named_holder() {
        let now = Instant::now();
        let joiner = client(1);
        let holder = client(9);
        let stale = client(2);
        let mut table = online_at(&[(joiner, Seq(7)), (holder, Seq(7)), (stale, Seq(6))]);
        let mut hub = RelayHub::new(RelayLimits::default());
        let view = hub
            .views_mut()
            .select_view(&table, joiner, Seq(7), now)
            .unwrap();
        assert_eq!(view.holder, holder);

        // The random selector would accept `stale`; the token must not.
        table.table.get_mut(&stale).unwrap().state = SessionState::Resyncing;
        assert_eq!(
            open(&mut hub, &table, joiner, view.session.get(), now),
            RouteAction::Open {
                to: holder,
                id: view.session
            }
        );
        let session = hub.session(&view.session).unwrap();
        assert_eq!(session.origin, joiner);
        assert_eq!(session.peer, holder);
        assert_eq!(session.state, RelayState::Open);
        assert!(
            hub.views().is_empty(),
            "a token opens exactly one relay session"
        );
    }

    #[test]
    fn server_relay_view_token_refuses_a_foreign_joiner() {
        let now = Instant::now();
        let joiner = client(1);
        let holder = client(9);
        let intruder = client(0x0b);
        let table = online_at(&[(joiner, Seq(7)), (intruder, Seq(7)), (holder, Seq(7))]);
        let mut hub = RelayHub::new(RelayLimits::default());
        let view = hub
            .views_mut()
            .select_view(&table, joiner, Seq(7), now)
            .unwrap();

        assert_eq!(
            open(&mut hub, &table, intruder, view.session.get(), now),
            RouteAction::Reject {
                to: intruder,
                reason: TrnReason::Protocol
            }
        );
        // The owner's token survives a foreign attempt.
        assert_eq!(
            open(&mut hub, &table, joiner, view.session.get(), now),
            RouteAction::Open {
                to: holder,
                id: view.session
            }
        );
    }

    #[test]
    fn server_relay_expired_view_token_is_not_honoured() {
        let now = Instant::now();
        let joiner = client(1);
        let holder = client(9);
        let table = online_at(&[(joiner, Seq(7)), (holder, Seq(7))]);
        let mut hub = RelayHub::new(RelayLimits::default());
        let view = hub
            .views_mut()
            .select_view(&table, joiner, Seq(7), now)
            .unwrap();

        let later = now + crate::server::view_registry::VIEW_ROUTE_TTL + Duration::from_secs(1);
        let alone = online_at(&[(joiner, Seq(7))]);
        assert_eq!(
            open(&mut hub, &alone, joiner, view.session.get(), later),
            RouteAction::Reject {
                to: joiner,
                reason: TrnReason::NoPeer
            },
            "an expired token must fall back to the selector, which finds nobody"
        );
        assert!(hub.views().is_empty());
    }

    #[test]
    fn server_relay_view_token_holder_offline_is_no_peer() {
        let now = Instant::now();
        let joiner = client(1);
        let holder = client(9);
        let table = online_at(&[(joiner, Seq(7)), (holder, Seq(7))]);
        let mut hub = RelayHub::new(RelayLimits::default());
        let view = hub
            .views_mut()
            .select_view(&table, joiner, Seq(7), now)
            .unwrap();

        let alone = online_at(&[(joiner, Seq(7))]);
        assert_eq!(
            open(&mut hub, &alone, joiner, view.session.get(), now),
            RouteAction::Reject {
                to: joiner,
                reason: TrnReason::NoPeer
            }
        );
        assert_eq!(hub.session_count(), 0);
    }

    #[test]
    fn server_relay_two_joiners_share_a_holder_and_the_third_waits() {
        let now = Instant::now();
        let holder = client(9);
        let first = client(1);
        let second = client(2);
        let third = client(3);
        let table = online(&[holder, first, second, third]);
        let mut hub = RelayHub::new(RelayLimits::default());

        assert_eq!(
            hub.open_to(first, SessionId(50), holder, &table, now),
            Ok(())
        );
        assert_eq!(
            hub.open_to(second, SessionId(51), holder, &table, now),
            Ok(())
        );
        assert_eq!(
            hub.open_to(third, SessionId(52), holder, &table, now),
            Err(TrnReason::NoPeer),
            "the third joiner waits until a slot frees"
        );
        assert_eq!(hub.session_count(), 2);

        // Freeing one slot admits the waiting joiner.
        assert_eq!(hub.drop_by_client(first, now).len(), 1);
        assert_eq!(
            hub.open_to(third, SessionId(52), holder, &table, now),
            Ok(())
        );
        assert_eq!(hub.session_count(), 2);
    }

    fn prefix(id: u128, stream: StreamId) -> RoutePrefix {
        RoutePrefix::new(SessionId(id), stream, 0, 0)
    }

    fn open(
        hub: &mut RelayHub,
        table: &OnlineTable,
        from: ClientId,
        id: u128,
        now: Instant,
    ) -> RouteAction {
        hub.route(
            from,
            MsgType::RELAY,
            Flags::ENC.with(Flags::ROUTED),
            &prefix(id, StreamId::CTRL),
            100,
            table,
            now,
        )
    }

    #[test]
    fn server_relay_open_selects_an_online_peer_and_forwards_both_ways() {
        let now = Instant::now();
        let a = client(1);
        let b = client(2);
        let table = online(&[a, b]);
        let mut hub = RelayHub::new(RelayLimits::default());
        assert_eq!(
            open(&mut hub, &table, a, 7, now),
            RouteAction::Open {
                to: b,
                id: SessionId(7)
            }
        );
        assert_eq!(hub.session_count(), 1);
        assert_eq!(
            hub.route(
                a,
                MsgType::RELAY,
                Flags::ENC.with(Flags::ROUTED),
                &prefix(7, StreamId::BLOCK),
                1000,
                &table,
                now,
            ),
            RouteAction::Forward { to: b }
        );
        assert_eq!(
            hub.route(
                b,
                MsgType::STREAM_DATA,
                Flags::ENC.with(Flags::ROUTED),
                &prefix(7, StreamId::BLOCK),
                2000,
                &table,
                now,
            ),
            RouteAction::Forward { to: a }
        );
        let session = hub.session(&SessionId(7)).unwrap();
        assert_eq!(session.bytes, [1000, 2000]);
        assert_eq!(session.state, RelayState::Streaming);
        assert_eq!(session.o2p.inflight, 1000);
        assert_eq!(session.p2o.inflight, 2000);
    }

    #[test]
    fn server_relay_rejects_unknown_non_open_full_and_foreign_frames() {
        let now = Instant::now();
        let a = client(1);
        let b = client(2);
        let stranger = client(3);
        let table = online(&[a, b]);
        let with_stranger = online(&[a, b, stranger]);
        let mut hub = RelayHub::new(RelayLimits {
            max_sessions: 1,
            ..RelayLimits::default()
        });

        assert_eq!(
            hub.route(
                a,
                MsgType::RELAY,
                Flags::ENC.with(Flags::ROUTED),
                &prefix(1, StreamId::BLOCK),
                10,
                &table,
                now,
            ),
            RouteAction::Reject {
                to: a,
                reason: TrnReason::SessionUnknown
            }
        );
        assert_eq!(
            open(&mut hub, &table, a, 2, now),
            RouteAction::Open {
                to: b,
                id: SessionId(2)
            }
        );
        assert_eq!(
            open(&mut hub, &table, stranger, 3, now),
            RouteAction::Reject {
                to: stranger,
                reason: TrnReason::SessionFull
            }
        );
        assert_eq!(
            hub.route(
                stranger,
                MsgType::RELAY,
                Flags::ENC.with(Flags::ROUTED),
                &prefix(2, StreamId::BLOCK),
                10,
                &with_stranger,
                now,
            ),
            RouteAction::Reject {
                to: stranger,
                reason: TrnReason::Protocol
            }
        );
        assert_eq!(
            hub.route(
                a,
                MsgType::RELAY,
                Flags::ENC.with(Flags::ROUTED),
                &prefix(2, StreamId::BLOCK),
                RELAY_FRAME_BYTES as usize + 1,
                &table,
                now,
            ),
            RouteAction::Reject {
                to: a,
                reason: TrnReason::BadFrame
            }
        );
    }

    #[test]
    fn server_relay_accepts_the_largest_legal_stream_data_frame() {
        let now = Instant::now();
        let a = client(1);
        let b = client(2);
        let table = online(&[a, b]);
        let mut hub = RelayHub::new(RelayLimits::default());
        assert!(matches!(
            open(&mut hub, &table, a, 12, now),
            RouteAction::Open { .. }
        ));

        // One full fragment: CHUNK_PLAIN plus the sealed envelope, the route
        // prefix and the frame header. This is exactly what the uplink sends
        // for every non-final 64 KiB fragment of a data operation.
        let prefix = Prefix::Route(RoutePrefix::new(SessionId(12), StreamId::OP_DATA, 0, 1));
        let body = vec![0_u8; ENV_OVERHEAD as usize + CHUNK_PLAIN];
        let mut header = FrameHeader::new(
            MsgType::STREAM_DATA,
            Flags::ENC.with(Flags::ROUTED),
            0,
            Seq::UNSEQUENCED,
        );
        header.len = u32::try_from(prefix.encoded_len() + body.len()).unwrap();
        let frame = FrameBuf::new(header, prefix, body);
        assert_eq!(frame.encoded_len() as u64, RELAY_FRAME_BYTES);
        assert_eq!(
            hub.route(
                a,
                MsgType::STREAM_DATA,
                frame.header.flags,
                frame.prefix.as_route().unwrap(),
                frame.encoded_len(),
                &table,
                now,
            ),
            RouteAction::Forward { to: b }
        );
    }

    #[test]
    fn server_relay_window_is_eight_mib_per_direction_and_flow_releases_it() {
        let now = Instant::now();
        let a = client(1);
        let b = client(2);
        let table = online(&[a, b]);
        let mut hub = RelayHub::new(RelayLimits::default());
        assert!(matches!(
            open(&mut hub, &table, a, 9, now),
            RouteAction::Open { .. }
        ));

        let frame = RELAY_FRAME_BYTES as usize;
        let frames = RELAY_WINDOW_BYTES / RELAY_FRAME_BYTES;
        let filled = frames * RELAY_FRAME_BYTES;
        for _ in 0..frames {
            assert_eq!(
                hub.route(
                    a,
                    MsgType::RELAY,
                    Flags::ENC.with(Flags::ROUTED),
                    &prefix(9, StreamId::BLOCK),
                    frame,
                    &table,
                    now,
                ),
                RouteAction::Forward { to: b }
            );
        }
        assert_eq!(hub.session(&SessionId(9)).unwrap().o2p.inflight, filled);
        assert_eq!(
            hub.route(
                a,
                MsgType::RELAY,
                Flags::ENC.with(Flags::ROUTED),
                &prefix(9, StreamId::BLOCK),
                frame,
                &table,
                now,
            ),
            RouteAction::Reject {
                to: a,
                reason: TrnReason::Backpressure
            }
        );
        // The peer's FLOW releases exactly one frame of credit.
        assert_eq!(
            hub.on_flow(b, &prefix(9, StreamId::CTRL), frame as u32, &table, now),
            RouteAction::Forward { to: a }
        );
        assert_eq!(
            hub.route(
                a,
                MsgType::RELAY,
                Flags::ENC.with(Flags::ROUTED),
                &prefix(9, StreamId::BLOCK),
                frame,
                &table,
                now,
            ),
            RouteAction::Forward { to: b }
        );
        let session = hub.session(&SessionId(9)).unwrap();
        assert_eq!(session.o2p.inflight, filled);
        assert_eq!(session.bytes[0], filled + frame as u64);
    }

    #[test]
    fn server_relay_sync_end_releases_the_slot() {
        let now = Instant::now();
        let a = client(1);
        let b = client(2);
        let table = online(&[a, b]);
        let mut hub = RelayHub::new(RelayLimits::default());
        assert!(matches!(
            open(&mut hub, &table, a, 11, now),
            RouteAction::Open { .. }
        ));
        assert_eq!(
            hub.route(
                a,
                MsgType::SYNC_END,
                Flags::ROUTED,
                &prefix(11, StreamId::CTRL),
                8,
                &table,
                now,
            ),
            RouteAction::Forward { to: b }
        );
        assert!(hub.session(&SessionId(11)).is_none());
        assert_eq!(hub.session_count(), 0);
    }

    #[test]
    fn server_relay_disconnect_releases_slots_and_cools_the_peer() {
        let now = Instant::now();
        let a = client(1);
        let b = client(2);
        let c = client(3);
        let table = online(&[a, b, c]);
        let mut hub = RelayHub::new(RelayLimits::default());
        assert!(matches!(
            open(&mut hub, &table, a, 13, now),
            RouteAction::Open { .. }
        ));
        let failed = hub.session(&SessionId(13)).unwrap().peer;
        let removed = hub.drop_by_client(failed, now);
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].survivor(failed), Some(a));
        assert_eq!(hub.session_count(), 0);
        // The failed source is cooling down for 60s, so the next open must
        // choose the other one.
        let next = open(&mut hub, &table, a, 14, now + Duration::from_secs(1));
        let RouteAction::Open { to, .. } = next else {
            panic!("expected a fresh source, got {next:?}");
        };
        assert_eq!(
            hub.session(&SessionId(14)).unwrap().peer,
            to,
            "the failed source must not be reselected during cooldown"
        );
        assert_ne!(to, failed, "the failed source is excluded");
    }

    #[test]
    fn server_relay_source_change_budget_is_three() {
        let now = Instant::now();
        let a = client(1);
        let b = client(2);
        let c = client(3);
        let table = online(&[a, b, c]);
        let mut hub = RelayHub::new(RelayLimits::default());
        assert!(matches!(
            open(&mut hub, &table, a, 20, now),
            RouteAction::Open { .. }
        ));
        for step in 1..=3_u64 {
            let at = now + Duration::from_secs(61 * step);
            let action = open(&mut hub, &table, a, 20 + step as u128, at);
            assert!(
                matches!(action, RouteAction::Open { .. }),
                "replacement {step} is within budget: {action:?}"
            );
        }
        let at = now + Duration::from_secs(61 * 4);
        assert_eq!(
            open(&mut hub, &table, a, 30, at),
            RouteAction::Reject {
                to: a,
                reason: TrnReason::NoPeer
            }
        );
        assert_eq!(hub.peers.retries(a), 3);
    }

    #[test]
    fn server_relay_idle_reap_releases_the_slot_without_cooling_the_source() {
        let now = Instant::now();
        let a = client(1);
        let b = client(2);
        let c = client(3);
        let table = online(&[a, b]);
        let mut hub = RelayHub::new(RelayLimits {
            idle_timeout: Duration::from_secs(5),
            ..RelayLimits::default()
        });
        assert_eq!(
            open(&mut hub, &table, a, 40, now),
            RouteAction::Open {
                to: b,
                id: SessionId(40)
            }
        );
        assert!(hub.reap(now + Duration::from_secs(4)).is_empty());
        let later = now + Duration::from_secs(6);
        let reaped = hub.reap(later);
        assert_eq!(reaped.len(), 1);
        assert_eq!(reaped[0].id, SessionId(40));
        assert_eq!(reaped[0].survivor(a), Some(b));
        assert!(!hub.peers.is_cooling(b, later));
        assert_eq!(hub.peers.retries(a), 0);

        // Another origin still finds the same holder: an idle route is not a
        // peer failure.
        let second = online(&[b, c]);
        assert_eq!(
            open(&mut hub, &second, c, 41, later),
            RouteAction::Open {
                to: b,
                id: SessionId(41)
            }
        );
    }

    #[test]
    fn server_relay_absolute_expiry_releases_the_slot_without_cooling_the_source() {
        let now = Instant::now();
        let a = client(1);
        let b = client(2);
        let table = online(&[a, b]);
        let mut hub = RelayHub::new(RelayLimits {
            session_ttl: Duration::from_secs(5),
            ..RelayLimits::default()
        });
        assert_eq!(
            open(&mut hub, &table, a, 42, now),
            RouteAction::Open {
                to: b,
                id: SessionId(42)
            }
        );
        // The route is still active; only the absolute deadline fires.
        let later = now + Duration::from_secs(6);
        let reaped = hub.reap(later);
        assert_eq!(reaped.len(), 1);
        assert!(!hub.peers.is_cooling(b, later));
        assert_eq!(hub.peers.retries(a), 0);
    }

    use crate::protocol::{
        ClientId as Id, FrameBuf, FrameHeader, Message, MsgType, Prefix, Seq, StreamId,
        decode_plain,
    };
    use crate::server::Epoch;
    use crate::server::config::ServeConfig;
    use crate::server::sequencer::{HelloReply, HelloRequest, Metrics, Sequencer};
    use crate::transport::MpscBody;
    use std::sync::Arc;

    async fn register(
        sequencer: &Sequencer,
        id: Id,
        nonce: u64,
        outbox: &OutboxConfig,
    ) -> (HelloReply, MpscBody) {
        let (outbox, data, ctrl) = Outbox::new(outbox);
        let reply = sequencer
            .hello(HelloRequest {
                nonce,
                client_id: id,
                epoch_seen: sequencer.epoch().get(),
                applied_seq: Seq::UNSEQUENCED,
                peer: PeerId::from_serial(nonce),
                outbox,
                data,
                ctrl,
            })
            .await
            .unwrap();
        let (out, body) = MpscBody::channel(8);
        sequencer.events(nonce, out).await.unwrap();
        (reply, body)
    }

    fn ordered_frame() -> FrameBuf {
        let body = vec![0x5a; 32];
        let mut header = FrameHeader::new(MsgType::ORDERED, Flags::ENC, 0, Seq::UNSEQUENCED);
        header.len = u32::try_from(body.len()).unwrap();
        FrameBuf::new(header, Prefix::None, body)
    }

    fn relay_frame(id: u128, stream: StreamId, body: &[u8]) -> FrameBuf {
        let prefix = Prefix::Route(RoutePrefix::new(SessionId(id), stream, 0, 0));
        let mut header = FrameHeader::new(
            MsgType::RELAY,
            Flags::ENC.with(Flags::ROUTED),
            0,
            Seq::UNSEQUENCED,
        );
        header.len = u32::try_from(prefix.encoded_len() + body.len()).unwrap();
        FrameBuf::new(header, prefix, body.to_vec())
    }

    fn sync_end_frame(id: u128) -> FrameBuf {
        let body = crate::protocol::SyncEnd {
            reason: crate::protocol::SyncEndReason::Done,
            detail: None,
        }
        .encode()
        .unwrap();
        let prefix = Prefix::Route(RoutePrefix::new(SessionId(id), StreamId::CTRL, 0, 0));
        let mut header = FrameHeader::new(MsgType::SYNC_END, Flags::ROUTED, 0, Seq::UNSEQUENCED);
        header.len = u32::try_from(prefix.encoded_len() + body.len()).unwrap();
        FrameBuf::new(header, prefix, body)
    }

    fn kick_reason(bytes: &bytes::Bytes) -> crate::protocol::KickReason {
        let mut decoder = crate::protocol::FrameDecoder::new(crate::protocol::Limits::default());
        decoder.push(bytes).unwrap();
        let frame = decoder.next_frame_owned().unwrap().unwrap();
        assert_eq!(frame.header.msg_type, MsgType::KICK);
        match decode_plain(
            MsgType::KICK,
            &frame.body,
            &crate::protocol::Limits::default(),
        )
        .unwrap()
        {
            Message::Kick(kick) => kick.reason,
            other => panic!("expected KICK, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn server_relay_mixed_load_keeps_ordering_and_the_actor_responsive() {
        let config = ServeConfig::for_tests();
        let outbox = config.outbox;
        let epoch = Epoch::new(77);
        let metrics = Arc::new(Metrics::new(epoch));
        let (sequencer, task) = Sequencer::start(Arc::new(config), epoch, Arc::clone(&metrics));

        let mut replies = Vec::new();
        let mut bodies = Vec::new();
        for index in 0..8_u8 {
            let (reply, body) =
                register(&sequencer, client(index + 1), u64::from(index) + 1, &outbox).await;
            replies.push(reply);
            bodies.push(body);
        }
        let _bodies = bodies;
        let mut observer_data = replies.remove(0).data;
        // Every non-observer writer drains its queues so no session is kicked
        // for queue overflow during the mixed run.
        let mut drains = Vec::new();
        for reply in replies {
            let mut data = reply.data;
            let mut ctrl = reply.ctrl;
            drains.push(tokio::spawn(async move {
                loop {
                    tokio::select! {
                        biased;
                        Some(_) = ctrl.recv() => {}
                        Some(_) = data.recv() => {}
                        else => break,
                    }
                }
            }));
        }

        // Four routed sessions, opened by four distinct origins.
        for index in 1..=4_u8 {
            let frame = relay_frame(u128::from(index), StreamId::CTRL, b"open");
            sequencer.relay(client(index + 1), frame).await.unwrap();
        }
        // Interleave 100 sequenced ops with 100 routed frames.
        for step in 0..100_u64 {
            sequencer.ordered(client(1), ordered_frame()).await.unwrap();
            let origin = (step % 4) as u8 + 2;
            sequencer
                .relay(
                    client(origin),
                    relay_frame(u128::from(origin - 1), StreamId::BLOCK, b"payload"),
                )
                .await
                .unwrap();
        }

        let mut seqs = Vec::with_capacity(100);
        while seqs.len() < 100 {
            let bytes = observer_data.recv().await.unwrap();
            let mut decoder =
                crate::protocol::FrameDecoder::new(crate::protocol::Limits::default());
            decoder.push(&bytes).unwrap();
            let frame = decoder.next_frame_owned().unwrap().unwrap();
            if frame.header.msg_type == MsgType::ORDERED {
                seqs.push(frame.header.seq.get());
            }
        }
        assert_eq!(seqs, (1..=100).collect::<Vec<_>>());
        assert_eq!(sequencer.current_seq(), Seq(100));
        assert_eq!(
            metrics
                .sync_sessions
                .load(std::sync::atomic::Ordering::Acquire),
            4,
            "routed frames do not consume sequence numbers"
        );
        eprintln!(
            "W10 evidence: mixed load 100 ORDERED + 100 RELAY; seq 1..=100 no gaps; sync_sessions={}",
            metrics
                .sync_sessions
                .load(std::sync::atomic::Ordering::Acquire)
        );

        sequencer.shutdown().await.unwrap();
        task.await.unwrap();
        for drain in drains {
            drain.abort();
        }
    }

    #[tokio::test]
    async fn server_relay_forwards_the_same_bytes_without_rewriting() {
        let config = ServeConfig::for_tests();
        let outbox = config.outbox;
        let epoch = Epoch::new(91);
        let metrics = Arc::new(Metrics::new(epoch));
        let (sequencer, task) = Sequencer::start(Arc::new(config), epoch, Arc::clone(&metrics));
        let (_origin, _origin_body) = register(&sequencer, client(1), 1, &outbox).await;
        let (peer, _peer_body) = register(&sequencer, client(2), 2, &outbox).await;
        let mut peer_data = peer.data;

        sequencer
            .relay(client(1), relay_frame(7, StreamId::CTRL, b"open"))
            .await
            .unwrap();
        let frame = relay_frame(7, StreamId::BLOCK, b"ciphertext-that-must-not-change");
        let expected = crate::protocol::encode_frame(&crate::protocol::FrameRef::new(
            &frame.header,
            &frame.prefix,
            &frame.body,
        ))
        .unwrap();
        sequencer.relay(client(1), frame).await.unwrap();
        let forwarded = peer_data.recv().await.unwrap();
        assert_eq!(
            forwarded.as_ref(),
            expected.as_slice(),
            "the forwarded frame is byte-identical, including route_prefix"
        );
        eprintln!(
            "W10 evidence: relay forwarded {} bytes unchanged (header+route_prefix+body)",
            forwarded.len()
        );
        sequencer.relay(client(1), sync_end_frame(7)).await.unwrap();
        let _ = sequencer.snapshot().await.unwrap();
        assert_eq!(
            metrics
                .sync_sessions
                .load(std::sync::atomic::Ordering::Acquire),
            0
        );
        sequencer.shutdown().await.unwrap();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn server_relay_duplicate_client_kicks_the_old_session_and_frees_its_slots() {
        let config = ServeConfig::for_tests();
        let outbox = config.outbox;
        let epoch = Epoch::new(88);
        let metrics = Arc::new(Metrics::new(epoch));
        let (sequencer, task) = Sequencer::start(Arc::new(config), epoch, Arc::clone(&metrics));

        let (old, _old_body) = register(&sequencer, client(1), 1, &outbox).await;
        let mut old_ctrl = old.ctrl;
        let _old_data = old.data;
        let (_peer, _peer_body) = register(&sequencer, client(2), 2, &outbox).await;

        // Give the old session a routed slot so T4 must release it too.
        sequencer
            .relay(client(1), relay_frame(99, StreamId::CTRL, b"open"))
            .await
            .unwrap();

        let (_new, _new_body) = register(&sequencer, client(1), 3, &outbox).await;
        let mut reason = None;
        while let Some(bytes) = old_ctrl.recv().await {
            if bytes.len() > 2 && bytes[2] == MsgType::KICK.get() {
                reason = Some(kick_reason(&bytes));
                break;
            }
        }
        assert_eq!(reason, Some(crate::protocol::KickReason::DuplicateClient));
        // A snapshot command is ordered after the HELLO, so the mirrors are
        // current by the time it returns.
        let snapshot = sequencer.snapshot().await.unwrap();
        assert_eq!(snapshot.clients, 2);
        assert_eq!(
            metrics
                .sync_sessions
                .load(std::sync::atomic::Ordering::Acquire),
            0,
            "T4 released the old session's relay slot"
        );
        eprintln!(
            "W10 evidence: duplicate client -> KICK{{DUPLICATE_CLIENT}}; relay slots={}",
            metrics
                .sync_sessions
                .load(std::sync::atomic::Ordering::Acquire)
        );

        sequencer.shutdown().await.unwrap();
        task.await.unwrap();
    }
}
