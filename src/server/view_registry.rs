//! View-source registry: which online holder serves a joiner's manifest view.
//!
//! The manifest-only join path needs one holder that is `Online`, whose writer
//! halves are alive, and whose applied watermark equals the current sequence.
//! `WELCOME` names that holder in three optional fields
//! (`F_VIEW_HOLDER`, `F_VIEW_SEQ`, `F_VIEW_SESSION`); the third is a random
//! 128-bit token the joiner carries on its first `RELAY{CTRL,0,0}` frame.
//!
//! This module owns the server side of that promise:
//!
//! ```text
//! select_view  caught-up online holder, smallest client_id → ViewSource
//! route        session token → { joiner, holder, deadline }
//! resolve      relay opening finds the route; spend retires it on success
//! invalidate   either endpoint leaving drops every route it touches
//! on_tick      unused routes expire after 120 s
//! ```
//!
//! A route is a capability, not a hint. The token is random, bound to one
//! joiner, and spent on first use, so a copied `WELCOME` cannot redirect
//! another client and a stale token cannot survive a holder restart.
//!
//! Selection observes only server-visible state: no frame is parsed, no
//! snapshot is read, and the holder never learns it was chosen.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::protocol::{ClientId, Seq, SessionId};

use super::online::{OnlineTable, SessionState};

/// Lifetime of one view route, counted from `WELCOME`.
///
/// The joiner must open its relay session inside this window; a token older
/// than this is void even if the holder is still online.
pub const VIEW_ROUTE_TTL: Duration = Duration::from_secs(120);

/// What the server can offer a joiner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ViewChoice {
    /// Another client serves the view over a relay session.
    Holder(ViewSource),
    /// The joiner is the only member and has already applied `seq`; it may
    /// use its own local manifest.
    SelfView {
        /// Sequence the local manifest must cover.
        seq: Seq,
    },
}

/// One selected view source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ViewSource {
    /// Client that serves the view.
    pub holder: ClientId,
    /// Sequence the holder has applied; equal to the joiner's current.
    pub seq: Seq,
    /// Relay session token to place in `WELCOME`.
    pub session: SessionId,
}

/// One outstanding token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ViewRoute {
    /// Client the token was minted for.
    pub joiner: ClientId,
    /// Client expected to serve.
    pub holder: ClientId,
    /// Instant after which the token is void.
    pub expires: Instant,
}

/// What a token lookup found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ViewLookup {
    /// The token belongs to this joiner and is still valid; it is now spent.
    Hit(ClientId),
    /// The token exists but was minted for another joiner; it stays valid
    /// for its owner.
    Mismatch,
    /// The token outlived [`VIEW_ROUTE_TTL`]; it has been removed.
    Expired,
    /// No route carries this token.
    Unknown,
}

/// Outstanding view routes, keyed by the session token in `WELCOME`.
#[derive(Debug, Default)]
pub struct ViewRegistry {
    routes: HashMap<SessionId, ViewRoute>,
}

impl ViewRegistry {
    /// Empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of live routes.
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// Whether no route exists.
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// Borrow one route. Diagnostics and tests only.
    pub fn route(&self, session: &SessionId) -> Option<&ViewRoute> {
        self.routes.get(session)
    }

    /// Choose a holder for `joiner` and record the route.
    ///
    /// A candidate must be a different client, `Online`, have both outbox
    /// channels open, and report exactly `current` as its applied sequence.
    /// Among candidates the smallest `client_id` by bytes wins, so the
    /// choice is deterministic for a given table.
    pub fn select_view(
        &mut self,
        online: &OnlineTable,
        joiner: ClientId,
        current: Seq,
        now: Instant,
    ) -> Option<ViewSource> {
        let holder = online
            .iter()
            .filter(|(client, session)| {
                client.as_bytes() != joiner.as_bytes()
                    && session.state == SessionState::Online
                    && !session.outbox.data.is_closed()
                    && !session.outbox.ctrl.is_closed()
                    && session.watermark.applied_seq() == current
            })
            .map(|(client, _)| *client)
            .min_by(|left, right| left.as_bytes().cmp(right.as_bytes()))?;
        let session = self.mint_session();
        self.routes.insert(
            session,
            ViewRoute {
                joiner,
                holder,
                expires: now + VIEW_ROUTE_TTL,
            },
        );
        Some(ViewSource {
            holder,
            seq: current,
            session,
        })
    }

    /// Choose a holder, or fall back to a self view when the joiner is the
    /// only member.
    ///
    /// A holder always wins. A self view requires all of:
    ///
    /// * `current` is sequenced (a zero watermark already has an exact empty
    ///   view and needs no special case),
    /// * the client reported the current epoch,
    /// * its applied watermark is `current`, or one behind it: a disconnect
    ///   while `Online` injects a `LEAVE` pseudo-operation that consumes a
    ///   sequence but carries no content,
    /// * no other identity is attached (`OnlineTable::is_alone`),
    /// * the caller allows it (both sides advertised `VIEW_SELF`).
    ///
    /// A self view mints no session and records no route: there is nothing to
    /// redeem later, and a reconnect must recompute the decision.
    #[allow(clippy::too_many_arguments)]
    pub fn select_view_or_self(
        &mut self,
        online: &OnlineTable,
        joiner: ClientId,
        current: Seq,
        applied: Seq,
        epoch_seen: u64,
        epoch: u64,
        allow_self: bool,
        now: Instant,
    ) -> Option<ViewChoice> {
        if let Some(source) = self.select_view(online, joiner, current, now) {
            return Some(ViewChoice::Holder(source));
        }
        // A one-sequence gap is the `LEAVE` a crash-time disconnect injects.
        // The caller additionally proves the gap contains no `ORDERED`; this
        // function only enforces the bound.
        let caught_up = applied == current || applied.checked_next() == Some(current);
        let self_view = allow_self
            && current.is_sequenced()
            && epoch_seen == epoch
            && caught_up
            && online.is_alone(&joiner);
        self_view.then_some(ViewChoice::SelfView { seq: current })
    }

    /// Look `session` up for `joiner`.
    ///
    /// A hit does not consume the token: the caller retires it with
    /// [`ViewRegistry::spend`] only after the relay slot exists, so a holder
    /// that is briefly unavailable does not silently reroute the retry. An
    /// expired token is removed; a foreign lookup leaves the owner's token
    /// untouched.
    pub fn resolve(&mut self, joiner: ClientId, session: SessionId, now: Instant) -> ViewLookup {
        let Some(route) = self.routes.get(&session).copied() else {
            return ViewLookup::Unknown;
        };
        if now >= route.expires {
            self.routes.remove(&session);
            return ViewLookup::Expired;
        }
        if route.joiner.as_bytes() != joiner.as_bytes() {
            return ViewLookup::Mismatch;
        }
        ViewLookup::Hit(route.holder)
    }

    /// Retire one token after its relay slot opened.
    ///
    /// Returns whether a route was present.
    pub fn spend(&mut self, session: SessionId) -> bool {
        self.routes.remove(&session).is_some()
    }

    /// Drop every route in which `client` is either endpoint.
    ///
    /// Returns the number of routes removed.
    pub fn invalidate(&mut self, client: ClientId) -> usize {
        let before = self.routes.len();
        self.routes.retain(|_, route| {
            route.joiner.as_bytes() != client.as_bytes()
                && route.holder.as_bytes() != client.as_bytes()
        });
        before - self.routes.len()
    }

    /// Drop expired routes. Returns the number removed.
    pub fn on_tick(&mut self, now: Instant) -> usize {
        let before = self.routes.len();
        self.routes.retain(|_, route| route.expires > now);
        before - self.routes.len()
    }

    /// Draw a token that is nonzero and not already in the table.
    fn mint_session(&self) -> SessionId {
        loop {
            let candidate = SessionId(rand::random::<u128>());
            if candidate != SessionId::ZERO && !self.routes.contains_key(&candidate) {
                return candidate;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use bytes::Bytes;
    use tokio::sync::mpsc;

    use crate::server::config::OutboxConfig;
    use crate::server::online::{Outbox, Session, SessionInit};
    use crate::transport::PeerId;

    fn client(byte: u8) -> ClientId {
        ClientId::from_bytes([byte; 16])
    }

    type Receivers = (mpsc::Receiver<Bytes>, mpsc::Receiver<Bytes>);

    fn session(byte: u8, applied: Seq, state: SessionState) -> (Session, Receivers) {
        let (outbox, data, ctrl) = Outbox::new(&OutboxConfig::default());
        let mut session = Session::new(SessionInit {
            client_id: client(byte),
            nonce: u64::from(byte),
            peer: PeerId::from_serial(u64::from(byte)),
            outbox,
            epoch: 1,
            epoch_seen: 1,
            applied_seq: applied,
            current_seq: applied,
            now: Instant::now(),
        });
        session.state = state;
        (session, (data, ctrl))
    }

    /// Table plus the writer halves, so `is_closed()` stays false.
    struct Online {
        table: OnlineTable,
        _keep: Vec<Receivers>,
    }

    fn online(entries: &[(u8, Seq)]) -> Online {
        let mut table = OnlineTable::new();
        let mut keep = Vec::with_capacity(entries.len());
        for (byte, applied) in entries {
            let (session, receivers) = session(*byte, *applied, SessionState::Online);
            table.insert(session);
            keep.push(receivers);
        }
        Online { table, _keep: keep }
    }

    #[test]
    fn select_view_requires_caught_up_open_online_and_foreign() {
        let now = Instant::now();
        let joiner = client(0x10);
        let mut table = OnlineTable::new();
        let mut keep = Vec::new();

        // Caught up, but the writer is gone: not a holder.
        let (first, (data, ctrl)) = session(0x01, Seq(5), SessionState::Online);
        table.insert(first);
        drop((data, ctrl));

        // Online but stale.
        let (stale, receivers) = session(0x02, Seq(4), SessionState::Online);
        table.insert(stale);
        keep.push(receivers);

        // Caught up but already leaving the broadcast set.
        let (leaving, receivers) = session(0x03, Seq(5), SessionState::Kicking);
        table.insert(leaving);
        keep.push(receivers);

        // The joiner itself, caught up: never its own source.
        let (self_session, receivers) = session(0x10, Seq(5), SessionState::Online);
        table.insert(self_session);
        keep.push(receivers);

        // Smallest eligible id.
        let (holder, receivers) = session(0x04, Seq(5), SessionState::Online);
        table.insert(holder);
        keep.push(receivers);

        let mut registry = ViewRegistry::new();
        let source = registry.select_view(&table, joiner, Seq(5), now).unwrap();
        assert_eq!(source.holder, client(0x04));
        assert_eq!(source.seq, Seq(5));
        assert_ne!(source.session, SessionId::ZERO);
        assert_eq!(registry.len(), 1);
        let route = registry.route(&source.session).unwrap();
        assert_eq!(route.joiner, joiner);
        assert_eq!(route.holder, client(0x04));
        assert_eq!(route.expires, now + VIEW_ROUTE_TTL);
    }

    #[test]
    fn select_view_returns_none_when_no_holder_qualifies() {
        let now = Instant::now();
        let joiner = client(0x10);
        let table = online(&[(0x10, Seq(5)), (0x11, Seq(4))]);
        let mut registry = ViewRegistry::new();
        assert_eq!(
            registry.select_view(&table.table, joiner, Seq(5), now),
            None
        );
        assert!(registry.is_empty());
    }

    #[test]
    fn resolve_is_bound_to_the_joiner_and_spend_retires_the_token() {
        let now = Instant::now();
        let joiner = client(0x10);
        let intruder = client(0x11);
        let table = online(&[(0x10, Seq(5)), (0x20, Seq(5))]);
        let mut registry = ViewRegistry::new();
        let source = registry
            .select_view(&table.table, joiner, Seq(5), now)
            .unwrap();

        assert_eq!(
            registry.resolve(intruder, source.session, now),
            ViewLookup::Mismatch
        );
        assert_eq!(
            registry.resolve(joiner, source.session, now),
            ViewLookup::Hit(client(0x20)),
            "a failed opening keeps the token for the retry"
        );
        assert!(registry.spend(source.session));
        assert_eq!(
            registry.resolve(joiner, source.session, now),
            ViewLookup::Unknown,
            "a spent token opens no further relay session"
        );
        assert!(!registry.spend(source.session));
    }

    #[test]
    fn expired_routes_are_refused_and_reaped() {
        let now = Instant::now();
        let joiner = client(0x10);
        let table = online(&[(0x10, Seq(5)), (0x20, Seq(5))]);
        let mut registry = ViewRegistry::new();
        let source = registry
            .select_view(&table.table, joiner, Seq(5), now)
            .unwrap();

        let later = now + VIEW_ROUTE_TTL + Duration::from_secs(1);
        assert_eq!(
            registry.resolve(joiner, source.session, later),
            ViewLookup::Expired
        );
        assert!(registry.is_empty());

        let source = registry
            .select_view(&table.table, joiner, Seq(5), now)
            .unwrap();
        assert_eq!(registry.on_tick(later), 1);
        assert!(registry.route(&source.session).is_none());
    }

    #[test]
    fn invalidate_drops_routes_on_either_endpoint() {
        let now = Instant::now();
        let a = client(0x10);
        let b = client(0x20);
        let c = client(0x30);
        // `a` is only a joiner here, so both selections land on `b`.
        let table = online(&[(0x20, Seq(5)), (0x30, Seq(5))]);
        let mut registry = ViewRegistry::new();
        let first = registry.select_view(&table.table, a, Seq(5), now).unwrap();
        let second = registry.select_view(&table.table, c, Seq(5), now).unwrap();
        assert_eq!(first.holder, b);
        assert_eq!(second.holder, b);

        // `a` leaving drops its own token; `b` leaving drops every token
        // that names it as holder.
        assert_eq!(registry.invalidate(a), 1);
        assert_eq!(registry.len(), 1);
        assert_eq!(registry.invalidate(b), 1);
        assert!(registry.is_empty());
    }

    #[test]
    fn minted_tokens_differ_between_joiners() {
        let now = Instant::now();
        let table = online(&[(0x10, Seq(5)), (0x20, Seq(5)), (0x30, Seq(5))]);
        let mut registry = ViewRegistry::new();
        let first = registry
            .select_view(&table.table, client(0x10), Seq(5), now)
            .unwrap();
        let second = registry
            .select_view(&table.table, client(0x30), Seq(5), now)
            .unwrap();
        assert_ne!(first.session, second.session);
        assert_ne!(first.session, SessionId::ZERO);
        assert_ne!(second.session, SessionId::ZERO);
    }

    #[allow(clippy::too_many_arguments)]
    fn choose(
        registry: &mut ViewRegistry,
        table: &OnlineTable,
        joiner: ClientId,
        current: Seq,
        applied: Seq,
        epoch_seen: u64,
        epoch: u64,
        allow_self: bool,
        now: Instant,
    ) -> Option<ViewChoice> {
        registry.select_view_or_self(
            table, joiner, current, applied, epoch_seen, epoch, allow_self, now,
        )
    }

    #[test]
    fn self_view_requires_a_solo_caught_up_current_epoch_client() {
        let now = Instant::now();
        let joiner = client(0x10);
        let table = online(&[]);
        let mut registry = ViewRegistry::new();

        assert_eq!(
            choose(
                &mut registry,
                &table.table,
                joiner,
                Seq(5),
                Seq(5),
                1,
                1,
                true,
                now
            ),
            Some(ViewChoice::SelfView { seq: Seq(5) })
        );
        assert!(
            registry.is_empty(),
            "a self view mints no session and records no route"
        );

        // Repeating the decision after a duplicate HELLO leaves nothing
        // behind either.
        assert_eq!(
            choose(
                &mut registry,
                &table.table,
                joiner,
                Seq(5),
                Seq(5),
                1,
                1,
                true,
                now
            ),
            Some(ViewChoice::SelfView { seq: Seq(5) })
        );
        assert!(registry.is_empty());
    }

    #[test]
    fn self_view_rejects_a_lagging_foreign_epoch_or_zero_watermark() {
        let now = Instant::now();
        let joiner = client(0x10);
        let table = online(&[]);
        let mut registry = ViewRegistry::new();

        assert_eq!(
            choose(
                &mut registry,
                &table.table,
                joiner,
                Seq(5),
                Seq(3),
                1,
                1,
                true,
                now
            ),
            None,
            "a gap larger than one LEAVE is not a self view"
        );
        assert_eq!(
            choose(
                &mut registry,
                &table.table,
                joiner,
                Seq(5),
                Seq(5),
                0,
                1,
                true,
                now
            ),
            None,
            "epoch mismatch"
        );
        assert_eq!(
            choose(
                &mut registry,
                &table.table,
                joiner,
                Seq::UNSEQUENCED,
                Seq::UNSEQUENCED,
                1,
                1,
                true,
                now
            ),
            None,
            "zero watermark has an exact empty view already"
        );
        assert_eq!(
            choose(
                &mut registry,
                &table.table,
                joiner,
                Seq(5),
                Seq(5),
                1,
                1,
                false,
                now
            ),
            None,
            "VIEW_SELF was not negotiated"
        );
    }

    #[test]
    fn self_view_tolerates_exactly_one_leave_gap() {
        let now = Instant::now();
        let joiner = client(0x10);
        let table = online(&[]);
        let mut registry = ViewRegistry::new();

        // A crash-time disconnect injects LEAVE at `current`; the client
        // applied everything up to `current - 1`.
        assert_eq!(
            choose(
                &mut registry,
                &table.table,
                joiner,
                Seq(5),
                Seq(4),
                1,
                1,
                true,
                now
            ),
            Some(ViewChoice::SelfView { seq: Seq(5) })
        );
        assert!(registry.is_empty());

        // Two missing sequences cannot both be LEAVE pseudo-operations in a
        // single disconnect.
        assert_eq!(
            choose(
                &mut registry,
                &table.table,
                joiner,
                Seq(5),
                Seq(3),
                1,
                1,
                true,
                now
            ),
            None
        );
    }

    #[test]
    fn self_view_is_refused_while_any_other_identity_is_attached() {
        let now = Instant::now();
        let joiner = client(0x10);
        let other = client(0x20);

        for state in [
            SessionState::AwaitingDownstream,
            SessionState::Resyncing,
            SessionState::Kicking,
        ] {
            let mut table = online(&[(0x20, Seq(5))]);
            table.table.get_mut(&other).unwrap().state = state;
            let mut registry = ViewRegistry::new();
            assert_eq!(
                choose(
                    &mut registry,
                    &table.table,
                    joiner,
                    Seq(5),
                    Seq(5),
                    1,
                    1,
                    true,
                    now
                ),
                None,
                "another attached identity blocks a self view"
            );
            assert!(registry.is_empty());
        }

        // A stale online peer blocks it too: no holder, and not alone.
        let table = online(&[(0x20, Seq(4))]);
        let mut registry = ViewRegistry::new();
        assert_eq!(
            choose(
                &mut registry,
                &table.table,
                joiner,
                Seq(5),
                Seq(5),
                1,
                1,
                true,
                now
            ),
            None
        );
    }

    #[test]
    fn a_caught_up_holder_wins_over_a_self_view() {
        let now = Instant::now();
        let joiner = client(0x10);
        let table = online(&[(0x20, Seq(5)), (0x30, Seq(5))]);
        let mut registry = ViewRegistry::new();
        let choice = choose(
            &mut registry,
            &table.table,
            joiner,
            Seq(5),
            Seq(5),
            1,
            1,
            true,
            now,
        );
        let Some(ViewChoice::Holder(source)) = choice else {
            panic!("a holder must win, got {choice:?}");
        };
        assert_eq!(source.holder, client(0x20));
        assert_eq!(registry.len(), 1);
    }
}
