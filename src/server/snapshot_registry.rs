//! Snapshot metadata registry: OFFER, GRANT, ANNOUNCE, `latest_snapshot`.
//!
//! The server never touches snapshot content. It records three opaque
//! values and hands them back in `WELCOME`:
//!
//! ```text
//! latest_snapshot { covered_seq, root_chunk_id, holder }
//! ```
//!
//! # Flow
//!
//! ```text
//! OFFER     client applied covered_seq (k × 4096)   → candidate set
//! GRANT     tick: smallest covered_seq, then smallest client_id
//! ANNOUNCE  holder only, monotonic, covered ≤ current → latest
//! timeout   30 s without ANNOUNCE                    → pending cleared
//! NOW       latest missing/stale, 1/min/cluster      → smallest online id
//! ```
//!
//! `covered_seq` is an existing watermark, not an event: none of these
//! messages occupies a sequence (49 A7). The frozen wire (44) carries them
//! as out-of-band control messages; this registry is the server-side state
//! they mutate. It deliberately has no encoder: inventing a frame type here
//! would break the 14-type table.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use crate::protocol::{ClientId, Seq};

use super::online::{OnlineTable, SessionState};

/// Snapshot cadence in sequence numbers (39 §2.4).
pub const SNAPSHOT_INTERVAL: u64 = 4096;

/// At most one `SNAPSHOT_NOW` per cluster per minute (39 §2.4).
pub const SNAPSHOT_MIN_NOW_INTERVAL: Duration = Duration::from_secs(60);

/// A snapshot older than this counts as absent (42 §2.5).
pub const SNAPSHOT_STALE_AFTER: Duration = Duration::from_secs(10 * 60);

/// Time a grantee has to announce (42 §5.6).
pub const SNAPSHOT_GRANT_DEADLINE: Duration = Duration::from_secs(30);

/// Snapshot registry tunables.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotLimits {
    /// `covered_seq` must be a multiple of this.
    pub interval: u64,
    /// Minimum spacing between `SNAPSHOT_NOW` grants.
    pub min_now_interval: Duration,
    /// Age at which `latest` is ignored.
    pub stale_after: Duration,
    /// Grant lifetime.
    pub grant_deadline: Duration,
}

impl Default for SnapshotLimits {
    fn default() -> Self {
        Self {
            interval: SNAPSHOT_INTERVAL,
            min_now_interval: SNAPSHOT_MIN_NOW_INTERVAL,
            stale_after: SNAPSHOT_STALE_AFTER,
            grant_deadline: SNAPSHOT_GRANT_DEADLINE,
        }
    }
}

/// One registered snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotEntry {
    /// Sequence covered by the snapshot; not itself a sequence event.
    pub covered_seq: Seq,
    /// Opaque root chunk identifier.
    pub root_chunk_id: [u8; 32],
    /// Client that can serve the index over `RELAY`.
    pub holder: ClientId,
    /// Registration instant.
    pub registered_at: Instant,
}

/// A grant waiting for its announcement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Grant {
    /// Sequence the grantee must cover.
    pub covered_seq: Seq,
    /// Selected client.
    pub holder: ClientId,
    /// Deadline after which the grant is void.
    pub deadline: Instant,
}

/// What the actor must send for one tick.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotAction {
    /// Authorize `to` to generate `covered_seq`.
    Grant {
        /// Grantee.
        to: ClientId,
        /// Covered sequence.
        covered_seq: Seq,
        /// Deadline carried in the grant.
        deadline: Instant,
    },
    /// Ask `to` to generate a snapshot immediately.
    Now {
        /// Selected client.
        to: ClientId,
        /// Sequence to cover, normally the current one.
        covered_seq: Seq,
        /// Deadline carried in the request.
        deadline: Instant,
    },
}

/// Server-side snapshot metadata.
#[derive(Debug)]
pub struct SnapshotRegistry {
    latest: Option<SnapshotEntry>,
    offers: BTreeMap<Seq, BTreeSet<ClientId>>,
    pending: Option<Grant>,
    last_now_at: Option<Instant>,
    limits: SnapshotLimits,
}

impl SnapshotRegistry {
    /// Empty registry.
    pub fn new(limits: SnapshotLimits) -> Self {
        Self {
            latest: None,
            offers: BTreeMap::new(),
            pending: None,
            last_now_at: None,
            limits,
        }
    }

    /// Borrow the limits.
    pub const fn limits(&self) -> &SnapshotLimits {
        &self.limits
    }

    /// Current registered snapshot, even if stale.
    pub const fn view(&self) -> Option<&SnapshotEntry> {
        self.latest.as_ref()
    }

    /// Registered snapshot if it has not aged out.
    pub fn view_fresh(&self, now: Instant) -> Option<&SnapshotEntry> {
        self.latest.as_ref().filter(|entry| {
            now.saturating_duration_since(entry.registered_at) <= self.limits.stale_after
        })
    }

    /// Pending grant, if any.
    pub const fn pending(&self) -> Option<&Grant> {
        self.pending.as_ref()
    }

    /// Record one OFFER.
    ///
    /// Only an applied watermark that is a positive multiple of the frozen
    /// interval is meaningful. Offers at or below the registered snapshot
    /// are discarded; a second offer for the already-granted sequence is
    /// discarded as well (42 §5.6 step 2).
    pub fn on_offer(&mut self, covered: Seq, from: ClientId, current: Seq) -> bool {
        if covered == Seq::UNSEQUENCED || covered > current {
            return false;
        }
        if covered.get() % self.limits.interval != 0 {
            return false;
        }
        if self
            .latest
            .is_some_and(|latest| covered <= latest.covered_seq)
        {
            return false;
        }
        if self
            .pending
            .is_some_and(|grant| grant.covered_seq == covered)
        {
            return false;
        }
        self.offers.entry(covered).or_default().insert(from);
        true
    }

    /// Record one ANNOUNCE.
    ///
    /// All three conditions from 42 §5.6 are checked: covered within the
    /// current sequence, strictly newer than `latest`, and the announcer is
    /// the pending grantee.
    pub fn on_announce(
        &mut self,
        covered: Seq,
        root_chunk_id: [u8; 32],
        from: ClientId,
        current: Seq,
        now: Instant,
    ) -> bool {
        let Some(grant) = self.pending else {
            return false;
        };
        if grant.holder.as_bytes() != from.as_bytes() || grant.covered_seq != covered {
            return false;
        }
        if covered > current {
            return false;
        }
        if self
            .latest
            .is_some_and(|latest| covered <= latest.covered_seq)
        {
            return false;
        }
        self.latest = Some(SnapshotEntry {
            covered_seq: covered,
            root_chunk_id,
            holder: from,
            registered_at: now,
        });
        self.pending = None;
        true
    }

    /// Advance one tick: expire a grant, grant the smallest offer, or ask
    /// for an immediate snapshot.
    pub fn on_tick(
        &mut self,
        online: &OnlineTable,
        current: Seq,
        now: Instant,
    ) -> Vec<SnapshotAction> {
        let mut actions = Vec::new();
        if self.pending.is_some_and(|grant| now >= grant.deadline) {
            self.pending = None;
        }
        if self.pending.is_none() {
            if let Some(action) = self.grant_next(online, current, now) {
                actions.push(action);
            }
        }
        if self.pending.is_none() && self.needs_now(now) {
            if let Some(action) = self.now(online, current, now) {
                actions.push(action);
            }
        }
        actions
    }

    fn grant_next(
        &mut self,
        online: &OnlineTable,
        current: Seq,
        now: Instant,
    ) -> Option<SnapshotAction> {
        let covered = self.offers.keys().copied().find(|covered| {
            *covered <= current
                && self
                    .latest
                    .is_none_or(|latest| *covered > latest.covered_seq)
        })?;
        let candidates = self.offers.remove(&covered)?;
        // Older candidates can never win once a newer grant is chosen.
        self.offers.retain(|seq, _| *seq > covered);
        let holder = candidates
            .into_iter()
            .filter(|client| is_online(online, *client))
            .min_by(|left, right| left.as_bytes().cmp(right.as_bytes()))?;
        let deadline = now + self.limits.grant_deadline;
        self.pending = Some(Grant {
            covered_seq: covered,
            holder,
            deadline,
        });
        Some(SnapshotAction::Grant {
            to: holder,
            covered_seq: covered,
            deadline,
        })
    }

    fn needs_now(&self, now: Instant) -> bool {
        match self.latest {
            None => true,
            Some(entry) => {
                now.saturating_duration_since(entry.registered_at) > self.limits.stale_after
            }
        }
    }

    fn now(&mut self, online: &OnlineTable, current: Seq, now: Instant) -> Option<SnapshotAction> {
        if current == Seq::UNSEQUENCED {
            return None;
        }
        if self
            .last_now_at
            .is_some_and(|last| now.saturating_duration_since(last) < self.limits.min_now_interval)
        {
            return None;
        }
        let holder = online
            .iter()
            .filter(|(_, session)| session.state == SessionState::Online)
            .map(|(client, _)| *client)
            .min_by(|left, right| left.as_bytes().cmp(right.as_bytes()))?;
        let deadline = now + self.limits.grant_deadline;
        self.last_now_at = Some(now);
        self.pending = Some(Grant {
            covered_seq: current,
            holder,
            deadline,
        });
        Some(SnapshotAction::Now {
            to: holder,
            covered_seq: current,
            deadline,
        })
    }
}

fn is_online(online: &OnlineTable, client: ClientId) -> bool {
    online
        .get(&client)
        .is_some_and(|session| session.state == SessionState::Online)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::protocol::Seq;
    use crate::server::config::OutboxConfig;
    use crate::server::online::{Outbox, SessionInit};
    use crate::transport::PeerId;

    fn client(byte: u8) -> ClientId {
        ClientId::from_bytes([byte; 16])
    }

    fn online(ids: &[ClientId]) -> OnlineTable {
        let mut table = OnlineTable::new();
        for (index, id) in ids.iter().enumerate() {
            let (outbox, _data, _ctrl) = Outbox::new(&OutboxConfig::default());
            let mut session = super::super::online::Session::new(SessionInit {
                client_id: *id,
                nonce: index as u64 + 1,
                peer: PeerId::from_serial(index as u64 + 1),
                outbox,
                epoch: 1,
                epoch_seen: 1,
                applied_seq: Seq::UNSEQUENCED,
                current_seq: Seq::UNSEQUENCED,
                now: Instant::now(),
            });
            session.state = SessionState::Online;
            table.insert(session);
        }
        table
    }

    #[test]
    fn server_snapshot_grants_the_smallest_offer_then_the_smallest_client() {
        let now = Instant::now();
        let a = client(1);
        let b = client(2);
        let table = online(&[a, b]);
        let mut registry = SnapshotRegistry::new(SnapshotLimits::default());
        assert!(registry.on_offer(Seq(4096), b, Seq(10_000)));
        assert!(registry.on_offer(Seq(4096), a, Seq(10_000)));
        assert!(registry.on_offer(Seq(8192), a, Seq(10_000)));
        assert!(!registry.on_offer(Seq(4095), a, Seq(10_000)));
        assert!(!registry.on_offer(Seq(4096), a, Seq(1)));
        let actions = registry.on_tick(&table, Seq(10_000), now);
        assert_eq!(
            actions,
            vec![SnapshotAction::Grant {
                to: a,
                covered_seq: Seq(4096),
                deadline: now + SNAPSHOT_GRANT_DEADLINE,
            }]
        );
        assert_eq!(registry.pending().unwrap().holder, a);
    }

    #[test]
    fn server_snapshot_announce_requires_the_grantee_and_monotonic_cover() {
        let now = Instant::now();
        let a = client(1);
        let b = client(2);
        let table = online(&[a, b]);
        let mut registry = SnapshotRegistry::new(SnapshotLimits::default());
        assert!(registry.on_offer(Seq(4096), a, Seq(5000)));
        assert!(registry.on_tick(&table, Seq(5000), now).len() == 1);
        let root = [0xab; 32];
        assert!(!registry.on_announce(Seq(4096), root, b, Seq(5000), now));
        assert!(!registry.on_announce(Seq(8192), root, a, Seq(5000), now));
        assert!(registry.on_announce(Seq(4096), root, a, Seq(5000), now));
        let entry = registry.view().unwrap();
        assert_eq!(entry.covered_seq, Seq(4096));
        assert_eq!(entry.root_chunk_id, root);
        assert_eq!(entry.holder, a);
        assert!(registry.pending().is_none());
        // A second announce without a new grant is rejected.
        assert!(!registry.on_announce(Seq(8192), root, a, Seq(8192), now));
    }

    #[test]
    fn server_snapshot_grant_expires_after_thirty_seconds() {
        let now = Instant::now();
        let a = client(1);
        let table = online(&[a]);
        let mut registry = SnapshotRegistry::new(SnapshotLimits::default());
        assert!(registry.on_offer(Seq(4096), a, Seq(4096)));
        assert!(registry.on_tick(&table, Seq(4096), now).len() == 1);
        let expired = now + SNAPSHOT_GRANT_DEADLINE + Duration::from_secs(1);
        let actions = registry.on_tick(&table, Seq(4096), expired);
        // The offer was consumed, so the next action is SNAPSHOT_NOW.
        assert!(registry.pending().is_some());
        assert!(matches!(actions.as_slice(), [SnapshotAction::Now { .. }]));
    }

    #[test]
    fn server_snapshot_now_is_rate_limited_and_covers_the_current_sequence() {
        let now = Instant::now();
        let a = client(1);
        let b = client(2);
        let table = online(&[a, b]);
        let mut registry = SnapshotRegistry::new(SnapshotLimits::default());
        assert_eq!(
            registry.on_tick(&table, Seq(123), now),
            vec![SnapshotAction::Now {
                to: a,
                covered_seq: Seq(123),
                deadline: now + SNAPSHOT_GRANT_DEADLINE,
            }]
        );
        // The pending grant blocks another NOW; expire it and try again
        // before the one-minute cluster limit.
        let after_expiry = now + SNAPSHOT_GRANT_DEADLINE + Duration::from_secs(1);
        assert!(registry.on_tick(&table, Seq(123), after_expiry).is_empty());
        let after_limit = now + SNAPSHOT_MIN_NOW_INTERVAL + Duration::from_secs(1);
        assert_eq!(
            registry.on_tick(&table, Seq(124), after_limit),
            vec![SnapshotAction::Now {
                to: a,
                covered_seq: Seq(124),
                deadline: after_limit + SNAPSHOT_GRANT_DEADLINE,
            }]
        );
    }

    #[test]
    fn server_snapshot_becomes_stale_after_ten_minutes() {
        let now = Instant::now();
        let a = client(1);
        let table = online(&[a]);
        let mut registry = SnapshotRegistry::new(SnapshotLimits::default());
        assert!(registry.on_offer(Seq(4096), a, Seq(4096)));
        assert!(registry.on_tick(&table, Seq(4096), now).len() == 1);
        assert!(registry.on_announce(Seq(4096), [1; 32], a, Seq(4096), now));
        assert!(registry.view_fresh(now).is_some());
        assert!(
            registry
                .view_fresh(now + SNAPSHOT_STALE_AFTER + Duration::from_secs(1))
                .is_none()
        );
        let actions = registry.on_tick(
            &table,
            Seq(9000),
            now + SNAPSHOT_STALE_AFTER + Duration::from_secs(1),
        );
        assert!(matches!(actions.as_slice(), [SnapshotAction::Now { .. }]));
    }
}
