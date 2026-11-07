//! PSK handshake state machines.
//!
//! The handshake is sans-io: callers inject nonces, time and the transport.
//! Both sides derive the same handshake key from the two nonces and use it
//! for the `WELCOME` proof, `AUTH` and `ACCEPT`. The steady-state key is only
//! used after `ACCEPT` verifies.
//!
//! ```text
//! client  HELLO(plain) ───────────────▶ server
//!         ◀──────────── WELCOME(plain body + F_SERVER_PROOF)
//!         AUTH(sealed) ───────────────▶ server
//!         ◀──────────── ACCEPT(sealed)
//!         STEADY (enc)
//! ```
//!
//! A wrong PSK fails at the `WELCOME` proof, so the client never sends
//! `AUTH`. A failed `AUTH` closes the connection silently: the server does
//! not turn "wrong password" and "tampered transcript" into a distinguishable
//! oracle.

use std::collections::VecDeque;
use std::fmt;

use crate::protocol::crypto::{
    CryptoError, HandshakeKeys, PskKeyRing, SessionKey, WELCOME_PROOF_LEN,
};
use crate::protocol::frame::{
    ClientId, FrameHeader, Limits as FrameLimits, Prefix, Seq, SessionId,
};
use crate::protocol::messages::{
    Accept, Auth, Hello, MessageError, ResyncMode, Welcome, WelcomeLimits,
};
use crate::protocol::version::{Caps, Negotiated, ProtoVersion, VersionError, negotiate};

/// Client-side budget for the whole handshake, in milliseconds.
pub const CLIENT_HANDSHAKE_TIMEOUT_MS: u64 = 10_000;

/// Server-side budget for `AUTH` after `WELCOME`, in milliseconds.
pub const AUTH_TIMEOUT_MS: u64 = 5_000;

/// Largest number of remembered client nonces in one replay window.
pub const MAX_RECENT_NONCES: usize = 4_096;

/// Width of the client-nonce replay window, in milliseconds.
pub const NONCE_REPLAY_WINDOW_MS: u64 = 60_000;

/// Client handshake phase.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ClientPhase {
    /// `HELLO` has been built and sent; `WELCOME` is outstanding.
    HelloSent,
    /// `WELCOME` verified; `AUTH` has been built and sent.
    AuthSent,
    /// `ACCEPT` verified; the steady-state key is live.
    Steady,
    /// The handshake failed and must not continue.
    Failed,
}

/// A client-side PSK handshake.
///
/// One instance per connection attempt. A retry must use a fresh client nonce
/// and a fresh instance (or [`ClientHandshake::restart`]).
pub struct ClientHandshake {
    ring: PskKeyRing,
    client_id: ClientId,
    client_nonce: [u8; 32],
    proto: ProtoVersion,
    caps: Caps,
    phase: ClientPhase,
    deadline_ms: u64,
    negotiated: Option<Negotiated>,
    handshake: Option<HandshakeKeys>,
    session_id: Option<SessionId>,
    epoch: Option<u64>,
    server_nonce: Option<[u8; 32]>,
}

impl ClientHandshake {
    /// Start a handshake at `now_ms`.
    pub fn new(
        ring: PskKeyRing,
        client_id: ClientId,
        client_nonce: [u8; 32],
        proto: ProtoVersion,
        caps: Caps,
        now_ms: u64,
    ) -> Self {
        Self {
            ring,
            client_id,
            client_nonce,
            proto,
            caps,
            phase: ClientPhase::HelloSent,
            deadline_ms: now_ms.saturating_add(CLIENT_HANDSHAKE_TIMEOUT_MS),
            negotiated: None,
            handshake: None,
            session_id: None,
            epoch: None,
            server_nonce: None,
        }
    }

    /// The `HELLO` body to send.
    pub const fn hello(&self) -> Hello {
        Hello::new(self.proto, self.caps, self.client_id, self.client_nonce)
    }

    /// Current phase.
    pub const fn phase(&self) -> ClientPhase {
        self.phase
    }

    /// Negotiated version and capabilities, once `WELCOME` verified.
    pub const fn negotiated(&self) -> Option<Negotiated> {
        self.negotiated
    }

    /// The join session, once `WELCOME` verified.
    pub const fn session_id(&self) -> Option<SessionId> {
        self.session_id
    }

    /// The server epoch, once `WELCOME` verified.
    pub const fn epoch(&self) -> Option<u64> {
        self.epoch
    }

    /// The client nonce used by this attempt.
    pub const fn client_nonce(&self) -> &[u8; 32] {
        &self.client_nonce
    }

    /// Fail the handshake. Subsequent calls return [`HandshakeError::WrongPhase`].
    pub fn fail(&mut self) {
        self.phase = ClientPhase::Failed;
        self.handshake = None;
    }

    /// Check the whole-handshake deadline.
    ///
    /// # Errors
    ///
    /// [`HandshakeError::Timeout`] when `now_ms` is at or past the deadline.
    pub fn check_deadline(&self, now_ms: u64) -> Result<(), HandshakeError> {
        if now_ms >= self.deadline_ms {
            return Err(HandshakeError::Timeout);
        }
        Ok(())
    }

    /// Verify `WELCOME` and build `AUTH`.
    ///
    /// `body` is the raw plaintext `WELCOME` body, including
    /// `F_SERVER_PROOF`. The proof covers the canonical body without that
    /// field; a wrong PSK and a tampered body both fail as
    /// [`HandshakeError::AuthFailed`].
    ///
    /// # Errors
    ///
    /// [`HandshakeError::WrongPhase`], [`HandshakeError::Timeout`],
    /// [`HandshakeError::Version`], [`HandshakeError::ClientIdMismatch`],
    /// [`HandshakeError::MissingSession`], [`HandshakeError::MissingServerProof`]
    /// or [`HandshakeError::AuthFailed`].
    pub fn on_welcome(
        &mut self,
        welcome: &Welcome,
        body: &[u8],
        now_ms: u64,
    ) -> Result<Auth, HandshakeError> {
        self.expect_phase(ClientPhase::HelloSent)?;
        self.check_deadline(now_ms)?;

        if welcome.client_id != self.client_id {
            self.fail();
            return Err(HandshakeError::ClientIdMismatch);
        }
        let negotiated = negotiate(self.proto, welcome.proto, self.caps, welcome.caps)?;
        let session_id = welcome.session_id;
        let limits = FrameLimits::default();
        let proof =
            Welcome::server_proof(body, &limits)?.ok_or(HandshakeError::MissingServerProof)?;
        let body_hash = Welcome::proof_input(body, &limits)?;

        let keys = self
            .ring
            .handshake_keys(&self.client_nonce, &welcome.server_nonce)?;
        if keys
            .open_welcome_proof(&self.client_nonce, &body_hash, &proof)
            .is_err()
        {
            self.fail();
            return Err(HandshakeError::AuthFailed);
        }

        self.negotiated = Some(negotiated);
        self.session_id = Some(session_id);
        self.epoch = Some(welcome.epoch);
        self.server_nonce = Some(welcome.server_nonce);
        self.handshake = Some(keys);
        self.phase = ClientPhase::AuthSent;

        Ok(Auth {
            client_nonce: self.client_nonce,
            server_nonce: welcome.server_nonce,
            session_id,
            epoch: welcome.epoch,
            client_id: self.client_id,
            proto: negotiated.proto,
            caps: negotiated.caps,
        })
    }

    /// The handshake keys used to seal `AUTH`, once `WELCOME` verified.
    pub fn handshake_keys(&self) -> Option<&HandshakeKeys> {
        self.handshake.as_ref()
    }

    /// Verify an already-opened `ACCEPT`.
    ///
    /// # Errors
    ///
    /// [`HandshakeError::WrongPhase`], [`HandshakeError::Timeout`],
    /// [`HandshakeError::EpochMismatch`] or [`HandshakeError::SessionMismatch`].
    pub fn on_accept(
        &mut self,
        accept: &Accept,
        now_ms: u64,
    ) -> Result<SessionKey, HandshakeError> {
        self.expect_phase(ClientPhase::AuthSent)?;
        self.check_deadline(now_ms)?;
        if Some(accept.epoch) != self.epoch {
            self.fail();
            return Err(HandshakeError::EpochMismatch);
        }
        if Some(accept.session_id) != self.session_id {
            self.fail();
            return Err(HandshakeError::SessionMismatch);
        }
        self.phase = ClientPhase::Steady;
        self.handshake = None;
        Ok(self.ring.session_key())
    }

    /// Open and verify a sealed `ACCEPT` frame body.
    ///
    /// # Errors
    ///
    /// [`HandshakeError::WrongPhase`], [`HandshakeError::Timeout`],
    /// [`HandshakeError::AuthFailed`] for a bad tag, or any error from
    /// [`ClientHandshake::on_accept`].
    pub fn open_accept(
        &mut self,
        header: &FrameHeader,
        body: &[u8],
        now_ms: u64,
    ) -> Result<SessionKey, HandshakeError> {
        self.expect_phase(ClientPhase::AuthSent)?;
        self.check_deadline(now_ms)?;
        let keys = self.handshake.as_ref().ok_or(HandshakeError::AuthFailed)?;
        let opened = keys
            .open(header, &Prefix::None, body)
            .map_err(|_| HandshakeError::AuthFailed)?;
        let accept = Accept::decode(opened.as_slice())?;
        self.on_accept(&accept, now_ms)
    }

    /// Start a new attempt with a fresh nonce.
    ///
    /// # Errors
    ///
    /// [`HandshakeError::ReplayNonce`] if `client_nonce` is unchanged: a retry
    /// must not reuse the old nonce.
    pub fn restart(&mut self, client_nonce: [u8; 32], now_ms: u64) -> Result<(), HandshakeError> {
        if client_nonce == self.client_nonce {
            return Err(HandshakeError::ReplayNonce);
        }
        self.client_nonce = client_nonce;
        self.phase = ClientPhase::HelloSent;
        self.deadline_ms = now_ms.saturating_add(CLIENT_HANDSHAKE_TIMEOUT_MS);
        self.negotiated = None;
        self.handshake = None;
        self.session_id = None;
        self.epoch = None;
        self.server_nonce = None;
        Ok(())
    }

    /// The server nonce from the verified `WELCOME`.
    pub const fn server_nonce(&self) -> Option<[u8; 32]> {
        self.server_nonce
    }

    fn expect_phase(&self, expected: ClientPhase) -> Result<(), HandshakeError> {
        if self.phase == expected {
            Ok(())
        } else {
            Err(HandshakeError::WrongPhase {
                expected,
                actual: self.phase,
            })
        }
    }
}

impl fmt::Debug for ClientHandshake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientHandshake")
            .field("phase", &self.phase)
            .field("client_id", &self.client_id)
            .field("deadline_ms", &self.deadline_ms)
            .finish_non_exhaustive()
    }
}

/// Inputs the transport supplies for one `WELCOME`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct HelloInput {
    /// Join session identifier.
    pub session_id: SessionId,
    /// Fresh 32-byte server nonce.
    pub server_nonce: [u8; 32],
    /// Fresh 12-byte nonce for the `WELCOME` proof.
    pub proof_nonce: [u8; 12],
    /// Server clock.
    pub server_time: u64,
    /// Resync mode the server requests.
    pub resync: ResyncMode,
}

/// A `WELCOME` body ready to send.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct WelcomeReply {
    /// Parsed message.
    pub welcome: Welcome,
    /// Encoded body including `F_SERVER_PROOF`.
    pub body: Vec<u8>,
}

/// A verified `AUTH`, plus the key still needed to seal `ACCEPT`.
pub struct Accepted {
    /// `ACCEPT` body to seal under [`Accepted::keys`].
    pub accept: Accept,
    /// Handshake key for `ACCEPT`; drop it after sealing.
    pub keys: HandshakeKeys,
    /// Client identity claimed in `HELLO` and confirmed by `AUTH`.
    pub client_id: ClientId,
    /// Join session identifier.
    pub session_id: SessionId,
}

impl fmt::Debug for Accepted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Accepted")
            .field("accept", &self.accept)
            .field("client_id", &self.client_id)
            .field("session_id", &self.session_id)
            .finish_non_exhaustive()
    }
}

struct Pending {
    client_nonce: [u8; 32],
    server_nonce: [u8; 32],
    session_id: SessionId,
    epoch: u64,
    client_id: ClientId,
    proto: ProtoVersion,
    caps: Caps,
    deadline_ms: u64,
    keys: HandshakeKeys,
}

/// A server-side PSK handshake for one connection.
///
/// One `HELLO` per connection. `client_id` is only claimed here; the caller
/// must not insert the identity into any session or broadcast table until
/// `AUTH` verifies.
pub struct ServerHandshake {
    ring: PskKeyRing,
    epoch: u64,
    current_seq: Seq,
    limits: WelcomeLimits,
    caps: Caps,
    pending: Option<Pending>,
}

impl ServerHandshake {
    /// Bind the server state to one PSK ring and epoch.
    pub fn new(
        ring: PskKeyRing,
        epoch: u64,
        current_seq: Seq,
        limits: WelcomeLimits,
        caps: Caps,
    ) -> Self {
        Self {
            ring,
            epoch,
            current_seq,
            limits,
            caps,
            pending: None,
        }
    }

    /// The server epoch.
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The sequence the server advertises.
    pub const fn current_seq(&self) -> Seq {
        self.current_seq
    }

    /// Whether an `AUTH` is outstanding.
    pub const fn has_pending(&self) -> bool {
        self.pending.is_some()
    }

    /// Build `WELCOME` for `hello` and remember the pending handshake.
    ///
    /// The caller must run [`NonceReplayGuard::check_and_record`] first. The
    /// returned body is plain WCP with `F_SERVER_PROOF`; the proof is sealed
    /// under the per-connection handshake key.
    ///
    /// # Errors
    ///
    /// [`HandshakeError::Busy`] if a handshake is already pending,
    /// [`HandshakeError::Version`] for a major mismatch or missing capability,
    /// or a crypto/message error.
    pub fn on_hello(
        &mut self,
        hello: &Hello,
        input: HelloInput,
        now_ms: u64,
    ) -> Result<WelcomeReply, HandshakeError> {
        if self.pending.is_some() {
            return Err(HandshakeError::Busy);
        }
        let negotiated = negotiate(ProtoVersion::CURRENT, hello.proto, self.caps, hello.caps)?;
        let keys = self
            .ring
            .handshake_keys(&hello.client_nonce, &input.server_nonce)?;

        let welcome = Welcome {
            proto: negotiated.proto,
            caps: negotiated.caps,
            epoch: self.epoch,
            current_seq: self.current_seq,
            client_id: hello.client_id,
            resync: input.resync,
            limits: self.limits,
            server_time: input.server_time,
            server_nonce: input.server_nonce,
            session_id: input.session_id,
        };
        let plain = welcome.encode()?;
        let body_hash = Welcome::proof_input(&plain, &FrameLimits::default())?;
        let proof = keys.seal_welcome_proof(&hello.client_nonce, &body_hash, &input.proof_nonce)?;
        debug_assert_eq!(proof.len(), WELCOME_PROOF_LEN);
        let body = welcome.encode_with_proof(&proof)?;

        self.pending = Some(Pending {
            client_nonce: hello.client_nonce,
            server_nonce: input.server_nonce,
            session_id: input.session_id,
            epoch: self.epoch,
            client_id: hello.client_id,
            proto: negotiated.proto,
            caps: negotiated.caps,
            deadline_ms: now_ms.saturating_add(AUTH_TIMEOUT_MS),
            keys,
        });

        Ok(WelcomeReply { welcome, body })
    }

    /// Verify an already-opened `AUTH` and consume the pending handshake.
    ///
    /// # Errors
    ///
    /// [`HandshakeError::UnknownHandshake`] when no `AUTH` is outstanding or
    /// the nonce does not match, [`HandshakeError::Timeout`] after the
    /// deadline, or [`HandshakeError::AuthFailed`] when any transcript field
    /// differs. A replayed `AUTH` hits `UnknownHandshake` because the pending
    /// entry is removed on first success.
    pub fn on_auth(&mut self, auth: &Auth, now_ms: u64) -> Result<Accepted, HandshakeError> {
        let pending = self
            .pending
            .as_ref()
            .ok_or(HandshakeError::UnknownHandshake)?;
        if now_ms >= pending.deadline_ms {
            self.pending = None;
            return Err(HandshakeError::Timeout);
        }
        if auth.client_nonce != pending.client_nonce
            || auth.server_nonce != pending.server_nonce
            || auth.session_id != pending.session_id
            || auth.epoch != pending.epoch
            || auth.client_id != pending.client_id
            || auth.proto != pending.proto
            || auth.caps != pending.caps
        {
            self.pending = None;
            return Err(HandshakeError::AuthFailed);
        }

        let pending = self
            .pending
            .take()
            .ok_or(HandshakeError::UnknownHandshake)?;
        Ok(Accepted {
            accept: Accept {
                epoch: pending.epoch,
                session_id: pending.session_id,
                current_seq: self.current_seq,
            },
            keys: pending.keys,
            client_id: pending.client_id,
            session_id: pending.session_id,
        })
    }

    /// Open and verify a sealed `AUTH` frame body.
    ///
    /// # Errors
    ///
    /// [`HandshakeError::UnknownHandshake`], [`HandshakeError::Timeout`],
    /// [`HandshakeError::AuthFailed`] for a bad tag or malformed plaintext, or
    /// any error from [`ServerHandshake::on_auth`].
    pub fn open_auth(
        &mut self,
        header: &FrameHeader,
        body: &[u8],
        now_ms: u64,
    ) -> Result<Accepted, HandshakeError> {
        let pending = self
            .pending
            .as_ref()
            .ok_or(HandshakeError::UnknownHandshake)?;
        if now_ms >= pending.deadline_ms {
            self.pending = None;
            return Err(HandshakeError::Timeout);
        }
        let opened = pending
            .keys
            .open(header, &Prefix::None, body)
            .map_err(|_| HandshakeError::AuthFailed)?;
        let auth = Auth::decode(opened.as_slice())?;
        self.on_auth(&auth, now_ms)
    }

    /// Drop an expired pending handshake.
    ///
    /// Returns `true` when an entry was removed.
    pub fn expire(&mut self, now_ms: u64) -> bool {
        let expired = self
            .pending
            .as_ref()
            .is_some_and(|pending| now_ms >= pending.deadline_ms);
        if expired {
            self.pending = None;
        }
        expired
    }
}

impl fmt::Debug for ServerHandshake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerHandshake")
            .field("epoch", &self.epoch)
            .field("current_seq", &self.current_seq)
            .field("has_pending", &self.pending.is_some())
            .finish_non_exhaustive()
    }
}

/// A bounded recent-nonce set.
///
/// Callers must invoke this before accepting a `HELLO`; the same
/// `client_nonce` inside the window is a replay. The set is bounded so an
/// unauthenticated peer cannot grow it without limit.
pub struct NonceReplayGuard {
    entries: VecDeque<([u8; 32], u64)>,
    capacity: usize,
    window_ms: u64,
}

impl NonceReplayGuard {
    /// The default guard: 4096 entries over 60 seconds.
    pub fn new() -> Self {
        Self::with_limits(MAX_RECENT_NONCES, NONCE_REPLAY_WINDOW_MS)
    }

    /// A guard with explicit bounds.
    pub fn with_limits(capacity: usize, window_ms: u64) -> Self {
        Self {
            entries: VecDeque::new(),
            capacity,
            window_ms,
        }
    }

    /// Record `nonce`, or reject it as a replay.
    ///
    /// # Errors
    ///
    /// [`HandshakeError::ReplayNonce`] when the nonce is still in the window.
    pub fn check_and_record(&mut self, nonce: [u8; 32], now_ms: u64) -> Result<(), HandshakeError> {
        self.prune(now_ms);
        if self.entries.iter().any(|(seen, _)| *seen == nonce) {
            return Err(HandshakeError::ReplayNonce);
        }
        while self.entries.len() >= self.capacity && !self.entries.is_empty() {
            self.entries.pop_front();
        }
        self.entries.push_back((nonce, now_ms));
        Ok(())
    }

    /// Number of remembered nonces.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the guard remembers nothing.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn prune(&mut self, now_ms: u64) {
        while let Some((_, at)) = self.entries.front() {
            if now_ms.saturating_sub(*at) < self.window_ms {
                break;
            }
            self.entries.pop_front();
        }
    }
}

impl Default for NonceReplayGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for NonceReplayGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NonceReplayGuard")
            .field("len", &self.entries.len())
            .field("capacity", &self.capacity)
            .finish()
    }
}

/// A handshake failure. Never travels on the wire.
#[derive(Debug)]
#[non_exhaustive]
pub enum HandshakeError {
    /// The state machine is not in the phase this call requires.
    WrongPhase {
        /// Required phase.
        expected: ClientPhase,
        /// Observed phase.
        actual: ClientPhase,
    },
    /// A handshake deadline passed.
    Timeout,
    /// Version negotiation failed.
    Version(VersionError),
    /// A message body failed to parse.
    Message(MessageError),
    /// A key derivation or AEAD operation failed.
    Crypto(CryptoError),
    /// `WELCOME.client_id` is not the identity this client sent.
    ClientIdMismatch,
    /// `WELCOME` does not name a session.
    MissingSession,
    /// `WELCOME` has no `F_SERVER_PROOF`.
    MissingServerProof,
    /// The proof, tag or transcript does not verify. Deliberately does not
    /// distinguish a wrong PSK from tampering.
    AuthFailed,
    /// `ACCEPT.epoch` does not match the `WELCOME` epoch.
    EpochMismatch,
    /// `ACCEPT.session_id` does not match the `WELCOME` session.
    SessionMismatch,
    /// No `AUTH` is outstanding for this connection.
    UnknownHandshake,
    /// A `HELLO` already has a pending `AUTH`.
    Busy,
    /// A client nonce was seen inside the replay window, or a retry reused it.
    ReplayNonce,
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongPhase { expected, actual } => {
                write!(f, "handshake phase is {actual:?}, expected {expected:?}")
            }
            Self::Timeout => f.write_str("handshake timed out"),
            Self::Version(e) => write!(f, "{e}"),
            Self::Message(e) => write!(f, "{e}"),
            Self::Crypto(e) => write!(f, "{e}"),
            Self::ClientIdMismatch => f.write_str("welcome names a different client id"),
            Self::MissingSession => f.write_str("welcome does not name a session"),
            Self::MissingServerProof => f.write_str("welcome has no server proof"),
            Self::AuthFailed => f.write_str("master password rejected or transcript tampered"),
            Self::EpochMismatch => f.write_str("accept epoch does not match welcome"),
            Self::SessionMismatch => f.write_str("accept session does not match welcome"),
            Self::UnknownHandshake => f.write_str("no handshake is pending"),
            Self::Busy => f.write_str("a handshake is already pending"),
            Self::ReplayNonce => f.write_str("client nonce replayed"),
        }
    }
}

impl std::error::Error for HandshakeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Version(e) => Some(e),
            Self::Message(e) => Some(e),
            Self::Crypto(e) => Some(e),
            _ => None,
        }
    }
}

impl From<VersionError> for HandshakeError {
    fn from(value: VersionError) -> Self {
        Self::Version(value)
    }
}

impl From<MessageError> for HandshakeError {
    fn from(value: MessageError) -> Self {
        Self::Message(value)
    }
}

impl From<CryptoError> for HandshakeError {
    fn from(value: CryptoError) -> Self {
        Self::Crypto(value)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::protocol::crypto::{NonceMinter, PskSalt};
    use crate::protocol::frame::{Flags, MsgType};

    const NOW: u64 = 1_000;

    fn ring(byte: u8) -> PskKeyRing {
        PskKeyRing::derive(&[byte; 32], &PskSalt::DEFAULT).unwrap()
    }

    fn limits() -> WelcomeLimits {
        WelcomeLimits {
            max_frame: 131_072,
            credit_bytes: 1 << 20,
            session_ttl_s: 60,
            max_sessions: 8,
        }
    }

    fn hello() -> Hello {
        Hello::new(
            ProtoVersion::CURRENT,
            Caps::REQUIRED,
            ClientId::from_bytes([0x11; 16]),
            [0x22; 32],
        )
    }

    fn input() -> HelloInput {
        HelloInput {
            session_id: SessionId(0x3333),
            server_nonce: [0x44; 32],
            proof_nonce: [0x55; 12],
            server_time: 1_700_000_000,
            resync: ResyncMode::None,
        }
    }

    fn client(ring: PskKeyRing) -> ClientHandshake {
        ClientHandshake::new(
            ring,
            ClientId::from_bytes([0x11; 16]),
            [0x22; 32],
            ProtoVersion::CURRENT,
            Caps::REQUIRED,
            NOW,
        )
    }

    fn server(ring: PskKeyRing) -> ServerHandshake {
        ServerHandshake::new(ring, NOW, Seq(7), limits(), Caps::REQUIRED)
    }

    fn sealed_auth(client: &ClientHandshake, nonces: &NonceMinter) -> (FrameHeader, Vec<u8>) {
        let auth = client.handshake_keys().expect("handshake keys");
        let mut header = FrameHeader::new(MsgType::AUTH, Flags::ENC, 0, Seq::UNSEQUENCED);
        let body = auth
            .sealer(nonces)
            .seal(&mut header, &Prefix::None, &client_auth(client).encode())
            .unwrap();
        (header, body.into_vec())
    }

    fn client_auth(client: &ClientHandshake) -> Auth {
        Auth {
            client_nonce: *client.client_nonce(),
            server_nonce: client.server_nonce().unwrap(),
            session_id: client.session_id().unwrap(),
            epoch: client.epoch().unwrap(),
            client_id: ClientId::from_bytes([0x11; 16]),
            proto: client.negotiated().unwrap().proto,
            caps: client.negotiated().unwrap().caps,
        }
    }

    #[test]
    fn full_handshake_reaches_steady_with_the_enc_key() {
        let nonces = NonceMinter::with_instance(1);
        let expected = ring(0x01);
        let mut client = client(ring(0x01));
        let mut server = server(ring(0x01));

        let reply = server.on_hello(&client.hello(), input(), NOW).unwrap();
        assert_eq!(reply.welcome.epoch, NOW);
        assert_eq!(reply.welcome.current_seq, Seq(7));
        assert_eq!(reply.welcome.server_nonce, [0x44; 32]);
        assert_eq!(
            reply.body.len(),
            reply.welcome.encode().unwrap().len() + 3 + WELCOME_PROOF_LEN
        );

        let auth = client.on_welcome(&reply.welcome, &reply.body, NOW).unwrap();
        assert_eq!(auth.client_nonce, [0x22; 32]);
        assert_eq!(auth.server_nonce, [0x44; 32]);
        assert_eq!(auth.proto, ProtoVersion::CURRENT);
        assert_eq!(client.phase(), ClientPhase::AuthSent);

        let mut header = FrameHeader::new(MsgType::AUTH, Flags::ENC, 0, Seq::UNSEQUENCED);
        let sealed = client
            .handshake_keys()
            .unwrap()
            .sealer(&nonces)
            .seal(&mut header, &Prefix::None, &auth.encode())
            .unwrap();
        let accepted = server.open_auth(&header, sealed.as_bytes(), NOW).unwrap();
        assert_eq!(accepted.client_id, ClientId::from_bytes([0x11; 16]));
        assert_eq!(accepted.session_id, SessionId(0x3333));

        let mut accept_header = FrameHeader::new(MsgType::ACCEPT, Flags::ENC, 0, Seq::UNSEQUENCED);
        let accept_body = accepted
            .keys
            .sealer(&nonces)
            .seal(&mut accept_header, &Prefix::None, &accepted.accept.encode())
            .unwrap();
        let session_key = client
            .open_accept(&accept_header, accept_body.as_bytes(), NOW)
            .unwrap();
        assert_eq!(client.phase(), ClientPhase::Steady);
        assert_eq!(session_key.key(), expected.enc_key());
        assert_eq!(session_key.kid(), expected.kid());
        assert!(client.handshake_keys().is_none());
    }

    #[test]
    fn wrong_psk_fails_at_the_welcome_proof_and_sends_no_auth() {
        let mut client = client(ring(0x02));
        let mut server = server(ring(0x01));
        let reply = server.on_hello(&client.hello(), input(), NOW).unwrap();

        let error = client
            .on_welcome(&reply.welcome, &reply.body, NOW)
            .unwrap_err();
        assert!(matches!(error, HandshakeError::AuthFailed));
        assert_eq!(client.phase(), ClientPhase::Failed);
        assert!(client.handshake_keys().is_none());

        // The server never claimed the identity; the pending entry expires.
        assert!(server.has_pending());
        assert!(server.expire(NOW + AUTH_TIMEOUT_MS));
        assert!(!server.has_pending());
    }

    #[test]
    fn welcome_proof_is_bound_to_both_nonces_and_the_body() {
        let nonces = NonceMinter::with_instance(2);
        let psk_ring = ring(0x01);

        // A different server nonce yields a different handshake key.
        let first = psk_ring.handshake_keys(&[0x22; 32], &[0x44; 32]).unwrap();
        let second = psk_ring.handshake_keys(&[0x22; 32], &[0x45; 32]).unwrap();
        assert_ne!(first.kid(), second.kid());

        // A different client nonce does not verify the proof.
        let mut client = client(ring(0x01));
        let mut server = server(ring(0x01));
        let reply = server.on_hello(&client.hello(), input(), NOW).unwrap();
        let mut other = ClientHandshake::new(
            ring(0x01),
            ClientId::from_bytes([0x11; 16]),
            [0x23; 32],
            ProtoVersion::CURRENT,
            Caps::REQUIRED,
            NOW,
        );
        let error = other
            .on_welcome(&reply.welcome, &reply.body, NOW)
            .unwrap_err();
        assert!(matches!(error, HandshakeError::AuthFailed));

        // A tampered body fails even when the proof bytes are unchanged.
        let mut tampered = reply.welcome;
        tampered.epoch = tampered.epoch.wrapping_add(1);
        let proof = Welcome::server_proof(&reply.body, &FrameLimits::default())
            .unwrap()
            .unwrap();
        let body = tampered.encode_with_proof(&proof).unwrap();
        let error = client.on_welcome(&tampered, &body, NOW).unwrap_err();
        assert!(matches!(error, HandshakeError::AuthFailed));

        // A tampered proof fails.
        let mut client = self::client(ring(0x01));
        let mut server = self::server(ring(0x01));
        let reply = server.on_hello(&client.hello(), input(), NOW).unwrap();
        let mut proof = Welcome::server_proof(&reply.body, &FrameLimits::default())
            .unwrap()
            .unwrap();
        proof[0] = 7;
        let body = reply.welcome.encode_with_proof(&proof).unwrap();
        let error = client.on_welcome(&reply.welcome, &body, NOW).unwrap_err();
        assert!(matches!(error, HandshakeError::AuthFailed));
        let _ = nonces;
    }

    #[test]
    fn auth_replay_is_rejected_after_first_success() {
        let nonces = NonceMinter::with_instance(3);
        let mut client = client(ring(0x01));
        let mut server = server(ring(0x01));
        let reply = server.on_hello(&client.hello(), input(), NOW).unwrap();
        let _ = client.on_welcome(&reply.welcome, &reply.body, NOW).unwrap();
        let (header, body) = sealed_auth(&client, &nonces);

        assert!(server.open_auth(&header, &body, NOW).is_ok());
        let replay = server.open_auth(&header, &body, NOW).unwrap_err();
        assert!(matches!(replay, HandshakeError::UnknownHandshake));
    }

    #[test]
    fn auth_tag_tamper_fails_and_pending_expires() {
        let nonces = NonceMinter::with_instance(4);
        let mut client = client(ring(0x01));
        let mut server = server(ring(0x01));
        let reply = server.on_hello(&client.hello(), input(), NOW).unwrap();
        let _ = client.on_welcome(&reply.welcome, &reply.body, NOW).unwrap();
        let (header, mut body) = sealed_auth(&client, &nonces);
        let last = body.len() - 1;
        body[last] ^= 1;

        let error = server.open_auth(&header, &body, NOW).unwrap_err();
        assert!(matches!(error, HandshakeError::AuthFailed));
        assert!(server.has_pending());
        assert!(server.expire(NOW + AUTH_TIMEOUT_MS));
    }

    #[test]
    fn auth_field_mismatch_is_auth_failed() {
        let nonces = NonceMinter::with_instance(5);
        let mut client = client(ring(0x01));
        let mut server = server(ring(0x01));
        let reply = server.on_hello(&client.hello(), input(), NOW).unwrap();
        let _ = client.on_welcome(&reply.welcome, &reply.body, NOW).unwrap();

        let mut auth = client_auth(&client);
        auth.server_nonce = [0x99; 32];
        let error = server.on_auth(&auth, NOW).unwrap_err();
        assert!(matches!(error, HandshakeError::AuthFailed));
        assert!(!server.has_pending());

        let _ = nonces;
    }

    #[test]
    fn client_and_server_timeouts_are_enforced() {
        let client = client(ring(0x01));
        assert!(client.check_deadline(NOW).is_ok());
        assert!(matches!(
            client.check_deadline(NOW + CLIENT_HANDSHAKE_TIMEOUT_MS),
            Err(HandshakeError::Timeout)
        ));

        let mut server = server(ring(0x01));
        let hello = hello();
        let _ = server.on_hello(&hello, input(), NOW).unwrap();
        assert!(!server.expire(NOW + AUTH_TIMEOUT_MS - 1));
        assert!(server.expire(NOW + AUTH_TIMEOUT_MS));
    }

    #[test]
    fn restart_requires_a_fresh_nonce() {
        let mut client = client(ring(0x01));
        assert!(matches!(
            client.restart([0x22; 32], NOW),
            Err(HandshakeError::ReplayNonce)
        ));
        assert!(client.restart([0x23; 32], NOW).is_ok());
        assert_eq!(client.phase(), ClientPhase::HelloSent);
        assert_eq!(*client.client_nonce(), [0x23; 32]);
    }

    #[test]
    fn nonce_replay_guard_bounds_and_expires() {
        let mut guard = NonceReplayGuard::with_limits(2, 100);
        guard.check_and_record([1; 32], 0).unwrap();
        assert!(matches!(
            guard.check_and_record([1; 32], 1),
            Err(HandshakeError::ReplayNonce)
        ));
        guard.check_and_record([2; 32], 2).unwrap();
        guard.check_and_record([3; 32], 3).unwrap();
        assert_eq!(guard.len(), 2);
        // [1] was evicted by the capacity bound.
        guard.check_and_record([1; 32], 4).unwrap();
        // Everything expires after the window.
        assert_eq!(guard.len(), 2);
        guard.check_and_record([4; 32], 200).unwrap();
        assert_eq!(guard.len(), 1);
    }

    #[test]
    fn version_mismatch_is_rejected_before_keys() {
        let mut server = server(ring(0x01));
        let hello = Hello::new(
            ProtoVersion::V1_0,
            Caps::REQUIRED,
            ClientId::from_bytes([0x11; 16]),
            [0x22; 32],
        );
        let error = server.on_hello(&hello, input(), NOW).unwrap_err();
        assert!(matches!(error, HandshakeError::Version(_)));
        assert!(!server.has_pending());
    }

    #[test]
    fn a_second_hello_on_the_same_connection_is_busy() {
        let mut server = server(ring(0x01));
        let hello = hello();
        let _ = server.on_hello(&hello, input(), NOW).unwrap();
        let error = server.on_hello(&hello, input(), NOW).unwrap_err();
        assert!(matches!(error, HandshakeError::Busy));
    }

    #[test]
    fn accept_must_match_welcome_epoch_and_session() {
        let nonces = NonceMinter::with_instance(6);
        let mut client = client(ring(0x01));
        let mut server = server(ring(0x01));
        let reply = server.on_hello(&client.hello(), input(), NOW).unwrap();
        let _ = client.on_welcome(&reply.welcome, &reply.body, NOW).unwrap();

        let wrong_epoch = Accept {
            epoch: NOW + 1,
            session_id: SessionId(0x3333),
            current_seq: Seq(7),
        };
        let mut header = FrameHeader::new(MsgType::ACCEPT, Flags::ENC, 0, Seq::UNSEQUENCED);
        let body = {
            let keys = client.handshake_keys().unwrap();
            keys.sealer(&nonces)
                .seal(&mut header, &Prefix::None, &wrong_epoch.encode())
                .unwrap()
        };
        let error = client
            .open_accept(&header, body.as_bytes(), NOW)
            .unwrap_err();
        assert!(matches!(error, HandshakeError::EpochMismatch));
        assert_eq!(client.phase(), ClientPhase::Failed);
    }
}
