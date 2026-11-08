//! PSK handshake state machines.
//!
//! The handshake is sans-io: callers inject nonces, time and the transport.
//! One client flight and one server flight finish authentication:
//!
//! ```text
//! client  HELLO(plain header + sealed AUTH) ─────▶ server
//!         ◀───── WELCOME(plain header + server_nonce
//!                        + F_SERVER_PROOF + sealed ACCEPT)
//!         STEADY (enc)
//! ```
//!
//! `AUTH` is sealed under a key derived from the PSK and `client_nonce`, so
//! the client can produce it before it sees the server nonce. `ACCEPT` and
//! the `WELCOME` proof are sealed under a key derived from both nonces.
//!
//! A wrong PSK fails at `HELLO.AUTH` on the server and at the `WELCOME` proof
//! on the client. The server closes silently in both cases: it never turns
//! "wrong password" and "tampered transcript" into a distinguishable oracle.

use std::collections::VecDeque;
use std::fmt;

use crate::protocol::crypto::{
    ACCEPT_DOMAIN, AUTH_DOMAIN, CryptoError, NONCE_LEN, NonceMinter, PskKeyRing, SessionKey,
    WELCOME_PROOF_LEN,
};
use crate::protocol::frame::{
    CTRL_PREFIX_LEN, ClientId, CtrlPrefix, Limits as FrameLimits, Seq, SessionId,
};
use crate::protocol::messages::{
    ACCEPT_SEALED_LEN, AUTH_SEALED_LEN, Accept, Auth, Hello, MessageError, ResyncMode, Welcome,
    WelcomeLimits,
};
use crate::protocol::version::{Caps, Negotiated, ProtoVersion, VersionError, negotiate};

/// Client-side budget for the whole handshake, in milliseconds.
pub const CLIENT_HANDSHAKE_TIMEOUT_MS: u64 = 10_000;

/// Largest number of remembered client nonces in one replay window.
pub const MAX_RECENT_NONCES: usize = 4_096;

/// Width of the client-nonce replay window, in milliseconds.
pub const NONCE_REPLAY_WINDOW_MS: u64 = 60_000;

/// Client handshake phase.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ClientPhase {
    /// `HELLO` has been built and sent; `WELCOME` is outstanding.
    HelloSent,
    /// `WELCOME` verified; the steady-state key is live.
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
            session_id: None,
            epoch: None,
            server_nonce: None,
        }
    }

    /// Build the `HELLO` body, including a freshly sealed `AUTH`.
    ///
    /// `nonces` must belong to this connection: the `AUTH` envelope nonce is
    /// drawn from it and must never repeat under the same handshake key.
    /// `ctrl` is the plaintext control prefix of the same `HELLO` frame; its
    /// bytes are authenticated with the `AUTH`, so a relay cannot change the
    /// replay point without failing the handshake.
    ///
    /// # Errors
    ///
    /// [`HandshakeError::WrongPhase`], or a crypto error from key derivation
    /// or sealing.
    pub fn hello(
        &self,
        nonces: &NonceMinter,
        ctrl: &CtrlPrefix,
    ) -> Result<Hello, HandshakeError> {
        self.expect_phase(ClientPhase::HelloSent)?;
        let keys = self.ring.auth_keys(&self.client_nonce)?;
        let auth = Auth {
            client_nonce: self.client_nonce,
            client_id: self.client_id,
            proto: self.proto,
            caps: self.caps,
        };
        let nonce = nonces.next()?;
        let context = auth_context(&self.client_nonce, ctrl);
        let sealed = keys.seal_detached(AUTH_DOMAIN, &context, &auth.encode(), &nonce)?;
        let auth: [u8; AUTH_SEALED_LEN] = sealed
            .try_into()
            .map_err(|_| HandshakeError::Crypto(CryptoError::Aead))?;
        Ok(Hello::new(
            self.proto,
            self.caps,
            self.client_id,
            self.client_nonce,
            auth,
        ))
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

    /// The server nonce from the verified `WELCOME`.
    pub const fn server_nonce(&self) -> Option<[u8; 32]> {
        self.server_nonce
    }

    /// Fail the handshake. Subsequent calls return [`HandshakeError::WrongPhase`].
    pub fn fail(&mut self) {
        self.phase = ClientPhase::Failed;
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

    /// Verify `WELCOME`, including the server proof and the sealed `ACCEPT`,
    /// and return the steady-state key.
    ///
    /// `body` is the raw plaintext `WELCOME` body. The proof covers the
    /// canonical body without `F_SERVER_PROOF`; the sealed `ACCEPT` is part of
    /// that covered body, so neither attachment can be swapped.
    ///
    /// # Errors
    ///
    /// [`HandshakeError::WrongPhase`], [`HandshakeError::Timeout`],
    /// [`HandshakeError::Version`], [`HandshakeError::ClientIdMismatch`],
    /// [`HandshakeError::MissingServerProof`],
    /// [`HandshakeError::MissingAccept`], [`HandshakeError::EpochMismatch`],
    /// [`HandshakeError::SessionMismatch`] or [`HandshakeError::AuthFailed`].
    pub fn on_welcome(
        &mut self,
        welcome: &Welcome,
        body: &[u8],
        now_ms: u64,
    ) -> Result<SessionKey, HandshakeError> {
        self.expect_phase(ClientPhase::HelloSent)?;
        if let Err(error) = self.check_deadline(now_ms) {
            self.fail();
            return Err(error);
        }
        if welcome.client_id != self.client_id {
            self.fail();
            return Err(HandshakeError::ClientIdMismatch);
        }
        let negotiated = match negotiate(self.proto, welcome.proto, self.caps, welcome.caps) {
            Ok(negotiated) => negotiated,
            Err(error) => {
                self.fail();
                return Err(error.into());
            }
        };
        let limits = FrameLimits::default();
        let proof = match Welcome::server_proof(body, &limits) {
            Ok(Some(proof)) => proof,
            Ok(None) => {
                self.fail();
                return Err(HandshakeError::MissingServerProof);
            }
            Err(error) => {
                self.fail();
                return Err(error.into());
            }
        };
        let sealed_accept = match Welcome::sealed_accept(body, &limits) {
            Ok(Some(accept)) => accept,
            Ok(None) => {
                self.fail();
                return Err(HandshakeError::MissingAccept);
            }
            Err(error) => {
                self.fail();
                return Err(error.into());
            }
        };
        let body_hash = match Welcome::proof_input(body, &limits) {
            Ok(hash) => hash,
            Err(error) => {
                self.fail();
                return Err(error.into());
            }
        };
        let keys = match self
            .ring
            .handshake_keys(&self.client_nonce, &welcome.server_nonce)
        {
            Ok(keys) => keys,
            Err(error) => {
                self.fail();
                return Err(error.into());
            }
        };
        if keys
            .open_welcome_proof(&self.client_nonce, &body_hash, &proof)
            .is_err()
        {
            self.fail();
            return Err(HandshakeError::AuthFailed);
        }
        let context = accept_context(&self.client_nonce, &welcome.server_nonce);
        let opened = match keys.open_detached(ACCEPT_DOMAIN, &context, &sealed_accept) {
            Ok(opened) => opened,
            Err(_) => {
                self.fail();
                return Err(HandshakeError::AuthFailed);
            }
        };
        let accept = match Accept::decode(&opened) {
            Ok(accept) => accept,
            Err(error) => {
                self.fail();
                return Err(error.into());
            }
        };
        if accept.epoch != welcome.epoch {
            self.fail();
            return Err(HandshakeError::EpochMismatch);
        }
        if accept.session_id != welcome.session_id {
            self.fail();
            return Err(HandshakeError::SessionMismatch);
        }

        self.negotiated = Some(negotiated);
        self.session_id = Some(welcome.session_id);
        self.epoch = Some(welcome.epoch);
        self.server_nonce = Some(welcome.server_nonce);
        self.phase = ClientPhase::Steady;
        Ok(self.ring.session_key())
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
        self.session_id = None;
        self.epoch = None;
        self.server_nonce = None;
        Ok(())
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

/// Inputs the transport supplies for one `HELLO`/`WELCOME` exchange.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct HelloInput {
    /// Join session identifier.
    pub session_id: SessionId,
    /// Fresh 32-byte server nonce.
    pub server_nonce: [u8; 32],
    /// Fresh 12-byte nonce for the `WELCOME` proof.
    pub proof_nonce: [u8; NONCE_LEN],
    /// Fresh 12-byte nonce for the sealed `ACCEPT`.
    ///
    /// Must differ from [`HelloInput::proof_nonce`]: both are sealed under the
    /// same two-nonce handshake key.
    pub accept_nonce: [u8; NONCE_LEN],
    /// Server clock.
    pub server_time: u64,
    /// Resync mode the server requests.
    pub resync: ResyncMode,
    /// Plaintext control prefix from the `HELLO` frame.
    ///
    /// The prefix is part of the AUTH transcript, so a modified
    /// `applied_seq`/`epoch_seen` fails authentication instead of silently
    /// changing the replay point.
    pub ctrl: CtrlPrefix,
}

/// A verified `HELLO`, plus the encoded `WELCOME` ready to send.
pub struct Accepted {
    /// Parsed `WELCOME` message.
    pub welcome: Welcome,
    /// Encoded body including `F_SERVER_PROOF` and `F_SEALED_ACCEPT`.
    pub body: Vec<u8>,
    /// Join session identifier.
    pub session_id: SessionId,
}

impl fmt::Debug for Accepted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Accepted")
            .field("welcome", &self.welcome)
            .field("session_id", &self.session_id)
            .finish_non_exhaustive()
    }
}

/// A server-side PSK handshake for one connection.
///
/// The server verifies `HELLO.AUTH` before it builds `WELCOME`; there is no
/// second client flight and no pending handshake state. `client_id` is only
/// claimed here; the caller must not insert the identity into any session or
/// broadcast table until [`ServerHandshake::on_hello`] returns `Ok`.
pub struct ServerHandshake {
    ring: PskKeyRing,
    epoch: u64,
    current_seq: Seq,
    limits: WelcomeLimits,
    caps: Caps,
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

    /// Verify `HELLO.AUTH` and build `WELCOME`.
    ///
    /// The caller must run [`NonceReplayGuard::check_and_record`] first. A
    /// wrong PSK, a tampered `AUTH` and a transcript mismatch all return
    /// [`HandshakeError::AuthFailed`]; the caller must close silently.
    ///
    /// # Errors
    ///
    /// [`HandshakeError::Version`] for a major mismatch or missing capability,
    /// [`HandshakeError::AuthFailed`] when `AUTH` does not verify, or a
    /// crypto/message error.
    pub fn on_hello(
        &mut self,
        hello: &Hello,
        input: HelloInput,
    ) -> Result<Accepted, HandshakeError> {
        if input.proof_nonce == input.accept_nonce {
            return Err(HandshakeError::Crypto(CryptoError::Aead));
        }
        let negotiated = negotiate(ProtoVersion::CURRENT, hello.proto, self.caps, hello.caps)?;

        let auth_keys = self.ring.auth_keys(&hello.client_nonce)?;
        let context = auth_context(&hello.client_nonce, &input.ctrl);
        let opened = auth_keys
            .open_detached(AUTH_DOMAIN, &context, &hello.auth)
            .map_err(|_| HandshakeError::AuthFailed)?;
        let auth = Auth::decode(&opened)?;
        if auth.client_nonce != hello.client_nonce
            || auth.client_id != hello.client_id
            || auth.proto != hello.proto
            || auth.caps != hello.caps
        {
            return Err(HandshakeError::AuthFailed);
        }

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
        let accept = Accept {
            epoch: self.epoch,
            session_id: input.session_id,
            current_seq: self.current_seq,
        };
        let context = accept_context(&hello.client_nonce, &input.server_nonce);
        let sealed_accept = keys.seal_detached(
            ACCEPT_DOMAIN,
            &context,
            &accept.encode(),
            &input.accept_nonce,
        )?;
        let sealed_accept: [u8; ACCEPT_SEALED_LEN] = sealed_accept
            .try_into()
            .map_err(|_| HandshakeError::Crypto(CryptoError::Aead))?;

        // The proof covers the sealed ACCEPT, so hash a body that already
        // carries it. `proof_input` excludes only F_SERVER_PROOF, and the
        // placeholder proof value never enters the hash.
        let placeholder = welcome.encode_with_proof_and_accept(
            &[0u8; WELCOME_PROOF_LEN],
            &sealed_accept,
        )?;
        let body_hash = Welcome::proof_input(&placeholder, &FrameLimits::default())?;
        let proof = keys.seal_welcome_proof(
            &hello.client_nonce,
            &body_hash,
            &input.proof_nonce,
        )?;
        debug_assert_eq!(proof.len(), WELCOME_PROOF_LEN);

        let body = welcome.encode_with_proof_and_accept(&proof, &sealed_accept)?;

        Ok(Accepted {
            welcome,
            body,
            session_id: input.session_id,
        })
    }
}

impl fmt::Debug for ServerHandshake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerHandshake")
            .field("epoch", &self.epoch)
            .field("current_seq", &self.current_seq)
            .finish_non_exhaustive()
    }
}

fn accept_context(client_nonce: &[u8; 32], server_nonce: &[u8; 32]) -> [u8; 64] {
    let mut context = [0u8; 64];
    context[..32].copy_from_slice(client_nonce);
    context[32..].copy_from_slice(server_nonce);
    context
}

fn auth_context(client_nonce: &[u8; 32], ctrl: &CtrlPrefix) -> [u8; 32 + CTRL_PREFIX_LEN] {
    let mut context = [0u8; 32 + CTRL_PREFIX_LEN];
    context[..32].copy_from_slice(client_nonce);
    context[32..].copy_from_slice(&ctrl.encode());
    context
}

/// A bounded recent-nonce set.
///
/// Callers hold the guard across [`NonceReplayGuard::contains`] and the AUTH
/// verification, then call [`NonceReplayGuard::record`] only after the AUTH
/// succeeds. A failed AUTH therefore consumes no capacity, and the same
/// `client_nonce` inside the window is a replay. The set is bounded so a
/// peer cannot grow it without limit.
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
        if self.contains(nonce, now_ms) {
            return Err(HandshakeError::ReplayNonce);
        }
        self.record(nonce, now_ms);
        Ok(())
    }

    /// Whether `nonce` is still inside the window, without recording it.
    pub fn contains(&mut self, nonce: [u8; 32], now_ms: u64) -> bool {
        self.prune(now_ms);
        self.entries.iter().any(|(seen, _)| *seen == nonce)
    }

    /// Record an already-verified `nonce`.
    ///
    /// Callers that authenticate first must hold the guard across the check,
    /// the verification and this call, so two connections cannot both pass
    /// the check with the same nonce.
    pub fn record(&mut self, nonce: [u8; 32], now_ms: u64) {
        self.prune(now_ms);
        while self.entries.len() >= self.capacity && !self.entries.is_empty() {
            self.entries.pop_front();
        }
        self.entries.push_back((nonce, now_ms));
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
    /// `WELCOME` has no `F_SERVER_PROOF`.
    MissingServerProof,
    /// `WELCOME` has no sealed `ACCEPT`.
    MissingAccept,
    /// The proof, tag or transcript does not verify. Deliberately does not
    /// distinguish a wrong PSK from tampering.
    AuthFailed,
    /// The sealed `ACCEPT` epoch does not match the `WELCOME` epoch.
    EpochMismatch,
    /// The sealed `ACCEPT` session does not match the `WELCOME` session.
    SessionMismatch,
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
            Self::MissingServerProof => f.write_str("welcome has no server proof"),
            Self::MissingAccept => f.write_str("welcome has no sealed accept"),
            Self::AuthFailed => f.write_str("master password rejected or transcript tampered"),
            Self::EpochMismatch => f.write_str("accept epoch does not match welcome"),
            Self::SessionMismatch => f.write_str("accept session does not match welcome"),
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
    use crate::protocol::crypto::PskSalt;

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

    fn input() -> HelloInput {
        HelloInput {
            session_id: SessionId(0x3333),
            server_nonce: [0x44; 32],
            proof_nonce: [0x55; 12],
            accept_nonce: [0x56; 12],
            server_time: 1_700_000_000,
            resync: ResyncMode::None,
            ctrl: ctrl(),
        }
    }

    fn ctrl() -> CtrlPrefix {
        CtrlPrefix::new(Seq::UNSEQUENCED, 0)
    }

    fn input_with_ctrl(ctrl: CtrlPrefix) -> HelloInput {
        HelloInput { ctrl, ..input() }
    }

    fn client_with(ring: PskKeyRing, nonce: [u8; 32], proto: ProtoVersion) -> ClientHandshake {
        ClientHandshake::new(
            ring,
            ClientId::from_bytes([0x11; 16]),
            nonce,
            proto,
            Caps::REQUIRED,
            NOW,
        )
    }

    fn client(ring: PskKeyRing) -> ClientHandshake {
        client_with(ring, [0x22; 32], ProtoVersion::CURRENT)
    }

    fn server(ring: PskKeyRing) -> ServerHandshake {
        ServerHandshake::new(ring, NOW, Seq(7), limits(), Caps::REQUIRED)
    }

    fn seal_hello(client: &ClientHandshake, nonces: &NonceMinter) -> Hello {
        client.hello(nonces, &ctrl()).unwrap()
    }

    fn pair(
        ring_byte: u8,
        client_nonce: [u8; 32],
        nonces: &NonceMinter,
    ) -> (ClientHandshake, Accepted) {
        let client = client_with(ring(ring_byte), client_nonce, ProtoVersion::CURRENT);
        let hello = seal_hello(&client, nonces);
        let mut server = server(ring(ring_byte));
        let reply = server.on_hello(&hello, input()).unwrap();
        (client, reply)
    }

    #[test]
    fn full_handshake_is_one_round_trip() {
        let nonces = NonceMinter::with_instance(1);
        let expected = ring(0x01);
        let mut client = client(ring(0x01));
        let mut server = server(ring(0x01));

        // Flight 1: one client message. HELLO carries the sealed AUTH.
        let hello = seal_hello(&client, &nonces);
        assert_eq!(hello.client_nonce, [0x22; 32]);
        assert_eq!(hello.auth.len(), AUTH_SEALED_LEN);
        assert_eq!(client.phase(), ClientPhase::HelloSent);

        // Flight 2: one server message. WELCOME carries the proof and the
        // sealed ACCEPT; there is no AUTH/ACCEPT frame and no third flight.
        let reply = server.on_hello(&hello, input()).unwrap();
        assert_eq!(reply.welcome.epoch, NOW);
        assert_eq!(reply.welcome.current_seq, Seq(7));
        assert_eq!(reply.welcome.server_nonce, [0x44; 32]);
        assert_eq!(reply.welcome.proto, ProtoVersion::CURRENT);
        assert_eq!(reply.welcome.session_id, SessionId(0x3333));
        assert!(
            Welcome::sealed_accept(&reply.body, &FrameLimits::default())
                .unwrap()
                .is_some()
        );

        let session_key = client.on_welcome(&reply.welcome, &reply.body, NOW).unwrap();
        assert_eq!(client.phase(), ClientPhase::Steady);
        assert_eq!(session_key.key(), expected.enc_key());
        assert_eq!(session_key.kid(), expected.kid());
        assert_eq!(client.session_id(), Some(SessionId(0x3333)));
        assert_eq!(client.epoch(), Some(NOW));
        assert_eq!(client.server_nonce(), Some([0x44; 32]));
        assert_eq!(
            client.negotiated().unwrap().proto,
            ProtoVersion::CURRENT,
            "the handshake keeps proto v3"
        );
        assert_eq!(ProtoVersion::CURRENT, ProtoVersion::V3_0);
    }

    #[test]
    fn wrong_psk_is_rejected_at_hello_auth() {
        let nonces = NonceMinter::with_instance(2);
        let client = client(ring(0x02));
        let mut server = server(ring(0x01));
        let hello = seal_hello(&client, &nonces);
        let error = server.on_hello(&hello, input()).unwrap_err();
        assert!(matches!(error, HandshakeError::AuthFailed));
    }

    #[test]
    fn wrong_psk_client_rejects_the_welcome_proof() {
        let nonces = NonceMinter::with_instance(3);
        let mut wrong = client(ring(0x02));
        let good_client = client(ring(0x01));
        let mut server = server(ring(0x01));
        let hello = seal_hello(&good_client, &nonces);
        let reply = server.on_hello(&hello, input()).unwrap();

        let error = wrong
            .on_welcome(&reply.welcome, &reply.body, NOW)
            .unwrap_err();
        assert!(matches!(error, HandshakeError::AuthFailed));
        assert_eq!(wrong.phase(), ClientPhase::Failed);
    }

    #[test]
    fn wrong_psk_and_tampered_auth_are_indistinguishable() {
        let nonces = NonceMinter::with_instance(4);
        let wrong = client(ring(0x02));
        let good = client(ring(0x01));
        let mut server = server(ring(0x01));

        let wrong_hello = seal_hello(&wrong, &nonces);
        let wrong_error = server.on_hello(&wrong_hello, input()).unwrap_err();

        let good_hello = seal_hello(&good, &nonces);
        let mut tampered_hello = good_hello;
        let last = tampered_hello.auth.len() - 1;
        tampered_hello.auth[last] ^= 1;
        let tampered_error = server.on_hello(&tampered_hello, input()).unwrap_err();

        assert!(matches!(wrong_error, HandshakeError::AuthFailed));
        assert!(matches!(tampered_error, HandshakeError::AuthFailed));
        assert_eq!(wrong_error.to_string(), tampered_error.to_string());
    }

    #[test]
    fn hello_auth_is_bound_to_the_nonce_and_the_plaintext_transcript() {
        let nonces = NonceMinter::with_instance(5);
        let client = client(ring(0x01));
        let hello = seal_hello(&client, &nonces);
        let mut server = server(ring(0x01));

        let mut changed_nonce = hello;
        changed_nonce.client_nonce = [0x23; 32];
        assert!(matches!(
            server.on_hello(&changed_nonce, input()).unwrap_err(),
            HandshakeError::AuthFailed
        ));

        let mut renamed = hello;
        renamed.client_id = ClientId::from_bytes([0x99; 16]);
        assert!(matches!(
            server.on_hello(&renamed, input()).unwrap_err(),
            HandshakeError::AuthFailed
        ));

        let mut newer_minor = hello;
        newer_minor.proto = ProtoVersion { major: 3, minor: 1 };
        assert!(matches!(
            server.on_hello(&newer_minor, input()).unwrap_err(),
            HandshakeError::AuthFailed
        ));

        let mut extra_caps = hello;
        extra_caps.caps = Caps::from_bits(Caps::REQUIRED.bits() | 0x100);
        assert!(matches!(
            server.on_hello(&extra_caps, input()).unwrap_err(),
            HandshakeError::AuthFailed
        ));

        let moved_prefix = input_with_ctrl(CtrlPrefix::new(Seq(1), 0));
        assert!(matches!(
            server.on_hello(&hello, moved_prefix).unwrap_err(),
            HandshakeError::AuthFailed
        ));
    }

    #[test]
    fn welcome_proof_and_accept_are_bound_to_the_body() {
        let limits = FrameLimits::default();

        // A tampered proof fails.
        let nonces = NonceMinter::with_instance(6);
        let (mut client, reply) = pair(0x01, [0x22; 32], &nonces);
        let mut proof = Welcome::server_proof(&reply.body, &limits).unwrap().unwrap();
        let accept = Welcome::sealed_accept(&reply.body, &limits).unwrap().unwrap();
        proof[0] ^= 1;
        let body = reply
            .welcome
            .encode_with_proof_and_accept(&proof, &accept)
            .unwrap();
        assert!(matches!(
            client.on_welcome(&reply.welcome, &body, NOW).unwrap_err(),
            HandshakeError::AuthFailed
        ));

        // A tampered plaintext field fails even with the original proof.
        let nonces = NonceMinter::with_instance(7);
        let (mut client, reply) = pair(0x01, [0x23; 32], &nonces);
        let proof = Welcome::server_proof(&reply.body, &limits).unwrap().unwrap();
        let accept = Welcome::sealed_accept(&reply.body, &limits).unwrap().unwrap();
        let mut tampered = reply.welcome;
        tampered.epoch = tampered.epoch.wrapping_add(1);
        let body = tampered
            .encode_with_proof_and_accept(&proof, &accept)
            .unwrap();
        assert!(matches!(
            client.on_welcome(&tampered, &body, NOW).unwrap_err(),
            HandshakeError::AuthFailed
        ));

        // A tampered ACCEPT with a valid proof fails the AEAD tag.
        let nonces = NonceMinter::with_instance(8);
        let (mut client, reply) = pair(0x01, [0x24; 32], &nonces);
        let mut accept = Welcome::sealed_accept(&reply.body, &limits).unwrap().unwrap();
        let last = accept.len() - 1;
        accept[last] ^= 1;
        let placeholder = reply
            .welcome
            .encode_with_proof_and_accept(&[0u8; WELCOME_PROOF_LEN], &accept)
            .unwrap();
        let hash = Welcome::proof_input(&placeholder, &limits).unwrap();
        let keys = ring(0x01)
            .handshake_keys(&[0x24; 32], &input().server_nonce)
            .unwrap();
        let proof = keys
            .seal_welcome_proof(&[0x24; 32], &hash, &[0x77; 12])
            .unwrap();
        let body = reply
            .welcome
            .encode_with_proof_and_accept(&proof, &accept)
            .unwrap();
        assert!(matches!(
            client.on_welcome(&reply.welcome, &body, NOW).unwrap_err(),
            HandshakeError::AuthFailed
        ));
    }

    #[test]
    fn welcome_without_a_proof_or_accept_is_rejected() {
        let limits = FrameLimits::default();

        let nonces = NonceMinter::with_instance(9);
        let (mut client, reply) = pair(0x01, [0x22; 32], &nonces);
        let body = reply.welcome.encode().unwrap();
        assert!(matches!(
            client.on_welcome(&reply.welcome, &body, NOW).unwrap_err(),
            HandshakeError::MissingServerProof
        ));

        let nonces = NonceMinter::with_instance(10);
        let (mut client, reply) = pair(0x01, [0x23; 32], &nonces);
        let plain = reply.welcome.encode().unwrap();
        let hash = Welcome::proof_input(&plain, &limits).unwrap();
        let keys = ring(0x01)
            .handshake_keys(&[0x23; 32], &input().server_nonce)
            .unwrap();
        let proof = keys
            .seal_welcome_proof(&[0x23; 32], &hash, &[0x78; 12])
            .unwrap();
        let body = reply.welcome.encode_with_proof(&proof).unwrap();
        assert!(matches!(
            client.on_welcome(&reply.welcome, &body, NOW).unwrap_err(),
            HandshakeError::MissingAccept
        ));
    }

    #[test]
    fn accept_must_match_welcome_epoch() {
        let limits = FrameLimits::default();
        let nonces = NonceMinter::with_instance(11);
        let (mut client, reply) = pair(0x01, [0x22; 32], &nonces);
        let keys = ring(0x01)
            .handshake_keys(&[0x22; 32], &input().server_nonce)
            .unwrap();
        let bad_accept = Accept {
            epoch: reply.welcome.epoch + 1,
            session_id: reply.welcome.session_id,
            current_seq: reply.welcome.current_seq,
        };
        let context = accept_context(&[0x22; 32], &input().server_nonce);
        let sealed = keys
            .seal_detached(
                ACCEPT_DOMAIN,
                &context,
                &bad_accept.encode(),
                &[0x79; 12],
            )
            .unwrap();
        let sealed: [u8; ACCEPT_SEALED_LEN] = sealed.try_into().unwrap();
        let placeholder = reply
            .welcome
            .encode_with_proof_and_accept(&[0u8; WELCOME_PROOF_LEN], &sealed)
            .unwrap();
        let hash = Welcome::proof_input(&placeholder, &limits).unwrap();
        let proof = keys
            .seal_welcome_proof(&[0x22; 32], &hash, &[0x7a; 12])
            .unwrap();
        let body = reply
            .welcome
            .encode_with_proof_and_accept(&proof, &sealed)
            .unwrap();
        assert!(matches!(
            client.on_welcome(&reply.welcome, &body, NOW).unwrap_err(),
            HandshakeError::EpochMismatch
        ));
        assert_eq!(client.phase(), ClientPhase::Failed);
    }

    #[test]
    fn client_timeout_is_enforced() {
        let mut client = client(ring(0x01));
        assert!(client.check_deadline(NOW).is_ok());
        assert!(matches!(
            client.check_deadline(NOW + CLIENT_HANDSHAKE_TIMEOUT_MS),
            Err(HandshakeError::Timeout)
        ));

        let nonces = NonceMinter::with_instance(12);
        let hello = seal_hello(&client, &nonces);
        let mut server = server(ring(0x01));
        let reply = server.on_hello(&hello, input()).unwrap();
        let error = client
            .on_welcome(
                &reply.welcome,
                &reply.body,
                NOW + CLIENT_HANDSHAKE_TIMEOUT_MS,
            )
            .unwrap_err();
        assert!(matches!(error, HandshakeError::Timeout));
        assert_eq!(client.phase(), ClientPhase::Failed);
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
    fn replayed_hello_nonce_is_rejected_before_auth() {
        let nonces = NonceMinter::with_instance(15);
        let client = client(ring(0x01));
        let hello = seal_hello(&client, &nonces);
        let mut guard = NonceReplayGuard::new();
        assert!(guard.check_and_record(hello.client_nonce, NOW).is_ok());
        assert!(matches!(
            guard.check_and_record(hello.client_nonce, NOW + 1),
            Err(HandshakeError::ReplayNonce)
        ));

        let fresh = client_with(ring(0x01), [0x23; 32], ProtoVersion::CURRENT);
        let fresh_hello = seal_hello(&fresh, &nonces);
        assert!(guard
            .check_and_record(fresh_hello.client_nonce, NOW + 2)
            .is_ok());
    }

    #[test]
    fn reused_proof_and_accept_nonce_is_rejected() {
        let nonces = NonceMinter::with_instance(16);
        let client = client(ring(0x01));
        let hello = seal_hello(&client, &nonces);
        let mut server = server(ring(0x01));
        let mut input = input();
        input.accept_nonce = input.proof_nonce;
        assert!(matches!(
            server.on_hello(&hello, input).unwrap_err(),
            HandshakeError::Crypto(CryptoError::Aead)
        ));
    }

    #[test]
    fn version_mismatch_is_rejected_before_keys() {
        let nonces = NonceMinter::with_instance(13);
        let client = client_with(ring(0x01), [0x22; 32], ProtoVersion::V2_0);
        let hello = seal_hello(&client, &nonces);
        let mut server = server(ring(0x01));
        let error = server.on_hello(&hello, input()).unwrap_err();
        assert!(matches!(
            error,
            HandshakeError::Version(VersionError::MajorMismatch {
                local: 3,
                remote: 2
            })
        ));
    }

    #[test]
    fn old_v2_welcome_is_rejected_as_a_version_mismatch() {
        let nonces = NonceMinter::with_instance(17);
        let mut client = client(ring(0x01));
        let _hello = seal_hello(&client, &nonces);

        // The body a 2.0 server would send: the same plain fields, but no
        // server proof and no sealed ACCEPT. Negotiation runs first, so the
        // client reports the version break, not a missing attachment.
        let welcome = Welcome {
            proto: ProtoVersion::V2_0,
            caps: Caps::REQUIRED,
            epoch: NOW,
            current_seq: Seq(7),
            client_id: ClientId::from_bytes([0x11; 16]),
            resync: ResyncMode::None,
            limits: limits(),
            server_time: NOW,
            server_nonce: [0x44; 32],
            session_id: SessionId(0x3333),
        };
        let body = welcome.encode().unwrap();
        let error = client.on_welcome(&welcome, &body, NOW).unwrap_err();
        assert!(matches!(
            error,
            HandshakeError::Version(VersionError::MajorMismatch {
                local: 3,
                remote: 2
            })
        ));
        assert_eq!(client.phase(), ClientPhase::Failed);
    }

    #[test]
    fn phase_order_is_enforced() {
        let nonces = NonceMinter::with_instance(14);
        let mut client = client(ring(0x01));
        let mut server = server(ring(0x01));
        let hello = seal_hello(&client, &nonces);
        let reply = server.on_hello(&hello, input()).unwrap();
        let _ = client.on_welcome(&reply.welcome, &reply.body, NOW).unwrap();
        assert!(matches!(
            client.on_welcome(&reply.welcome, &reply.body, NOW).unwrap_err(),
            HandshakeError::WrongPhase {
                expected: ClientPhase::HelloSent,
                actual: ClientPhase::Steady
            }
        ));
    }
}
