//! SMM1 authentication: hello proof, session keys and request MACs.
//!
//! This module is sans-io. Time, the master key and the nonce guard are
//! injected; nothing reads a clock or an RNG here.
//!
//! # Key schedule
//!
//! ```text
//! K_hello = BLAKE3 derive_key("sm/1.1/mm/hello", master_key)
//! hello proof = keyed_blake3(K_hello, client_id || client_nonce || timestamp_le)
//! welcome proof = keyed_blake3(K_hello, client_nonce || server_nonce
//!                                     || session_id || session_expires_le)
//! K_s = BLAKE3 derive_key("sm/1.1/mm/session",
//!                         master_key || client_nonce || server_nonce || session_id)
//! request MAC = keyed_blake3(K_s, method || 0 || path || 0 || seq_le
//!                               || BLAKE3(meta) || BLAKE3(payload))
//! ```
//!
//! The session key is never printed. The request MAC covers the *bytes* of
//! the meta stream and payload, not a re-encoding of the decoded values, so a
//! verifier never has to reproduce a peer's field order.

use std::fmt;

use subtle::ConstantTimeEq;

use crate::protocol::handshake::{HandshakeError, NonceReplayGuard};

use super::error::{AuthError, ProtoError};
use super::header::Header;
use super::messages::{Hello, Welcome};

/// Derivation context for the hello key.
pub const HELLO_CONTEXT: &str = "sm/1.1/mm/hello";
/// Derivation context for the session key.
pub const SESSION_CONTEXT: &str = "sm/1.1/mm/session";
/// Accepted clock skew, in milliseconds.
pub const TIMESTAMP_WINDOW_MS: u64 = 60_000;
/// Default idle session lifetime.
pub const SESSION_TTL_MS: u64 = 10 * 60 * 1000;
/// Largest MAC path.
pub const MAX_MAC_PATH: usize = 4096;

/// HTTP header carrying the session id.
pub const HEADER_SESSION: &str = "x-sm-mm-session";
/// HTTP header carrying the request sequence.
pub const HEADER_SEQ: &str = "x-sm-mm-seq";
/// HTTP header carrying the request MAC.
pub const HEADER_MAC: &str = "x-sm-mm-mac";

/// The hello key, derived once per master key.
pub fn derive_hello_key(master_key: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key(HELLO_CONTEXT, master_key)
}

/// The session key.
pub fn derive_session_key(
    master_key: &[u8; 32],
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
    session_id: &[u8; 16],
) -> [u8; 32] {
    let mut material = [0u8; 112];
    material[..32].copy_from_slice(master_key);
    material[32..64].copy_from_slice(client_nonce);
    material[64..96].copy_from_slice(server_nonce);
    material[96..112].copy_from_slice(session_id);
    blake3::derive_key(SESSION_CONTEXT, &material)
}

/// The client's hello proof.
pub fn hello_proof(
    hello_key: &[u8; 32],
    client_id: &[u8; 16],
    client_nonce: &[u8; 32],
    timestamp_ms: u64,
) -> [u8; 32] {
    let mut input = [0u8; 16 + 32 + 8];
    input[..16].copy_from_slice(client_id);
    input[16..48].copy_from_slice(client_nonce);
    input[48..].copy_from_slice(&timestamp_ms.to_le_bytes());
    *blake3::keyed_hash(hello_key, &input).as_bytes()
}

/// The server's welcome proof.
pub fn welcome_proof(
    hello_key: &[u8; 32],
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
    session_id: &[u8; 16],
    session_expires_at_ms: u64,
) -> [u8; 32] {
    let mut input = [0u8; 32 + 32 + 16 + 8];
    input[..32].copy_from_slice(client_nonce);
    input[32..64].copy_from_slice(server_nonce);
    input[64..80].copy_from_slice(session_id);
    input[80..].copy_from_slice(&session_expires_at_ms.to_le_bytes());
    *blake3::keyed_hash(hello_key, &input).as_bytes()
}

/// Check `timestamp_ms` against `now_ms` with a ±60 s window.
///
/// # Errors
///
/// [`AuthError::TimestampSkew`].
pub fn check_timestamp(now_ms: u64, timestamp_ms: u64) -> Result<(), AuthError> {
    if now_ms.abs_diff(timestamp_ms) > TIMESTAMP_WINDOW_MS {
        return Err(AuthError::TimestampSkew {
            now_ms,
            timestamp_ms,
        });
    }
    Ok(())
}

/// Verify a `HELLO` and consume its nonce.
///
/// The nonce is recorded only after the proof verifies, so a failed hello
/// cannot burn replay-window capacity.
///
/// # Errors
///
/// [`AuthError::TimestampSkew`], [`AuthError::BadProof`] or
/// [`AuthError::NonceReplay`].
pub fn verify_hello(
    hello: &Hello,
    now_ms: u64,
    hello_key: &[u8; 32],
    guard: &mut NonceReplayGuard,
) -> Result<(), AuthError> {
    check_timestamp(now_ms, hello.timestamp_ms)?;
    let expected = hello_proof(
        hello_key,
        &hello.client_id,
        &hello.client_nonce,
        hello.timestamp_ms,
    );
    if !bool::from(expected.ct_eq(&hello.proof)) {
        return Err(AuthError::BadProof);
    }
    match guard.check_and_record(hello.client_nonce, now_ms) {
        Ok(()) => Ok(()),
        Err(HandshakeError::ReplayNonce) => Err(AuthError::NonceReplay),
        // The guard has one failure mode today. Treat anything else as a
        // replay rather than silently accepting an unrecorded nonce.
        Err(_) => Err(AuthError::NonceReplay),
    }
}

/// Verify a `WELCOME` against the hello nonce.
///
/// # Errors
///
/// [`AuthError::BadProof`].
pub fn verify_welcome(
    welcome: &Welcome,
    hello_key: &[u8; 32],
    client_nonce: &[u8; 32],
) -> Result<(), AuthError> {
    let expected = welcome_proof(
        hello_key,
        client_nonce,
        &welcome.server_nonce,
        &welcome.session_id,
        welcome.session_expires_at_ms,
    );
    if !bool::from(expected.ct_eq(&welcome.proof)) {
        return Err(AuthError::BadProof);
    }
    Ok(())
}

/// Derive the session key after verifying the welcome proof.
///
/// # Errors
///
/// [`AuthError::BadProof`] or an invalid advertised limit set.
pub fn accept_welcome(
    master_key: &[u8; 32],
    hello: &Hello,
    welcome: &Welcome,
) -> Result<SessionKeys, ProtoError> {
    let hello_key = derive_hello_key(master_key);
    verify_welcome(welcome, &hello_key, &hello.client_nonce)?;
    welcome.limits.validate()?;
    Ok(SessionKeys {
        key: derive_session_key(
            master_key,
            &hello.client_nonce,
            &welcome.server_nonce,
            &welcome.session_id,
        ),
        session_id: welcome.session_id,
        expires_at_ms: welcome.session_expires_at_ms,
    })
}

/// A live session key.
#[derive(Clone)]
pub struct SessionKeys {
    key: [u8; 32],
    session_id: [u8; 16],
    expires_at_ms: u64,
}

impl SessionKeys {
    /// Build from raw parts. The caller must have verified the welcome.
    pub fn new(key: [u8; 32], session_id: [u8; 16], expires_at_ms: u64) -> Self {
        Self {
            key,
            session_id,
            expires_at_ms,
        }
    }

    /// The session id.
    pub const fn session_id(&self) -> &[u8; 16] {
        &self.session_id
    }

    /// The session deadline.
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    /// The request MAC for these parts.
    ///
    /// # Errors
    ///
    /// [`AuthError::BadMethod`] or [`AuthError::BadPath`].
    pub fn mac(&self, parts: &MacParts<'_>) -> Result<[u8; 32], AuthError> {
        parts.validate()?;
        let input = parts.encode();
        Ok(*blake3::keyed_hash(&self.key, &input).as_bytes())
    }

    /// Verify a request MAC in constant time.
    ///
    /// # Errors
    ///
    /// [`AuthError::BadMethod`], [`AuthError::BadPath`] or
    /// [`AuthError::BadMac`].
    pub fn verify_mac(&self, parts: &MacParts<'_>, mac: &[u8; 32]) -> Result<(), AuthError> {
        let expected = self.mac(parts)?;
        if bool::from(expected.ct_eq(mac)) {
            Ok(())
        } else {
            Err(AuthError::BadMac)
        }
    }
}

impl fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionKeys")
            .field("session_id", &self.session_id)
            .field("expires_at_ms", &self.expires_at_ms)
            .finish_non_exhaustive()
    }
}

impl Drop for SessionKeys {
    fn drop(&mut self) {
        self.key.fill(0);
    }
}

/// The canonical MAC input parts.
#[derive(Clone, Copy, Debug)]
pub struct MacParts<'a> {
    /// `GET` or `POST`.
    pub method: &'a str,
    /// Request path, including the query string.
    pub path: &'a str,
    /// Request sequence.
    pub seq: u64,
    /// BLAKE3 of the meta bytes.
    pub meta_hash: [u8; 32],
    /// BLAKE3 of the payload bytes.
    pub payload_hash: [u8; 32],
}

impl MacParts<'_> {
    /// Check the canonical method and path.
    ///
    /// # Errors
    ///
    /// [`AuthError::BadMethod`] or [`AuthError::BadPath`].
    pub fn validate(&self) -> Result<(), AuthError> {
        if self.method != "GET" && self.method != "POST" {
            return Err(AuthError::BadMethod);
        }
        if self.path.is_empty()
            || !self.path.starts_with('/')
            || self.path.len() > MAX_MAC_PATH
            || self.path.as_bytes().contains(&0)
        {
            return Err(AuthError::BadPath);
        }
        Ok(())
    }

    fn encode(&self) -> Vec<u8> {
        let mut input =
            Vec::with_capacity(self.method.len() + 1 + self.path.len() + 1 + 8 + 32 + 32);
        input.extend_from_slice(self.method.as_bytes());
        input.push(0);
        input.extend_from_slice(self.path.as_bytes());
        input.push(0);
        input.extend_from_slice(&self.seq.to_le_bytes());
        input.extend_from_slice(&self.meta_hash);
        input.extend_from_slice(&self.payload_hash);
        input
    }
}

/// The server's per-session sequence gate.
#[derive(Clone, Copy, Debug)]
pub struct SessionGuard {
    expires_at_ms: u64,
    last_seq: u64,
}

impl SessionGuard {
    /// A guard for a session that expires at `expires_at_ms`.
    pub const fn new(expires_at_ms: u64) -> Self {
        Self {
            expires_at_ms,
            last_seq: 0,
        }
    }

    /// The highest accepted sequence.
    pub const fn last_seq(&self) -> u64 {
        self.last_seq
    }

    /// The session deadline.
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    /// Check the session deadline.
    ///
    /// # Errors
    ///
    /// [`AuthError::SessionExpired`].
    pub fn check_expiry(&self, now_ms: u64) -> Result<(), AuthError> {
        if now_ms > self.expires_at_ms {
            return Err(AuthError::SessionExpired {
                now_ms,
                expires_at_ms: self.expires_at_ms,
            });
        }
        Ok(())
    }

    /// Check and advance the request sequence.
    ///
    /// # Errors
    ///
    /// [`AuthError::SeqReplay`] when `seq <= last_seq`.
    pub fn check_seq(&mut self, seq: u64) -> Result<(), AuthError> {
        if seq <= self.last_seq {
            return Err(AuthError::SeqReplay {
                seq,
                last_seq: self.last_seq,
            });
        }
        self.last_seq = seq;
        Ok(())
    }

    /// Verify expiry, MAC and sequence, in that order.
    ///
    /// The sequence advances only after the MAC verifies, so a forged request
    /// cannot consume a sequence number.
    ///
    /// # Errors
    ///
    /// [`AuthError::SessionExpired`], [`AuthError::BadMac`] or
    /// [`AuthError::SeqReplay`].
    pub fn verify(
        &mut self,
        keys: &SessionKeys,
        parts: &MacParts<'_>,
        mac: &[u8; 32],
        now_ms: u64,
    ) -> Result<(), ProtoError> {
        self.check_expiry(now_ms)?;
        keys.verify_mac(parts, mac)?;
        self.check_seq(parts.seq)?;
        Ok(())
    }
}

/// Hex-encode a session id for the `X-SM-MM-Session` header.
pub fn encode_session_id(session_id: &[u8; 16]) -> String {
    hex::encode(session_id)
}

/// Parse a 32-character session id.
///
/// # Errors
///
/// [`AuthError::BadProof`] on any non-hex or wrong-length input.
pub fn parse_session_id(raw: &str) -> Result<[u8; 16], AuthError> {
    let bytes = hex::decode(raw).map_err(|_| AuthError::BadProof)?;
    bytes.try_into().map_err(|_| AuthError::BadProof)
}

/// Hex-encode a request MAC.
pub fn encode_mac(mac: &[u8; 32]) -> String {
    hex::encode(mac)
}

/// Parse a 64-character request MAC.
///
/// # Errors
///
/// [`AuthError::BadMac`] on any non-hex or wrong-length input.
pub fn parse_mac(raw: &str) -> Result<[u8; 32], AuthError> {
    let bytes = hex::decode(raw).map_err(|_| AuthError::BadMac)?;
    bytes.try_into().map_err(|_| AuthError::BadMac)
}

/// Parse the `X-SM-MM-Seq` header.
///
/// # Errors
///
/// [`AuthError::SeqReplay`] is not used here; a malformed sequence is a bad
/// request. The caller maps it to `BAD_REQUEST`.
pub fn parse_seq(raw: &str) -> Result<u64, AuthError> {
    if raw.is_empty() || raw.len() > 20 || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(AuthError::BadProof);
    }
    raw.parse::<u64>().map_err(|_| AuthError::BadProof)
}

/// The canonical request MAC input, exposed for vectors.
pub fn mac_input(parts: &MacParts<'_>) -> Vec<u8> {
    parts.encode()
}

/// Hash the meta bytes a request will MAC.
pub fn hash_meta(meta: &[u8]) -> [u8; 32] {
    *blake3::hash(meta).as_bytes()
}

/// Hash the payload bytes a request will MAC.
pub fn hash_payload(payload: &[u8]) -> [u8; 32] {
    *blake3::hash(payload).as_bytes()
}

/// Hash a whole frame's meta and payload without buffering the payload.
#[derive(Debug, Default)]
pub struct FrameHasher {
    meta: blake3::Hasher,
    payload: blake3::Hasher,
}

impl FrameHasher {
    /// A fresh hasher.
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed meta bytes.
    pub fn update_meta(&mut self, bytes: &[u8]) {
        self.meta.update(bytes);
    }

    /// Feed payload bytes.
    pub fn update_payload(&mut self, bytes: &[u8]) {
        self.payload.update(bytes);
    }

    /// Finish both hashes.
    pub fn finish(self) -> ([u8; 32], [u8; 32]) {
        (
            *self.meta.finalize().as_bytes(),
            *self.payload.finalize().as_bytes(),
        )
    }
}

/// Check that a header's meta length matches the bytes about to be hashed.
///
/// # Errors
///
/// [`ProtoError::Truncated`] when the lengths differ.
pub fn check_meta_len(header: &Header, meta: &[u8]) -> Result<(), ProtoError> {
    if header.meta_len as usize != meta.len() {
        return Err(ProtoError::Truncated {
            need: header.meta_len as usize,
            got: meta.len(),
        });
    }
    Ok(())
}

#[cfg(all(test, feature = "mmap-tests"))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    const MASTER: [u8; 32] = [0x42; 32];
    const CLIENT: [u8; 16] = [0x11; 16];
    const CLIENT_NONCE: [u8; 32] = [0x22; 32];
    const SERVER_NONCE: [u8; 32] = [0x33; 32];
    const SESSION: [u8; 16] = [0x44; 16];

    fn hello(now: u64) -> Hello {
        let key = derive_hello_key(&MASTER);
        Hello {
            client_id: CLIENT,
            client_nonce: CLIENT_NONCE,
            timestamp_ms: now,
            proof: hello_proof(&key, &CLIENT, &CLIENT_NONCE, now),
        }
    }

    fn welcome(now: u64) -> Welcome {
        let key = derive_hello_key(&MASTER);
        let expires = now + SESSION_TTL_MS;
        Welcome {
            session_id: SESSION,
            server_nonce: SERVER_NONCE,
            session_expires_at_ms: expires,
            limits: super::super::limits::Limits::new(),
            proof: welcome_proof(&key, &CLIENT_NONCE, &SERVER_NONCE, &SESSION, expires),
        }
    }

    fn keys() -> SessionKeys {
        SessionKeys::new(
            derive_session_key(&MASTER, &CLIENT_NONCE, &SERVER_NONCE, &SESSION),
            SESSION,
            u64::MAX,
        )
    }

    fn parts(seq: u64) -> MacParts<'static> {
        MacParts {
            method: "POST",
            path: "/private-mm/mm/v1/checkout",
            seq,
            meta_hash: hash_meta(b"meta"),
            payload_hash: hash_payload(b"payload"),
        }
    }

    #[test]
    fn hello_round_trip_verifies_and_derives_the_same_session_key() {
        let now = 1_000_000;
        let hello = hello(now);
        let welcome = welcome(now);
        let mut guard = NonceReplayGuard::new();
        verify_hello(&hello, now, &derive_hello_key(&MASTER), &mut guard).unwrap();

        let server_key = accept_welcome(&MASTER, &hello, &welcome).unwrap();
        let client_key = SessionKeys::new(
            derive_session_key(&MASTER, &CLIENT_NONCE, &SERVER_NONCE, &SESSION),
            SESSION,
            welcome.session_expires_at_ms,
        );
        let mac = client_key.mac(&parts(1)).unwrap();
        server_key.verify_mac(&parts(1), &mac).unwrap();
    }

    #[test]
    fn hello_rejects_skew_bad_proof_and_replay() {
        let now = 1_000_000;
        let key = derive_hello_key(&MASTER);
        let mut guard = NonceReplayGuard::new();

        let old = hello(now - TIMESTAMP_WINDOW_MS - 1);
        assert!(matches!(
            verify_hello(&old, now, &key, &mut guard),
            Err(AuthError::TimestampSkew { .. })
        ));

        let future = hello(now + TIMESTAMP_WINDOW_MS + 1);
        assert!(matches!(
            verify_hello(&future, now, &key, &mut guard),
            Err(AuthError::TimestampSkew { .. })
        ));

        let mut forged = hello(now);
        forged.proof[0] ^= 1;
        assert!(matches!(
            verify_hello(&forged, now, &key, &mut guard),
            Err(AuthError::BadProof)
        ));

        let good = hello(now);
        verify_hello(&good, now, &key, &mut guard).unwrap();
        assert!(matches!(
            verify_hello(&good, now, &key, &mut guard),
            Err(AuthError::NonceReplay)
        ));
    }

    #[test]
    fn failed_hello_does_not_consume_the_nonce_window() {
        let now = 1_000_000;
        let key = derive_hello_key(&MASTER);
        let mut guard = NonceReplayGuard::new();
        let mut forged = hello(now);
        forged.proof = [0u8; 32];
        assert!(verify_hello(&forged, now, &key, &mut guard).is_err());
        let good = hello(now);
        verify_hello(&good, now, &key, &mut guard).unwrap();
    }

    #[test]
    fn welcome_rejects_a_forged_proof() {
        let now = 1_000_000;
        let mut welcome = welcome(now);
        welcome.proof[31] ^= 1;
        assert!(matches!(
            verify_welcome(&welcome, &derive_hello_key(&MASTER), &CLIENT_NONCE),
            Err(AuthError::BadProof)
        ));
    }

    #[test]
    fn request_mac_binds_method_path_seq_and_hashes() {
        let keys = keys();
        let base = parts(7);
        let mac = keys.mac(&base).unwrap();

        for mutated in [
            MacParts {
                method: "GET",
                ..base
            },
            MacParts {
                path: "/private-mm/mm/v1/other",
                ..base
            },
            MacParts { seq: 8, ..base },
            MacParts {
                meta_hash: [0xAA; 32],
                ..base
            },
            MacParts {
                payload_hash: [0xBB; 32],
                ..base
            },
        ] {
            assert!(matches!(
                keys.verify_mac(&mutated, &mac),
                Err(AuthError::BadMac)
            ));
        }
    }

    #[test]
    fn session_guard_rejects_replay_and_expiry() {
        let keys = keys();
        let mut guard = SessionGuard::new(1_000);
        let request = parts(1);
        let mac = keys.mac(&request).unwrap();
        guard.verify(&keys, &request, &mac, 999).unwrap();
        assert!(matches!(
            guard.verify(&keys, &request, &mac, 999),
            Err(ProtoError::Auth(AuthError::SeqReplay {
                seq: 1,
                last_seq: 1
            }))
        ));

        let next = parts(2);
        let mac = keys.mac(&next).unwrap();
        assert!(matches!(
            guard.verify(&keys, &next, &mac, 1_001),
            Err(ProtoError::Auth(AuthError::SessionExpired { .. }))
        ));
    }

    #[test]
    fn forged_mac_does_not_advance_the_sequence() {
        let keys = keys();
        let mut guard = SessionGuard::new(u64::MAX);
        let request = parts(5);
        let mac = keys.mac(&request).unwrap();
        let mut forged = mac;
        forged[0] ^= 1;
        assert!(guard.verify(&keys, &request, &forged, 0).is_err());
        assert_eq!(guard.last_seq(), 0);
        guard.verify(&keys, &request, &mac, 0).unwrap();
        assert_eq!(guard.last_seq(), 5);
    }

    #[test]
    fn methods_and_paths_are_canonical() {
        for method in ["get", "POST ", "", "PATCH"] {
            let parts = MacParts { method, ..parts(1) };
            assert!(matches!(parts.validate(), Err(AuthError::BadMethod)));
        }
        for path in ["", "mm/v1", "/a\0b"] {
            let parts = MacParts { path, ..parts(1) };
            assert!(matches!(parts.validate(), Err(AuthError::BadPath)));
        }
    }

    #[test]
    fn header_codecs_round_trip() {
        assert_eq!(
            parse_session_id(&encode_session_id(&SESSION)).unwrap(),
            SESSION
        );
        let mac = [0x5A; 32];
        assert_eq!(parse_mac(&encode_mac(&mac)).unwrap(), mac);
        assert_eq!(parse_seq("18446744073709551615").unwrap(), u64::MAX);
        for bad in ["", "-1", "+1", "1x", "18446744073709551616"] {
            assert!(parse_seq(bad).is_err());
        }
        assert!(parse_session_id("zz").is_err());
        assert!(parse_mac("00").is_err());
    }

    #[test]
    fn session_key_debug_does_not_print_the_key() {
        let text = format!("{:?}", keys());
        assert!(!text.contains("42"));
    }
}
