//! Protocol AEAD: key derivation, nonce minting, AAD and the sealed envelope.
//!
//! This module owns the byte layout of `enc_body` (44 §4.4):
//!
//! ```text
//! enc_body = alg u8 | kid u8 | nonce 12 | ciphertext n | tag 16
//! ```
//!
//! and the v2 AAD (44 §4.3, 49 A11):
//!
//! ```text
//! aad = "sm/v2/aad\0"                     10 B
//!     | alg u8 | kid u8                    2 B
//!     | magic u8 | ver u8 | type u8        3 B
//!     | flags u16 LE | req_id u32 LE       6 B
//!     | len u32 LE                         4 B
//!     | prefix_tag u8                      1 B
//!     | prefix bytes                       0 / 25 / 18 B
//! ```
//!
//! The fixed part is 26 bytes and the largest AAD is 51 bytes, so no AAD
//! allocation is ever needed. `seq` is deliberately absent: the sender does
//! not know it when sealing and the server rewrites it on rebroadcast
//! (44 INV-06/INV-17). The server holds the same PSK, so it can decrypt
//! `ORDERED` for validation and persistence, but it forwards the original
//! ciphertext unchanged.
//!
//! The module is sans-io: entropy and frame headers are injected. It never
//! returns plaintext before the tag verifies, and plaintext is held in a
//! [`Zeroizing`] buffer.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(feature = "reduced-round")]
use chacha20poly1305::ChaCha8Poly1305;
use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce, Tag};
use hkdf::Hkdf;
use rand_core::Rng;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::protocol::frame::{CTRL_PREFIX_LEN, HEADER_LEN, ROUTE_PREFIX_LEN};
use crate::protocol::{ENV_OVERHEAD, FrameHeader, MAX_PLAINTEXT, Prefix};

/// Envelope algorithm byte for ChaCha8-Poly1305 (44 §4.4).
pub const ALG_CHACHA8: u8 = 0;

/// Envelope algorithm byte for ChaCha20-Poly1305 (44 §4.4).
pub const ALG_CHACHA20: u8 = 1;

/// Algorithm selected by the build's feature set.
///
/// `reduced-round` on (the default) means ChaCha8-Poly1305, `alg=0`; off means
/// ChaCha20-Poly1305, `alg=1`. The two builds do not interoperate.
#[cfg(feature = "reduced-round")]
pub const DEFAULT_ALG: u8 = ALG_CHACHA8;

/// Algorithm selected by the build's feature set.
///
/// `reduced-round` on (the default) means ChaCha8-Poly1305, `alg=0`; off means
/// ChaCha20-Poly1305, `alg=1`. The two builds do not interoperate.
#[cfg(not(feature = "reduced-round"))]
pub const DEFAULT_ALG: u8 = ALG_CHACHA20;

/// Nonce width in bytes.
pub const NONCE_LEN: usize = 12;

/// Poly1305 tag width in bytes.
pub const TAG_LEN: usize = 16;

/// AAD domain separator, including the terminating NUL (44 §4.3).
pub const AAD_DOMAIN: &[u8; 10] = b"sm/v2/aad\0";

/// AAD bytes before the variable prefix: 10 + 2 + (21 - 8) + 1 = 26.
pub const AAD_FIXED_LEN: usize = 26;

/// Largest AAD: fixed part plus a route prefix.
pub const AAD_MAX_LEN: usize = AAD_FIXED_LEN + ROUTE_PREFIX_LEN;

/// HKDF info for the payload key (49 A13).
pub const ENC_INFO: &[u8] = b"sm/v2/enc";

/// HKDF info for the control key (49 A13).
pub const CTRL_INFO: &[u8] = b"sm/v2/ctrl";

/// HKDF info for the handshake master key (49 A13).
pub const HS_INFO: &[u8] = b"sm/v2/hs";

/// HKDF info for the per-connection handshake key.
pub const HS_SESSION_INFO: &[u8] = b"sm/v2/hs/session";

/// HKDF info for the client-nonce handshake key that seals `AUTH`.
///
/// `AUTH` travels inside the first `HELLO`, before the client knows the
/// server nonce, so its key can only be bound to the client nonce.
pub const HS_AUTH_INFO: &[u8] = b"sm/v2/hs/auth";

/// AAD domain for the sealed `AUTH` carried in `HELLO`.
pub const AUTH_DOMAIN: &[u8] = b"sm/v2/auth\0";

/// AAD domain for the sealed `ACCEPT` carried in `WELCOME`.
pub const ACCEPT_DOMAIN: &[u8] = b"sm/v2/accept\0";

/// Overhead of a detached seal: `alg u8 | nonce 12 | tag 16`.
pub const DETACHED_OVERHEAD: usize = 1 + NONCE_LEN + TAG_LEN;

/// BLAKE3 domain for the key identifier (44 §4.1).
pub const KID_DOMAIN: &[u8] = b"sm/v2/kid";

/// AAD domain for the `WELCOME` server proof.
pub const WELCOME_PROOF_DOMAIN: &[u8] = b"sm/v2/welcome\0";

/// Width of the fixed PSK salt.
pub const PSK_SALT_LEN: usize = 16;

/// Fixed 16-byte PSK salt.
///
/// Frozen value of the legacy `default_cluster()`:
/// `BLAKE3("sm/v1/cluster\0" ‖ "default")[..16]`. The domain string is part
/// of the salt value, not of the v2 protocol domains, so it must not be
/// rewritten. The URL never enters this value.
pub const PSK_SALT: [u8; PSK_SALT_LEN] = [
    0x60, 0xce, 0x80, 0xb3, 0xc3, 0x3b, 0xdf, 0x8b, 0x76, 0x3a, 0xf7, 0x46, 0x4a, 0xd1, 0x31, 0xda,
];

/// Width of a `WELCOME` server proof: `alg u8 | nonce 12 | ct 32 | tag 16`.
pub const WELCOME_PROOF_LEN: usize = 1 + NONCE_LEN + 32 + TAG_LEN;

const _: () = {
    assert!(AAD_FIXED_LEN == AAD_DOMAIN.len() + 2 + (HEADER_LEN - 8) + 1);
    assert!(AAD_MAX_LEN == 51);
};

/// Whether this build can seal or open `alg`.
pub const fn is_supported_alg(alg: u8) -> bool {
    matches!(alg, ALG_CHACHA20) || (matches!(alg, ALG_CHACHA8) && cfg!(feature = "reduced-round"))
}

/// A local crypto failure. Never travels on the wire.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum CryptoError {
    /// The envelope `kid` does not match the ring's `kid`.
    UnknownKey,
    /// AEAD authentication failed, or the envelope is malformed.
    Aead,
    /// The 32-bit nonce counter is exhausted; the key must be replaced.
    NonceExhausted,
    /// The envelope names an algorithm this build does not implement.
    BadAlg(u8),
    /// Plaintext exceeds [`MAX_PLAINTEXT`].
    PlaintextTooLarge {
        /// Requested plaintext width.
        len: usize,
        /// Largest accepted width.
        max: usize,
    },
    /// HKDF could not produce a 32-byte key. Impossible with SHA-256; kept so
    /// callers never have to unwrap.
    Kdf,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownKey => f.write_str("unknown encryption key"),
            Self::Aead => f.write_str("AEAD authentication failed"),
            Self::NonceExhausted => f.write_str("nonce counter exhausted"),
            Self::BadAlg(alg) => write!(f, "unsupported envelope algorithm {alg}"),
            Self::PlaintextTooLarge { len, max } => {
                write!(f, "plaintext too large: {len} > {max}")
            }
            Self::Kdf => f.write_str("key derivation failed"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// A 16-byte cluster identifier. It is the HKDF salt (44 §4.1).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ClusterId([u8; 16]);

impl ClusterId {
    /// Encoded width.
    pub const LEN: usize = 16;

    /// Wrap raw bytes.
    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    /// Raw bytes, used verbatim as the HKDF salt.
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl From<[u8; ClusterId::LEN]> for ClusterId {
    fn from(bytes: [u8; ClusterId::LEN]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl fmt::Debug for ClusterId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClusterId(")?;
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        f.write_str(")")
    }
}

impl fmt::Display for ClusterId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// The fixed 16-byte salt used by Argon2id and HKDF.
///
/// A distinct type keeps the PSK salt from being confused with the legacy
/// [`ClusterId`]. The default is [`PSK_SALT`], the frozen value every client
/// in the cluster uses.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PskSalt([u8; PSK_SALT_LEN]);

impl PskSalt {
    /// The frozen default salt.
    pub const DEFAULT: Self = Self(PSK_SALT);

    /// Wrap explicit bytes. Tests and golden vectors only.
    pub const fn from_bytes(bytes: [u8; PSK_SALT_LEN]) -> Self {
        Self(bytes)
    }

    /// Raw bytes.
    pub const fn as_bytes(&self) -> &[u8; PSK_SALT_LEN] {
        &self.0
    }
}

impl Default for PskSalt {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl fmt::Debug for PskSalt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PskSalt(")?;
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        f.write_str(")")
    }
}

/// Keys derived from the pre-shared key.
///
/// `enc` seals steady-state frames, `ctrl` is reserved, and `hs` is the input
/// keying material for per-connection handshake keys. The PSK itself never
/// enters an AEAD.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PskKeyRing {
    kid: u8,
    enc: [u8; 32],
    ctrl: [u8; 32],
    hs: [u8; 32],
}

impl PskKeyRing {
    /// Derive the ring with HKDF-SHA256.
    ///
    /// `salt = salt`, `ikm = psk`, and the info strings are [`ENC_INFO`],
    /// [`CTRL_INFO`] and [`HS_INFO`]. The key id is
    /// `BLAKE3(enc_key ‖ "sm/v2/kid")[0]`.
    ///
    /// # Errors
    ///
    /// [`CryptoError::Kdf`] only if HKDF rejects a 32-byte output, which
    /// SHA-256 cannot do.
    pub fn derive(psk: &[u8; 32], salt: &PskSalt) -> Result<Self, CryptoError> {
        let hk = Hkdf::<Sha256>::new(Some(salt.as_bytes()), psk);
        let mut ring = Self {
            kid: 0,
            enc: [0u8; 32],
            ctrl: [0u8; 32],
            hs: [0u8; 32],
        };
        hk.expand(ENC_INFO, &mut ring.enc)
            .map_err(|_| CryptoError::Kdf)?;
        hk.expand(CTRL_INFO, &mut ring.ctrl)
            .map_err(|_| CryptoError::Kdf)?;
        hk.expand(HS_INFO, &mut ring.hs)
            .map_err(|_| CryptoError::Kdf)?;

        let mut hasher = blake3::Hasher::new();
        hasher.update(&ring.enc);
        hasher.update(KID_DOMAIN);
        ring.kid = hasher.finalize().as_bytes()[0];
        Ok(ring)
    }

    /// The steady-state key identifier.
    pub const fn kid(&self) -> u8 {
        self.kid
    }

    /// The steady-state encryption key.
    pub const fn enc_key(&self) -> &[u8; 32] {
        &self.enc
    }

    /// The control key. Reserved; exposed for KDF registry tests.
    pub const fn ctrl_key(&self) -> &[u8; 32] {
        &self.ctrl
    }

    /// The steady-state session key for [`Sealer`] and [`Opener`].
    pub const fn session_key(&self) -> SessionKey {
        SessionKey {
            key: self.enc,
            kid: self.kid,
        }
    }

    /// Derive the handshake key for one connection.
    ///
    /// `salt = client_nonce ‖ server_nonce`, `ikm = hs`, and the info string
    /// is [`HS_SESSION_INFO`]. The handshake key id is
    /// `BLAKE3(hs_key ‖ "sm/v2/kid")[0]`.
    ///
    /// # Errors
    ///
    /// [`CryptoError::Kdf`] only if HKDF rejects a 32-byte output.
    pub fn handshake_keys(
        &self,
        client_nonce: &[u8; 32],
        server_nonce: &[u8; 32],
    ) -> Result<HandshakeKeys, CryptoError> {
        let mut salt = [0u8; 64];
        salt[..32].copy_from_slice(client_nonce);
        salt[32..].copy_from_slice(server_nonce);
        let hk = Hkdf::<Sha256>::new(Some(&salt), &self.hs);
        let mut key = [0u8; 32];
        hk.expand(HS_SESSION_INFO, &mut key)
            .map_err(|_| CryptoError::Kdf)?;

        let mut hasher = blake3::Hasher::new();
        hasher.update(&key);
        hasher.update(KID_DOMAIN);
        let kid = hasher.finalize().as_bytes()[0];
        salt.zeroize();
        Ok(HandshakeKeys { key, kid })
    }

    /// Derive the key that seals `AUTH` inside `HELLO`.
    ///
    /// `salt = client_nonce`, `ikm = hs`, and the info string is
    /// [`HS_AUTH_INFO`]. The client derives this key before it knows the
    /// server nonce; the server derives the same key from the nonce it reads
    /// in `HELLO`.
    ///
    /// # Errors
    ///
    /// [`CryptoError::Kdf`] only if HKDF rejects a 32-byte output.
    pub fn auth_keys(&self, client_nonce: &[u8; 32]) -> Result<HandshakeKeys, CryptoError> {
        let hk = Hkdf::<Sha256>::new(Some(client_nonce), &self.hs);
        let mut key = [0u8; 32];
        hk.expand(HS_AUTH_INFO, &mut key)
            .map_err(|_| CryptoError::Kdf)?;

        let mut hasher = blake3::Hasher::new();
        hasher.update(&key);
        hasher.update(KID_DOMAIN);
        let kid = hasher.finalize().as_bytes()[0];
        Ok(HandshakeKeys { key, kid })
    }
}

impl fmt::Debug for PskKeyRing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PskKeyRing")
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

/// A 32-byte key plus its one-byte envelope identifier.
///
/// The key is zeroized on drop. This is the unit [`Sealer`] and [`Opener`]
/// accept; it is either the steady-state `enc` key or a handshake key.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SessionKey {
    key: [u8; 32],
    kid: u8,
}

impl SessionKey {
    /// Wrap an explicit key and identifier.
    pub const fn new(key: [u8; 32], kid: u8) -> Self {
        Self { key, kid }
    }

    /// The key bytes.
    pub const fn key(&self) -> &[u8; 32] {
        &self.key
    }

    /// The envelope identifier.
    pub const fn kid(&self) -> u8 {
        self.kid
    }
}

impl fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionKey")
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

/// A per-connection handshake key.
///
/// [`PskKeyRing::auth_keys`] derives the key that seals `AUTH` from the
/// client nonce alone. [`PskKeyRing::handshake_keys`] derives the key that
/// seals the `WELCOME` proof and the `ACCEPT` from both nonces.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HandshakeKeys {
    key: [u8; 32],
    kid: u8,
}

impl HandshakeKeys {
    /// Wrap an explicit key and identifier. Tests only.
    pub const fn new(key: [u8; 32], kid: u8) -> Self {
        Self { key, kid }
    }

    /// The envelope identifier used by [`HandshakeKeys::sealer`] and
    /// [`HandshakeKeys::opener`]. Detached handshake sub-bodies do not carry
    /// it: their format is `alg | nonce | ciphertext | tag`.
    pub const fn kid(&self) -> u8 {
        self.kid
    }

    /// A sealer bound to this key.
    pub fn sealer<'a>(&self, nonces: &'a NonceMinter) -> Sealer<'a> {
        Sealer::with_key(&self.key, self.kid, nonces)
    }

    /// An opener bound to this key.
    pub fn opener(&self) -> Opener<'static> {
        Opener::with_key(&self.key, self.kid)
    }

    /// Seal a frame body under this handshake key.
    ///
    /// # Errors
    ///
    /// As [`Sealer::seal`].
    pub fn seal(
        &self,
        header: &mut FrameHeader,
        prefix: &Prefix,
        plaintext: &[u8],
        nonces: &NonceMinter,
    ) -> Result<Sealed, CryptoError> {
        self.sealer(nonces).seal(header, prefix, plaintext)
    }

    /// Open a frame body sealed under this handshake key.
    ///
    /// # Errors
    ///
    /// As [`Opener::open`].
    pub fn open(
        &self,
        header: &FrameHeader,
        prefix: &Prefix,
        body: &[u8],
    ) -> Result<Opened, CryptoError> {
        self.opener().open(header, prefix, body)
    }

    /// Seal a detached sub-body with an explicit nonce and AAD context.
    ///
    /// The output is `alg u8 | nonce 12 | ciphertext n | tag 16`, the same
    /// layout as the `WELCOME` proof. `domain` separates handshake messages;
    /// `context` binds the nonces that the caller already committed to.
    ///
    /// # Errors
    ///
    /// [`CryptoError::BadAlg`] if this build lacks the default algorithm.
    pub fn seal_detached(
        &self,
        domain: &[u8],
        context: &[u8],
        plaintext: &[u8],
        nonce: &[u8; NONCE_LEN],
    ) -> Result<Vec<u8>, CryptoError> {
        let aad = detached_aad(domain, context);
        let mut out = Vec::with_capacity(DETACHED_OVERHEAD + plaintext.len());
        out.push(DEFAULT_ALG);
        out.extend_from_slice(nonce);
        out.extend_from_slice(plaintext);
        let tag = encrypt_in_place(
            DEFAULT_ALG,
            &self.key,
            nonce,
            &aad,
            &mut out[1 + NONCE_LEN..],
        )?;
        out.extend_from_slice(&tag);
        Ok(out)
    }

    /// Open a detached sub-body produced by [`HandshakeKeys::seal_detached`].
    ///
    /// # Errors
    ///
    /// [`CryptoError::Aead`] for a short or tampered envelope, or
    /// [`CryptoError::BadAlg`] for an algorithm this build lacks.
    pub fn open_detached(
        &self,
        domain: &[u8],
        context: &[u8],
        sealed: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        if sealed.len() < DETACHED_OVERHEAD {
            return Err(CryptoError::Aead);
        }
        let alg = sealed[0];
        if !is_supported_alg(alg) {
            return Err(CryptoError::BadAlg(alg));
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&sealed[1..1 + NONCE_LEN]);
        let tag_at = sealed.len() - TAG_LEN;
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&sealed[tag_at..]);
        let mut plaintext = Zeroizing::new(sealed[1 + NONCE_LEN..tag_at].to_vec());
        let aad = detached_aad(domain, context);
        decrypt_in_place(
            alg,
            &self.key,
            &nonce,
            &aad,
            plaintext.as_mut_slice(),
            &tag,
        )?;
        Ok(plaintext)
    }

    /// Seal the `WELCOME` server proof.
    ///
    /// The proof is `alg u8 | nonce 12 | ciphertext 32 | tag 16`, where the
    /// ciphertext is `body_hash` and the AAD is
    /// `"sm/v2/welcome\0" ‖ client_nonce`. The caller supplies the nonce so
    /// this function stays deterministic; it must be fresh per proof.
    ///
    /// # Errors
    ///
    /// [`CryptoError::BadAlg`] if this build lacks the default algorithm.
    pub fn seal_welcome_proof(
        &self,
        client_nonce: &[u8; 32],
        body_hash: &[u8; 32],
        nonce: &[u8; NONCE_LEN],
    ) -> Result<[u8; WELCOME_PROOF_LEN], CryptoError> {
        let mut aad = [0u8; WELCOME_PROOF_DOMAIN.len() + 32];
        aad[..WELCOME_PROOF_DOMAIN.len()].copy_from_slice(WELCOME_PROOF_DOMAIN);
        aad[WELCOME_PROOF_DOMAIN.len()..].copy_from_slice(client_nonce);

        let mut proof = [0u8; WELCOME_PROOF_LEN];
        proof[0] = DEFAULT_ALG;
        proof[1..1 + NONCE_LEN].copy_from_slice(nonce);
        proof[1 + NONCE_LEN..1 + NONCE_LEN + 32].copy_from_slice(body_hash);
        let tag = encrypt_in_place(
            DEFAULT_ALG,
            &self.key,
            nonce,
            &aad,
            &mut proof[1 + NONCE_LEN..1 + NONCE_LEN + 32],
        )?;
        proof[1 + NONCE_LEN + 32..].copy_from_slice(&tag);
        Ok(proof)
    }

    /// Verify the `WELCOME` server proof against a locally computed body hash.
    ///
    /// # Errors
    ///
    /// [`CryptoError::Aead`] for a bad algorithm byte, a malformed proof, a
    /// tag mismatch, or a body hash mismatch. The caller must not distinguish
    /// these cases on the wire.
    pub fn open_welcome_proof(
        &self,
        client_nonce: &[u8; 32],
        body_hash: &[u8; 32],
        proof: &[u8; WELCOME_PROOF_LEN],
    ) -> Result<(), CryptoError> {
        if !is_supported_alg(proof[0]) {
            return Err(CryptoError::BadAlg(proof[0]));
        }
        let mut aad = [0u8; WELCOME_PROOF_DOMAIN.len() + 32];
        aad[..WELCOME_PROOF_DOMAIN.len()].copy_from_slice(WELCOME_PROOF_DOMAIN);
        aad[WELCOME_PROOF_DOMAIN.len()..].copy_from_slice(client_nonce);

        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&proof[1..1 + NONCE_LEN]);
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&proof[1 + NONCE_LEN + 32..]);
        let mut plaintext = [0u8; 32];
        plaintext.copy_from_slice(&proof[1 + NONCE_LEN..1 + NONCE_LEN + 32]);
        let result = decrypt_in_place(proof[0], &self.key, &nonce, &aad, &mut plaintext, &tag);
        let matches = plaintext.ct_eq(body_hash);
        plaintext.zeroize();
        result?;
        if bool::from(matches) {
            Ok(())
        } else {
            Err(CryptoError::Aead)
        }
    }
}

fn detached_aad(domain: &[u8], context: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(domain.len() + context.len());
    aad.extend_from_slice(domain);
    aad.extend_from_slice(context);
    aad
}

impl fmt::Debug for HandshakeKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HandshakeKeys")
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

/// Keys derived from the master key for one cluster.
///
/// This is the legacy v2-domain ring retained for existing callers. New code
/// should use [`PskKeyRing`]. `enc` seals payload frames and `ctrl` is
/// reserved.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct KeyRing {
    kid: u8,
    enc: [u8; 32],
    ctrl: [u8; 32],
}

impl KeyRing {
    /// Derive the ring with HKDF-SHA256.
    ///
    /// `salt = cluster_id`, `ikm = master_key`, and the info strings are
    /// [`ENC_INFO`] and [`CTRL_INFO`]. The key id is
    /// `BLAKE3(enc_key ‖ "sm/v2/kid")[0]` (44 §4.1).
    ///
    /// # Errors
    ///
    /// [`CryptoError::Kdf`] only if HKDF rejects a 32-byte output, which
    /// SHA-256 cannot do.
    pub fn derive(master_key: &[u8], cluster: &ClusterId) -> Result<Self, CryptoError> {
        let hk = Hkdf::<Sha256>::new(Some(cluster.as_bytes()), master_key);
        let mut ring = Self {
            kid: 0,
            enc: [0u8; 32],
            ctrl: [0u8; 32],
        };
        hk.expand(ENC_INFO, &mut ring.enc)
            .map_err(|_| CryptoError::Kdf)?;
        hk.expand(CTRL_INFO, &mut ring.ctrl)
            .map_err(|_| CryptoError::Kdf)?;

        let mut hasher = blake3::Hasher::new();
        hasher.update(&ring.enc);
        hasher.update(KID_DOMAIN);
        ring.kid = hasher.finalize().as_bytes()[0];
        Ok(ring)
    }

    /// The key identifier placed in every envelope and bound by the AAD.
    pub const fn kid(&self) -> u8 {
        self.kid
    }

    /// The control key. Reserved; exposed so the KDF registry can be
    /// tested without a second derivation path.
    pub const fn ctrl_key(&self) -> &[u8; 32] {
        &self.ctrl
    }

    /// The steady-state session key for [`Sealer`] and [`Opener`].
    pub const fn session_key(&self) -> SessionKey {
        SessionKey {
            key: self.enc,
            kid: self.kid,
        }
    }
}

impl fmt::Debug for KeyRing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyRing")
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

/// Per-process nonce source: `instance u64 ‖ counter u32` (44 D6).
///
/// The instance is random per process, so two processes collide only if their
/// 64-bit prefixes collide. The counter is monotonic and stops at
/// [`CryptoError::NonceExhausted`] rather than reusing a nonce.
///
/// The 12 nonce bytes are big-endian in both halves. The layout is local, not
/// a wire field; big-endian keeps the counter readable in a hex dump.
///
/// The atomic is 64-bit only to encode the exhausted state beyond the 32-bit
/// counter; the wire-visible counter is still exactly `u32`.
#[derive(Debug)]
pub struct NonceMinter {
    instance: u64,
    counter: AtomicU64,
}

/// First counter state that is no longer usable.
const EXHAUSTED: u64 = u32::MAX as u64 + 1;

impl NonceMinter {
    /// Draw a fresh instance from the injected entropy source.
    pub fn new<R: Rng + ?Sized>(entropy: &mut R) -> Self {
        Self::with_instance(entropy.next_u64())
    }

    /// Use an explicit instance. Deterministic tests and golden vectors only.
    pub const fn with_instance(instance: u64) -> Self {
        Self {
            instance,
            counter: AtomicU64::new(0),
        }
    }

    /// Resume from an explicit instance and counter. Tests only.
    pub const fn from_parts(instance: u64, counter: u32) -> Self {
        Self {
            instance,
            counter: AtomicU64::new(counter as u64),
        }
    }

    /// The instance half of every nonce.
    pub const fn instance(&self) -> u64 {
        self.instance
    }

    /// The next counter value that will be used, saturated at `u32::MAX`.
    pub fn counter(&self) -> u32 {
        u32::try_from(self.counter.load(Ordering::Relaxed)).unwrap_or(u32::MAX)
    }

    /// Mint the next nonce.
    ///
    /// # Errors
    ///
    /// [`CryptoError::NonceExhausted`] after 2^32 successful calls.
    pub fn next(&self) -> Result<[u8; NONCE_LEN], CryptoError> {
        let counter = self
            .counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |state| {
                if state >= EXHAUSTED {
                    None
                } else {
                    Some(state + 1)
                }
            })
            .map_err(|_| CryptoError::NonceExhausted)?;
        let counter = u32::try_from(counter).map_err(|_| CryptoError::NonceExhausted)?;

        let mut nonce = [0u8; NONCE_LEN];
        nonce[..8].copy_from_slice(&self.instance.to_be_bytes());
        nonce[8..].copy_from_slice(&counter.to_be_bytes());
        Ok(nonce)
    }
}

/// The V1Minimal additional authenticated data (44 §4.3, 49 A11).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Aad {
    bytes: [u8; AAD_MAX_LEN],
    len: usize,
}

impl Aad {
    /// Build the AAD for one envelope.
    ///
    /// The header contributes every byte except `seq`; the prefix contributes
    /// its tag and encoded bytes.
    pub fn new(header: &FrameHeader, prefix: &Prefix, alg: u8, kid: u8) -> Self {
        let mut aad = Self {
            bytes: [0u8; AAD_MAX_LEN],
            len: AAD_FIXED_LEN,
        };
        let mut at = 0;

        aad.bytes[at..at + AAD_DOMAIN.len()].copy_from_slice(AAD_DOMAIN);
        at += AAD_DOMAIN.len();

        aad.bytes[at] = alg;
        at += 1;
        aad.bytes[at] = kid;
        at += 1;

        aad.bytes[at] = header.magic();
        at += 1;
        aad.bytes[at] = header.ver;
        at += 1;
        aad.bytes[at] = header.msg_type.get();
        at += 1;

        aad.bytes[at..at + 2].copy_from_slice(&header.flags.bits().to_le_bytes());
        at += 2;
        aad.bytes[at..at + 4].copy_from_slice(&header.req_id.to_le_bytes());
        at += 4;
        aad.bytes[at..at + 4].copy_from_slice(&header.len.to_le_bytes());
        at += 4;

        aad.bytes[at] = prefix.kind().tag();
        at += 1;

        match prefix {
            Prefix::None => {}
            Prefix::Route(route) => {
                aad.bytes[at..at + ROUTE_PREFIX_LEN].copy_from_slice(&route.encode());
                at += ROUTE_PREFIX_LEN;
            }
            Prefix::Ctrl(ctrl) => {
                aad.bytes[at..at + CTRL_PREFIX_LEN].copy_from_slice(&ctrl.encode());
                at += CTRL_PREFIX_LEN;
            }
        }

        aad.len = at;
        aad
    }

    /// The encoded AAD, exactly `26 + prefix_len` bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// Encoded width.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Always false: the fixed AAD part is never empty. Present because
    /// [`Aad::len`] is public.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl fmt::Debug for Aad {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Aad")
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

/// A sealed envelope. The bytes are `alg | kid | nonce | ciphertext | tag`.
pub struct Sealed(Vec<u8>);

impl Sealed {
    /// Borrow the envelope.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Take ownership of the envelope.
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }

    /// Envelope width.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the envelope is empty. Never true for a valid envelope.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl AsRef<[u8]> for Sealed {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Debug for Sealed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sealed({} bytes)", self.0.len())
    }
}

/// Authenticated plaintext. Zeroized on drop.
pub struct Opened(Zeroizing<Vec<u8>>);

impl Opened {
    /// Borrow the plaintext.
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Keep the zeroizing buffer.
    pub fn into_zeroizing(self) -> Zeroizing<Vec<u8>> {
        self.0
    }

    /// Plaintext width.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the plaintext is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::ops::Deref for Opened {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.as_slice()
    }
}

impl AsRef<[u8]> for Opened {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl fmt::Debug for Opened {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Opened({} bytes)", self.0.len())
    }
}

/// Seals plaintext into an envelope and sets `header.len`.
///
/// The key is copied from the ring or session key at construction and
/// zeroized on drop. A sealer never borrows key material from its caller.
pub struct Sealer<'k> {
    key: [u8; 32],
    kid: u8,
    nonces: &'k NonceMinter,
    alg: u8,
}

impl<'k> Sealer<'k> {
    /// Use the build's default algorithm with a legacy [`KeyRing`].
    pub const fn new(ring: &KeyRing, nonces: &'k NonceMinter) -> Self {
        Self {
            key: ring.enc,
            kid: ring.kid,
            nonces,
            alg: DEFAULT_ALG,
        }
    }

    /// Use the build's default algorithm with any session key.
    pub const fn with_session_key(session: &SessionKey, nonces: &'k NonceMinter) -> Self {
        Self::with_key(session.key(), session.kid(), nonces)
    }

    /// Use an explicit key and identifier.
    pub const fn with_key(key: &[u8; 32], kid: u8, nonces: &'k NonceMinter) -> Self {
        Self {
            key: *key,
            kid,
            nonces,
            alg: DEFAULT_ALG,
        }
    }

    /// Use an explicit algorithm with a legacy [`KeyRing`].
    ///
    /// # Errors
    ///
    /// [`CryptoError::BadAlg`] if this build does not implement `alg`.
    pub fn with_alg(ring: &KeyRing, nonces: &'k NonceMinter, alg: u8) -> Result<Self, CryptoError> {
        Self::with_session_key_and_alg(&ring.session_key(), nonces, alg)
    }

    /// Use an explicit session key and algorithm.
    ///
    /// # Errors
    ///
    /// [`CryptoError::BadAlg`] if this build does not implement `alg`.
    pub fn with_session_key_and_alg(
        session: &SessionKey,
        nonces: &'k NonceMinter,
        alg: u8,
    ) -> Result<Self, CryptoError> {
        if !is_supported_alg(alg) {
            return Err(CryptoError::BadAlg(alg));
        }
        Ok(Self {
            key: *session.key(),
            kid: session.kid(),
            nonces,
            alg,
        })
    }

    /// The algorithm this sealer writes.
    pub const fn alg(&self) -> u8 {
        self.alg
    }

    /// The envelope identifier this sealer writes.
    pub const fn kid(&self) -> u8 {
        self.kid
    }

    /// Seal `plaintext` and set `header.len` to prefix plus body.
    ///
    /// # Errors
    ///
    /// [`CryptoError::PlaintextTooLarge`] above [`MAX_PLAINTEXT`], and
    /// [`CryptoError::NonceExhausted`] when the minter is spent.
    pub fn seal(
        &self,
        header: &mut FrameHeader,
        prefix: &Prefix,
        plaintext: &[u8],
    ) -> Result<Sealed, CryptoError> {
        let nonce = self.nonces.next()?;
        self.seal_with_nonce(header, prefix, plaintext, &nonce)
    }

    /// Seal with an explicit nonce.
    ///
    /// The caller must guarantee the nonce is fresh for this key. Tests and
    /// the deterministic proof path use this; steady-state frames should use
    /// [`Sealer::seal`].
    ///
    /// # Errors
    ///
    /// [`CryptoError::PlaintextTooLarge`] above [`MAX_PLAINTEXT`].
    pub fn seal_with_nonce(
        &self,
        header: &mut FrameHeader,
        prefix: &Prefix,
        plaintext: &[u8],
        nonce: &[u8; NONCE_LEN],
    ) -> Result<Sealed, CryptoError> {
        let max = MAX_PLAINTEXT as usize;
        if plaintext.len() > max {
            return Err(CryptoError::PlaintextTooLarge {
                len: plaintext.len(),
                max,
            });
        }

        let len = u32::try_from(prefix.encoded_len() + ENV_OVERHEAD as usize + plaintext.len())
            .map_err(|_| CryptoError::PlaintextTooLarge {
                len: plaintext.len(),
                max,
            })?;
        header.len = len;

        let aad = Aad::new(header, prefix, self.alg, self.kid);

        let mut out = Vec::with_capacity(2 + NONCE_LEN + plaintext.len() + TAG_LEN);
        out.push(self.alg);
        out.push(self.kid);
        out.extend_from_slice(nonce);
        out.extend_from_slice(plaintext);

        let tag = encrypt_in_place(
            self.alg,
            &self.key,
            nonce,
            aad.as_bytes(),
            &mut out[2 + NONCE_LEN..],
        )?;
        out.extend_from_slice(&tag);
        Ok(Sealed(out))
    }
}

impl Drop for Sealer<'_> {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl fmt::Debug for Sealer<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sealer")
            .field("kid", &self.kid)
            .field("alg", &self.alg)
            .finish_non_exhaustive()
    }
}

/// Opens an envelope and authenticates it before exposing plaintext.
pub struct Opener<'k> {
    key: [u8; 32],
    kid: u8,
    _borrow: std::marker::PhantomData<&'k ()>,
}

impl<'k> Opener<'k> {
    /// Bind the opener to a legacy [`KeyRing`].
    pub const fn new(ring: &'k KeyRing) -> Self {
        Self {
            key: ring.enc,
            kid: ring.kid,
            _borrow: std::marker::PhantomData,
        }
    }

    /// Bind the opener to any session key.
    pub const fn with_session_key(session: &'k SessionKey) -> Self {
        Self::with_key(session.key(), session.kid())
    }

    /// Bind the opener to an explicit key and identifier.
    pub const fn with_key(key: &[u8; 32], kid: u8) -> Self {
        Self {
            key: *key,
            kid,
            _borrow: std::marker::PhantomData,
        }
    }

    /// Authenticate `body` and return the plaintext.
    ///
    /// # Errors
    ///
    /// * [`CryptoError::Aead`] for a short or tampered envelope.
    /// * [`CryptoError::BadAlg`] for an algorithm this build lacks.
    /// * [`CryptoError::UnknownKey`] when `kid` is not this opener's `kid`.
    pub fn open(
        &self,
        header: &FrameHeader,
        prefix: &Prefix,
        body: &[u8],
    ) -> Result<Opened, CryptoError> {
        if body.len() < ENV_OVERHEAD as usize {
            return Err(CryptoError::Aead);
        }

        let alg = body[0];
        if !is_supported_alg(alg) {
            return Err(CryptoError::BadAlg(alg));
        }

        let kid = body[1];
        if kid != self.kid {
            return Err(CryptoError::UnknownKey);
        }

        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&body[2..2 + NONCE_LEN]);

        let tag_at = body.len() - TAG_LEN;
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&body[tag_at..]);

        let aad = Aad::new(header, prefix, alg, kid);
        let mut plaintext = Zeroizing::new(body[2 + NONCE_LEN..tag_at].to_vec());
        decrypt_in_place(
            alg,
            &self.key,
            &nonce,
            aad.as_bytes(),
            plaintext.as_mut_slice(),
            &tag,
        )?;
        Ok(Opened(plaintext))
    }
}

impl Drop for Opener<'_> {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl fmt::Debug for Opener<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Opener")
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

fn encrypt_in_place(
    alg: u8,
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buffer: &mut [u8],
) -> Result<[u8; TAG_LEN], CryptoError> {
    let nonce = Nonce::from(*nonce);
    let mut key = Key::from(*key);
    let tag = match alg {
        ALG_CHACHA20 => {
            let cipher = ChaCha20Poly1305::new(&key);
            {
                let key_bytes: &mut [u8] = key.as_mut();
                key_bytes.zeroize();
            }
            cipher.encrypt_inout_detached(&nonce, aad, buffer.into())
        }
        #[cfg(feature = "reduced-round")]
        ALG_CHACHA8 => {
            let cipher = ChaCha8Poly1305::new(&key);
            {
                let key_bytes: &mut [u8] = key.as_mut();
                key_bytes.zeroize();
            }
            cipher.encrypt_inout_detached(&nonce, aad, buffer.into())
        }
        other => return Err(CryptoError::BadAlg(other)),
    }
    .map_err(|_| CryptoError::Aead)?;

    let mut out = [0u8; TAG_LEN];
    out.copy_from_slice(tag.as_slice());
    Ok(out)
}

fn decrypt_in_place(
    alg: u8,
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buffer: &mut [u8],
    tag: &[u8; TAG_LEN],
) -> Result<(), CryptoError> {
    let nonce = Nonce::from(*nonce);
    let mut key = Key::from(*key);
    let tag = Tag::from(*tag);
    match alg {
        ALG_CHACHA20 => {
            let cipher = ChaCha20Poly1305::new(&key);
            {
                let key_bytes: &mut [u8] = key.as_mut();
                key_bytes.zeroize();
            }
            cipher.decrypt_inout_detached(&nonce, aad, buffer.into(), &tag)
        }
        #[cfg(feature = "reduced-round")]
        ALG_CHACHA8 => {
            let cipher = ChaCha8Poly1305::new(&key);
            {
                let key_bytes: &mut [u8] = key.as_mut();
                key_bytes.zeroize();
            }
            cipher.decrypt_inout_detached(&nonce, aad, buffer.into(), &tag)
        }
        other => return Err(CryptoError::BadAlg(other)),
    }
    .map_err(|_| CryptoError::Aead)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::collections::HashSet;

    use super::*;
    use crate::protocol::Flags;
    use crate::protocol::frame::{CtrlPrefix, MsgType, RoutePrefix, Seq, SessionId, StreamId};

    fn cluster() -> ClusterId {
        ClusterId::from_bytes([0x42; 16])
    }

    fn ring() -> KeyRing {
        KeyRing::derive(&[0x24; 32], &cluster()).unwrap()
    }

    fn other_ring() -> KeyRing {
        KeyRing::derive(&[0x25; 32], &cluster()).unwrap()
    }

    fn route_prefix() -> Prefix {
        Prefix::Route(RoutePrefix::new(
            SessionId::new(0x0001_0203_0405_0607_0809_0a0b_0c0d_0e0f),
            StreamId::BLOCK,
            3,
            9,
        ))
    }

    fn ctrl_prefix() -> Prefix {
        Prefix::Ctrl(CtrlPrefix::new(Seq(7), 11))
    }

    fn route_header() -> FrameHeader {
        FrameHeader::new(
            MsgType::RELAY,
            Flags::ENC.with(Flags::ROUTED),
            0x1122_3344,
            Seq::UNSEQUENCED,
        )
    }

    #[test]
    fn key_derivation_is_deterministic_and_domain_separated() {
        let first = ring();
        let second = ring();
        assert_eq!(first.kid(), second.kid());
        assert_eq!(first.enc, second.enc);
        assert_eq!(first.ctrl, second.ctrl);

        let other_cluster =
            KeyRing::derive(&[0x24; 32], &ClusterId::from_bytes([0x43; 16])).unwrap();
        assert_ne!(first.enc, other_cluster.enc);

        let other_master = other_ring();
        assert_ne!(first.enc, other_master.enc);

        assert_ne!(first.enc, first.ctrl);
    }

    #[test]
    fn kid_is_blake3_of_enc_key_and_domain() {
        let ring = ring();
        let mut hasher = blake3::Hasher::new();
        hasher.update(&ring.enc);
        hasher.update(KID_DOMAIN);
        assert_eq!(ring.kid(), hasher.finalize().as_bytes()[0]);
    }

    #[test]
    fn aad_layout_is_frozen() {
        let mut header = route_header();
        header.len = 64;
        let aad = Aad::new(&header, &route_prefix(), ALG_CHACHA8, 0xab);
        assert_eq!(aad.len(), AAD_FIXED_LEN + ROUTE_PREFIX_LEN);
        let bytes = aad.as_bytes();
        assert_eq!(&bytes[..10], b"sm/v2/aad\0");
        assert_eq!(bytes[10], ALG_CHACHA8);
        assert_eq!(bytes[11], 0xab);
        assert_eq!(&bytes[12..15], &[0x53, 0x01, 0x12]);
        assert_eq!(&bytes[15..17], &0x0018u16.to_le_bytes());
        assert_eq!(&bytes[17..21], &0x1122_3344u32.to_le_bytes());
        assert_eq!(&bytes[21..25], &64u32.to_le_bytes());
        assert_eq!(bytes[25], 1);
        assert_eq!(
            &bytes[26..42],
            &0x0001_0203_0405_0607_0809_0a0b_0c0d_0e0fu128.to_le_bytes()
        );
        assert_eq!(bytes[42], 2);
        assert_eq!(&bytes[43..47], &3u32.to_le_bytes());
        assert_eq!(&bytes[47..51], &9u32.to_le_bytes());
    }

    #[test]
    fn aad_ignores_seq() {
        let mut first = route_header();
        first.len = 64;
        first.seq = Seq::UNSEQUENCED;
        let mut second = first;
        second.seq = Seq(0xdead_beef);

        let aad_first = Aad::new(&first, &route_prefix(), ALG_CHACHA8, 1);
        let aad_second = Aad::new(&second, &route_prefix(), ALG_CHACHA8, 1);
        assert_eq!(aad_first, aad_second);
        assert_eq!(aad_first.as_bytes(), aad_second.as_bytes());
    }

    #[test]
    fn seal_open_round_trip_for_every_prefix() {
        let ring = ring();
        let nonces = NonceMinter::with_instance(0x0102_0304_0506_0708);
        let cases = [
            (MsgType::ORDERED, Flags::ENC, Prefix::None),
            (
                MsgType::RELAY,
                Flags::ENC.with(Flags::ROUTED),
                route_prefix(),
            ),
            (MsgType::PING, Flags::ENC.with(Flags::CTRL), ctrl_prefix()),
        ];

        for alg in [ALG_CHACHA8, ALG_CHACHA20] {
            if !is_supported_alg(alg) {
                continue;
            }
            let sealer = Sealer::with_alg(&ring, &nonces, alg).unwrap();
            for (msg_type, flags, prefix) in cases {
                let mut header = FrameHeader::new(msg_type, flags, 0x0a0b_0c0d, Seq::UNSEQUENCED);
                let plaintext = b"protocol crypto round trip";
                let sealed = sealer.seal(&mut header, &prefix, plaintext).unwrap();

                assert_eq!(
                    header.len as usize,
                    prefix.encoded_len() + 30 + plaintext.len()
                );
                assert_eq!(sealed.len(), 2 + NONCE_LEN + plaintext.len() + TAG_LEN);
                assert_eq!(sealed.as_bytes()[0], alg);
                assert_eq!(sealed.as_bytes()[1], ring.kid());

                let opened = Opener::new(&ring)
                    .open(&header, &prefix, sealed.as_bytes())
                    .unwrap();
                assert_eq!(opened.as_slice(), plaintext);
            }
        }
    }

    #[test]
    fn seal_open_round_trip_for_empty_plaintext() {
        let ring = ring();
        let nonces = NonceMinter::with_instance(1);
        let sealer = Sealer::new(&ring, &nonces);
        let prefix = Prefix::None;
        let mut header = FrameHeader::new(MsgType::ORDERED, Flags::ENC, 0, Seq::UNSEQUENCED);

        let sealed = sealer.seal(&mut header, &prefix, b"").unwrap();
        assert_eq!(header.len, ENV_OVERHEAD);
        assert_eq!(sealed.len(), ENV_OVERHEAD as usize);

        let opened = Opener::new(&ring)
            .open(&header, &prefix, sealed.as_bytes())
            .unwrap();
        assert!(opened.is_empty());
    }

    #[test]
    fn aad_tamper_matrix_rejects_every_bound_field() {
        let ring = ring();
        let nonces = NonceMinter::with_instance(7);
        let sealer = Sealer::new(&ring, &nonces);
        let prefix = route_prefix();
        let mut header = route_header();
        let plaintext = b"tamper matrix";
        let sealed = sealer.seal(&mut header, &prefix, plaintext).unwrap();
        let body = sealed.as_bytes();

        let expect_aead = |header: &FrameHeader, prefix: &Prefix| {
            let result = Opener::new(&ring).open(header, prefix, body);
            assert!(
                matches!(result, Err(CryptoError::Aead)),
                "expected Aead, got {result:?}"
            );
        };

        let mut tampered = header;
        tampered.ver = 2;
        expect_aead(&tampered, &prefix);

        let mut tampered = header;
        tampered.msg_type = MsgType::STREAM_DATA;
        expect_aead(&tampered, &prefix);

        let mut tampered = header;
        tampered.flags = Flags::from_bits(header.flags.bits() | Flags::URGENT.bits());
        expect_aead(&tampered, &prefix);

        let mut tampered = header;
        tampered.req_id ^= 1;
        expect_aead(&tampered, &prefix);

        let mut tampered = header;
        tampered.len ^= 1;
        expect_aead(&tampered, &prefix);

        let route = match prefix {
            Prefix::Route(route) => route,
            _ => unreachable!(),
        };

        let mut tampered = route;
        tampered.session_id = SessionId::new(route.session_id.get() ^ 1);
        expect_aead(&header, &Prefix::Route(tampered));

        let mut tampered = route;
        tampered.stream = StreamId(route.stream.get() ^ 1);
        expect_aead(&header, &Prefix::Route(tampered));

        let mut tampered = route;
        tampered.chunk_index ^= 1;
        expect_aead(&header, &Prefix::Route(tampered));

        let mut tampered = route;
        tampered.total_chunks ^= 1;
        expect_aead(&header, &Prefix::Route(tampered));

        expect_aead(&header, &Prefix::None);
        expect_aead(&header, &ctrl_prefix());

        // seq is deliberately outside the AAD: changing it must still verify.
        let mut resequenced = header;
        resequenced.seq = Seq(0xfeed_face);
        let opened = Opener::new(&ring)
            .open(&resequenced, &prefix, body)
            .unwrap();
        assert_eq!(opened.as_slice(), plaintext);
    }

    #[test]
    fn aad_magic_tamper_rejects() {
        let ring = ring();
        let nonces = NonceMinter::with_instance(17);
        let prefix = route_prefix();
        let mut header = route_header();
        let plaintext = b"magic";
        let sealed = Sealer::new(&ring, &nonces)
            .seal(&mut header, &prefix, plaintext)
            .unwrap();
        assert_eq!(
            Opener::new(&ring)
                .open(&header, &prefix, sealed.as_bytes())
                .unwrap()
                .as_slice(),
            plaintext
        );

        // `FrameHeader::magic` is a constant, so the only way to present a
        // different magic byte is to seal under a hand-built AAD.
        let mut aad = Aad::new(&header, &prefix, DEFAULT_ALG, ring.kid())
            .as_bytes()
            .to_vec();
        let magic_at = AAD_DOMAIN.len() + 2;
        assert_eq!(aad[magic_at], header.magic());
        aad[magic_at] ^= 1;

        let nonce = [0x6b; NONCE_LEN];
        let mut body = vec![DEFAULT_ALG, ring.kid()];
        body.extend_from_slice(&nonce);
        body.extend_from_slice(plaintext);
        let tag = encrypt_in_place(
            DEFAULT_ALG,
            &ring.enc,
            &nonce,
            &aad,
            &mut body[2 + NONCE_LEN..],
        )
        .unwrap();
        body.extend_from_slice(&tag);

        let result = Opener::new(&ring).open(&header, &prefix, &body);
        assert!(
            matches!(result, Err(CryptoError::Aead)),
            "expected Aead, got {result:?}"
        );
    }

    #[test]
    fn aad_ctrl_prefix_tamper_matrix_rejects() {
        let ring = ring();
        let nonces = NonceMinter::with_instance(19);
        let prefix = ctrl_prefix();
        let mut header = FrameHeader::new(
            MsgType::PING,
            Flags::ENC.with(Flags::CTRL),
            0x99,
            Seq::UNSEQUENCED,
        );
        let sealed = Sealer::new(&ring, &nonces)
            .seal(&mut header, &prefix, b"ctrl")
            .unwrap();
        let body = sealed.as_bytes();
        let ctrl = match prefix {
            Prefix::Ctrl(ctrl) => ctrl,
            _ => unreachable!(),
        };

        let tampered = [
            CtrlPrefix {
                applied_seq: Seq(ctrl.applied_seq.get() ^ 1),
                ..ctrl
            },
            CtrlPrefix {
                epoch_seen: ctrl.epoch_seen ^ 1,
                ..ctrl
            },
            CtrlPrefix {
                reserved: 1,
                ..ctrl
            },
        ];
        for tampered in tampered {
            let result = Opener::new(&ring).open(&header, &Prefix::Ctrl(tampered), body);
            assert!(
                matches!(result, Err(CryptoError::Aead)),
                "expected Aead, got {result:?}"
            );
        }
    }

    #[test]
    fn envelope_tamper_matrix_rejects() {
        let ring = ring();
        let nonces = NonceMinter::with_instance(9);
        let sealer = Sealer::new(&ring, &nonces);
        let prefix = route_prefix();
        let mut header = route_header();
        let sealed = sealer.seal(&mut header, &prefix, b"envelope").unwrap();
        let body = sealed.as_bytes();

        let expect_aead = |body: &[u8]| {
            let result = Opener::new(&ring).open(&header, &prefix, body);
            assert!(
                matches!(result, Err(CryptoError::Aead)),
                "expected Aead, got {result:?}"
            );
        };

        expect_aead(&body[..ENV_OVERHEAD as usize - 1]);

        let mut tampered = body.to_vec();
        tampered[2] ^= 1; // nonce
        expect_aead(&tampered);

        let mut tampered = body.to_vec();
        tampered[2 + NONCE_LEN] ^= 1; // first ciphertext byte
        expect_aead(&tampered);

        let mut tampered = body.to_vec();
        let last = tampered.len() - 1;
        tampered[last] ^= 1; // tag
        expect_aead(&tampered);

        let mut tampered = body.to_vec();
        tampered[0] = 7; // unknown algorithm
        assert!(matches!(
            Opener::new(&ring).open(&header, &prefix, &tampered),
            Err(CryptoError::BadAlg(7))
        ));

        let mut tampered = body.to_vec();
        tampered[1] = ring.kid().wrapping_add(1);
        assert!(matches!(
            Opener::new(&ring).open(&header, &prefix, &tampered),
            Err(CryptoError::UnknownKey)
        ));
    }

    #[test]
    fn wrong_key_fails_after_kid_rewrite() {
        let ring = ring();
        let other = other_ring();
        let nonces = NonceMinter::with_instance(11);
        let sealer = Sealer::new(&ring, &nonces);
        let prefix = route_prefix();
        let mut header = route_header();
        let sealed = sealer.seal(&mut header, &prefix, b"wrong key").unwrap();

        let mut body = sealed.into_vec();
        body[1] = other.kid();
        let result = Opener::new(&other).open(&header, &prefix, &body);
        assert!(
            matches!(result, Err(CryptoError::Aead)),
            "expected Aead, got {result:?}"
        );
    }

    #[test]
    fn debug_output_never_contains_key_material() {
        let ring = ring();
        let secrets = [format!("{:?}", ring.enc), format!("{:?}", ring.ctrl)];

        let rendered = format!("{ring:?}");
        assert!(rendered.contains("kid"));
        for secret in &secrets {
            assert!(!rendered.contains(secret.as_str()), "Debug leaked a key");
        }

        let nonces = NonceMinter::with_instance(0x0102_0304_0506_0708);
        let sealer = Sealer::new(&ring, &nonces);
        let opener = Opener::new(&ring);
        let aad = Aad::new(&route_header(), &route_prefix(), DEFAULT_ALG, ring.kid());
        let mut header = route_header();
        let sealed = sealer
            .seal(&mut header, &Prefix::None, b"secret plaintext")
            .unwrap();
        let opened = opener
            .open(&header, &Prefix::None, sealed.as_bytes())
            .unwrap();

        let debug_forms = [
            format!("{sealer:?}"),
            format!("{opener:?}"),
            format!("{aad:?}"),
            format!("{sealed:?}"),
            format!("{opened:?}"),
        ];
        for rendered in &debug_forms {
            for secret in &secrets {
                assert!(!rendered.contains(secret.as_str()), "Debug leaked a key");
            }
            assert!(!rendered.contains("secret plaintext"));
        }
    }

    #[test]
    fn plaintext_limit_is_enforced() {
        let ring = ring();
        let nonces = NonceMinter::with_instance(13);
        let sealer = Sealer::new(&ring, &nonces);
        let prefix = Prefix::None;
        let mut header = FrameHeader::new(MsgType::ORDERED, Flags::ENC, 0, Seq::UNSEQUENCED);

        let max = vec![0u8; MAX_PLAINTEXT as usize];
        assert!(sealer.seal(&mut header, &prefix, &max).is_ok());

        let too_large = vec![0u8; MAX_PLAINTEXT as usize + 1];
        assert!(matches!(
            sealer.seal(&mut header, &prefix, &too_large),
            Err(CryptoError::PlaintextTooLarge { .. })
        ));
    }

    #[test]
    fn nonce_layout_and_uniqueness() {
        let instance = 0x0102_0304_0506_0708;
        let minter = NonceMinter::with_instance(instance);
        let mut seen = HashSet::with_capacity(1_000_000);

        // 44:V4 asks for 10^7 single-threaded draws. The exact counter
        // comparison proves uniqueness for all of them; the set keeps an
        // independent duplicate check over the first million without holding
        // ten million nonces in memory.
        for expected in 0..10_000_000u32 {
            let nonce = minter.next().unwrap();
            assert_eq!(&nonce[..8], &instance.to_be_bytes());
            assert_eq!(u32::from_be_bytes(nonce[8..].try_into().unwrap()), expected);
            if expected < 1_000_000 {
                assert!(seen.insert(nonce), "duplicate nonce at counter {expected}");
            }
        }
        assert_eq!(minter.counter(), 10_000_000);
    }

    #[test]
    fn nonce_uniqueness_under_concurrency() {
        let minter = NonceMinter::with_instance(0xa5a5_5a5a_1234_5678);
        let mut seen = HashSet::with_capacity(8 * 50_000);

        std::thread::scope(|scope| {
            let mut handles = Vec::with_capacity(8);
            for _ in 0..8 {
                handles.push(scope.spawn(|| {
                    let mut local = Vec::with_capacity(50_000);
                    for _ in 0..50_000 {
                        local.push(minter.next().unwrap());
                    }
                    local
                }));
            }
            for handle in handles {
                for nonce in handle.join().unwrap() {
                    assert!(seen.insert(nonce), "duplicate nonce across threads");
                }
            }
        });

        assert_eq!(seen.len(), 8 * 50_000);
    }

    #[test]
    fn nonce_counter_exhaustion_is_an_error() {
        let minter = NonceMinter::from_parts(0x1122_3344_5566_7788, u32::MAX);
        let last = minter.next().unwrap();
        assert_eq!(u32::from_be_bytes(last[8..].try_into().unwrap()), u32::MAX);
        assert_eq!(minter.next(), Err(CryptoError::NonceExhausted));
        assert_eq!(minter.next(), Err(CryptoError::NonceExhausted));
    }

    #[test]
    fn psk_ring_is_deterministic_and_domain_separated() {
        let salt = PskSalt::DEFAULT;
        let first = PskKeyRing::derive(&[0x24; 32], &salt).unwrap();
        let second = PskKeyRing::derive(&[0x24; 32], &salt).unwrap();
        assert_eq!(first.kid(), second.kid());
        assert_eq!(first.enc_key(), second.enc_key());
        assert_eq!(first.ctrl_key(), second.ctrl_key());

        let other_psk = PskKeyRing::derive(&[0x25; 32], &salt).unwrap();
        assert_ne!(first.enc_key(), other_psk.enc_key());
        let other_salt = PskKeyRing::derive(&[0x24; 32], &PskSalt::from_bytes([0x99; 16])).unwrap();
        assert_ne!(first.enc_key(), other_salt.enc_key());

        assert_ne!(first.enc_key(), first.ctrl_key());
        assert_eq!(PskSalt::DEFAULT.as_bytes(), &PSK_SALT);
        assert_eq!(PSK_SALT.len(), PSK_SALT_LEN);
    }

    #[test]
    fn handshake_key_binds_both_nonces_and_has_its_own_kid() {
        let ring = PskKeyRing::derive(&[0x24; 32], &PskSalt::DEFAULT).unwrap();
        let first = ring.handshake_keys(&[0x01; 32], &[0x02; 32]).unwrap();
        let again = ring.handshake_keys(&[0x01; 32], &[0x02; 32]).unwrap();
        assert_eq!(first.kid(), again.kid());
        assert_ne!(first.kid(), ring.kid());

        let other_client = ring.handshake_keys(&[0x03; 32], &[0x02; 32]).unwrap();
        let other_server = ring.handshake_keys(&[0x01; 32], &[0x04; 32]).unwrap();
        assert_ne!(first.kid(), other_client.kid());
        assert_ne!(first.kid(), other_server.kid());
        assert_ne!(other_client.kid(), other_server.kid());
    }

    #[test]
    fn welcome_proof_roundtrips_and_binds_client_nonce_and_body() {
        let ring = PskKeyRing::derive(&[0x24; 32], &PskSalt::DEFAULT).unwrap();
        let keys = ring.handshake_keys(&[0x01; 32], &[0x02; 32]).unwrap();
        let body_hash = [0x5a; 32];
        let nonce = [0x6b; NONCE_LEN];
        let proof = keys
            .seal_welcome_proof(&[0x01; 32], &body_hash, &nonce)
            .unwrap();
        assert_eq!(proof.len(), WELCOME_PROOF_LEN);
        assert_eq!(proof[0], DEFAULT_ALG);
        assert_eq!(&proof[1..1 + NONCE_LEN], &nonce);

        keys.open_welcome_proof(&[0x01; 32], &body_hash, &proof)
            .unwrap();
        assert!(matches!(
            keys.open_welcome_proof(&[0x09; 32], &body_hash, &proof),
            Err(CryptoError::Aead)
        ));
        assert!(matches!(
            keys.open_welcome_proof(&[0x01; 32], &[0x5b; 32], &proof),
            Err(CryptoError::Aead)
        ));

        let mut tampered = proof;
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(matches!(
            keys.open_welcome_proof(&[0x01; 32], &body_hash, &tampered),
            Err(CryptoError::Aead)
        ));
    }

    #[test]
    fn handshake_keys_seal_and_open_with_the_handshake_kid() {
        let ring = PskKeyRing::derive(&[0x24; 32], &PskSalt::DEFAULT).unwrap();
        let keys = ring.handshake_keys(&[0x01; 32], &[0x02; 32]).unwrap();
        let nonces = NonceMinter::with_instance(0x1122_3344_5566_7788);
        let mut header = FrameHeader::new(MsgType::ORDERED, Flags::ENC, 0, Seq::UNSEQUENCED);
        let plaintext = [0x77u8; 112];
        let sealed = keys
            .seal(&mut header, &Prefix::None, &plaintext, &nonces)
            .unwrap();
        assert_eq!(sealed.as_bytes()[1], keys.kid());
        assert_eq!(header.len, ENV_OVERHEAD + 112);
        let opened = keys
            .open(&header, &Prefix::None, sealed.as_bytes())
            .unwrap();
        assert_eq!(opened.as_slice(), &plaintext);

        // The steady-state ring must not open a handshake envelope.
        assert!(matches!(
            Opener::with_session_key(&ring.session_key()).open(
                &header,
                &Prefix::None,
                sealed.as_bytes()
            ),
            Err(CryptoError::UnknownKey) | Err(CryptoError::Aead)
        ));
    }

    #[test]
    fn session_key_sealer_matches_the_ring() {
        let ring = ring();
        let session = ring.session_key();
        let nonces = NonceMinter::with_instance(21);
        let mut header = FrameHeader::new(MsgType::ORDERED, Flags::ENC, 0, Seq::UNSEQUENCED);
        let sealed = Sealer::with_session_key(&session, &nonces)
            .seal(&mut header, &Prefix::None, b"session")
            .unwrap();
        let opened = Opener::with_session_key(&session)
            .open(&header, &Prefix::None, sealed.as_bytes())
            .unwrap();
        assert_eq!(opened.as_slice(), b"session");
        assert_eq!(session.kid(), ring.kid());
        assert_eq!(session.key(), &ring.enc);
    }

    #[test]
    fn default_algorithm_matches_feature() {
        if cfg!(feature = "reduced-round") {
            assert_eq!(DEFAULT_ALG, ALG_CHACHA8);
            assert!(is_supported_alg(ALG_CHACHA8));
        } else {
            assert_eq!(DEFAULT_ALG, ALG_CHACHA20);
            assert!(!is_supported_alg(ALG_CHACHA8));
        }
        assert!(is_supported_alg(ALG_CHACHA20));
        assert!(!is_supported_alg(2));
    }

    #[test]
    #[ignore = "V17 throughput measurement; run with --ignored --release"]
    fn seal_open_throughput() {
        use std::time::Instant;

        let ring = ring();
        let nonces = NonceMinter::with_instance(0xfeed_face_dead_beef);
        let sealer = Sealer::new(&ring, &nonces);
        let opener = Opener::new(&ring);
        let prefix = Prefix::None;
        let plaintext = vec![0x5a; MAX_PLAINTEXT as usize];
        let mut header = FrameHeader::new(MsgType::ORDERED, Flags::ENC, 0, Seq::UNSEQUENCED);

        const FRAMES: usize = 1024;
        let mut sealed = Vec::with_capacity(FRAMES);
        let start = Instant::now();
        for _ in 0..FRAMES {
            sealed.push(sealer.seal(&mut header, &prefix, &plaintext).unwrap());
        }
        let seal = start.elapsed();

        let start = Instant::now();
        for body in &sealed {
            let opened = opener.open(&header, &prefix, body.as_bytes()).unwrap();
            assert_eq!(opened.len(), plaintext.len());
        }
        let open = start.elapsed();

        let mib = (FRAMES * plaintext.len()) as f64 / (1024.0 * 1024.0);
        println!(
            "V17 64KiB frames: seal {:.1} MiB/s, open {:.1} MiB/s",
            mib / seal.as_secs_f64(),
            mib / open.as_secs_f64()
        );
    }
}
