//! Protocol AEAD: key derivation, nonce minting, AAD and the sealed envelope.
//!
//! This module owns the byte layout of `enc_body` (44 §4.4):
//!
//! ```text
//! enc_body = alg u8 | kid u8 | nonce 12 | ciphertext n | tag 16
//! ```
//!
//! and the V1Minimal AAD (44 §4.3, 49 A11):
//!
//! ```text
//! aad = "sm/v1/aad\0"                     10 B
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
//! not know it when sealing and the server, which has no key, rewrites it on
//! rebroadcast (44 INV-06/INV-17). Operation-level binding is the Ed25519
//! signature's job (50), not the AAD's.
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
pub const AAD_DOMAIN: &[u8; 10] = b"sm/v1/aad\0";

/// AAD bytes before the variable prefix: 10 + 2 + (21 - 8) + 1 = 26.
pub const AAD_FIXED_LEN: usize = 26;

/// Largest AAD: fixed part plus a route prefix.
pub const AAD_MAX_LEN: usize = AAD_FIXED_LEN + ROUTE_PREFIX_LEN;

/// HKDF info for the payload key (49 A13).
pub const ENC_INFO: &[u8] = b"sm/v1/enc";

/// HKDF info for the control key. Reserved in v1 (49 A13).
pub const CTRL_INFO: &[u8] = b"sm/v1/ctrl";

/// HKDF info for the key-binding key used by `KEY_ANNOUNCE` (49 A13).
pub const KEYBIND_INFO: &[u8] = b"sm/v1/keybind";

/// BLAKE3 domain for the key identifier (44 §4.1).
pub const KID_DOMAIN: &[u8] = b"sm/v1/kid";

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

/// Keys derived from the master key for one cluster.
///
/// `enc` seals payload frames, `keybind` authenticates `KEY_ANNOUNCE`, and
/// `ctrl` is reserved in v1 (49 A13). There is no `auth_key`: the server holds
/// no keys at all (49 A9/D-4).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct KeyRing {
    kid: u8,
    enc: [u8; 32],
    ctrl: [u8; 32],
    keybind: [u8; 32],
}

impl KeyRing {
    /// Derive the ring with HKDF-SHA256.
    ///
    /// `salt = cluster_id`, `ikm = master_key`, and the info strings are
    /// [`ENC_INFO`], [`CTRL_INFO`] and [`KEYBIND_INFO`]. The key id is
    /// `BLAKE3(enc_key ‖ "sm/v1/kid")[0]` (44 §4.1).
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
            keybind: [0u8; 32],
        };
        hk.expand(ENC_INFO, &mut ring.enc)
            .map_err(|_| CryptoError::Kdf)?;
        hk.expand(CTRL_INFO, &mut ring.ctrl)
            .map_err(|_| CryptoError::Kdf)?;
        hk.expand(KEYBIND_INFO, &mut ring.keybind)
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

    /// The key-binding key for `KEY_ANNOUNCE` MACs (44 §4.7).
    pub const fn keybind_key(&self) -> &[u8; 32] {
        &self.keybind
    }

    /// The control key. Reserved in v1; exposed so the KDF registry can be
    /// tested without a second derivation path.
    pub const fn ctrl_key(&self) -> &[u8; 32] {
        &self.ctrl
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
#[derive(Debug)]
pub struct Sealer<'k> {
    ring: &'k KeyRing,
    nonces: &'k NonceMinter,
    alg: u8,
}

impl<'k> Sealer<'k> {
    /// Use the build's default algorithm.
    pub const fn new(ring: &'k KeyRing, nonces: &'k NonceMinter) -> Self {
        Self {
            ring,
            nonces,
            alg: DEFAULT_ALG,
        }
    }

    /// Use an explicit algorithm.
    ///
    /// # Errors
    ///
    /// [`CryptoError::BadAlg`] if this build does not implement `alg`.
    pub fn with_alg(
        ring: &'k KeyRing,
        nonces: &'k NonceMinter,
        alg: u8,
    ) -> Result<Self, CryptoError> {
        if !is_supported_alg(alg) {
            return Err(CryptoError::BadAlg(alg));
        }
        Ok(Self { ring, nonces, alg })
    }

    /// The algorithm this sealer writes.
    pub const fn alg(&self) -> u8 {
        self.alg
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

        let aad = Aad::new(header, prefix, self.alg, self.ring.kid);
        let nonce = self.nonces.next()?;

        let mut out = Vec::with_capacity(2 + NONCE_LEN + plaintext.len() + TAG_LEN);
        out.push(self.alg);
        out.push(self.ring.kid);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(plaintext);

        let tag = encrypt_in_place(
            self.alg,
            &self.ring.enc,
            &nonce,
            aad.as_bytes(),
            &mut out[2 + NONCE_LEN..],
        )?;
        out.extend_from_slice(&tag);
        Ok(Sealed(out))
    }
}

/// Opens an envelope and authenticates it before exposing plaintext.
#[derive(Debug)]
pub struct Opener<'k> {
    ring: &'k KeyRing,
}

impl<'k> Opener<'k> {
    /// Bind the opener to a key ring.
    pub const fn new(ring: &'k KeyRing) -> Self {
        Self { ring }
    }

    /// Authenticate `body` and return the plaintext.
    ///
    /// # Errors
    ///
    /// * [`CryptoError::Aead`] for a short or tampered envelope.
    /// * [`CryptoError::BadAlg`] for an algorithm this build lacks.
    /// * [`CryptoError::UnknownKey`] when `kid` is not this ring's `kid`.
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
        if kid != self.ring.kid {
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
            &self.ring.enc,
            &nonce,
            aad.as_bytes(),
            plaintext.as_mut_slice(),
            &tag,
        )?;
        Ok(Opened(plaintext))
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
        assert_eq!(first.keybind, second.keybind);

        let other_cluster =
            KeyRing::derive(&[0x24; 32], &ClusterId::from_bytes([0x43; 16])).unwrap();
        assert_ne!(first.enc, other_cluster.enc);

        let other_master = other_ring();
        assert_ne!(first.enc, other_master.enc);
        assert_ne!(first.keybind, other_master.keybind);

        assert_ne!(first.enc, first.ctrl);
        assert_ne!(first.enc, first.keybind);
        assert_ne!(first.ctrl, first.keybind);
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
        assert_eq!(&bytes[..10], b"sm/v1/aad\0");
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
        let secrets = [
            format!("{:?}", ring.enc),
            format!("{:?}", ring.ctrl),
            format!("{:?}", ring.keybind),
        ];

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
