//! Client identity, operation signatures and the public-key directory (W4).
//!
//! The server holds no key and verifies no signature (49 A9/D-4). Every
//! `ORDERED` operation is signed by its author inside the AEAD plaintext, so a
//! server or a network attacker can neither forge nor alter an operation, and
//! a member cannot sign under another member's `client_id` (50 §0).
//!
//! # Self-certifying identity (50 D2)
//!
//! ```text
//! client_id = BLAKE3("sm/v1/client-id" ‖ cluster_id ‖ public_key)[..16]
//! skid      = BLAKE3("sm/v1/skid"      ‖ public_key)[..8]
//! ```
//!
//! The binding needs no directory: anyone holding the public key can recompute
//! the id. `skid` is only a cache index, never an identity.
//!
//! # Signature input (W4 field set)
//!
//! ```text
//! sig_msg = "sm/v1/op\0"           9 B
//!         | client_id             16 B
//!         | key_epoch u32 LE       4 B
//!         | op_id                 16 B
//!         | op_class u8            1 B
//!         | msg_type u8            1 B
//!         | flags u16 LE           2 B
//!         | payload_hash          32 B
//!                                  = 81 B
//! ```
//!
//! `seq` is deliberately absent: the sender does not know it when signing, and
//! the server rewrites it on rebroadcast without a key (44 INV-06/INV-17).
//!
//! # AUTH block (50 §4.4)
//!
//! ```text
//! offset size field
//! 0      1    auth_ver   = 1
//! 1      1    auth_alg   = 1 (Ed25519)
//! 2      1    auth_flags bit0 INLINE_PUBKEY, bit1 CHAIN (reserved, 0),
//!                        bits 2..=7 must be zero
//! 3      8    skid
//! 11     64   sig
//! 75     32   public_key   only when auth_flags.bit0 is set
//! ```
//!
//! The block sits in the AEAD plaintext before the WCP body; `len` includes
//! it, `payload_hash` does not. Base cost is 75 B, 107 B with the inline key.
//! The inline key is required on a client's first frame and at least every 64
//! frames (50 §4.4); a receiver that missed it asks with `KEY_REQ` instead of
//! guessing.
//!
//! # Relation to 44 and 50
//!
//! 44 §4.7 bound announcements with `key_mac = HMAC(keybind_key, …)` and 44
//! §4.6 signed `client_id + key_epoch + op_id + payload_hash`. 50 supersedes
//! both (51 §7.5): the announcement travels inside `enc_key` ciphertext, so
//! PSK possession is already proven by AEAD, and a self-signature
//! (`sm/v1/keyentry\0`) proves possession of the private key. `key_mac` is
//! therefore not carried here. The signature input keeps the 44 field order
//! plus `op_class`, `msg_type` and `flags`; 50 additionally binds `cluster_id`
//! and a `sig_ver` byte, which remain a CCR away.

use std::collections::BTreeMap;
use std::fmt;

use blake3::Hasher;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

use crate::protocol::crypto::ClusterId;
use crate::protocol::frame::{ClientId, Flags, MsgType, OpId, Seq};
use crate::protocol::messages::OpClass;

/// Domain separator for `client_id` derivation (50 §2.4).
pub const CLIENT_ID_DOMAIN: &[u8] = b"sm/v1/client-id";

/// Domain separator for `skid` derivation (50 §2.4).
pub const SKID_DOMAIN: &[u8] = b"sm/v1/skid";

/// Domain separator for the operation signature (49 A13).
pub const OP_DOMAIN: &[u8; 9] = b"sm/v1/op\0";

/// Domain separator for the canonical op-body hash (44 §4.6).
pub const OP_BODY_DOMAIN: &[u8] = b"sm/v1/op-body\0";

/// Domain separator for a `KeyEntry` self-signature (50 §3.3).
pub const KEY_ENTRY_DOMAIN: &[u8] = b"sm/v1/keyentry\0";

/// Domain separator for a rotation proof (44 §4.7).
pub const ROTATE_DOMAIN: &[u8] = b"sm/v1/rotate\0";

/// Ed25519 public-key width.
pub const PUBLIC_KEY_LEN: usize = 32;

/// Ed25519 signature width.
pub const SIGNATURE_LEN: usize = 64;

/// `skid` width.
pub const SKID_LEN: usize = 8;

/// Length of [`sig_msg`].
///
/// `9 + 16 + 4 + 16 + 1 + 1 + 2 + 32`.
pub const SIG_MSG_LEN: usize = 81;

/// `auth_ver` value understood by this implementation.
pub const AUTH_VER: u8 = 1;

/// `auth_alg` value for Ed25519.
pub const AUTH_ALG_ED25519: u8 = 1;

/// `auth_flags` bit 0: the block carries a 32-byte public key.
pub const AUTH_FLAG_INLINE_PUBKEY: u8 = 1 << 0;

/// `auth_flags` bit 1: chained keys. Reserved and must be zero in v1.
pub const AUTH_FLAG_CHAIN: u8 = 1 << 1;

/// Fixed part of an AUTH block: version, algorithm, flags, `skid`, signature.
pub const AUTH_BLOCK_LEN: usize = 3 + SKID_LEN + SIGNATURE_LEN;

/// AUTH block with an inline public key.
pub const AUTH_INLINE_LEN: usize = AUTH_BLOCK_LEN + PUBLIC_KEY_LEN;

/// Default bound on frames parked while a public key is unknown (44 §4.7).
pub const UNKNOWN_KEY_CAPACITY: usize = 64;

/// A key epoch: a per-client monotonic counter (`u32` on the wire).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Debug)]
pub struct KeyEpoch(pub u32);

impl KeyEpoch {
    /// The epoch of a freshly installed client.
    pub const INITIAL: Self = Self(0);

    /// Raw value.
    pub const fn get(self) -> u32 {
        self.0
    }

    /// Next epoch, or `None` at the `u32` ceiling.
    pub const fn checked_next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(next) => Some(Self(next)),
            None => None,
        }
    }
}

impl fmt::Display for KeyEpoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// An Ed25519 public key.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKey([u8; PUBLIC_KEY_LEN]);

impl PublicKey {
    /// Encoded width.
    pub const LEN: usize = PUBLIC_KEY_LEN;

    /// Wrap raw bytes without validating the curve point.
    ///
    /// Validation happens in [`PublicKey::verifying_key`] and therefore in
    /// every verification path.
    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    /// Copy from a slice.
    ///
    /// # Errors
    ///
    /// [`SignatureError::MalformedPublicKey`] if `bytes` is not 32 bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, SignatureError> {
        let array: [u8; Self::LEN] = bytes
            .try_into()
            .map_err(|_| SignatureError::MalformedPublicKey)?;
        Ok(Self(array))
    }

    /// Borrow the raw bytes.
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }

    /// Copy the raw bytes.
    pub const fn to_bytes(self) -> [u8; Self::LEN] {
        self.0
    }

    /// Parse and validate the curve point.
    ///
    /// # Errors
    ///
    /// [`SignatureError::MalformedPublicKey`] if the bytes are not a canonical
    /// Ed25519 point.
    pub fn verifying_key(&self) -> Result<VerifyingKey, SignatureError> {
        VerifyingKey::from_bytes(&self.0).map_err(|_| SignatureError::MalformedPublicKey)
    }

    /// Verify `signature` over `message` with `verify_strict` (50 §2.1).
    ///
    /// `verify_strict` rejects small-order keys and non-canonical `R`, which
    /// the plain verification equation does not. It is the only verification
    /// entry point in this module.
    ///
    /// # Errors
    ///
    /// [`SignatureError::MalformedPublicKey`] or [`SignatureError::Invalid`].
    pub fn verify_strict(
        &self,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), SignatureError> {
        let key = self.verifying_key()?;
        key.verify_strict(message, &signature.to_dalek())
            .map_err(|_| SignatureError::Invalid)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PublicKey(")?;
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        f.write_str(")")
    }
}

/// An Ed25519 signature.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; SIGNATURE_LEN]);

impl Signature {
    /// Encoded width.
    pub const LEN: usize = SIGNATURE_LEN;

    /// Wrap raw bytes. Any 64-byte string is a syntactically valid signature;
    /// verification decides whether it is a real one.
    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    /// Copy from a slice.
    ///
    /// # Errors
    ///
    /// [`SignatureError::MalformedSignature`] if `bytes` is not 64 bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, SignatureError> {
        let array: [u8; Self::LEN] = bytes
            .try_into()
            .map_err(|_| SignatureError::MalformedSignature)?;
        Ok(Self(array))
    }

    /// Borrow the raw bytes.
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }

    /// Copy the raw bytes.
    pub const fn to_bytes(self) -> [u8; Self::LEN] {
        self.0
    }

    /// Convert to the `ed25519` representation used by the verifier.
    pub fn to_dalek(self) -> ed25519_dalek::Signature {
        ed25519_dalek::Signature::from_bytes(&self.0)
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Signature(")?;
        for byte in &self.0[..8] {
            write!(f, "{byte:02x}")?;
        }
        f.write_str("..)")
    }
}

/// Derive the self-certifying client id (50 §2.4).
pub fn client_id(cluster: &ClusterId, public: &PublicKey) -> ClientId {
    let mut hasher = Hasher::new();
    hasher.update(CLIENT_ID_DOMAIN);
    hasher.update(cluster.as_bytes());
    hasher.update(public.as_bytes());
    let mut id = [0u8; ClientId::LEN];
    id.copy_from_slice(&hasher.finalize().as_bytes()[..ClientId::LEN]);
    ClientId::from_bytes(id)
}

/// Derive the 8-byte cache index for a public key (50 §2.4).
///
/// `skid` is never an identity: a collision is resolved by checking
/// `client_id == H(cluster_id ‖ pk)`.
pub fn skid(public: &PublicKey) -> [u8; SKID_LEN] {
    let mut hasher = Hasher::new();
    hasher.update(SKID_DOMAIN);
    hasher.update(public.as_bytes());
    let mut out = [0u8; SKID_LEN];
    out.copy_from_slice(&hasher.finalize().as_bytes()[..SKID_LEN]);
    out
}

/// The 81-byte operation signature input (see module docs).
///
/// `seq` is not a parameter: it is not signed.
pub fn sig_msg(
    client: ClientId,
    epoch: KeyEpoch,
    op_id: OpId,
    op_class: OpClass,
    msg_type: MsgType,
    flags: Flags,
    payload_hash: &[u8; 32],
) -> [u8; SIG_MSG_LEN] {
    let mut out = [0u8; SIG_MSG_LEN];
    out[..OP_DOMAIN.len()].copy_from_slice(OP_DOMAIN);
    let mut at = OP_DOMAIN.len();
    out[at..at + ClientId::LEN].copy_from_slice(client.as_bytes());
    at += ClientId::LEN;
    out[at..at + 4].copy_from_slice(&epoch.get().to_le_bytes());
    at += 4;
    out[at..at + OpId::LEN].copy_from_slice(op_id.as_bytes());
    at += OpId::LEN;
    out[at] = op_class.get();
    at += 1;
    out[at] = msg_type.get();
    at += 1;
    out[at..at + 2].copy_from_slice(&flags.bits().to_le_bytes());
    at += 2;
    out[at..at + 32].copy_from_slice(payload_hash);
    out
}

/// `BLAKE3("sm/v1/op-body\0" ‖ canonical op body)` (44 §4.6, INV-24).
///
/// The caller builds the canonical body with
/// `Ordered::canonical_bytes_excluding(&[F_SIG, F_PAYLOAD_HASH,
/// F_SENDER_PUB, F_KEY_MAC])`. The four excluded fields are the signature
/// itself and the key-distribution metadata; excluding them avoids
/// self-reference and keeps "who signed" separate from "what was signed".
pub fn payload_hash(canonical_op_body: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(OP_BODY_DOMAIN);
    hasher.update(canonical_op_body);
    *hasher.finalize().as_bytes()
}

/// Signer interface. Persistence lives in `crypto/sign.rs` (W7); this module
/// only defines what a signer must provide.
///
/// Implementations hold the seed, never expose it, and must not implement
/// `Debug` in a way that prints it (44 INV-19).
pub trait Identity {
    /// Self-certifying id of this key.
    fn client_id(&self) -> ClientId;
    /// Current public key.
    fn public_key(&self) -> PublicKey;
    /// Current key epoch.
    fn key_epoch(&self) -> KeyEpoch;
    /// Sign arbitrary domain-separated bytes.
    fn sign_bytes(&self, message: &[u8]) -> Signature;

    /// Sign one operation.
    fn sign_op(
        &self,
        op_id: OpId,
        op_class: OpClass,
        msg_type: MsgType,
        flags: Flags,
        payload_hash: &[u8; 32],
    ) -> Signature {
        let message = sig_msg(
            self.client_id(),
            self.key_epoch(),
            op_id,
            op_class,
            msg_type,
            flags,
            payload_hash,
        );
        self.sign_bytes(&message)
    }
}

/// One signed operation, as verified by [`KeyDirectory::verify_op`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SignedOp<'a> {
    /// Author, as carried in `F_CLIENT_ID`.
    pub client: ClientId,
    /// Author epoch, as carried in `F_KEY_EPOCH`.
    pub epoch: KeyEpoch,
    /// Operation id.
    pub op_id: OpId,
    /// Operation class.
    pub op_class: OpClass,
    /// Frame type (`ORDERED` for every signed operation).
    pub msg_type: MsgType,
    /// Frame flags.
    pub flags: Flags,
    /// Canonical op-body hash.
    pub payload_hash: &'a [u8; 32],
    /// Signature from the AUTH block.
    pub signature: &'a Signature,
}

/// A signature failure. Local only: it never travels on the wire, because the
/// server has no verification ability and must not receive such feedback
/// (44 §7.4, 50 D5).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SignatureError {
    /// No key for `(client, epoch)` is known yet.
    UnknownKey {
        /// Author.
        client: ClientId,
        /// Epoch named by the frame.
        epoch: KeyEpoch,
    },
    /// No key at all is known for the client.
    UnknownClient {
        /// Author.
        client: ClientId,
    },
    /// The key found for the client does not match the one presented.
    KeyMismatch {
        /// Author.
        client: ClientId,
    },
    /// The 32 bytes are not a valid Ed25519 public key.
    MalformedPublicKey,
    /// The 64 bytes are not a signature-sized input.
    MalformedSignature,
    /// `client_id` does not equal `H(cluster_id ‖ public_key)`.
    ClientIdMismatch {
        /// Id claimed by the frame.
        claimed: ClientId,
        /// Id derived from the public key.
        derived: ClientId,
    },
    /// `skid` does not equal `H(public_key)[..8]`.
    SkidMismatch {
        /// `skid` claimed by the AUTH block.
        claimed: [u8; SKID_LEN],
        /// `skid` derived from the public key.
        derived: [u8; SKID_LEN],
    },
    /// `verify_strict` rejected the signature.
    Invalid,
}

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownKey { client, epoch } => {
                write!(f, "unknown public key for {client} at epoch {epoch}")
            }
            Self::UnknownClient { client } => write!(f, "unknown client {client}"),
            Self::KeyMismatch { client } => write!(f, "public key mismatch for {client}"),
            Self::MalformedPublicKey => f.write_str("malformed Ed25519 public key"),
            Self::MalformedSignature => f.write_str("malformed Ed25519 signature"),
            Self::ClientIdMismatch { claimed, derived } => {
                write!(f, "client id {claimed} does not match key id {derived}")
            }
            Self::SkidMismatch { claimed, derived } => write!(
                f,
                "skid {} does not match key skid {}",
                hex8(claimed),
                hex8(derived)
            ),
            Self::Invalid => f.write_str("invalid operation signature"),
        }
    }
}

impl std::error::Error for SignatureError {}

fn hex8(bytes: &[u8; SKID_LEN]) -> String {
    let mut text = String::with_capacity(2 * SKID_LEN);
    for byte in bytes {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

/// A key-directory failure.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeyError {
    /// Announcements are `ORDERED` and must have a real sequence number.
    Unsequenced,
    /// The announcement arrived before the entry already held for this client.
    OutOfOrder {
        /// Sequence of the entry already held.
        first_seq: Seq,
        /// Sequence of the late announcement.
        at: Seq,
    },
    /// The claimed `client_id` is not derived from the announced key.
    SelfCertificationMismatch {
        /// Id claimed by the announcement.
        claimed: ClientId,
        /// Id derived from the public key.
        derived: ClientId,
    },
    /// The `sm/v1/keyentry` self-signature did not verify.
    InvalidSelfSignature,
    /// Same client and epoch, different key. Cryptographically impossible
    /// under 50 D2, kept as a defence in depth.
    Conflict {
        /// Client.
        client: ClientId,
        /// Epoch.
        epoch: KeyEpoch,
    },
    /// The announcement is older than the entry already held.
    Stale {
        /// Client.
        client: ClientId,
        /// Announced epoch.
        announced: KeyEpoch,
        /// Epoch already held.
        known: KeyEpoch,
    },
    /// A higher epoch arrived without a rotation proof (44 §4.7).
    RotationProofMissing {
        /// Client.
        client: ClientId,
        /// Announced epoch.
        epoch: KeyEpoch,
    },
    /// The rotation proof did not verify under the old key.
    RotationProofInvalid {
        /// Client.
        client: ClientId,
        /// Announced epoch.
        epoch: KeyEpoch,
    },
    /// The announced public key is not a valid curve point.
    MalformedPublicKey,
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsequenced => f.write_str("key announcement has no sequence number"),
            Self::OutOfOrder { first_seq, at } => {
                write!(f, "announcement at seq {at} precedes entry seq {first_seq}")
            }
            Self::SelfCertificationMismatch { claimed, derived } => {
                write!(
                    f,
                    "announced client id {claimed} does not match key id {derived}"
                )
            }
            Self::InvalidSelfSignature => f.write_str("invalid key-entry self-signature"),
            Self::Conflict { client, epoch } => {
                write!(f, "conflicting public key for {client} at epoch {epoch}")
            }
            Self::Stale {
                client,
                announced,
                known,
            } => write!(
                f,
                "stale key announcement for {client}: epoch {announced} < {known}"
            ),
            Self::RotationProofMissing { client, epoch } => {
                write!(f, "epoch {epoch} for {client} has no rotation proof")
            }
            Self::RotationProofInvalid { client, epoch } => {
                write!(f, "invalid rotation proof for {client} at epoch {epoch}")
            }
            Self::MalformedPublicKey => f.write_str("malformed Ed25519 public key"),
        }
    }
}

impl std::error::Error for KeyError {}

/// A public-key announcement (`OP_CLASS_KEY_ANNOUNCE` = 15).
///
/// It travels inside `enc_key` ciphertext, so the AEAD already proves PSK
/// possession. `self_sig` proves possession of the private key and is the
/// 50 §3.3 replacement for 44's `key_mac`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct KeyAnnounce {
    /// Claimed author.
    pub client: ClientId,
    /// Announced epoch.
    pub epoch: KeyEpoch,
    /// Announced public key.
    pub public: PublicKey,
    /// `Ed25519(sk, "sm/v1/keyentry\0" ‖ cluster_id ‖ client_id ‖ pk ‖ epoch)`.
    pub self_sig: Signature,
    /// Rotation proof for a higher epoch: the old key signs
    /// `"sm/v1/rotate\0" ‖ client_id ‖ epoch ‖ new_pk` (44 §4.7).
    pub prev_sig: Option<Signature>,
}

impl KeyAnnounce {
    /// Build and self-sign an announcement with `identity`.
    ///
    /// `epoch` is explicit because the signer's current epoch may differ from
    /// the epoch being announced.
    pub fn sign(
        identity: &dyn Identity,
        cluster: &ClusterId,
        epoch: KeyEpoch,
        prev_sig: Option<Signature>,
    ) -> Self {
        let public = identity.public_key();
        let client = client_id(cluster, &public);
        let self_sig = identity.sign_bytes(&key_entry_msg(cluster, client, &public, epoch));
        Self {
            client,
            epoch,
            public,
            self_sig,
            prev_sig,
        }
    }
}

/// The bytes a `KeyEntry` self-signature covers (50 §3.3).
pub fn key_entry_msg(
    cluster: &ClusterId,
    client: ClientId,
    public: &PublicKey,
    epoch: KeyEpoch,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(KEY_ENTRY_DOMAIN.len() + 16 + 16 + 32 + 4);
    out.extend_from_slice(KEY_ENTRY_DOMAIN);
    out.extend_from_slice(cluster.as_bytes());
    out.extend_from_slice(client.as_bytes());
    out.extend_from_slice(public.as_bytes());
    out.extend_from_slice(&epoch.get().to_le_bytes());
    out
}

/// The bytes a rotation proof covers (44 §4.7).
pub fn rotation_msg(client: ClientId, epoch: KeyEpoch, new_public: &PublicKey) -> Vec<u8> {
    let mut out = Vec::with_capacity(ROTATE_DOMAIN.len() + 16 + 4 + 32);
    out.extend_from_slice(ROTATE_DOMAIN);
    out.extend_from_slice(client.as_bytes());
    out.extend_from_slice(&epoch.get().to_le_bytes());
    out.extend_from_slice(new_public.as_bytes());
    out
}

/// One accepted directory entry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct KeyEntry {
    /// Client.
    pub client: ClientId,
    /// Current epoch.
    pub epoch: KeyEpoch,
    /// Current public key.
    pub public: PublicKey,
    /// `skid` of [`KeyEntry::public`].
    pub skid: [u8; SKID_LEN],
    /// Sequence of the first announcement of this client.
    pub first_seq: Seq,
    /// The self-signature stored for re-verification after a reload.
    pub self_sig: Signature,
    /// Previous `(epoch, key)`, kept for a local grace window (44 §4.7).
    pub previous: Option<(KeyEpoch, PublicKey)>,
}

/// The result of applying one announcement.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeyUpdate {
    /// First announcement for this client.
    Inserted,
    /// Same epoch and key as the entry already held.
    Idempotent,
    /// A higher epoch with a valid rotation proof.
    Rotated,
}

/// Public-key directory, ordered by sequence (44 §4.7, INV-25).
///
/// `apply` is called in nondecreasing `seq` order by the replayer. First wins
/// by the smallest sequence; a higher epoch needs a proof signed by the old
/// key; a lower epoch is stale and never replaces the entry.
#[derive(Clone, Debug)]
pub struct KeyDirectory {
    cluster: ClusterId,
    entries: BTreeMap<ClientId, KeyEntry>,
}

impl KeyDirectory {
    /// Empty directory for one cluster.
    pub const fn new(cluster: ClusterId) -> Self {
        Self {
            cluster,
            entries: BTreeMap::new(),
        }
    }

    /// Cluster id used for self-certification.
    pub const fn cluster(&self) -> &ClusterId {
        &self.cluster
    }

    /// Number of known clients.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no client is known.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Entry for one client.
    pub fn get(&self, client: ClientId) -> Option<&KeyEntry> {
        self.entries.get(&client)
    }

    /// Public key for `(client, epoch)`, or `None` if unknown or stale.
    pub fn public_key(&self, client: ClientId, epoch: KeyEpoch) -> Option<PublicKey> {
        self.entries
            .get(&client)
            .filter(|entry| entry.epoch == epoch)
            .map(|entry| entry.public)
    }

    /// Iterate over entries in deterministic `ClientId` order.
    pub fn iter(&self) -> impl Iterator<Item = &KeyEntry> {
        self.entries.values()
    }

    /// Apply one announcement at sequence `at`.
    ///
    /// # Errors
    ///
    /// [`KeyError`] for an unsequenced, out-of-order, self-inconsistent,
    /// unproven or stale announcement. The directory is unchanged on error.
    pub fn apply(&mut self, announce: &KeyAnnounce, at: Seq) -> Result<KeyUpdate, KeyError> {
        if !at.is_sequenced() {
            return Err(KeyError::Unsequenced);
        }
        self.install(announce, at)
    }

    /// Install a key whose binding was proven outside the `ORDERED` stream.
    ///
    /// `JOIN_PROOF`/`JOIN_ACCEPT` (50 §3.2) establish a key before the peer
    /// has a sequence number, so [`KeyDirectory::apply`] cannot be used: it
    /// rejects unsequenced announcements by design. The checks that matter
    /// are unchanged — a valid curve point, `client_id == H(cluster ‖ pk)`,
    /// and the `sm/v1/keyentry` self-signature. The entry records
    /// [`Seq::UNSEQUENCED`] as its `first_seq`, so a later real announcement
    /// at any sequence is still accepted in order.
    ///
    /// # Errors
    ///
    /// [`KeyError`] for a self-inconsistent, unproven, stale or conflicting
    /// announcement. The directory is unchanged on error.
    pub fn trust(&mut self, announce: &KeyAnnounce) -> Result<KeyUpdate, KeyError> {
        self.install(announce, Seq::UNSEQUENCED)
    }

    /// Shared body of [`KeyDirectory::apply`] and [`KeyDirectory::trust`].
    ///
    /// `at == Seq::UNSEQUENCED` means the key was proven out of band and has
    /// no place in the stream, so the sequence checks do not apply.
    fn install(&mut self, announce: &KeyAnnounce, at: Seq) -> Result<KeyUpdate, KeyError> {
        announce
            .public
            .verifying_key()
            .map_err(|_| KeyError::MalformedPublicKey)?;

        let derived = client_id(&self.cluster, &announce.public);
        if derived != announce.client {
            return Err(KeyError::SelfCertificationMismatch {
                claimed: announce.client,
                derived,
            });
        }

        announce
            .public
            .verify_strict(
                &key_entry_msg(
                    &self.cluster,
                    announce.client,
                    &announce.public,
                    announce.epoch,
                ),
                &announce.self_sig,
            )
            .map_err(|_| KeyError::InvalidSelfSignature)?;

        let Some(entry) = self.entries.get(&announce.client).copied() else {
            self.entries.insert(
                announce.client,
                KeyEntry {
                    client: announce.client,
                    epoch: announce.epoch,
                    public: announce.public,
                    skid: skid(&announce.public),
                    first_seq: at,
                    self_sig: announce.self_sig,
                    previous: None,
                },
            );
            return Ok(KeyUpdate::Inserted);
        };

        if at.is_sequenced() && at < entry.first_seq {
            return Err(KeyError::OutOfOrder {
                first_seq: entry.first_seq,
                at,
            });
        }

        if announce.epoch < entry.epoch {
            return Err(KeyError::Stale {
                client: announce.client,
                announced: announce.epoch,
                known: entry.epoch,
            });
        }

        if announce.epoch == entry.epoch {
            if announce.public == entry.public {
                return Ok(KeyUpdate::Idempotent);
            }
            return Err(KeyError::Conflict {
                client: announce.client,
                epoch: announce.epoch,
            });
        }

        let proof = announce.prev_sig.ok_or(KeyError::RotationProofMissing {
            client: announce.client,
            epoch: announce.epoch,
        })?;
        entry
            .public
            .verify_strict(
                &rotation_msg(announce.client, announce.epoch, &announce.public),
                &proof,
            )
            .map_err(|_| KeyError::RotationProofInvalid {
                client: announce.client,
                epoch: announce.epoch,
            })?;

        self.entries.insert(
            announce.client,
            KeyEntry {
                client: announce.client,
                epoch: announce.epoch,
                public: announce.public,
                skid: skid(&announce.public),
                first_seq: entry.first_seq,
                self_sig: announce.self_sig,
                previous: Some((entry.epoch, entry.public)),
            },
        );
        Ok(KeyUpdate::Rotated)
    }

    /// Verify one signed operation (50 §5.1 steps 5–6).
    ///
    /// Looks up the key by `client`, requires the epoch to match, and runs
    /// `verify_strict` over [`sig_msg`]. `payload_hash` must be recomputed by
    /// the caller from the canonical op body; the value carried inside the op
    /// is not trusted (44 §4.7).
    ///
    /// # Errors
    ///
    /// [`SignatureError::UnknownKey`] when the key has not been announced yet;
    /// [`SignatureError::Invalid`] when the signature does not verify.
    pub fn verify_op(&self, op: &SignedOp<'_>) -> Result<(), SignatureError> {
        let public = self
            .public_key(op.client, op.epoch)
            .ok_or(SignatureError::UnknownKey {
                client: op.client,
                epoch: op.epoch,
            })?;
        verify_with_key(&public, op)
    }

    /// Resolve an AUTH block and verify the operation in one step (50 §5.1).
    ///
    /// The signature verified is the one carried by `block`, not
    /// `op.signature`; the two are the same in a well-formed frame. When the
    /// directory already holds the client, its epoch and `skid` are
    /// authoritative. Otherwise an inline key is required and is checked
    /// against `client_id` and `skid`.
    ///
    /// # Errors
    ///
    /// [`SignatureError`] for an unknown key, an epoch mismatch, an
    /// inconsistent block or an invalid signature.
    pub fn verify_op_with_auth(
        &self,
        block: &AuthBlock,
        op: &SignedOp<'_>,
    ) -> Result<(), SignatureError> {
        let signed = SignedOp {
            signature: &block.signature,
            ..*op
        };
        match self.entries.get(&op.client) {
            Some(entry) => {
                if entry.epoch != op.epoch {
                    return Err(SignatureError::UnknownKey {
                        client: op.client,
                        epoch: op.epoch,
                    });
                }
                if entry.skid != block.skid {
                    return Err(SignatureError::SkidMismatch {
                        claimed: block.skid,
                        derived: entry.skid,
                    });
                }
                verify_with_key(&entry.public, &signed)
            }
            None => {
                let public = self.resolve_auth(block, op.client)?;
                verify_with_key(&public, &signed)
            }
        }
    }

    /// Resolve the key presented by an AUTH block (50 §5.1 step 4).
    ///
    /// An inline key is checked against `skid` and `client_id` and does not
    /// need a directory entry. Without one, the directory entry for
    /// `expected_client` must exist and its `skid` must match.
    ///
    /// # Errors
    ///
    /// [`SignatureError`] when the block is inconsistent or the key is
    /// unknown.
    pub fn resolve_auth(
        &self,
        block: &AuthBlock,
        expected_client: ClientId,
    ) -> Result<PublicKey, SignatureError> {
        if let Some(public) = block.inline_public {
            let derived_skid = skid(&public);
            if derived_skid != block.skid {
                return Err(SignatureError::SkidMismatch {
                    claimed: block.skid,
                    derived: derived_skid,
                });
            }
            let derived = client_id(&self.cluster, &public);
            if derived != expected_client {
                return Err(SignatureError::ClientIdMismatch {
                    claimed: expected_client,
                    derived,
                });
            }
            if let Some(entry) = self.entries.get(&expected_client) {
                if entry.public != public {
                    return Err(SignatureError::KeyMismatch {
                        client: expected_client,
                    });
                }
            }
            return Ok(public);
        }

        let entry = self
            .entries
            .get(&expected_client)
            .ok_or(SignatureError::UnknownClient {
                client: expected_client,
            })?;
        if entry.skid != block.skid {
            return Err(SignatureError::SkidMismatch {
                claimed: block.skid,
                derived: entry.skid,
            });
        }
        Ok(entry.public)
    }
}

/// Verify a signature with an already-resolved public key.
///
/// # Errors
///
/// [`SignatureError::MalformedPublicKey`] or [`SignatureError::Invalid`].
pub fn verify_with_key(public: &PublicKey, op: &SignedOp<'_>) -> Result<(), SignatureError> {
    let message = sig_msg(
        op.client,
        op.epoch,
        op.op_id,
        op.op_class,
        op.msg_type,
        op.flags,
        op.payload_hash,
    );
    public.verify_strict(&message, op.signature)
}

/// AUTH block: the signature carrier inside the AEAD plaintext (50 §4.4).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AuthBlock {
    /// `skid` of the signing key; a cache index only.
    pub skid: [u8; SKID_LEN],
    /// Ed25519 signature over [`sig_msg`].
    pub signature: Signature,
    /// Public key, present on the first frame and periodically thereafter.
    pub inline_public: Option<PublicKey>,
}

impl AuthBlock {
    /// Base block without an inline key.
    pub const fn new(skid: [u8; SKID_LEN], signature: Signature) -> Self {
        Self {
            skid,
            signature,
            inline_public: None,
        }
    }

    /// Block that also carries the public key.
    pub const fn with_inline_public(
        skid: [u8; SKID_LEN],
        signature: Signature,
        public: PublicKey,
    ) -> Self {
        Self {
            skid,
            signature,
            inline_public: Some(public),
        }
    }

    /// Sign `message` with `identity` and build the block.
    pub fn sign(identity: &dyn Identity, message: &[u8], inline_public: bool) -> Self {
        let public = identity.public_key();
        let signature = identity.sign_bytes(message);
        let key_skid = skid(&public);
        if inline_public {
            Self::with_inline_public(key_skid, signature, public)
        } else {
            Self::new(key_skid, signature)
        }
    }

    /// Encoded width: 75 B, or 107 B with an inline key.
    pub const fn encoded_len(&self) -> usize {
        match self.inline_public {
            None => AUTH_BLOCK_LEN,
            Some(_) => AUTH_INLINE_LEN,
        }
    }

    /// Encode to a fresh buffer.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        self.encode_to(&mut out);
        out
    }

    /// Append the wire bytes to `out`.
    pub fn encode_to(&self, out: &mut Vec<u8>) {
        out.push(AUTH_VER);
        out.push(AUTH_ALG_ED25519);
        let flags = if self.inline_public.is_some() {
            AUTH_FLAG_INLINE_PUBKEY
        } else {
            0
        };
        out.push(flags);
        out.extend_from_slice(&self.skid);
        out.extend_from_slice(self.signature.as_bytes());
        if let Some(public) = self.inline_public {
            out.extend_from_slice(public.as_bytes());
        }
    }

    /// Decode one block from the start of `bytes`.
    ///
    /// Returns the block and the number of bytes consumed, so the WCP body
    /// starts at `consumed`. An inline key is checked against `skid`.
    ///
    /// # Errors
    ///
    /// [`AuthBlockError`] for truncation, an unknown version/algorithm, a
    /// reserved flag, or an inline key whose `skid` does not match.
    pub fn decode(bytes: &[u8]) -> Result<(Self, usize), AuthBlockError> {
        if bytes.len() < AUTH_BLOCK_LEN {
            return Err(AuthBlockError::TooShort {
                need: AUTH_BLOCK_LEN,
                got: bytes.len(),
            });
        }
        if bytes[0] != AUTH_VER {
            return Err(AuthBlockError::BadVersion(bytes[0]));
        }
        if bytes[1] != AUTH_ALG_ED25519 {
            return Err(AuthBlockError::BadAlgorithm(bytes[1]));
        }
        let flags = bytes[2];
        if flags & !AUTH_FLAG_INLINE_PUBKEY != 0 {
            return Err(AuthBlockError::ReservedFlags(flags));
        }

        let mut block_skid = [0u8; SKID_LEN];
        block_skid.copy_from_slice(&bytes[3..3 + SKID_LEN]);
        let mut signature = [0u8; SIGNATURE_LEN];
        signature.copy_from_slice(&bytes[3 + SKID_LEN..AUTH_BLOCK_LEN]);
        let signature = Signature::from_bytes(signature);

        if flags & AUTH_FLAG_INLINE_PUBKEY == 0 {
            return Ok((
                Self {
                    skid: block_skid,
                    signature,
                    inline_public: None,
                },
                AUTH_BLOCK_LEN,
            ));
        }

        if bytes.len() < AUTH_INLINE_LEN {
            return Err(AuthBlockError::TooShort {
                need: AUTH_INLINE_LEN,
                got: bytes.len(),
            });
        }
        let public = PublicKey::from_slice(&bytes[AUTH_BLOCK_LEN..AUTH_INLINE_LEN])
            .map_err(|_| AuthBlockError::MalformedPublicKey)?;
        public
            .verifying_key()
            .map_err(|_| AuthBlockError::MalformedPublicKey)?;
        let derived = skid(&public);
        if derived != block_skid {
            return Err(AuthBlockError::SkidMismatch {
                claimed: block_skid,
                derived,
            });
        }
        Ok((
            Self {
                skid: block_skid,
                signature,
                inline_public: Some(public),
            },
            AUTH_INLINE_LEN,
        ))
    }
}

/// An AUTH block decoding failure.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AuthBlockError {
    /// Fewer bytes than the block requires.
    TooShort {
        /// Bytes required.
        need: usize,
        /// Bytes available.
        got: usize,
    },
    /// Unknown `auth_ver`.
    BadVersion(u8),
    /// Unknown `auth_alg`.
    BadAlgorithm(u8),
    /// A reserved `auth_flags` bit was set (including `CHAIN`).
    ReservedFlags(u8),
    /// The inline key is not a valid Ed25519 point.
    MalformedPublicKey,
    /// The inline key does not hash to the block's `skid`.
    SkidMismatch {
        /// `skid` carried by the block.
        claimed: [u8; SKID_LEN],
        /// `skid` derived from the inline key.
        derived: [u8; SKID_LEN],
    },
}

impl fmt::Display for AuthBlockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { need, got } => {
                write!(f, "AUTH block needs {need} bytes, got {got}")
            }
            Self::BadVersion(version) => write!(f, "unsupported auth_ver {version}"),
            Self::BadAlgorithm(alg) => write!(f, "unsupported auth_alg {alg}"),
            Self::ReservedFlags(flags) => {
                write!(f, "reserved auth_flags bits set: 0x{flags:02x}")
            }
            Self::MalformedPublicKey => f.write_str("malformed inline public key"),
            Self::SkidMismatch { claimed, derived } => write!(
                f,
                "inline key skid {} does not match block skid {}",
                hex8(derived),
                hex8(claimed)
            ),
        }
    }
}

impl std::error::Error for AuthBlockError {}

/// One frame parked because its key is unknown.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PendingOp<T> {
    /// Author.
    pub client: ClientId,
    /// Epoch named by the frame.
    pub epoch: KeyEpoch,
    /// Opaque payload, owned by the caller.
    pub payload: T,
}

/// Bounded holding area for frames whose key has not been announced yet
/// (44 §4.7, 50 §5.2).
///
/// The buffer is sans-io: the 5-second timeout is the caller's policy. While
/// an op waits, the caller sends `KEY_REQ`; when the key arrives,
/// [`UnknownKeyBuffer::take_ready`] returns the ops in arrival order. On
/// timeout the caller drops them (fail-closed, `applied_seq` does not move).
#[derive(Clone, Debug)]
pub struct UnknownKeyBuffer<T> {
    capacity: usize,
    pending: Vec<PendingOp<T>>,
}

impl<T> UnknownKeyBuffer<T> {
    /// Buffer with an explicit bound.
    pub const fn new(capacity: usize) -> Self {
        Self {
            capacity,
            pending: Vec::new(),
        }
    }

    /// Buffer with [`UNKNOWN_KEY_CAPACITY`].
    pub const fn with_default_capacity() -> Self {
        Self::new(UNKNOWN_KEY_CAPACITY)
    }

    /// Current bound.
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Number of parked frames.
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Whether no frame is parked.
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Park one frame.
    ///
    /// # Errors
    ///
    /// [`UnknownKeyError::Full`] when the bound is reached; the caller must
    /// drop the frame or fail closed, never grow without bound.
    pub fn push(
        &mut self,
        client: ClientId,
        epoch: KeyEpoch,
        payload: T,
    ) -> Result<(), UnknownKeyError> {
        if self.pending.len() >= self.capacity {
            return Err(UnknownKeyError::Full {
                capacity: self.capacity,
            });
        }
        self.pending.push(PendingOp {
            client,
            epoch,
            payload,
        });
        Ok(())
    }

    /// Remove and return frames whose `(client, epoch)` is now known.
    ///
    /// Arrival order is preserved. Frames for other clients stay parked.
    pub fn take_ready(&mut self, directory: &KeyDirectory) -> Vec<T> {
        let mut ready = Vec::new();
        let mut index = 0;
        while index < self.pending.len() {
            let op = &self.pending[index];
            if directory.public_key(op.client, op.epoch).is_some() {
                let op = self.pending.remove(index);
                ready.push(op.payload);
            } else {
                index += 1;
            }
        }
        ready
    }

    /// Drop everything and return the payloads (fail-closed path).
    pub fn drain_all(&mut self) -> Vec<T> {
        self.pending.drain(..).map(|op| op.payload).collect()
    }
}

impl<T> Default for UnknownKeyBuffer<T> {
    fn default() -> Self {
        Self::with_default_capacity()
    }
}

/// An unknown-key buffering failure.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UnknownKeyError {
    /// The buffer is full.
    Full {
        /// Configured bound.
        capacity: usize,
    },
}

impl fmt::Display for UnknownKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full { capacity } => {
                write!(f, "unknown-key buffer is full ({capacity} frames)")
            }
        }
    }
}

impl std::error::Error for UnknownKeyError {}

/// In-memory signer for tests and for `crypto/sign.rs` (W7) to build on.
///
/// This type performs no persistence; W7 owns the `0600` key file. It holds
/// the seed only inside [`SigningKey`], which zeroizes on drop, and never
/// prints it (44 INV-19).
pub struct MemoryIdentity {
    key: SigningKey,
    cluster: ClusterId,
    epoch: KeyEpoch,
}

impl MemoryIdentity {
    /// Build an identity from a 32-byte seed.
    pub fn from_seed(cluster: ClusterId, epoch: KeyEpoch, seed: [u8; 32]) -> Self {
        let key = SigningKey::from_bytes(&seed);
        Self {
            key,
            cluster,
            epoch,
        }
    }
}

impl Identity for MemoryIdentity {
    fn client_id(&self) -> ClientId {
        client_id(&self.cluster, &self.public_key())
    }

    fn public_key(&self) -> PublicKey {
        PublicKey::from_bytes(self.key.verifying_key().to_bytes())
    }

    fn key_epoch(&self) -> KeyEpoch {
        self.epoch
    }

    fn sign_bytes(&self, message: &[u8]) -> Signature {
        Signature::from_bytes(self.key.sign(message).to_bytes())
    }
}

impl fmt::Debug for MemoryIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemoryIdentity")
            .field("client_id", &self.client_id())
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    const RFC8032_SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    const RFC8032_PUBLIC: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];

    fn cluster() -> ClusterId {
        ClusterId::from_bytes([0x11; 16])
    }

    fn epoch() -> KeyEpoch {
        KeyEpoch(7)
    }

    fn op_id() -> OpId {
        OpId::from_bytes([0x22; 16])
    }

    static PAYLOAD: [u8; 32] = [0x33; 32];

    fn payload() -> [u8; 32] {
        PAYLOAD
    }

    fn rfc_identity() -> MemoryIdentity {
        MemoryIdentity::from_seed(cluster(), epoch(), RFC8032_SEED)
    }

    fn op<'a>(identity: &MemoryIdentity, signature: &'a Signature) -> SignedOp<'a> {
        SignedOp {
            client: identity.client_id(),
            epoch: identity.key_epoch(),
            op_id: op_id(),
            op_class: OpClass::WRITE,
            msg_type: MsgType::ORDERED,
            flags: Flags::ENC,
            payload_hash: &PAYLOAD,
            signature,
        }
    }

    fn announce(identity: &MemoryIdentity) -> KeyAnnounce {
        KeyAnnounce::sign(identity, &cluster(), identity.key_epoch(), None)
    }

    fn hex(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    /// 50 §2.4: `client_id` and `skid` are deterministic functions of the key.
    #[test]
    fn u_identity_derivation_is_deterministic() {
        let public = PublicKey::from_bytes(RFC8032_PUBLIC);
        let first = client_id(&cluster(), &public);
        let second = client_id(&cluster(), &public);
        assert_eq!(first, second);
        assert_ne!(
            first,
            client_id(&ClusterId::from_bytes([0x12; 16]), &public)
        );
        assert_eq!(skid(&public), skid(&public));

        let other = PublicKey::from_bytes([0x44; 32]);
        assert_ne!(
            client_id(&cluster(), &public),
            client_id(&cluster(), &other)
        );
    }

    /// 44:V14 / 50 §11.6: fixed seed, fixed fields, fixed bytes.
    #[test]
    fn u_identity_golden_vectors() {
        let identity = rfc_identity();
        let public = identity.public_key();
        assert_eq!(public.to_bytes(), RFC8032_PUBLIC);
        assert_eq!(
            hex(client_id(&cluster(), &public).as_bytes()),
            "b1632678182555581e58ef982e1e7f12"
        );
        assert_eq!(hex(&skid(&public)), "c3c1c046716d8efe");
        assert_eq!(
            hex(&sig_msg(
                identity.client_id(),
                identity.key_epoch(),
                op_id(),
                OpClass::WRITE,
                MsgType::ORDERED,
                Flags::ENC,
                &payload(),
            )),
            "736d2f76312f6f7000b1632678182555581e58ef982e1e7f120700000022222222222222222222222222222222011008003333333333333333333333333333333333333333333333333333333333333333"
        );
        let signature = identity.sign_op(
            op_id(),
            OpClass::WRITE,
            MsgType::ORDERED,
            Flags::ENC,
            &payload(),
        );
        assert_eq!(
            hex(signature.as_bytes()),
            "76d3b70ffb2794de8b2db505be64d89ea224984b428d14dac2d77c1d8ca77d368e29d20ea696644dfcea702763c53042807b992aaabc783c264b618c32acf60a"
        );

        let block = AuthBlock::with_inline_public(skid(&public), signature, public);
        assert_eq!(block.encoded_len(), AUTH_INLINE_LEN);
        assert_eq!(
            hex(&block.encode()),
            "010101c3c1c046716d8efe76d3b70ffb2794de8b2db505be64d89ea224984b428d14dac2d77c1d8ca77d368e29d20ea696644dfcea702763c53042807b992aaabc783c264b618c32acf60ad75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
    }

    /// 44:V14: every signed field is bound; flipping any one fails.
    #[test]
    fn u_identity_signature_matrix_rejects_every_field() {
        let identity = rfc_identity();
        let signature = identity.sign_op(
            op_id(),
            OpClass::WRITE,
            MsgType::ORDERED,
            Flags::ENC,
            &payload(),
        );
        let public = identity.public_key();
        assert!(verify_with_key(&public, &op(&identity, &signature)).is_ok());

        let mut changed = op(&identity, &signature);
        changed.client = ClientId::from_bytes([0x55; 16]);
        assert_eq!(
            verify_with_key(&public, &changed),
            Err(SignatureError::Invalid)
        );

        let mut changed = op(&identity, &signature);
        changed.epoch = KeyEpoch(8);
        assert_eq!(
            verify_with_key(&public, &changed),
            Err(SignatureError::Invalid)
        );

        let mut changed = op(&identity, &signature);
        changed.op_id = OpId::from_bytes([0x23; 16]);
        assert_eq!(
            verify_with_key(&public, &changed),
            Err(SignatureError::Invalid)
        );

        let mut changed = op(&identity, &signature);
        changed.op_class = OpClass::UNLINK;
        assert_eq!(
            verify_with_key(&public, &changed),
            Err(SignatureError::Invalid)
        );

        let mut changed = op(&identity, &signature);
        changed.msg_type = MsgType::RELAY;
        assert_eq!(
            verify_with_key(&public, &changed),
            Err(SignatureError::Invalid)
        );

        let mut changed = op(&identity, &signature);
        changed.flags = Flags::ENC.with(Flags::URGENT);
        assert_eq!(
            verify_with_key(&public, &changed),
            Err(SignatureError::Invalid)
        );

        let other_hash = [0x34; 32];
        let mut changed = op(&identity, &signature);
        changed.payload_hash = &other_hash;
        assert_eq!(
            verify_with_key(&public, &changed),
            Err(SignatureError::Invalid)
        );
    }

    /// 50 §4.2: `seq` is structurally outside the signature input.
    #[test]
    fn u_identity_seq_is_not_signed() {
        let identity = rfc_identity();
        let message = sig_msg(
            identity.client_id(),
            identity.key_epoch(),
            op_id(),
            OpClass::WRITE,
            MsgType::ORDERED,
            Flags::ENC,
            &payload(),
        );
        assert_eq!(message.len(), SIG_MSG_LEN);
        assert_eq!(&message[..OP_DOMAIN.len()], OP_DOMAIN);
        assert_eq!(
            &message[OP_DOMAIN.len()..OP_DOMAIN.len() + ClientId::LEN],
            identity.client_id().as_bytes()
        );
        assert_eq!(
            &message[OP_DOMAIN.len() + ClientId::LEN..OP_DOMAIN.len() + ClientId::LEN + 4],
            &identity.key_epoch().get().to_le_bytes()
        );
        assert_eq!(
            &message[OP_DOMAIN.len() + ClientId::LEN + 4
                ..OP_DOMAIN.len() + ClientId::LEN + 4 + OpId::LEN],
            op_id().as_bytes()
        );
        assert_eq!(&message[SIG_MSG_LEN - 32..], &payload()[..]);
    }

    /// 50 §3.3: a self-signature binds cluster, client, key and epoch.
    #[test]
    fn u_identity_key_announce_self_signature_binds_fields() {
        let identity = rfc_identity();
        let announce = announce(&identity);
        let mut directory = KeyDirectory::new(cluster());
        assert_eq!(directory.apply(&announce, Seq(5)), Ok(KeyUpdate::Inserted));

        let mut tampered = announce;
        tampered.epoch = KeyEpoch(8);
        let mut other = KeyDirectory::new(cluster());
        assert_eq!(
            other.apply(&tampered, Seq(5)),
            Err(KeyError::InvalidSelfSignature)
        );

        let mut tampered = announce;
        tampered.public = PublicKey::from_bytes([0x66; 32]);
        assert_eq!(
            other.apply(&tampered, Seq(5)),
            Err(KeyError::SelfCertificationMismatch {
                claimed: announce.client,
                derived: client_id(&cluster(), &tampered.public),
            })
        );

        let mut wrong_cluster = KeyDirectory::new(ClusterId::from_bytes([0x12; 16]));
        assert_eq!(
            wrong_cluster.apply(&announce, Seq(5)),
            Err(KeyError::SelfCertificationMismatch {
                claimed: announce.client,
                derived: client_id(&ClusterId::from_bytes([0x12; 16]), &announce.public),
            })
        );
    }

    /// W4/W5 boundary: the wire `KEY_ANNOUNCE` fields feed the directory.
    #[test]
    fn u_identity_key_announce_from_wire() {
        use crate::protocol::frame::Limits;
        use crate::protocol::messages::{OpArgs, Ordered, WcpWriter, fid};

        let identity = rfc_identity();
        let announce = announce(&identity);

        let mut writer = WcpWriter::new();
        writer.bytes(fid::F_CLIENT_ID, announce.client.as_bytes());
        writer.u32(fid::F_KEY_EPOCH, announce.epoch.get());
        writer.u8(fid::F_OP_CLASS, OpClass::KEY_ANNOUNCE.get());
        writer.bytes(fid::F_SENDER_PUB, announce.public.as_bytes());
        writer.bytes(fid::F_SELF_SIG, announce.self_sig.as_bytes());
        let body = writer.finish().unwrap();

        let ordered = Ordered::decode(&body, &Limits::default_const()).unwrap();
        let wire = KeyAnnounce {
            client: ordered.client_id,
            epoch: KeyEpoch(ordered.key_epoch),
            public: PublicKey::from_bytes(ordered.sender_pub.unwrap()),
            self_sig: Signature::from_bytes(ordered.self_sig().unwrap()),
            prev_sig: match ordered.args {
                OpArgs::KeyAnnounce { prev_sig, .. } => prev_sig.map(Signature::from_bytes),
                _ => None,
            },
        };
        assert_eq!(wire, announce);

        let mut directory = KeyDirectory::new(cluster());
        assert_eq!(directory.apply(&wire, Seq(5)), Ok(KeyUpdate::Inserted));
    }

    /// 44:V15: first wins by sequence, later repeats are idempotent.
    #[test]
    fn u_identity_key_directory_first_wins() {
        let identity = rfc_identity();
        let announce = announce(&identity);
        let mut directory = KeyDirectory::new(cluster());

        assert_eq!(directory.len(), 0);
        assert_eq!(directory.apply(&announce, Seq(5)), Ok(KeyUpdate::Inserted));
        assert_eq!(directory.len(), 1);
        assert_eq!(
            directory.public_key(announce.client, announce.epoch),
            Some(announce.public)
        );
        assert_eq!(directory.public_key(announce.client, KeyEpoch(8)), None);

        assert_eq!(
            directory.apply(&announce, Seq(5)),
            Ok(KeyUpdate::Idempotent)
        );
        assert_eq!(
            directory.apply(&announce, Seq(9)),
            Ok(KeyUpdate::Idempotent)
        );
        assert_eq!(
            directory.get(announce.client).map(|e| e.first_seq),
            Some(Seq(5))
        );

        assert_eq!(
            directory.apply(&announce, Seq(4)),
            Err(KeyError::OutOfOrder {
                first_seq: Seq(5),
                at: Seq(4),
            })
        );
        assert_eq!(
            directory.apply(&announce, Seq::UNSEQUENCED),
            Err(KeyError::Unsequenced)
        );

        let entry = directory.get(announce.client).unwrap();
        assert_eq!(entry.skid, skid(&announce.public));
        assert_eq!(entry.previous, None);
    }

    /// 44 §4.7: a higher epoch needs a proof from the old key; lower is stale.
    #[test]
    fn u_identity_key_directory_rotation_rules() {
        let identity = rfc_identity();
        let announce = announce(&identity);
        let mut directory = KeyDirectory::new(cluster());
        directory.apply(&announce, Seq(5)).unwrap();

        let mut higher = announce;
        higher.epoch = KeyEpoch(8);
        higher.self_sig = identity.sign_bytes(&key_entry_msg(
            &cluster(),
            higher.client,
            &higher.public,
            higher.epoch,
        ));
        assert_eq!(
            directory.apply(&higher, Seq(6)),
            Err(KeyError::RotationProofMissing {
                client: higher.client,
                epoch: KeyEpoch(8),
            })
        );

        let proof = identity.sign_bytes(&rotation_msg(higher.client, higher.epoch, &higher.public));
        higher.prev_sig = Some(proof);
        assert_eq!(directory.apply(&higher, Seq(6)), Ok(KeyUpdate::Rotated));
        assert_eq!(
            directory.public_key(higher.client, KeyEpoch(8)),
            Some(higher.public)
        );
        assert_eq!(
            directory.public_key(higher.client, KeyEpoch(7)),
            None,
            "only the current epoch is selectable"
        );
        assert_eq!(
            directory.get(higher.client).and_then(|e| e.previous),
            Some((KeyEpoch(7), announce.public))
        );

        let mut lower = announce;
        lower.epoch = KeyEpoch(6);
        lower.self_sig = identity.sign_bytes(&key_entry_msg(
            &cluster(),
            lower.client,
            &lower.public,
            lower.epoch,
        ));
        assert_eq!(
            directory.apply(&lower, Seq(7)),
            Err(KeyError::Stale {
                client: lower.client,
                announced: KeyEpoch(6),
                known: KeyEpoch(8),
            })
        );
    }

    /// 44:V14: unknown keys fail closed; verification never guesses.
    #[test]
    fn u_identity_unknown_key_is_an_error() {
        let identity = rfc_identity();
        let signature = identity.sign_op(
            op_id(),
            OpClass::WRITE,
            MsgType::ORDERED,
            Flags::ENC,
            &payload(),
        );
        let directory = KeyDirectory::new(cluster());
        assert_eq!(
            directory.verify_op(&op(&identity, &signature)),
            Err(SignatureError::UnknownKey {
                client: identity.client_id(),
                epoch: identity.key_epoch(),
            })
        );
    }

    /// 50 §5.1 step 4: inline keys are checked against `skid` and `client_id`.
    #[test]
    fn u_identity_auth_block_resolution() {
        let identity = rfc_identity();
        let public = identity.public_key();
        let signature = identity.sign_op(
            op_id(),
            OpClass::WRITE,
            MsgType::ORDERED,
            Flags::ENC,
            &payload(),
        );
        let directory = KeyDirectory::new(cluster());

        let inline = AuthBlock::with_inline_public(skid(&public), signature, public);
        assert_eq!(
            directory.resolve_auth(&inline, identity.client_id()),
            Ok(public)
        );

        let wrong_client = ClientId::from_bytes([0x77; 16]);
        assert_eq!(
            directory.resolve_auth(&inline, wrong_client),
            Err(SignatureError::ClientIdMismatch {
                claimed: wrong_client,
                derived: identity.client_id(),
            })
        );

        let mut wrong_skid = inline;
        wrong_skid.skid = [0x88; 8];
        assert!(matches!(
            directory.resolve_auth(&wrong_skid, identity.client_id()),
            Err(SignatureError::SkidMismatch { .. })
        ));

        let no_inline = AuthBlock::new(skid(&public), signature);
        assert_eq!(
            directory.resolve_auth(&no_inline, identity.client_id()),
            Err(SignatureError::UnknownClient {
                client: identity.client_id(),
            })
        );

        let mut known = KeyDirectory::new(cluster());
        known.apply(&announce(&identity), Seq(5)).unwrap();
        assert_eq!(
            known.resolve_auth(&no_inline, identity.client_id()),
            Ok(public)
        );
        assert_eq!(known.verify_op(&op(&identity, &signature)), Ok(()));
    }

    /// 50 §5.1: one call resolves the AUTH block and verifies the signature.
    #[test]
    fn u_identity_verify_op_with_auth() {
        let identity = rfc_identity();
        let public = identity.public_key();
        let signature = identity.sign_op(
            op_id(),
            OpClass::WRITE,
            MsgType::ORDERED,
            Flags::ENC,
            &payload(),
        );
        let signed = op(&identity, &signature);
        let inline = AuthBlock::with_inline_public(skid(&public), signature, public);

        // First frame: the inline key is enough.
        let empty = KeyDirectory::new(cluster());
        assert_eq!(empty.verify_op_with_auth(&inline, &signed), Ok(()));

        // Known client: the directory is authoritative.
        let mut known = KeyDirectory::new(cluster());
        known.apply(&announce(&identity), Seq(5)).unwrap();
        assert_eq!(known.verify_op_with_auth(&inline, &signed), Ok(()));

        // A valid signature at another epoch is still an unknown key.
        let mut other_epoch = signed;
        other_epoch.epoch = KeyEpoch(8);
        let other_sig = identity.sign_bytes(&sig_msg(
            identity.client_id(),
            KeyEpoch(8),
            op_id(),
            OpClass::WRITE,
            MsgType::ORDERED,
            Flags::ENC,
            &payload(),
        ));
        let other_block = AuthBlock::with_inline_public(skid(&public), other_sig, public);
        assert_eq!(
            known.verify_op_with_auth(&other_block, &other_epoch),
            Err(SignatureError::UnknownKey {
                client: identity.client_id(),
                epoch: KeyEpoch(8),
            })
        );

        // A block whose skid does not match the known entry is rejected.
        let mut wrong_skid = inline;
        wrong_skid.skid = [0x88; 8];
        assert!(matches!(
            known.verify_op_with_auth(&wrong_skid, &signed),
            Err(SignatureError::SkidMismatch { .. })
        ));
    }

    /// 50 §3.2: a key proven out of band (`JOIN_PROOF`) installs without a
    /// sequence number, and the same binding checks still apply.
    #[test]
    fn u_identity_trust_installs_an_unsequenced_key() {
        let identity = rfc_identity();
        let announce = announce(&identity);
        let mut directory = KeyDirectory::new(cluster());

        assert_eq!(directory.trust(&announce), Ok(KeyUpdate::Inserted));
        let entry = directory.get(identity.client_id()).expect("entry");
        assert_eq!(entry.first_seq, Seq::UNSEQUENCED);
        assert_eq!(entry.public, identity.public_key());
        assert_eq!(entry.skid, skid(&identity.public_key()));

        // Repeated proofs are idempotent, and a real announcement at any
        // sequence still applies in order.
        assert_eq!(directory.trust(&announce), Ok(KeyUpdate::Idempotent));
        assert_eq!(
            directory.apply(&announce, Seq::FIRST),
            Ok(KeyUpdate::Idempotent)
        );

        // Self-certification and the key-entry self-signature are enforced.
        let mut wrong_client = announce;
        wrong_client.client = ClientId::from_bytes([0x77; 16]);
        assert!(matches!(
            directory.trust(&wrong_client),
            Err(KeyError::SelfCertificationMismatch { .. })
        ));

        let mut bad_signature = announce;
        bad_signature.self_sig = Signature::from_bytes([0u8; SIGNATURE_LEN]);
        assert_eq!(
            directory.trust(&bad_signature),
            Err(KeyError::InvalidSelfSignature)
        );
    }

    /// 50 §4.4: AUTH block layout is 75 B, 107 B with the inline key.
    #[test]
    fn u_identity_auth_block_layout() {
        let identity = rfc_identity();
        let public = identity.public_key();
        let signature = identity.sign_bytes(b"auth");
        let block = AuthBlock::new(skid(&public), signature);
        let bytes = block.encode();
        assert_eq!(bytes.len(), AUTH_BLOCK_LEN);
        assert_eq!(bytes[0], AUTH_VER);
        assert_eq!(bytes[1], AUTH_ALG_ED25519);
        assert_eq!(bytes[2], 0);
        assert_eq!(&bytes[3..11], &skid(&public));
        assert_eq!(&bytes[11..75], signature.as_bytes());
        assert_eq!(AuthBlock::decode(&bytes), Ok((block, AUTH_BLOCK_LEN)));

        let inline = AuthBlock::with_inline_public(skid(&public), signature, public);
        let bytes = inline.encode();
        assert_eq!(bytes.len(), AUTH_INLINE_LEN);
        assert_eq!(bytes[2], AUTH_FLAG_INLINE_PUBKEY);
        assert_eq!(&bytes[75..107], public.as_bytes());
        assert_eq!(AuthBlock::decode(&bytes), Ok((inline, AUTH_INLINE_LEN)));

        let (decoded, consumed) = AuthBlock::decode(&bytes).unwrap();
        assert_eq!(consumed, AUTH_INLINE_LEN);
        assert_eq!(decoded, inline);
    }

    /// 50 §4.4: unknown versions, algorithms and reserved flags fail closed.
    #[test]
    fn u_identity_auth_block_rejects_malformed() {
        let identity = rfc_identity();
        let public = identity.public_key();
        let signature = identity.sign_bytes(b"auth");
        let bytes = AuthBlock::new(skid(&public), signature).encode();

        assert_eq!(
            AuthBlock::decode(&bytes[..AUTH_BLOCK_LEN - 1]),
            Err(AuthBlockError::TooShort {
                need: AUTH_BLOCK_LEN,
                got: AUTH_BLOCK_LEN - 1,
            })
        );

        let mut bad = bytes.clone();
        bad[0] = 2;
        assert_eq!(AuthBlock::decode(&bad), Err(AuthBlockError::BadVersion(2)));

        let mut bad = bytes.clone();
        bad[1] = 2;
        assert_eq!(
            AuthBlock::decode(&bad),
            Err(AuthBlockError::BadAlgorithm(2))
        );

        let mut bad = bytes.clone();
        bad[2] = AUTH_FLAG_CHAIN;
        assert_eq!(
            AuthBlock::decode(&bad),
            Err(AuthBlockError::ReservedFlags(AUTH_FLAG_CHAIN))
        );

        let mut bad = bytes;
        bad[2] = 0x80;
        assert_eq!(
            AuthBlock::decode(&bad),
            Err(AuthBlockError::ReservedFlags(0x80))
        );

        let inline = AuthBlock::with_inline_public(skid(&public), signature, public).encode();
        let mut bad = inline;
        let invalid = [
            0x7f, 0xc1, 0xe3, 0xde, 0xc2, 0x95, 0xe0, 0xa1, 0xa2, 0x85, 0x59, 0x75, 0xa7, 0xe2,
            0x07, 0x1b, 0xc9, 0x5c, 0xb9, 0xe0, 0x66, 0x2c, 0x84, 0x4c, 0xa4, 0x87, 0x01, 0x1a,
            0xd4, 0x09, 0x7e, 0x1c,
        ];
        bad[AUTH_BLOCK_LEN..].copy_from_slice(&invalid);
        assert_eq!(
            AuthBlock::decode(&bad),
            Err(AuthBlockError::MalformedPublicKey)
        );
    }

    /// 50 §10: plain server control frames carry no AUTH block; a forged op
    /// under another client's id cannot verify.
    #[test]
    fn u_identity_control_frames_are_not_authenticated() {
        let kick = crate::protocol::messages::Kick {
            reason: crate::protocol::KickReason::AuthFail,
        };
        let body = kick.encode().unwrap();
        assert!(
            AuthBlock::decode(&body).is_err(),
            "a plain KICK body must not parse as an AUTH block"
        );

        let identity = rfc_identity();
        let attacker = MemoryIdentity::from_seed(cluster(), epoch(), [0x99; 32]);
        let signature = attacker.sign_op(
            op_id(),
            OpClass::WRITE,
            MsgType::ORDERED,
            Flags::ENC,
            &payload(),
        );

        // Attacker signs with its own key but claims the victim's id.
        let mut forged = op(&attacker, &signature);
        forged.client = identity.client_id();
        let mut directory = KeyDirectory::new(cluster());
        directory.apply(&announce(&identity), Seq(5)).unwrap();
        assert_eq!(directory.verify_op(&forged), Err(SignatureError::Invalid));

        // Inline attacker key under the victim's id is rejected before verify.
        let inline = AuthBlock::with_inline_public(
            skid(&attacker.public_key()),
            signature,
            attacker.public_key(),
        );
        assert_eq!(
            directory.resolve_auth(&inline, identity.client_id()),
            Err(SignatureError::ClientIdMismatch {
                claimed: identity.client_id(),
                derived: attacker.client_id(),
            })
        );
    }

    /// 44 §4.7 / 50 §5.2: unknown-key frames are bounded and later replayed.
    #[test]
    fn u_identity_unknown_key_buffer() {
        let identity = rfc_identity();
        let announce = announce(&identity);
        let client = announce.client;

        let mut buffer = UnknownKeyBuffer::new(2);
        assert!(buffer.is_empty());
        buffer.push(client, announce.epoch, 1u8).unwrap();
        buffer.push(client, announce.epoch, 2u8).unwrap();
        assert_eq!(
            buffer.push(client, announce.epoch, 3u8),
            Err(UnknownKeyError::Full { capacity: 2 })
        );
        assert_eq!(buffer.len(), 2);

        let directory = KeyDirectory::new(cluster());
        assert!(buffer.take_ready(&directory).is_empty());
        assert_eq!(buffer.len(), 2);

        let mut directory = KeyDirectory::new(cluster());
        directory.apply(&announce, Seq(5)).unwrap();
        assert_eq!(buffer.take_ready(&directory), vec![1, 2]);
        assert!(buffer.is_empty());

        buffer.push(client, KeyEpoch(8), 4u8).unwrap();
        assert!(buffer.take_ready(&directory).is_empty());
        assert_eq!(buffer.drain_all(), vec![4]);
    }

    /// 44 §4.6 / INV-24: the payload hash has its own domain separator.
    #[test]
    fn u_identity_payload_hash_is_domain_separated() {
        let body = b"\x01\x00\x01\x00\x00";
        assert_eq!(payload_hash(body), payload_hash(body));
        assert_ne!(payload_hash(body), payload_hash(b""));
        let mut plain = Hasher::new();
        plain.update(body);
        assert_ne!(payload_hash(body), *plain.finalize().as_bytes());
    }

    /// 50 D2: a member cannot derive another member's id from a stolen key.
    #[test]
    fn u_identity_signing_is_bound_to_its_key() {
        let a = rfc_identity();
        let b = MemoryIdentity::from_seed(cluster(), epoch(), [0xab; 32]);
        assert_ne!(a.client_id(), b.client_id());

        let signature = b.sign_op(
            op_id(),
            OpClass::WRITE,
            MsgType::ORDERED,
            Flags::ENC,
            &payload(),
        );
        let mut forged = op(&b, &signature);
        forged.client = a.client_id();
        assert_eq!(
            verify_with_key(&a.public_key(), &forged),
            Err(SignatureError::Invalid)
        );
    }
}
