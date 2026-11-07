//! JOIN_PROOF sealing and opening (33, 44 D5, 50 §3.2).
//!
//! The proof is carried inside `RELAY{CTRL, JOIN_PROOF}`; the server forwards
//! it without reading it. Both nonces are bound twice: they derive the key,
//! and they are repeated in the authenticated plaintext.
//!
//! ```text
//! join_key   = HKDF-SHA256(salt = cluster_id,
//!                          ikm  = master_key,
//!                          info = "sm/v1/join"  ‖ client_nonce ‖ server_nonce)
//! join_nonce = HKDF-SHA256(salt = cluster_id,
//!                          ikm  = master_key,
//!                          info = "sm/v1/jnonce" ‖ client_nonce ‖ server_nonce)[..12]
//! aad        = "sm/v1/proof"
//! ```
//!
//! Plaintext (196 bytes):
//!
//! ```text
//! offset size field
//! 0      32   client_nonce
//! 32     32   server_nonce
//! 64     8    cluster epoch (u64 LE)
//! 72     2    protocol major (u16 LE)
//! 74     2    protocol minor (u16 LE)
//! 76     16   client_id
//! 92     32   public_key
//! 124    8    skid
//! 132    64   self_sig = Ed25519("sm/v1/keyproof\0" ‖ cluster_id ‖
//!                                client_id ‖ pk ‖ cn ‖ sn ‖ epoch)
//! ```
//!
//! Opening verifies the self-certifying `client_id`, `skid`, and the
//! self-signature. A caller can therefore treat the returned public key as
//! bound to the joining client.

use std::fmt;

#[cfg(feature = "reduced-round")]
use chacha20poly1305::ChaCha8Poly1305;
#[cfg(not(feature = "reduced-round"))]
use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::secret::MasterKey;
use crate::crypto::sign::{SigningKey, client_id_for, keyproof_input, skid_for, verify_strict};
use crate::protocol::crypto::ClusterId;
use crate::protocol::frame::ClientId;
use crate::protocol::version::ProtoVersion;

#[cfg(feature = "reduced-round")]
type ProofCipher = ChaCha8Poly1305;
#[cfg(not(feature = "reduced-round"))]
type ProofCipher = ChaCha20Poly1305;

/// HKDF info prefix for the proof key (49 A13).
pub const JOIN_INFO: &[u8] = b"sm/v1/join";

/// HKDF info prefix for the proof nonce (49 A13).
pub const JOIN_NONCE_INFO: &[u8] = b"sm/v1/jnonce";

/// AAD domain for the proof ciphertext (49 A13).
pub const PROOF_AAD: &[u8] = b"sm/v1/proof";

/// Width of each handshake nonce.
pub const NONCE_LEN: usize = 32;

/// Width of the derived AEAD nonce.
pub const JOIN_NONCE_LEN: usize = 12;

/// Plaintext width.
pub const PROOF_PLAINTEXT_LEN: usize = 196;

/// Sealed width: plaintext plus a Poly1305 tag.
pub const PROOF_SEALED_LEN: usize = PROOF_PLAINTEXT_LEN + 16;

/// A JOIN_PROOF with a verified signer binding.
#[derive(Clone, PartialEq, Eq)]
pub struct Proof {
    cluster: ClusterId,
    client_nonce: [u8; NONCE_LEN],
    server_nonce: [u8; NONCE_LEN],
    epoch: u64,
    proto_major: u16,
    proto_minor: u16,
    client_id: ClientId,
    public_key: [u8; 32],
    skid: [u8; 8],
    self_sig: [u8; 64],
}

impl Proof {
    /// Build and self-sign a proof.
    ///
    /// `epoch` is the server's cluster epoch (`F_EPOCH`, `u64`), not the
    /// per-client key epoch (`KeyEpoch`, `u32`).
    pub fn new(
        signer: &SigningKey,
        client_nonce: [u8; NONCE_LEN],
        server_nonce: [u8; NONCE_LEN],
        epoch: u64,
        proto: ProtoVersion,
    ) -> Self {
        let client_id = signer.client_id();
        let public_key = signer.public_key();
        let skid = signer.skid();
        let self_sig = signer.sign(&keyproof_input(
            &signer.cluster(),
            client_id,
            &public_key,
            &client_nonce,
            &server_nonce,
            epoch,
        ));
        Self {
            cluster: signer.cluster(),
            client_nonce,
            server_nonce,
            epoch,
            proto_major: proto.major,
            proto_minor: proto.minor,
            client_id,
            public_key,
            skid,
            self_sig,
        }
    }

    /// Encrypt the proof for `cluster`.
    ///
    /// The local fields are re-verified first, so a proof whose `client_id`,
    /// `skid`, or signature was altered cannot be sealed.
    ///
    /// # Errors
    ///
    /// [`ProofError::WrongCluster`] if the proof belongs to another cluster,
    /// [`ProofError::ClientIdMismatch`], [`ProofError::SkidMismatch`], or
    /// [`ProofError::BadSignature`] if the binding is broken, and
    /// [`ProofError::Kdf`] or [`ProofError::Aead`] if the cipher fails.
    pub fn seal(&self, master: &MasterKey, cluster: &ClusterId) -> Result<Vec<u8>, ProofError> {
        self.verify(cluster)?;
        let (mut key, nonce) =
            derive_join_keys(master, cluster, &self.client_nonce, &self.server_nonce)?;
        let cipher = ProofCipher::new_from_slice(&key).map_err(|_| ProofError::Kdf);
        key.zeroize();
        let cipher = cipher?;
        let plaintext = self.encode();
        cipher
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: &plaintext[..],
                    aad: PROOF_AAD,
                },
            )
            .map_err(|_| ProofError::Aead)
    }

    /// Decrypt and verify a proof.
    ///
    /// The verifier must know the handshake nonces: `client_nonce` from
    /// `HELLO`, `server_nonce` from `WELCOME(PENDING)`. They are also the
    /// key-derivation inputs, so a wrong nonce fails authentication.
    ///
    /// # Errors
    ///
    /// [`ProofError::Length`] for a wrong sealed width,
    /// [`ProofError::Aead`] for a wrong key or tampered bytes, and
    /// [`ProofError::NonceMismatch`], [`ProofError::ClientIdMismatch`],
    /// [`ProofError::SkidMismatch`], or [`ProofError::BadSignature`] if the
    /// authenticated contents are not a valid binding.
    pub fn open(
        master: &MasterKey,
        cluster: &ClusterId,
        client_nonce: &[u8; NONCE_LEN],
        server_nonce: &[u8; NONCE_LEN],
        sealed: &[u8],
    ) -> Result<Self, ProofError> {
        if sealed.len() != PROOF_SEALED_LEN {
            return Err(ProofError::Length(sealed.len()));
        }
        let (mut key, nonce) = derive_join_keys(master, cluster, client_nonce, server_nonce)?;
        let cipher = ProofCipher::new_from_slice(&key).map_err(|_| ProofError::Kdf);
        key.zeroize();
        let cipher = cipher?;
        let plaintext = cipher
            .decrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: sealed,
                    aad: PROOF_AAD,
                },
            )
            .map_err(|_| ProofError::Aead)?;
        let plaintext = Zeroizing::new(plaintext);
        if plaintext.len() != PROOF_PLAINTEXT_LEN {
            return Err(ProofError::Length(plaintext.len()));
        }

        let proof = Self::decode(cluster, &plaintext);
        if proof.client_nonce != *client_nonce || proof.server_nonce != *server_nonce {
            return Err(ProofError::NonceMismatch);
        }
        proof.verify(cluster)?;
        Ok(proof)
    }

    /// The server's cluster epoch (`u64`).
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The protocol version echoed in the proof.
    pub const fn proto(&self) -> ProtoVersion {
        ProtoVersion {
            major: self.proto_major,
            minor: self.proto_minor,
        }
    }

    /// The client nonce from `HELLO`.
    pub const fn client_nonce(&self) -> &[u8; NONCE_LEN] {
        &self.client_nonce
    }

    /// The server nonce from `WELCOME(PENDING)`.
    pub const fn server_nonce(&self) -> &[u8; NONCE_LEN] {
        &self.server_nonce
    }

    /// The self-certifying client id.
    pub const fn client_id(&self) -> ClientId {
        self.client_id
    }

    /// The bound Ed25519 public key.
    pub const fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    /// The cache index of [`Proof::public_key`].
    pub const fn skid(&self) -> &[u8; 8] {
        &self.skid
    }

    /// The self-signature over the key binding.
    pub const fn self_sig(&self) -> &[u8; 64] {
        &self.self_sig
    }

    fn encode(&self) -> Zeroizing<[u8; PROOF_PLAINTEXT_LEN]> {
        let mut out = Zeroizing::new([0u8; PROOF_PLAINTEXT_LEN]);
        let bytes = out.as_mut();
        let mut at = 0;
        bytes[at..at + NONCE_LEN].copy_from_slice(&self.client_nonce);
        at += NONCE_LEN;
        bytes[at..at + NONCE_LEN].copy_from_slice(&self.server_nonce);
        at += NONCE_LEN;
        bytes[at..at + 8].copy_from_slice(&self.epoch.to_le_bytes());
        at += 8;
        bytes[at..at + 2].copy_from_slice(&self.proto_major.to_le_bytes());
        at += 2;
        bytes[at..at + 2].copy_from_slice(&self.proto_minor.to_le_bytes());
        at += 2;
        bytes[at..at + ClientId::LEN].copy_from_slice(self.client_id.as_bytes());
        at += ClientId::LEN;
        bytes[at..at + 32].copy_from_slice(&self.public_key);
        at += 32;
        bytes[at..at + 8].copy_from_slice(&self.skid);
        at += 8;
        bytes[at..at + 64].copy_from_slice(&self.self_sig);
        out
    }

    fn decode(cluster: &ClusterId, bytes: &[u8]) -> Self {
        let mut client_nonce = [0u8; NONCE_LEN];
        let mut server_nonce = [0u8; NONCE_LEN];
        let mut proto_major = [0u8; 2];
        let mut proto_minor = [0u8; 2];
        let mut client_id = [0u8; ClientId::LEN];
        let mut public_key = [0u8; 32];
        let mut skid = [0u8; 8];
        let mut self_sig = [0u8; 64];

        let mut at = 0;
        client_nonce.copy_from_slice(&bytes[at..at + NONCE_LEN]);
        at += NONCE_LEN;
        server_nonce.copy_from_slice(&bytes[at..at + NONCE_LEN]);
        at += NONCE_LEN;
        let mut epoch_bytes = [0u8; 8];
        epoch_bytes.copy_from_slice(&bytes[at..at + 8]);
        let epoch = u64::from_le_bytes(epoch_bytes);
        at += 8;
        proto_major.copy_from_slice(&bytes[at..at + 2]);
        at += 2;
        proto_minor.copy_from_slice(&bytes[at..at + 2]);
        at += 2;
        client_id.copy_from_slice(&bytes[at..at + ClientId::LEN]);
        at += ClientId::LEN;
        public_key.copy_from_slice(&bytes[at..at + 32]);
        at += 32;
        skid.copy_from_slice(&bytes[at..at + 8]);
        at += 8;
        self_sig.copy_from_slice(&bytes[at..at + 64]);

        Self {
            cluster: *cluster,
            client_nonce,
            server_nonce,
            epoch,
            proto_major: u16::from_le_bytes(proto_major),
            proto_minor: u16::from_le_bytes(proto_minor),
            client_id: ClientId::from_bytes(client_id),
            public_key,
            skid,
            self_sig,
        }
    }

    fn verify(&self, cluster: &ClusterId) -> Result<(), ProofError> {
        if self.cluster != *cluster {
            return Err(ProofError::WrongCluster);
        }
        if self.client_id != client_id_for(cluster, &self.public_key) {
            return Err(ProofError::ClientIdMismatch);
        }
        if self.skid != skid_for(&self.public_key) {
            return Err(ProofError::SkidMismatch);
        }
        let message = keyproof_input(
            cluster,
            self.client_id,
            &self.public_key,
            &self.client_nonce,
            &self.server_nonce,
            self.epoch,
        );
        verify_strict(&self.public_key, &message, &self.self_sig)
            .map_err(|_| ProofError::BadSignature)
    }
}

impl fmt::Debug for Proof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Proof")
            .field("cluster", &self.cluster)
            .field("client_id", &self.client_id)
            .field("epoch", &self.epoch)
            .field("proto", &self.proto())
            .finish_non_exhaustive()
    }
}

/// A JOIN_PROOF failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ProofError {
    /// The sealed or plaintext width is wrong.
    #[error("join proof has wrong length {0}")]
    Length(usize),
    /// AEAD authentication failed: wrong password, wrong cluster, wrong
    /// nonce, or tampered bytes.
    #[error("join proof authentication failed")]
    Aead,
    /// HKDF could not derive the proof key.
    #[error("join proof key derivation failed")]
    Kdf,
    /// The authenticated nonces differ from the handshake nonces.
    #[error("join proof nonces do not match the handshake")]
    NonceMismatch,
    /// The proof was sealed for another cluster.
    #[error("join proof belongs to another cluster")]
    WrongCluster,
    /// `client_id` does not hash the bound public key.
    #[error("join proof client_id does not match its public key")]
    ClientIdMismatch,
    /// `skid` does not hash the bound public key.
    #[error("join proof skid does not match its public key")]
    SkidMismatch,
    /// The keyproof self-signature did not verify.
    #[error("join proof self-signature is invalid")]
    BadSignature,
}

fn derive_join_keys(
    master: &MasterKey,
    cluster: &ClusterId,
    client_nonce: &[u8; NONCE_LEN],
    server_nonce: &[u8; NONCE_LEN],
) -> Result<([u8; 32], [u8; JOIN_NONCE_LEN]), ProofError> {
    let hk = Hkdf::<Sha256>::new(Some(cluster.as_bytes()), master.as_bytes());

    let mut info = Zeroizing::new(Vec::with_capacity(JOIN_INFO.len() + 64));
    info.extend_from_slice(JOIN_INFO);
    info.extend_from_slice(client_nonce);
    info.extend_from_slice(server_nonce);
    let mut key = [0u8; 32];
    hk.expand(info.as_slice(), &mut key)
        .map_err(|_| ProofError::Kdf)?;

    let mut nonce_info = Zeroizing::new(Vec::with_capacity(JOIN_NONCE_INFO.len() + 64));
    nonce_info.extend_from_slice(JOIN_NONCE_INFO);
    nonce_info.extend_from_slice(client_nonce);
    nonce_info.extend_from_slice(server_nonce);
    let mut nonce = [0u8; JOIN_NONCE_LEN];
    if hk.expand(nonce_info.as_slice(), &mut nonce).is_err() {
        key.zeroize();
        return Err(ProofError::Kdf);
    }
    Ok((key, nonce))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::sync::LazyLock;

    use super::*;
    use crate::crypto::sign::SigningKey;

    fn cluster(byte: u8) -> ClusterId {
        ClusterId::from_bytes([byte; 16])
    }

    static MASTER: LazyLock<MasterKey> = LazyLock::new(|| {
        MasterKey::derive_from_password(b"correct horse battery staple", &cluster(0x11)).unwrap()
    });

    fn master() -> &'static MasterKey {
        &MASTER
    }

    fn signer() -> SigningKey {
        SigningKey::from_seed(&cluster(0x11), [9; 32])
    }

    fn client_nonce() -> [u8; NONCE_LEN] {
        [0x11; NONCE_LEN]
    }

    fn server_nonce() -> [u8; NONCE_LEN] {
        [0x22; NONCE_LEN]
    }

    fn proof() -> Proof {
        Proof::new(
            &signer(),
            client_nonce(),
            server_nonce(),
            7,
            ProtoVersion::V1_0,
        )
    }

    #[test]
    fn roundtrip() {
        let sealed = proof().seal(master(), &cluster(0x11)).unwrap();
        assert_eq!(sealed.len(), PROOF_SEALED_LEN);

        let opened = Proof::open(
            master(),
            &cluster(0x11),
            &client_nonce(),
            &server_nonce(),
            &sealed,
        )
        .unwrap();
        assert_eq!(opened.client_id(), signer().client_id());
        assert_eq!(opened.public_key(), &signer().public_key());
        assert_eq!(opened.skid(), &signer().skid());
        assert_eq!(opened.epoch(), 7);
        assert_eq!(opened.proto(), ProtoVersion::V1_0);
        assert_eq!(opened.client_nonce(), &client_nonce());
        assert_eq!(opened.server_nonce(), &server_nonce());
    }

    #[test]
    fn sealing_is_deterministic_for_the_same_handshake() {
        let first = proof().seal(master(), &cluster(0x11)).unwrap();
        let second = proof().seal(master(), &cluster(0x11)).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn wrong_password_fails_authentication() {
        let sealed = proof().seal(master(), &cluster(0x11)).unwrap();
        let wrong = MasterKey::derive_from_password(b"wrong password", &cluster(0x11)).unwrap();
        let error = Proof::open(
            &wrong,
            &cluster(0x11),
            &client_nonce(),
            &server_nonce(),
            &sealed,
        )
        .unwrap_err();
        assert!(matches!(error, ProofError::Aead));
    }

    #[test]
    fn wrong_cluster_fails_authentication() {
        let sealed = proof().seal(master(), &cluster(0x11)).unwrap();
        let error = Proof::open(
            master(),
            &cluster(0x22),
            &client_nonce(),
            &server_nonce(),
            &sealed,
        )
        .unwrap_err();
        assert!(matches!(error, ProofError::Aead));
    }

    #[test]
    fn tampering_fails_authentication() {
        let mut sealed = proof().seal(master(), &cluster(0x11)).unwrap();
        sealed[0] ^= 1;
        let error = Proof::open(
            master(),
            &cluster(0x11),
            &client_nonce(),
            &server_nonce(),
            &sealed,
        )
        .unwrap_err();
        assert!(matches!(error, ProofError::Aead));
    }

    #[test]
    fn nonce_binding_is_enforced() {
        let sealed = proof().seal(master(), &cluster(0x11)).unwrap();
        let error = Proof::open(
            master(),
            &cluster(0x11),
            &[0x33; NONCE_LEN],
            &server_nonce(),
            &sealed,
        )
        .unwrap_err();
        assert!(matches!(error, ProofError::Aead));
    }

    #[test]
    fn public_key_is_bound_to_client_id() {
        let mut bad = proof();
        bad.public_key[0] ^= 1;
        let error = bad.seal(master(), &cluster(0x11)).unwrap_err();
        assert!(matches!(error, ProofError::ClientIdMismatch));
    }

    #[test]
    fn self_signature_is_verified() {
        let mut bad = proof();
        bad.self_sig[0] ^= 1;
        let error = bad.seal(master(), &cluster(0x11)).unwrap_err();
        assert!(matches!(error, ProofError::BadSignature));
    }

    #[test]
    fn foreign_cluster_proof_is_rejected() {
        let error = proof().seal(master(), &cluster(0x22)).unwrap_err();
        assert!(matches!(error, ProofError::WrongCluster));
    }
}
