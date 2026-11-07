//! Per-client Ed25519 identity and its `0600` key file.
//!
//! The seed is generated locally and never derived from the cluster PSK: a
//! shared PSK must not let one member compute another member's private key
//! (50 §2.5). The key file is bound to one cluster, and a load for another
//! cluster is rejected.
//!
//! # File layout (50 §2.3)
//!
//! ```text
//! offset size field
//! 0      8    magic = "SMEDKEY1"
//! 8      1    version = 1
//! 9      1    alg = 1 (Ed25519)
//! 10     16   cluster_id
//! 26     32   public_key
//! 58     32   seed
//! 90     32   checksum = BLAKE3(bytes[0..90])
//! ```
//!
//! The file is opened with `O_NOFOLLOW`, must be owned by the current user,
//! and must not grant any group or other permission. Creation writes a
//! temporary file in the same directory, fsyncs it, and links it into place
//! with `hard_link`, which fails instead of replacing an existing key.

use std::env;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use ed25519_dalek::Signer;
use ed25519_dalek::SigningKey as DalekSigningKey;
use rand::TryRng;
use thiserror::Error;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::protocol::crypto::ClusterId;
use crate::protocol::frame::ClientId;
use crate::protocol::identity::{
    Identity, KeyEpoch, PublicKey, Signature, SignatureError, client_id, key_entry_msg, skid,
};

/// Magic at the start of every key file.
pub const KEY_FILE_MAGIC: [u8; 8] = *b"SMEDKEY1";

/// Key-file format version.
pub const KEY_FILE_VERSION: u8 = 1;

/// Key-file algorithm id for Ed25519.
pub const KEY_FILE_ALG_ED25519: u8 = 1;

/// Seed width.
pub const SEED_LEN: usize = 32;

/// Public-key width.
pub const PUBLIC_KEY_LEN: usize = 32;

/// Signature width.
pub const SIGNATURE_LEN: usize = 64;

/// Total key-file width.
pub const KEY_FILE_LEN: usize = 122;

/// Domain separator for the JOIN_PROOF self-signature (50 §3.2).
///
/// `client_id`, `skid` and `KeyEntry` domains live in `protocol::identity`;
/// this one belongs to the proof, which is owned here.
pub const KEYPROOF_DOMAIN: &[u8] = b"sm/v1/keyproof\0";

/// Length of [`keyproof_input`].
///
/// `15 + 16 + 16 + 32 + 32 + 32 + 8`.
pub const KEYPROOF_INPUT_LEN: usize = 151;

/// A local key-file or signature failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SignError {
    /// A filesystem operation failed.
    #[error("key file {path} is not accessible: {source}")]
    Io {
        /// Path being accessed.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: io::Error,
    },
    /// The key path is a symbolic link.
    #[error("key file {0} is a symbolic link")]
    Symlink(PathBuf),
    /// The key path is not a regular file.
    #[error("key path {0} is not a regular file")]
    NotAFile(PathBuf),
    /// The path has no parent directory.
    #[error("key path {0} has no parent directory")]
    NoParent(PathBuf),
    /// A file or directory grants group or other access.
    #[error("path {path} has insecure permissions {mode:o}")]
    InsecurePermissions {
        /// Offending path.
        path: PathBuf,
        /// Permission bits.
        mode: u32,
    },
    /// The file belongs to another user.
    #[error("key file {0} is not owned by the current user")]
    WrongOwner(PathBuf),
    /// The file length is not [`KEY_FILE_LEN`].
    #[error("key file {path} has length {len}")]
    BadLength {
        /// Offending path.
        path: PathBuf,
        /// Observed length.
        len: usize,
    },
    /// The magic, version, or algorithm byte is wrong.
    #[error("key file {0} has a bad header")]
    BadHeader(PathBuf),
    /// The file belongs to another cluster.
    #[error("key file {0} belongs to another cluster")]
    WrongCluster(PathBuf),
    /// The checksum does not match the first 90 bytes.
    #[error("key file {0} does not match its checksum")]
    BadChecksum(PathBuf),
    /// The stored public key does not match the stored seed.
    #[error("key file {0} has a seed/public-key mismatch")]
    KeyMismatch(PathBuf),
    /// An existing key could not be loaded, and was not overwritten.
    #[error("key file {path} exists but is invalid")]
    ExistingInvalid {
        /// Existing path.
        path: PathBuf,
        /// Why the existing file was rejected.
        #[source]
        source: Box<SignError>,
    },
    /// Neither `XDG_STATE_HOME` nor `HOME` is usable.
    #[error("cannot determine the state directory; set XDG_STATE_HOME or HOME")]
    NoStateDir,
    /// The operating system did not provide entropy.
    #[error("the operating system did not provide entropy")]
    Entropy,
    /// A public key is not a canonical Ed25519 point.
    #[error("public key is invalid")]
    BadPublicKey,
    /// A signature did not verify.
    #[error("signature is invalid")]
    BadSignature,
}

/// A persisted Ed25519 identity.
///
/// The seed is held in [`Zeroizing`] and the underlying `ed25519-dalek` key
/// zeroizes its copy on drop. `Debug` prints only public fields.
pub struct SigningKey {
    seed: Zeroizing<[u8; SEED_LEN]>,
    inner: DalekSigningKey,
    cluster: ClusterId,
    epoch: KeyEpoch,
    public_key: [u8; PUBLIC_KEY_LEN],
    client_id: ClientId,
    skid: [u8; 8],
}

impl SigningKey {
    /// Load the default key for `cluster`, creating it when absent.
    ///
    /// The path is
    /// `$XDG_STATE_HOME/syncmount/keys/<cluster_hex>/ed25519.key`, with
    /// `$HOME/.local/state` as the fallback base (50 §2.3).
    ///
    /// # Errors
    ///
    /// [`SignError`] if the path cannot be resolved, created, or read.
    pub fn load_or_create(cluster: &ClusterId) -> Result<Self, SignError> {
        let path = default_key_path(cluster)?;
        Self::load_or_create_at(&path, cluster)
    }

    /// Load `path`, creating it when absent. An existing key is never
    /// replaced.
    ///
    /// # Errors
    ///
    /// [`SignError`] if an existing file is invalid, or a new one cannot be
    /// written.
    pub fn load_or_create_at(path: &Path, cluster: &ClusterId) -> Result<Self, SignError> {
        match fs::symlink_metadata(path) {
            Ok(_) => Self::load_at(path, cluster),
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                Self::create_at(path, cluster)
            }
            Err(source) => Err(io_error(path, source)),
        }
    }

    /// Load an existing key file.
    ///
    /// # Errors
    ///
    /// [`SignError`] if the file is missing, a symlink, owned by another
    /// user, accessible to group or other, malformed, or for another cluster.
    pub fn load_at(path: &Path, cluster: &ClusterId) -> Result<Self, SignError> {
        check_private_directory(path)?;
        let metadata = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
        if metadata.file_type().is_symlink() {
            return Err(SignError::Symlink(path.to_path_buf()));
        }
        if !metadata.file_type().is_file() {
            return Err(SignError::NotAFile(path.to_path_buf()));
        }
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(SignError::InsecurePermissions {
                path: path.to_path_buf(),
                mode,
            });
        }
        if metadata.uid() != rustix::process::geteuid().as_raw() {
            return Err(SignError::WrongOwner(path.to_path_buf()));
        }

        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|source| io_error(path, source))?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(KEY_FILE_LEN));
        file.read_to_end(&mut bytes)
            .map_err(|source| io_error(path, source))?;
        if bytes.len() != KEY_FILE_LEN {
            return Err(SignError::BadLength {
                path: path.to_path_buf(),
                len: bytes.len(),
            });
        }
        Self::parse_file(path, cluster, &bytes)
    }

    /// The cluster this key belongs to.
    pub const fn cluster(&self) -> ClusterId {
        self.cluster
    }

    /// The self-certifying client id.
    pub const fn client_id(&self) -> ClientId {
        self.client_id
    }

    /// The raw Ed25519 public key.
    pub const fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.public_key
    }

    /// The cache index derived from the public key.
    pub const fn skid(&self) -> [u8; 8] {
        self.skid
    }

    /// The key epoch. A freshly installed client starts at
    /// [`KeyEpoch::INITIAL`]; v1 does not rotate a key under one id.
    pub const fn key_epoch(&self) -> KeyEpoch {
        self.epoch
    }

    /// Return this key with another epoch. Tests and future rotation only.
    pub const fn with_key_epoch(mut self, epoch: KeyEpoch) -> Self {
        self.epoch = epoch;
        self
    }

    /// Sign `message` with Ed25519.
    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.inner.sign(message).to_bytes()
    }

    /// Build from an explicit seed. Tests and in-memory identities only.
    pub(crate) fn from_seed(cluster: &ClusterId, seed: [u8; SEED_LEN]) -> Self {
        Self::from_seed_with_epoch(cluster, KeyEpoch::INITIAL, seed)
    }

    /// Build from an explicit seed and epoch. Tests only.
    pub(crate) fn from_seed_with_epoch(
        cluster: &ClusterId,
        epoch: KeyEpoch,
        seed: [u8; SEED_LEN],
    ) -> Self {
        let inner = DalekSigningKey::from_bytes(&seed);
        let public_key = inner.verifying_key().to_bytes();
        Self::from_parts(cluster, epoch, seed, inner, public_key)
    }

    fn from_parts(
        cluster: &ClusterId,
        epoch: KeyEpoch,
        seed: [u8; SEED_LEN],
        inner: DalekSigningKey,
        public_key: [u8; PUBLIC_KEY_LEN],
    ) -> Self {
        let client_id = client_id_for(cluster, &public_key);
        let skid = skid_for(&public_key);
        Self {
            seed: Zeroizing::new(seed),
            inner,
            cluster: *cluster,
            epoch,
            public_key,
            client_id,
            skid,
        }
    }

    fn parse_file(path: &Path, cluster: &ClusterId, bytes: &[u8]) -> Result<Self, SignError> {
        if bytes[..KEY_FILE_MAGIC.len()] != KEY_FILE_MAGIC {
            return Err(SignError::BadHeader(path.to_path_buf()));
        }
        if bytes[8] != KEY_FILE_VERSION || bytes[9] != KEY_FILE_ALG_ED25519 {
            return Err(SignError::BadHeader(path.to_path_buf()));
        }
        if bytes[10..26] != *cluster.as_bytes() {
            return Err(SignError::WrongCluster(path.to_path_buf()));
        }
        let mut public_key = [0u8; PUBLIC_KEY_LEN];
        public_key.copy_from_slice(&bytes[26..58]);
        let mut seed = Zeroizing::new([0u8; SEED_LEN]);
        seed.copy_from_slice(&bytes[58..90]);

        let checksum = blake3::hash(&bytes[..90]);
        if checksum.as_bytes() != &bytes[90..122] {
            return Err(SignError::BadChecksum(path.to_path_buf()));
        }

        let inner = DalekSigningKey::from_bytes(&seed);
        if inner.verifying_key().to_bytes() != public_key {
            return Err(SignError::KeyMismatch(path.to_path_buf()));
        }
        Ok(Self::from_parts(
            cluster,
            KeyEpoch::INITIAL,
            *seed,
            inner,
            public_key,
        ))
    }

    fn create_at(path: &Path, cluster: &ClusterId) -> Result<Self, SignError> {
        let parent = path
            .parent()
            .ok_or_else(|| SignError::NoParent(path.to_path_buf()))?;
        fs::create_dir_all(parent).map_err(|source| io_error(parent, source))?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
            .map_err(|source| io_error(parent, source))?;

        let mut seed = Zeroizing::new([0u8; SEED_LEN]);
        rand::rngs::SysRng
            .try_fill_bytes(&mut *seed)
            .map_err(|_| SignError::Entropy)?;
        let key = Self::from_seed(cluster, *seed);

        let mut bytes = Zeroizing::new([0u8; KEY_FILE_LEN]);
        let out = bytes.as_mut();
        out[..8].copy_from_slice(&KEY_FILE_MAGIC);
        out[8] = KEY_FILE_VERSION;
        out[9] = KEY_FILE_ALG_ED25519;
        out[10..26].copy_from_slice(cluster.as_bytes());
        out[26..58].copy_from_slice(&key.public_key);
        out[58..90].copy_from_slice(&*key.seed);
        let checksum = blake3::hash(&out[..90]);
        out[90..122].copy_from_slice(checksum.as_bytes());

        let temp = parent.join(format!(
            ".ed25519.key.{}.{}.tmp",
            std::process::id(),
            next_temp_id()
        ));
        let _guard = TempGuard::new(temp.clone());
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC)
            .open(&temp)
            .map_err(|source| io_error(&temp, source))?;
        file.write_all(out)
            .map_err(|source| io_error(&temp, source))?;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|source| io_error(&temp, source))?;
        file.sync_all().map_err(|source| io_error(&temp, source))?;
        drop(file);

        match fs::hard_link(&temp, path) {
            Ok(()) => {
                sync_dir(parent)?;
            }
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
                return Self::load_at(path, cluster).map_err(|source| SignError::ExistingInvalid {
                    path: path.to_path_buf(),
                    source: Box::new(source),
                });
            }
            Err(source) => return Err(io_error(path, source)),
        }
        Self::load_at(path, cluster)
    }
}

impl Identity for SigningKey {
    fn client_id(&self) -> ClientId {
        self.client_id
    }

    fn public_key(&self) -> PublicKey {
        PublicKey::from_bytes(self.public_key)
    }

    fn key_epoch(&self) -> KeyEpoch {
        self.epoch
    }

    fn sign_bytes(&self, message: &[u8]) -> Signature {
        Signature::from_bytes(self.sign(message))
    }
}

impl ZeroizeOnDrop for SigningKey {}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey")
            .field("cluster", &self.cluster)
            .field("client_id", &self.client_id)
            .field("skid", &self.skid)
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

/// Default key path for `cluster` (50 §2.3).
///
/// # Errors
///
/// [`SignError::NoStateDir`] if neither `XDG_STATE_HOME` nor `HOME` is set.
pub fn default_key_path(cluster: &ClusterId) -> Result<PathBuf, SignError> {
    let base = match env::var_os("XDG_STATE_HOME") {
        Some(value) if Path::new(&value).is_absolute() => PathBuf::from(value),
        _ => {
            let home = env::var_os("HOME").ok_or(SignError::NoStateDir)?;
            PathBuf::from(home).join(".local").join("state")
        }
    };
    Ok(base
        .join("syncmount")
        .join("keys")
        .join(cluster.to_string())
        .join("ed25519.key"))
}

/// Derive `client_id` through the single implementation in
/// `protocol::identity`.
pub fn client_id_for(cluster: &ClusterId, public_key: &[u8; PUBLIC_KEY_LEN]) -> ClientId {
    client_id(cluster, &PublicKey::from_bytes(*public_key))
}

/// Derive `skid` through the single implementation in `protocol::identity`.
pub fn skid_for(public_key: &[u8; PUBLIC_KEY_LEN]) -> [u8; 8] {
    skid(&PublicKey::from_bytes(*public_key))
}

/// `KeyEntry` self-signature input, delegated to `protocol::identity`.
pub fn keyentry_input(
    cluster: &ClusterId,
    client_id: ClientId,
    public_key: &[u8; PUBLIC_KEY_LEN],
    epoch: KeyEpoch,
) -> Vec<u8> {
    key_entry_msg(
        cluster,
        client_id,
        &PublicKey::from_bytes(*public_key),
        epoch,
    )
}

/// The bytes a JOIN_PROOF self-signature covers (50 §3.2).
///
/// `"sm/v1/keyproof\0" ‖ cluster_id ‖ client_id ‖ pk ‖ cn ‖ sn ‖ epoch`.
pub fn keyproof_input(
    cluster: &ClusterId,
    client_id: ClientId,
    public_key: &[u8; PUBLIC_KEY_LEN],
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
    epoch: u64,
) -> [u8; KEYPROOF_INPUT_LEN] {
    let mut out = [0u8; KEYPROOF_INPUT_LEN];
    let mut at = 0;
    out[at..at + KEYPROOF_DOMAIN.len()].copy_from_slice(KEYPROOF_DOMAIN);
    at += KEYPROOF_DOMAIN.len();
    out[at..at + ClusterId::LEN].copy_from_slice(cluster.as_bytes());
    at += ClusterId::LEN;
    out[at..at + ClientId::LEN].copy_from_slice(client_id.as_bytes());
    at += ClientId::LEN;
    out[at..at + PUBLIC_KEY_LEN].copy_from_slice(public_key);
    at += PUBLIC_KEY_LEN;
    out[at..at + 32].copy_from_slice(client_nonce);
    at += 32;
    out[at..at + 32].copy_from_slice(server_nonce);
    at += 32;
    out[at..at + 8].copy_from_slice(&epoch.to_le_bytes());
    out
}

/// Verify an Ed25519 signature through `protocol::identity`.
pub fn verify_strict(
    public_key: &[u8; PUBLIC_KEY_LEN],
    message: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> Result<(), SignError> {
    match PublicKey::from_bytes(*public_key)
        .verify_strict(message, &Signature::from_bytes(*signature))
    {
        Ok(()) => Ok(()),
        Err(SignatureError::MalformedPublicKey) => Err(SignError::BadPublicKey),
        Err(_) => Err(SignError::BadSignature),
    }
}

fn check_private_directory(path: &Path) -> Result<(), SignError> {
    let parent = path
        .parent()
        .ok_or_else(|| SignError::NoParent(path.to_path_buf()))?;
    let metadata = fs::metadata(parent).map_err(|source| io_error(parent, source))?;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(SignError::InsecurePermissions {
            path: parent.to_path_buf(),
            mode,
        });
    }
    Ok(())
}

fn io_error(path: &Path, source: io::Error) -> SignError {
    SignError::Io {
        path: path.to_path_buf(),
        source,
    }
}

fn sync_dir(path: &Path) -> Result<(), SignError> {
    let dir = File::open(path).map_err(|source| io_error(path, source))?;
    dir.sync_all().map_err(|source| io_error(path, source))
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn next_temp_id() -> u64 {
    TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
}

struct TempGuard {
    path: PathBuf,
}

impl TempGuard {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl Drop for TempGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use std::os::unix::fs::symlink;
    use zeroize::Zeroize;

    fn cluster(byte: u8) -> ClusterId {
        ClusterId::from_bytes([byte; 16])
    }

    fn key_path(dir: &tempfile::TempDir) -> PathBuf {
        dir.path()
            .join("keys")
            .join(cluster(0x11).to_string())
            .join("ed25519.key")
    }

    #[test]
    fn load_or_create_sets_private_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = key_path(&dir);
        let key = SigningKey::load_or_create_at(&path, &cluster(0x11)).unwrap();

        let file_mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        let dir_mode = fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(file_mode, 0o600);
        assert_eq!(dir_mode, 0o700);
        assert_eq!(
            key.client_id(),
            client_id_for(&cluster(0x11), &key.public_key())
        );
        assert_eq!(key.skid(), skid_for(&key.public_key()));
    }

    #[test]
    fn load_or_create_never_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let path = key_path(&dir);
        let first = SigningKey::load_or_create_at(&path, &cluster(0x11)).unwrap();
        let first_bytes = fs::read(&path).unwrap();
        let second = SigningKey::load_or_create_at(&path, &cluster(0x11)).unwrap();

        assert_eq!(first.client_id(), second.client_id());
        assert_eq!(first.public_key(), second.public_key());
        assert_eq!(first_bytes, fs::read(&path).unwrap());
    }

    #[test]
    fn key_file_layout_is_stable() {
        let dir = tempfile::tempdir().unwrap();
        let path = key_path(&dir);
        let key = SigningKey::load_or_create_at(&path, &cluster(0x11)).unwrap();
        let bytes = fs::read(&path).unwrap();

        assert_eq!(bytes.len(), KEY_FILE_LEN);
        assert_eq!(&bytes[..8], &KEY_FILE_MAGIC);
        assert_eq!(bytes[8], KEY_FILE_VERSION);
        assert_eq!(bytes[9], KEY_FILE_ALG_ED25519);
        assert_eq!(&bytes[10..26], cluster(0x11).as_bytes());
        assert_eq!(&bytes[26..58], &key.public_key());
        let checksum = blake3::hash(&bytes[..90]);
        assert_eq!(&bytes[90..122], checksum.as_bytes());
    }

    #[test]
    fn world_readable_key_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = key_path(&dir);
        SigningKey::load_or_create_at(&path, &cluster(0x11)).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        let error = SigningKey::load_at(&path, &cluster(0x11)).unwrap_err();
        assert!(matches!(error, SignError::InsecurePermissions { .. }));
    }

    #[test]
    fn world_readable_directory_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = key_path(&dir);
        SigningKey::load_or_create_at(&path, &cluster(0x11)).unwrap();
        fs::set_permissions(path.parent().unwrap(), fs::Permissions::from_mode(0o755)).unwrap();

        let error = SigningKey::load_at(&path, &cluster(0x11)).unwrap_err();
        assert!(matches!(error, SignError::InsecurePermissions { .. }));
    }

    #[test]
    fn symlink_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = key_path(&dir);
        SigningKey::load_or_create_at(&path, &cluster(0x11)).unwrap();
        let link = path.parent().unwrap().join("link.key");
        symlink(&path, &link).unwrap();

        let error = SigningKey::load_at(&link, &cluster(0x11)).unwrap_err();
        assert!(matches!(error, SignError::Symlink(_)));
    }

    #[test]
    fn invalid_existing_file_is_not_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = key_path(&dir);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::set_permissions(path.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(&path, b"not a key").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        let error = SigningKey::load_or_create_at(&path, &cluster(0x11)).unwrap_err();
        assert!(matches!(error, SignError::BadLength { .. }));
        assert_eq!(fs::read(&path).unwrap(), b"not a key");
    }

    #[test]
    fn wrong_cluster_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = key_path(&dir);
        SigningKey::load_or_create_at(&path, &cluster(0x11)).unwrap();

        let error = SigningKey::load_at(&path, &cluster(0x22)).unwrap_err();
        assert!(matches!(error, SignError::WrongCluster(_)));
    }

    #[test]
    fn bad_checksum_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = key_path(&dir);
        SigningKey::load_or_create_at(&path, &cluster(0x11)).unwrap();
        let mut bytes = fs::read(&path).unwrap();
        bytes[60] ^= 1;
        fs::write(&path, &bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        let error = SigningKey::load_at(&path, &cluster(0x11)).unwrap_err();
        assert!(matches!(error, SignError::BadChecksum(_)));
    }

    #[test]
    fn sign_and_verify_strict_roundtrip() {
        let key = SigningKey::from_seed(&cluster(0x11), [7; SEED_LEN]);
        let signature = key.sign(b"hello");
        assert!(verify_strict(&key.public_key(), b"hello", &signature).is_ok());

        let mut tampered = signature;
        tampered[0] ^= 1;
        let error = verify_strict(&key.public_key(), b"hello", &tampered).unwrap_err();
        assert!(matches!(error, SignError::BadSignature));
    }

    #[test]
    fn seed_zeroizes() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<SigningKey>();

        let mut key = SigningKey::from_seed(&cluster(0x11), [3; SEED_LEN]);
        assert_ne!(*key.seed, [0u8; SEED_LEN]);
        key.seed.zeroize();
        assert_eq!(*key.seed, [0u8; SEED_LEN]);
    }

    #[test]
    fn identity_trait_uses_the_same_key() {
        let key = SigningKey::from_seed_with_epoch(&cluster(0x11), KeyEpoch(9), [5; SEED_LEN]);
        assert_eq!(Identity::client_id(&key), key.client_id());
        assert_eq!(Identity::public_key(&key).to_bytes(), key.public_key());
        assert_eq!(Identity::key_epoch(&key), KeyEpoch(9));
        let message = keyproof_input(
            &cluster(0x11),
            key.client_id(),
            &key.public_key(),
            &[1; 32],
            &[2; 32],
            3,
        );
        let signature = Identity::sign_bytes(&key, &message);
        assert!(
            Identity::public_key(&key)
                .verify_strict(&message, &signature)
                .is_ok()
        );
    }

    #[test]
    fn keyentry_input_delegates_to_identity() {
        let cluster = cluster(0x11);
        let key = SigningKey::from_seed(&cluster, [4; SEED_LEN]);
        let epoch = KeyEpoch(6);
        assert_eq!(
            keyentry_input(&cluster, key.client_id(), &key.public_key(), epoch),
            crate::protocol::identity::key_entry_msg(
                &cluster,
                key.client_id(),
                &PublicKey::from_bytes(key.public_key()),
                epoch,
            )
        );
    }
}
