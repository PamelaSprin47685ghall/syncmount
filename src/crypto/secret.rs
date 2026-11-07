//! Master-password input and Argon2id derivation.
//!
//! Sources, highest priority first (28 §2):
//!
//! 1. `SYNCMOUNT_MASTER_PASSWORD`
//! 2. `SYNCMOUNT_MASTER_PASSWORD_FILE` (one trailing `\n` or `\r\n` is
//!    stripped)
//! 3. an interactive prompt through `rpassword`
//!
//! Argon2id uses the RFC 9106 second recommended profile: `m = 64 MiB`,
//! `t = 3`, `p = 4`, version `0x13`, 32-byte output. The 16-byte
//! [`PskSalt`] is the salt, so every client with one password derives the same
//! PSK. The URL never enters the derivation.
//!
//! The derived key is never exposed outside this crate. Callers derive a
//! [`KeyRing`] or seal a proof.

use std::env;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::protocol::crypto::{ClusterId, KeyRing, PSK_SALT, PskKeyRing, PskSalt};

/// Argon2id memory cost in KiB (64 MiB).
pub const ARGON2_M_COST: u32 = 64 * 1024;

/// Argon2id iteration count.
pub const ARGON2_T_COST: u32 = 3;

/// Argon2id parallelism.
pub const ARGON2_P_COST: u32 = 4;

/// Argon2id output width.
pub const ARGON2_OUTPUT_LEN: usize = 32;

/// Direct-password environment variable.
pub const ENV_MASTER_PASSWORD: &str = "SYNCMOUNT_MASTER_PASSWORD";

/// Password-file environment variable.
pub const ENV_MASTER_PASSWORD_FILE: &str = "SYNCMOUNT_MASTER_PASSWORD_FILE";

/// Prompt shown on a TTY.
pub const PASSWORD_PROMPT: &str = "syncmount master password: ";

/// A 32-byte pre-shared key derived from the master password.
///
/// This is the Argon2id output and the PSK input to [`PskKeyRing`]. The bytes
/// are zeroized on drop. `Debug` never prints them.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey {
    bytes: [u8; ARGON2_OUTPUT_LEN],
}

impl MasterKey {
    /// Resolve the password from the environment or a TTY and derive the key.
    ///
    /// # Errors
    ///
    /// [`SecretError`] if no source is available, the password is empty, the
    /// password file cannot be read, or Argon2id fails.
    pub fn load(cluster: &ClusterId) -> Result<Self, SecretError> {
        let password = resolve_password(
            |name| env::var_os(name),
            || rpassword::prompt_password(PASSWORD_PROMPT),
        )?;
        Self::derive_from_password(password.as_slice(), cluster)
    }

    /// Resolve the password and derive the PSK with [`PskSalt::DEFAULT`].
    ///
    /// # Errors
    ///
    /// As [`MasterKey::load`].
    pub fn load_psk() -> Result<Self, SecretError> {
        let password = resolve_password(
            |name| env::var_os(name),
            || rpassword::prompt_password(PASSWORD_PROMPT),
        )?;
        Self::derive_psk_from_password(password.as_slice(), &PskSalt::DEFAULT)
    }

    /// Derive the key from explicit password bytes.
    ///
    /// Password bytes are used verbatim. This crate does not run NFKC; the
    /// caller owns normalization if it wants it.
    ///
    /// # Errors
    ///
    /// [`SecretError::EmptyPassword`] for an empty password, or
    /// [`SecretError::Argon2`] if Argon2id fails.
    pub fn derive_from_password(password: &[u8], cluster: &ClusterId) -> Result<Self, SecretError> {
        Self::derive_argon2(password, cluster.as_bytes())
    }

    /// Derive the PSK from explicit password bytes and a salt.
    ///
    /// # Errors
    ///
    /// [`SecretError::EmptyPassword`] for an empty password, or
    /// [`SecretError::Argon2`] if Argon2id fails.
    pub fn derive_psk_from_password(password: &[u8], salt: &PskSalt) -> Result<Self, SecretError> {
        Self::derive_argon2(password, salt.as_bytes())
    }

    fn derive_argon2(password: &[u8], salt: &[u8]) -> Result<Self, SecretError> {
        if password.is_empty() {
            return Err(SecretError::EmptyPassword);
        }
        let params = Params::new(
            ARGON2_M_COST,
            ARGON2_T_COST,
            ARGON2_P_COST,
            Some(ARGON2_OUTPUT_LEN),
        )
        .map_err(SecretError::Argon2)?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut bytes = [0u8; ARGON2_OUTPUT_LEN];
        if let Err(error) = argon2.hash_password_into(password, salt, &mut bytes) {
            bytes.zeroize();
            return Err(SecretError::Argon2(error));
        }
        Ok(Self { bytes })
    }

    /// Derive the payload and control keys for `cluster`.
    ///
    /// `salt = cluster_id`, `ikm = master_key`, with the info strings
    /// `sm/v2/enc` and `sm/v2/ctrl` (44 §4.1, 49 A13).
    ///
    /// # Errors
    ///
    /// [`SecretError::Kdf`] only if HKDF rejects a 32-byte output.
    pub fn derive_keyring(&self, cluster: &ClusterId) -> Result<KeyRing, SecretError> {
        KeyRing::derive(&self.bytes, cluster).map_err(|_| SecretError::Kdf)
    }

    /// Derive the PSK ring for `salt`.
    ///
    /// `salt = salt`, `ikm = this key`, with the info strings `sm/v2/enc`,
    /// `sm/v2/ctrl` and `sm/v2/hs`.
    ///
    /// # Errors
    ///
    /// [`SecretError::Kdf`] only if HKDF rejects a 32-byte output.
    pub fn derive_psk_keyring(&self, salt: &PskSalt) -> Result<PskKeyRing, SecretError> {
        PskKeyRing::derive(&self.bytes, salt).map_err(|_| SecretError::Kdf)
    }

    /// The default PSK salt, exposed so callers can log its identity.
    pub const fn default_salt() -> PskSalt {
        PskSalt::from_bytes(PSK_SALT)
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; ARGON2_OUTPUT_LEN] {
        &self.bytes
    }
}

impl fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MasterKey(<redacted>)")
    }
}

/// A master-password or key-derivation failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SecretError {
    /// The selected source produced an empty password.
    #[error("master password is empty")]
    EmptyPassword,
    /// The password file could not be read.
    #[error("failed to read master password file {path}: {source}")]
    PasswordFile {
        /// File path.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: io::Error,
    },
    /// The terminal prompt failed.
    #[error("failed to read the master password from the terminal: {0}")]
    Terminal(#[source] io::Error),
    /// Argon2id rejected its parameters or failed.
    #[error("Argon2id failed: {0}")]
    Argon2(argon2::Error),
    /// HKDF could not produce a 32-byte key.
    #[error("key derivation failed")]
    Kdf,
}

fn resolve_password<F, P>(env_var: F, prompt: P) -> Result<Zeroizing<Vec<u8>>, SecretError>
where
    F: Fn(&str) -> Option<OsString>,
    P: FnOnce() -> io::Result<String>,
{
    if let Some(raw) = env_var(ENV_MASTER_PASSWORD) {
        return password_bytes(raw);
    }
    if let Some(raw) = env_var(ENV_MASTER_PASSWORD_FILE) {
        return read_password_file(&PathBuf::from(raw));
    }
    let password = prompt().map_err(SecretError::Terminal)?;
    if password.is_empty() {
        return Err(SecretError::EmptyPassword);
    }
    Ok(Zeroizing::new(password.into_bytes()))
}

fn password_bytes(raw: OsString) -> Result<Zeroizing<Vec<u8>>, SecretError> {
    let bytes = raw.as_encoded_bytes().to_vec();
    if bytes.is_empty() {
        return Err(SecretError::EmptyPassword);
    }
    Ok(Zeroizing::new(bytes))
}

fn read_password_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, SecretError> {
    let mut bytes = fs::read(path).map_err(|source| SecretError::PasswordFile {
        path: path.to_path_buf(),
        source,
    })?;
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    if bytes.is_empty() {
        bytes.zeroize();
        return Err(SecretError::EmptyPassword);
    }
    Ok(Zeroizing::new(bytes))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn cluster(byte: u8) -> ClusterId {
        ClusterId::from_bytes([byte; 16])
    }

    fn env_lookup(pairs: Vec<(&'static str, OsString)>) -> impl Fn(&str) -> Option<OsString> {
        move |name| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.clone())
        }
    }

    #[test]
    fn kdf_parameters_are_the_rfc9106_profile() {
        assert_eq!(ARGON2_M_COST, 65_536);
        assert_eq!(ARGON2_T_COST, 3);
        assert_eq!(ARGON2_P_COST, 4);
        assert_eq!(ARGON2_OUTPUT_LEN, 32);
    }

    #[test]
    fn derivation_is_deterministic_and_cluster_scoped() {
        let first = MasterKey::derive_from_password(b"correct horse", &cluster(0x11)).unwrap();
        let second = MasterKey::derive_from_password(b"correct horse", &cluster(0x11)).unwrap();
        let other = MasterKey::derive_from_password(b"correct horse", &cluster(0x22)).unwrap();

        assert_eq!(first.as_bytes(), second.as_bytes());
        assert_ne!(first.as_bytes(), other.as_bytes());
    }

    #[test]
    fn direct_environment_wins_over_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("password");
        fs::write(&path, b"from-file\n").unwrap();
        let env = env_lookup(vec![
            (ENV_MASTER_PASSWORD, OsString::from("from-env")),
            (ENV_MASTER_PASSWORD_FILE, path.into_os_string()),
        ]);

        let password =
            resolve_password(env, || Err(io::Error::other("prompt must not run"))).unwrap();
        assert_eq!(password.as_slice(), b"from-env");
    }

    #[test]
    fn password_file_is_used_before_the_tty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("password");
        fs::write(&path, b"from-file\n").unwrap();
        let env = env_lookup(vec![(ENV_MASTER_PASSWORD_FILE, path.into_os_string())]);

        let password =
            resolve_password(env, || Err(io::Error::other("prompt must not run"))).unwrap();
        assert_eq!(password.as_slice(), b"from-file");
    }

    #[test]
    fn tty_is_the_last_source() {
        let env = env_lookup(Vec::new());
        let password = resolve_password(env, || Ok("from-tty".to_owned())).unwrap();
        assert_eq!(password.as_slice(), b"from-tty");
    }

    #[test]
    fn password_file_strips_one_line_ending() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("password");
        fs::write(&path, b"pass word\r\n").unwrap();

        let password = read_password_file(&path).unwrap();
        assert_eq!(password.as_slice(), b"pass word");
    }

    #[test]
    fn empty_password_is_rejected() {
        assert!(matches!(
            MasterKey::derive_from_password(b"", &cluster(0x11)),
            Err(SecretError::EmptyPassword)
        ));
    }

    #[test]
    fn master_key_zeroizes() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<MasterKey>();

        let mut key = MasterKey::derive_from_password(b"zeroize me", &cluster(0x11)).unwrap();
        assert_ne!(key.as_bytes(), &[0u8; ARGON2_OUTPUT_LEN]);
        key.zeroize();
        assert_eq!(key.as_bytes(), &[0u8; ARGON2_OUTPUT_LEN]);
    }

    #[test]
    fn keyring_derivation_is_stable() {
        let key = MasterKey::derive_from_password(b"keyring", &cluster(0x11)).unwrap();
        let first = key.derive_keyring(&cluster(0x11)).unwrap();
        let second = key.derive_keyring(&cluster(0x11)).unwrap();
        assert_eq!(first.kid(), second.kid());
        assert_eq!(first.ctrl_key(), second.ctrl_key());
    }

    #[test]
    fn psk_derivation_is_fixed_salt_and_domain_separated() {
        let first =
            MasterKey::derive_psk_from_password(b"correct horse", &PskSalt::DEFAULT).unwrap();
        let second =
            MasterKey::derive_psk_from_password(b"correct horse", &PskSalt::DEFAULT).unwrap();
        let wrong = MasterKey::derive_psk_from_password(b"wrong horse", &PskSalt::DEFAULT).unwrap();

        let ring = first.derive_psk_keyring(&PskSalt::DEFAULT).unwrap();
        let again = second.derive_psk_keyring(&PskSalt::DEFAULT).unwrap();
        let other = wrong.derive_psk_keyring(&PskSalt::DEFAULT).unwrap();
        assert_eq!(ring.kid(), again.kid());
        assert_eq!(ring.enc_key(), again.enc_key());
        assert_eq!(ring.ctrl_key(), again.ctrl_key());
        assert_ne!(ring.enc_key(), other.enc_key());

        let other_salt = PskSalt::from_bytes([0x11; 16]);
        let salted = first.derive_psk_keyring(&other_salt).unwrap();
        assert_ne!(ring.enc_key(), salted.enc_key());

        assert_ne!(ring.enc_key(), ring.ctrl_key());
        assert_eq!(MasterKey::default_salt(), PskSalt::DEFAULT);
    }

    #[test]
    fn handshake_keys_bind_both_nonces() {
        let master = MasterKey::derive_psk_from_password(b"handshake", &PskSalt::DEFAULT).unwrap();
        let ring = master.derive_psk_keyring(&PskSalt::DEFAULT).unwrap();
        let client = [0x11; 32];
        let server = [0x22; 32];
        let first = ring.handshake_keys(&client, &server).unwrap();
        let again = ring.handshake_keys(&client, &server).unwrap();
        assert_eq!(first.kid(), again.kid());

        let other_server = ring.handshake_keys(&client, &[0x23; 32]).unwrap();
        let other_client = ring.handshake_keys(&[0x12; 32], &server).unwrap();
        assert_ne!(first.kid(), other_server.kid());
        assert_ne!(first.kid(), other_client.kid());
        assert_ne!(first.kid(), ring.kid());
    }
}
