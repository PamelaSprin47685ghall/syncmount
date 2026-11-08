//! 1.1 `--mmap` HTTP client.
//!
//! The client owns one [`MmHttpClient`], which speaks SMM1 over HTTP/1.1 to a
//! `MmapServer`. It implements [`crate::mmap::shadow::MmRemote`], so the
//! shadow filesystem and the FUSE adapter above it never open a socket.
//!
//! # Namespace
//!
//! The URL path prefix is `/private-mm`; the SMM1 `namespace` field is
//! `private-mm`, without the leading slash. [`MmNamespace`] is the only place
//! that conversion happens. A caller that passes a URL into
//! [`MmClientConfig::from_url`] gets a validated pair, and the wire label is
//! never derived again from the URL.
//!
//! # Session
//!
//! One `HELLO` derives `K_s`. Every authenticated request carries
//! `X-SM-MM-Session`, a strictly increasing `X-SM-MM-Seq` and
//! `X-SM-MM-MAC`. A `401` invalidates that session, sends one fresh `HELLO`
//! and replays the request once. A session is refreshed before its ten-minute
//! deadline.
//!
//! # Failures
//!
//! `409` and `423` map to [`RemoteError`] variants that the shadow turns into
//! `EAGAIN`. Nothing is retried inside one call except the two protocol-level
//! recoveries the contract requires: re-authentication after `401`, and
//! acknowledgement recovery for an upload batch whose response was lost.

mod http;
mod remote;
mod wire;

pub use remote::{BatchStatus, DirVersionInfo};

#[cfg(all(test, feature = "mmap-tests"))]
mod tests;

use std::collections::HashMap;
use std::fmt;
use std::net::{SocketAddr, ToSocketAddrs};
#[cfg(feature = "fuse")]
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::client::config::{Endpoint, Scheme};
use crate::mmap::proto::{
    Kind, Limits, Message as _, SessionKeys, derive_hello_key, derive_session_key, hello_proof,
    verify_welcome,
};
use crate::mmap::shadow::{MmRemote, RemoteError, ShadowError, UploadRequest, UploadResponse};
use crate::mmap::types::{BatchId, DirAttrs, Ino, LockId, MmBase, MmSeq};

use self::http::{RequestAuth, WireFailure, WireResponse};

/// Canonical URL prefix of the 1.1 private namespace.
pub const MM_URL_PREFIX: &str = "/private-mm";
/// Canonical SMM1 label of the 1.1 private namespace.
pub const MM_WIRE_NAMESPACE: &str = "private-mm";
/// Requested idle-session lifetime. The server may advertise shorter.
pub const SESSION_TTL_MS: u64 = 10 * 60 * 1000;
/// Refresh a session this long before its absolute deadline.
pub const SESSION_REFRESH_MARGIN_MS: u64 = 30 * 1000;
/// Default connect timeout.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Default metadata request timeout.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

/// Why the client could not be constructed, configured or mounted.
#[derive(Debug, thiserror::Error)]
pub enum MmClientError {
    /// The URL, namespace or mount point is not usable.
    #[error("configuration: {0}")]
    Config(String),
    /// A socket or filesystem operation failed.
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
    /// The shadow layer refused to open.
    #[error("shadow: {0}")]
    Shadow(#[from] ShadowError),
    /// FUSE refused to mount.
    #[error("mount: {0}")]
    Mount(String),
}

/// One validated URL prefix / wire label pair.
///
/// This is the single conversion point between the HTTP namespace and the
/// SMM1 namespace. `wire` never contains a `/`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MmNamespace {
    url_prefix: String,
    wire: String,
}

impl MmNamespace {
    /// The documented private namespace.
    pub fn private_mm() -> Self {
        Self {
            url_prefix: MM_URL_PREFIX.to_owned(),
            wire: MM_WIRE_NAMESPACE.to_owned(),
        }
    }

    /// Validate one URL prefix.
    ///
    /// The prefix must be a single absolute component. The leading slash is
    /// removed exactly once for the SMM1 label.
    pub fn new(url_prefix: &str) -> Result<Self, MmClientError> {
        let trimmed = url_prefix.trim_end_matches('/');
        if !trimmed.starts_with('/') {
            return Err(MmClientError::Config(format!(
                "namespace prefix `{url_prefix}` must start with '/'"
            )));
        }
        let wire = &trimmed[1..];
        if wire.is_empty() || wire.contains('/') {
            return Err(MmClientError::Config(format!(
                "namespace prefix `{url_prefix}` must be one component"
            )));
        }
        if wire.contains('\0') {
            return Err(MmClientError::Config(
                "namespace prefix contains NUL".to_owned(),
            ));
        }
        if wire == "private" || wire == "public" {
            return Err(MmClientError::Config(format!(
                "`/{wire}` is a 1.0 namespace; use /private-mm or /public-mm"
            )));
        }
        Ok(Self {
            url_prefix: trimmed.to_owned(),
            wire: wire.to_owned(),
        })
    }

    /// URL path prefix, with the leading slash.
    pub fn url_prefix(&self) -> &str {
        &self.url_prefix
    }

    /// SMM1 namespace field, without any slash.
    pub fn wire_label(&self) -> &str {
        &self.wire
    }
}

/// Everything one mm client process needs.
#[derive(Clone)]
pub struct MmClientConfig {
    /// Namespace mapping.
    pub namespace: MmNamespace,
    /// Server host, without brackets.
    pub host: String,
    /// Server port.
    pub port: u16,
    /// Raw 32-byte master key shared with the server.
    pub master_key: [u8; 32],
    /// Stable 16-byte client id.
    pub client_id: [u8; 16],
    /// Connect timeout.
    pub connect_timeout: Duration,
    /// Read and write timeout for one request.
    pub request_timeout: Duration,
    /// Advertised caps; the server still enforces its own.
    pub limits: Limits,
}

impl fmt::Debug for MmClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MmClientConfig")
            .field("namespace", &self.namespace)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("master_key", &"<redacted>")
            .field("client_id", &hex::encode(self.client_id))
            .field("connect_timeout", &self.connect_timeout)
            .field("request_timeout", &self.request_timeout)
            .field("limits", &self.limits)
            .finish()
    }
}

impl MmClientConfig {
    /// Build a configuration from a URL such as
    /// `http://127.0.0.1:8081/private-mm`.
    ///
    /// A URL without a path selects [`MmNamespace::private_mm`]. `https` is
    /// rejected: TLS is terminated by the deployment in front of the mm
    /// listener, exactly as in 1.0.
    pub fn from_url(url: &str, master_key: [u8; 32]) -> Result<Self, MmClientError> {
        let endpoint = Endpoint::parse(url)
            .map_err(|error| MmClientError::Config(format!("invalid URL `{url}`: {error}")))?;
        if endpoint.scheme != Scheme::Http {
            return Err(MmClientError::Config(
                "the mm client speaks plain HTTP; terminate TLS in front of the listener"
                    .to_owned(),
            ));
        }
        let namespace = if endpoint.prefix.is_empty() {
            MmNamespace::private_mm()
        } else {
            MmNamespace::new(&endpoint.prefix)?
        };
        Ok(Self {
            namespace,
            host: endpoint.host,
            port: endpoint.port,
            master_key,
            client_id: derive_client_id(&master_key),
            connect_timeout: CONNECT_TIMEOUT,
            request_timeout: REQUEST_TIMEOUT,
            limits: Limits::new(),
        })
    }

    /// The `Host:` header value.
    fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// Full request path below the origin.
    fn path(&self, suffix: &str) -> String {
        format!("{}{}", self.namespace.url_prefix(), suffix)
    }
}

/// A stable client id derived from the master key.
pub fn derive_client_id(master_key: &[u8; 32]) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new_derive_key("sm/1.1/mm/client");
    hasher.update(master_key);
    let digest = hasher.finalize();
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest.as_bytes()[..16]);
    if id == [0u8; 16] {
        id[0] = 1;
    }
    id
}

/// Milliseconds since the Unix epoch, saturating at zero.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[derive(Debug)]
struct SessionEntry {
    keys: Arc<SessionKeys>,
    expires_at_ms: u64,
    seq: u64,
    generation: u64,
}

#[derive(Debug, Default)]
struct AuthState {
    session: Option<SessionEntry>,
    generation: u64,
}

#[derive(Debug)]
struct CachedSnapshot {
    base: MmBase,
    snapshot_seq: MmSeq,
    attrs: DirAttrs,
    entries: Vec<crate::mmap::shadow::CheckoutEntry>,
}

#[derive(Debug, Default)]
struct Cache {
    snapshots: HashMap<Ino, CachedSnapshot>,
    dir_attrs: HashMap<Ino, DirAttrs>,
    locks: HashMap<String, LockId>,
    active_batches: HashMap<Ino, (BatchId, LockId)>,
}

/// A synchronous SMM1/HTTP client.
///
/// Several FUSE worker threads may call it at once. Session negotiation is
/// serialized; ordinary requests allocate a sequence number under the auth
/// mutex and then run concurrently.
pub struct MmHttpClient {
    config: MmClientConfig,
    addrs: Vec<SocketAddr>,
    auth: Mutex<AuthState>,
    hello: Mutex<()>,
    cache: Mutex<Cache>,
}

impl fmt::Debug for MmHttpClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MmHttpClient")
            .field("config", &self.config)
            .field("addrs", &self.addrs)
            .finish_non_exhaustive()
    }
}

impl MmHttpClient {
    /// Validate the configuration, resolve the server and open no socket.
    pub fn new(config: MmClientConfig) -> Result<Self, MmClientError> {
        validate_client_id(&config.client_id)?;
        let addrs: Vec<SocketAddr> = (config.host.as_str(), config.port)
            .to_socket_addrs()
            .map_err(|error| {
                MmClientError::Config(format!(
                    "cannot resolve {}:{}: {error}",
                    config.host, config.port
                ))
            })?
            .collect();
        if addrs.is_empty() {
            return Err(MmClientError::Config(format!(
                "{}:{} resolved to no address",
                config.host, config.port
            )));
        }
        Ok(Self {
            config,
            addrs,
            auth: Mutex::new(AuthState::default()),
            hello: Mutex::new(()),
            cache: Mutex::new(Cache::default()),
        })
    }

    /// The active configuration.
    pub fn config(&self) -> &MmClientConfig {
        &self.config
    }

    fn auth(&self) -> std::sync::MutexGuard<'_, AuthState> {
        self.auth.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn cache(&self) -> std::sync::MutexGuard<'_, Cache> {
        self.cache.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn session_is_live(session: &SessionEntry, now: u64) -> bool {
        session.expires_at_ms > now.saturating_add(SESSION_REFRESH_MARGIN_MS)
    }

    fn auth_snapshot(session: &SessionEntry) -> RequestAuth {
        RequestAuth {
            keys: Arc::clone(&session.keys),
            seq: session.seq,
            generation: session.generation,
        }
    }

    /// Reuse a live session or send one `HELLO`.
    fn ensure_auth(&self) -> Result<RequestAuth, WireFailure> {
        let now = now_ms();
        {
            let mut state = self.auth();
            if let Some(session) = state.session.as_mut() {
                if Self::session_is_live(session, now) {
                    session.seq = session.seq.saturating_add(1);
                    return Ok(Self::auth_snapshot(session));
                }
            }
        }

        let _guard = self.hello.lock().unwrap_or_else(PoisonError::into_inner);
        let now = now_ms();
        {
            let mut state = self.auth();
            if let Some(session) = state.session.as_mut() {
                if Self::session_is_live(session, now) {
                    session.seq = session.seq.saturating_add(1);
                    return Ok(Self::auth_snapshot(session));
                }
            }
        }

        let session = self.handshake()?;
        let mut state = self.auth();
        state.generation = state.generation.wrapping_add(1);
        let generation = state.generation;
        let entry = SessionEntry {
            keys: Arc::new(session.keys),
            expires_at_ms: session.expires_at_ms,
            seq: 1,
            generation,
        };
        let snapshot = Self::auth_snapshot(&entry);
        state.session = Some(entry);
        Ok(snapshot)
    }

    fn invalidate(&self, generation: u64) {
        let mut state = self.auth();
        if state
            .session
            .as_ref()
            .is_some_and(|s| s.generation == generation)
        {
            state.session = None;
        }
    }

    fn handshake(&self) -> Result<Handshake, WireFailure> {
        let client_nonce = rand::random::<[u8; 32]>();
        let timestamp_ms = now_ms();
        let hello = crate::mmap::proto::Hello {
            client_id: self.config.client_id,
            client_nonce,
            timestamp_ms,
            proof: hello_proof(
                &derive_hello_key(&self.config.master_key),
                &self.config.client_id,
                &client_nonce,
                timestamp_ms,
            ),
        };
        let meta = hello
            .encode_meta()
            .map_err(|error| WireFailure::Protocol(error.to_string()))?;
        let response = self.exchange(
            "POST",
            "/mm/v1/hello",
            Some((Kind::Hello, &meta)),
            None,
            None,
        )?;
        let welcome: crate::mmap::proto::Welcome = response.decode()?;
        let hello_key = derive_hello_key(&self.config.master_key);
        verify_welcome(&welcome, &hello_key, &client_nonce)
            .map_err(|error| WireFailure::Protocol(error.to_string()))?;
        welcome
            .limits
            .validate()
            .map_err(|error| WireFailure::Protocol(error.to_string()))?;
        let key = derive_session_key(
            &self.config.master_key,
            &client_nonce,
            &welcome.server_nonce,
            &welcome.session_id,
        );
        Ok(Handshake {
            keys: SessionKeys::new(key, welcome.session_id, welcome.session_expires_at_ms),
            expires_at_ms: welcome.session_expires_at_ms,
        })
    }

    /// One authenticated request, with exactly one re-authentication retry.
    fn call(
        &self,
        method: &str,
        suffix: &str,
        frame: Option<(Kind, &[u8])>,
        payload: Option<&wire::CommitPlan<'_>>,
    ) -> Result<WireResponse, WireFailure> {
        self.call_with(method, suffix, payload, |_| {
            Ok(frame.map(|(kind, meta)| (kind, meta.to_vec())))
        })
    }

    /// One authenticated request whose meta depends on the session that will
    /// carry it. `build` runs after a sequence number has been allocated and
    /// again after a re-authentication retry.
    fn call_with<F>(
        &self,
        method: &str,
        suffix: &str,
        payload: Option<&wire::CommitPlan<'_>>,
        build: F,
    ) -> Result<WireResponse, WireFailure>
    where
        F: Fn(&RequestAuth) -> Result<Option<(Kind, Vec<u8>)>, WireFailure>,
    {
        let mut attempts = 0u32;
        loop {
            let auth = self.ensure_auth()?;
            let frame = build(&auth)?;
            let response = self.exchange(
                method,
                suffix,
                frame.as_ref().map(|(kind, meta)| (*kind, meta.as_slice())),
                payload,
                Some(&auth),
            )?;
            if response.status == 401 && attempts == 0 {
                self.invalidate(auth.generation);
                attempts += 1;
                continue;
            }
            return Ok(response);
        }
    }

    fn exchange(
        &self,
        method: &str,
        suffix: &str,
        frame: Option<(Kind, &[u8])>,
        payload: Option<&wire::CommitPlan<'_>>,
        auth: Option<&RequestAuth>,
    ) -> Result<WireResponse, WireFailure> {
        let path = self.config.path(suffix);
        http::exchange(
            &self.addrs,
            &self.config.authority(),
            self.config.connect_timeout,
            self.config.request_timeout,
            method,
            &path,
            frame,
            payload,
            auth,
            &self.config.limits,
        )
    }

    fn snapshot(
        &self,
        dir_ino: Ino,
    ) -> Option<(
        MmBase,
        MmSeq,
        DirAttrs,
        Vec<crate::mmap::shadow::CheckoutEntry>,
    )> {
        self.cache().snapshots.get(&dir_ino).map(|snapshot| {
            (
                snapshot.base,
                snapshot.snapshot_seq,
                snapshot.attrs,
                snapshot.entries.clone(),
            )
        })
    }

    fn remember_snapshot(
        &self,
        dir_ino: Ino,
        base: MmBase,
        snapshot_seq: MmSeq,
        attrs: DirAttrs,
        entries: Vec<crate::mmap::shadow::CheckoutEntry>,
    ) {
        let mut cache = self.cache();
        cache.dir_attrs.insert(dir_ino, attrs);
        cache.snapshots.insert(
            dir_ino,
            CachedSnapshot {
                base,
                snapshot_seq,
                attrs,
                entries,
            },
        );
    }

    fn dir_attrs(&self, dir_ino: Ino) -> Option<DirAttrs> {
        self.cache().dir_attrs.get(&dir_ino).copied()
    }

    fn lock_for_dir(&self, dir_path: &str) -> Option<LockId> {
        self.cache().locks.get(dir_path).copied()
    }

    fn remember_lock(&self, dir_path: &str, lock_id: LockId) {
        self.cache().locks.insert(dir_path.to_owned(), lock_id);
    }

    fn forget_lock(&self, lock_id: LockId) {
        let mut cache = self.cache();
        cache.locks.retain(|_, id| *id != lock_id);
        cache.active_batches.retain(|_, (_, id)| *id != lock_id);
    }

    fn remember_batch(&self, dir_ino: Ino, batch_id: BatchId, lock_id: LockId) {
        self.cache()
            .active_batches
            .insert(dir_ino, (batch_id, lock_id));
    }

    fn active_batch(&self, dir_ino: Ino) -> Option<(BatchId, LockId)> {
        self.cache().active_batches.get(&dir_ino).copied()
    }

    fn forget_batch(&self, batch_id: BatchId) {
        self.cache()
            .active_batches
            .retain(|_, (id, _)| *id != batch_id);
    }
}

#[derive(Debug)]
struct Handshake {
    keys: SessionKeys,
    expires_at_ms: u64,
}

fn validate_client_id(client_id: &[u8; 16]) -> Result<(), MmClientError> {
    if *client_id == [0u8; 16] {
        return Err(MmClientError::Config(
            "client id must not be all zeros".to_owned(),
        ));
    }
    Ok(())
}

/// Implement the shadow remote boundary for the HTTP client.
impl MmRemote for MmHttpClient {
    fn checkout(
        &self,
        request: &crate::mmap::shadow::CheckoutRequest,
    ) -> Result<crate::mmap::shadow::CheckoutOutcome, RemoteError> {
        self.checkout_endpoint(request)
    }

    fn signatures(
        &self,
        request: &crate::mmap::shadow::SignaturesRequest,
    ) -> Result<crate::mmap::shadow::SignaturesResponse, RemoteError> {
        self.signatures_endpoint(request)
    }

    fn upload(&self, request: &UploadRequest) -> Result<UploadResponse, RemoteError> {
        match request {
            UploadRequest::Begin(begin) => self.upload_begin(begin),
            UploadRequest::Commit(commit) => self.upload_commit(commit),
            UploadRequest::Abort(abort) => self.upload_abort(abort),
        }
    }

    fn lock(
        &self,
        request: &crate::mmap::shadow::LockRequest,
    ) -> Result<crate::mmap::shadow::LockResponse, RemoteError> {
        self.lock_endpoint(request)
    }

    fn file_read(
        &self,
        request: &crate::mmap::shadow::FileReadRequest,
    ) -> Result<crate::mmap::shadow::FileData, RemoteError> {
        self.file_read_endpoint(request)
    }

    fn batch_status(
        &self,
        batch_id: crate::mmap::types::BatchId,
    ) -> Result<crate::mmap::shadow::BatchStatus, RemoteError> {
        let status = MmHttpClient::batch_status(self, batch_id)?;
        Ok(crate::mmap::shadow::BatchStatus {
            batch_id: status.batch_id,
            state: match status.state {
                crate::mmap::proto::BatchState::Open => crate::mmap::shadow::BatchState::Open,
                crate::mmap::proto::BatchState::Committed => {
                    crate::mmap::shadow::BatchState::Committed
                }
                crate::mmap::proto::BatchState::Aborted => crate::mmap::shadow::BatchState::Aborted,
            },
            snapshot_seq: status.snapshot_seq,
            base_seq_after: status.base_seq_after,
            dir_version_after: status.dir_version_after,
            manifest_hash: status.manifest_hash,
            dir_path: status.dir_path,
        })
    }
}

/// Open a shadow mount that talks to an mm server over HTTP.
#[cfg(feature = "fuse")]
pub fn mount_shadow(
    config: MmClientConfig,
    mountpoint: &Path,
    shadow_dir: &Path,
    allow_other: bool,
) -> Result<(), MmClientError> {
    use std::sync::Arc;

    use crate::mmap::fuse::{ShadowFs, mount_config};
    use crate::mmap::shadow::{Shadow, ShadowConfig};

    if !mountpoint.is_absolute() {
        return Err(MmClientError::Config(format!(
            "mount point {} is not absolute",
            mountpoint.display()
        )));
    }
    let metadata = std::fs::metadata(mountpoint)?;
    if !metadata.is_dir() {
        return Err(MmClientError::Config(format!(
            "mount point {} is not a directory",
            mountpoint.display()
        )));
    }
    // Foundation tables key their namespace by the absolute path; the SMM1
    // label without the leading slash stays on the wire only.
    let namespace = config.namespace.url_prefix().to_owned();
    let client = Arc::new(MmHttpClient::new(config)?);
    let shadow = Shadow::open(
        ShadowConfig::new(shadow_dir.to_path_buf(), namespace),
        client,
    )?;
    let filesystem = ShadowFs::new(Arc::new(shadow));
    let mount_config = mount_config(allow_other);
    let session = fuser::spawn_mount(filesystem, mountpoint, &mount_config)
        .map_err(|error| MmClientError::Mount(error.to_string()))?;
    session
        .umount_and_join()
        .map_err(|error| MmClientError::Mount(error.to_string()))
}
