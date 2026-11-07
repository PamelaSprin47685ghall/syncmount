//! Command-line surface: subcommand dispatch, exit codes, implicit aliases.
//!
//! The argv shape is frozen (W1, 51 F7): `syncmount client URL MOUNTPOINT`,
//! `syncmount server URL`, `syncmount URL MOUNTPOINT` (client alias),
//! `syncmount URL` (server alias), `status`, and the four `debug-*` commands.
//!
//! # Secrets
//!
//! The master password never appears in argv (39 §2.1, 37 §5.1). It comes
//! from `SYNCMOUNT_MASTER_PASSWORD`, `SYNCMOUNT_MASTER_PASSWORD_FILE`, the
//! `--key-file` path (a 0600 file, checked here), or a terminal prompt. The
//! hidden `--key` argument exists only to refuse the unsafe spelling with a
//! clear message.
//!
//! # Cluster identity
//!
//! Every client uses one fixed 16-byte `ClusterId`,
//! `BLAKE3("sm/v1/cluster\0" ‖ "default")[0..16]`. The URL never takes part:
//! scheme, host, port, and prefix only choose the connection target, and the
//! server still routes by URL path as its namespace. `cluster_for` keeps the
//! old URL-derived id only to read caches written before the cutover.
//!
//! # Status data source
//!
//! A running client publishes one JSON document per mount under
//! `/run/syncmount/<mount_id>/status.json` (or `SYNCMOUNT_RUN_DIR`). The
//! `status` and `debug-*` commands are read-only projections of those files:
//! the client listens on no port, so there is no other IPC channel in v1.

use std::ffi::OsString;
use std::fs;
#[cfg(feature = "fuse")]
use std::io::IsTerminal;
use std::net::{SocketAddr, ToSocketAddrs};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
#[cfg(feature = "fuse")]
use std::sync::Arc;

use clap::{Args, Parser, Subcommand};
use serde_json::Value;
#[cfg(feature = "fuse")]
use zeroize::Zeroizing;

#[cfg(feature = "fuse")]
use crate::client::Client;
#[cfg(feature = "fuse")]
use crate::client::config::Config as ClientConfig;
use crate::client::config::Endpoint as ClientEndpoint;
#[cfg(feature = "fuse")]
use crate::crypto::secret::MasterKey;
#[cfg(feature = "fuse")]
use crate::crypto::sign::SigningKey;
use crate::logging::{self, LogFormat};
use crate::protocol::crypto::ClusterId;
use crate::server::{ServeConfig, Server};
use crate::store::RootFd;
use crate::store::runtime_dir::{self, RuntimeDir};
use crate::sync::manifest::LocalManifest;
use crate::version;

/// Normal exit.
pub const EXIT_OK: u8 = 0;
/// Argument or "already running" failure.
pub const EXIT_USAGE: u8 = 1;
/// Startup failure.
pub const EXIT_STARTUP: u8 = 2;
/// Audit log is corrupt; retained for inspection.
pub const EXIT_AUDIT: u8 = 3;
/// Disconnected or kicked; the mount has been released.
pub const EXIT_DISCONNECTED: u8 = 10;

/// Default server listen address (08 §3, 37 §6.1).
pub const DEFAULT_LISTEN: &str = "127.0.0.1:8080";

/// `/etc/fuse.conf`.
#[cfg(feature = "fuse")]
pub const FUSE_CONF: &str = "/etc/fuse.conf";

/// `/dev/fuse`.
#[cfg(feature = "fuse")]
pub const FUSE_DEVICE: &str = "/dev/fuse";

const SUBCOMMANDS: [&str; 7] = [
    "client",
    "server",
    "status",
    "debug-state",
    "debug-manifest-diff",
    "debug-seq-gaps",
    "debug-conntrace",
];

/// Flags that consume the following argv token.
const VALUE_FLAGS: [&str; 10] = [
    "--log-level",
    "--log-format",
    "--key",
    "--key-file",
    "--listen",
    "--port",
    "--mount-id",
    "--url",
    "--cluster",
    "--limit",
];

/// Parsed command line.
#[derive(Debug, Parser)]
#[command(
    name = "syncmount",
    about = "End-to-end encrypted, eventually consistent FUSE filesystem",
    long_about = None,
    version = version::SOFTWARE_VERSION,
    arg_required_else_help = true
)]
pub struct Cli {
    /// Log filter (`trace`, `debug`, `info`, `warn`, `error`, or an EnvFilter).
    ///
    /// Precedence: this flag, then `RUST_LOG`, then `SYNCMOUNT_LOG`, then
    /// `info`.
    #[arg(long, global = true, value_name = "FILTER")]
    pub log_level: Option<String>,

    /// Log rendering format.
    #[arg(long, global = true, value_enum, default_value = "text")]
    pub log_format: LogFormat,

    /// Run in the foreground. Both modes already do; the flag is a no-op
    /// placeholder for unit files and container entrypoints.
    #[arg(long, global = true)]
    pub foreground: bool,

    #[command(subcommand)]
    pub command: Command,
}

/// One of the frozen subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Mount the cluster namespace at MOUNTPOINT.
    Client(ClientArgs),
    /// Run the stateless sequencer.
    Server(ServerArgs),
    /// Print the status of running clients.
    Status(StatusArgs),
    /// Dump the replay/lifecycle state of a running client.
    DebugState(DebugArgs),
    /// Compare two local manifest caches.
    DebugManifestDiff(ManifestDiffArgs),
    /// Report seq gaps in the connection trace.
    DebugSeqGaps(DebugArgs),
    /// Dump the connection trace ring.
    DebugConntrace(ConntraceArgs),
}

/// `syncmount client URL MOUNTPOINT`.
#[derive(Debug, Args)]
pub struct ClientArgs {
    /// Cluster URL, including the namespace path prefix.
    pub url: String,
    /// Local mountpoint.
    pub mountpoint: PathBuf,

    /// Allow every local user to access the mount.
    ///
    /// Requires `user_allow_other` in `/etc/fuse.conf`.
    #[arg(long)]
    pub allow_other: bool,

    /// Accept a JOIN with no remote view above sequence zero.
    ///
    /// Cluster-wins then deletes every local-only path; this records consent.
    #[arg(long)]
    pub allow_empty_view: bool,

    /// Read the master password from this file (mode 0600).
    #[arg(long, value_name = "PATH")]
    pub key_file: Option<PathBuf>,

    /// Refused: a password in argv is visible in `ps` and shell history.
    #[arg(long, hide = true, value_name = "KEY")]
    pub key: Option<String>,
}

/// `syncmount server URL`.
#[derive(Debug, Args)]
pub struct ServerArgs {
    /// Cluster URL. Only the path becomes the namespace prefix.
    pub url: String,

    /// Listen address (`host:port`). Overrides `--port` and the default.
    #[arg(long, env = "SYNCMOUNT_LISTEN", value_name = "ADDR")]
    pub listen: Option<String>,

    /// Listen port on `127.0.0.1`.
    #[arg(long, value_name = "PORT", conflicts_with = "listen")]
    pub port: Option<u16>,
}

/// `syncmount status`.
#[derive(Debug, Args)]
pub struct StatusArgs {
    /// Emit the status documents as a JSON array.
    #[arg(long)]
    pub json: bool,

    /// Restrict output to one mount id.
    #[arg(long, value_name = "ID")]
    pub mount_id: Option<String>,
}

/// `syncmount debug-state` / `debug-seq-gaps`.
#[derive(Debug, Args)]
pub struct DebugArgs {
    /// Restrict output to one mount id.
    #[arg(long, value_name = "ID")]
    pub mount_id: Option<String>,

    /// Emit machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

/// `syncmount debug-conntrace`.
#[derive(Debug, Args)]
pub struct ConntraceArgs {
    /// Restrict output to one mount id.
    #[arg(long, value_name = "ID")]
    pub mount_id: Option<String>,

    /// Number of entries to print, newest last.
    #[arg(long, default_value_t = 100, value_name = "N")]
    pub limit: usize,
}

/// `syncmount debug-manifest-diff MOUNTPOINT [OTHER]`.
#[derive(Debug, Args)]
pub struct ManifestDiffArgs {
    /// Mountpoint whose local manifest cache is the left side.
    pub mountpoint: PathBuf,
    /// Optional second mountpoint; without it only the left summary prints.
    pub other: Option<PathBuf>,

    /// Derive the legacy URL-based cluster id (pre-cutover caches only).
    #[arg(long, value_name = "URL")]
    pub url: Option<String>,

    /// Explicit 16-byte cluster id as 32 hex characters.
    #[arg(long, value_name = "HEX", conflicts_with = "url")]
    pub cluster: Option<String>,
}

/// Errors that terminate the process.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error("failed to initialise logging: {0}")]
    Logging(#[from] logging::InitError),

    #[error("{0}")]
    Usage(String),

    #[error("{0}")]
    Startup(String),

    #[error("{0}")]
    Unavailable(String),

    #[error("syncmount exited with code {0}")]
    Exit(u8),
}

impl CliError {
    /// Process exit code for this error.
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Logging(_) | Self::Startup(_) => EXIT_STARTUP,
            Self::Usage(_) => EXIT_USAGE,
            Self::Unavailable(_) => EXIT_STARTUP,
            Self::Exit(code) => *code,
        }
    }
}

/// Parse argv and run the selected mode.
pub fn run() -> ExitCode {
    let mut args: Vec<OsString> = std::env::args_os().collect();

    if wants_version(&args) {
        println!("syncmount {}", version::long_version());
        return ExitCode::from(EXIT_OK);
    }

    normalize_args(&mut args);

    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(err) => {
            let code = err.exit_code();
            let _ = err.print();
            return ExitCode::from(u8::try_from(code).unwrap_or(EXIT_USAGE));
        }
    };

    match execute(cli) {
        Ok(()) => ExitCode::from(EXIT_OK),
        Err(err) => {
            eprintln!("syncmount: {err}");
            if matches!(err, CliError::Usage(_)) {
                eprintln!("syncmount: try `syncmount --help`");
            }
            ExitCode::from(err.exit_code())
        }
    }
}

fn wants_version(args: &[OsString]) -> bool {
    args.iter()
        .skip(1)
        .filter_map(|arg| arg.to_str())
        .any(|arg| arg == "-V" || arg == "--version")
}

/// Resolve the implicit aliases before clap sees the arguments.
///
/// * `syncmount URL MOUNTPOINT …` → `syncmount client URL MOUNTPOINT …`
/// * `syncmount URL …` → `syncmount server URL …`
///
/// A token is positional when it does not start with `-` and is not the value
/// of a preceding value-taking flag. A first positional token that is already
/// a subcommand, or that is not a URL, is left untouched so clap reports it.
fn normalize_args(args: &mut Vec<OsString>) {
    let first = match first_positional(args) {
        Some(index) => index,
        None => return,
    };
    let token = match args[first].to_str() {
        Some(token) => token,
        None => return,
    };
    if SUBCOMMANDS.contains(&token) || !token.contains("://") {
        return;
    }
    let positional_after = positional_count(args, first + 1);
    let command = if positional_after >= 1 {
        "client"
    } else {
        "server"
    };
    args.insert(first, OsString::from(command));
}

fn first_positional(args: &[OsString]) -> Option<usize> {
    let mut skip = false;
    for (index, arg) in args.iter().enumerate().skip(1) {
        if skip {
            skip = false;
            continue;
        }
        let Some(text) = arg.to_str() else {
            return Some(index);
        };
        if text.starts_with('-') {
            if takes_value(text) {
                skip = true;
            }
            continue;
        }
        return Some(index);
    }
    None
}

fn positional_count(args: &[OsString], from: usize) -> usize {
    let mut skip = false;
    let mut count = 0;
    for arg in args.iter().skip(from) {
        if skip {
            skip = false;
            continue;
        }
        let Some(text) = arg.to_str() else {
            count += 1;
            continue;
        };
        if text.starts_with('-') {
            if takes_value(text) {
                skip = true;
            }
            continue;
        }
        count += 1;
    }
    count
}

fn takes_value(flag: &str) -> bool {
    !flag.contains('=') && VALUE_FLAGS.contains(&flag)
}

fn execute(cli: Cli) -> Result<(), CliError> {
    logging::init_with(cli.log_format, cli.log_level.as_deref())?;
    // Both modes already run in the foreground; the flag is accepted for
    // unit files and container entrypoints (08 §3).
    let _ = cli.foreground;

    match cli.command {
        Command::Client(args) => run_client(args),
        Command::Server(args) => run_server(args),
        Command::Status(args) => run_status(args),
        Command::DebugState(args) => run_debug_state(args),
        Command::DebugManifestDiff(args) => run_manifest_diff(args),
        Command::DebugSeqGaps(args) => run_seq_gaps(args),
        Command::DebugConntrace(args) => run_conntrace(args),
    }
}

// ---------------------------------------------------------------------------
// client
// ---------------------------------------------------------------------------

#[cfg(not(feature = "fuse"))]
fn run_client(args: ClientArgs) -> Result<(), CliError> {
    let _ = args;
    Err(CliError::Startup(
        "this build has no FUSE support; rebuild with the `fuse` feature".to_owned(),
    ))
}

#[cfg(feature = "fuse")]
fn run_client(args: ClientArgs) -> Result<(), CliError> {
    run_client_fuse(args)
}

#[cfg(feature = "fuse")]
fn run_client_fuse(args: ClientArgs) -> Result<(), CliError> {
    if args.key.is_some() {
        return Err(CliError::Usage(
            "`--key` is refused: a master password in argv is visible in `ps` and shell \
             history; use SYNCMOUNT_MASTER_PASSWORD or --key-file"
                .to_owned(),
        ));
    }
    // Fail before the Argon2id derivation when the host cannot mount at all.
    check_fuse_prerequisites(args.allow_other)?;

    let endpoint = ClientEndpoint::parse(&args.url)
        .map_err(|error| CliError::Usage(format!("invalid URL `{}`: {error}", args.url)))?;
    let cluster = default_cluster();
    let master = load_master(&cluster, args.key_file.as_deref())?;
    let ring = Arc::new(
        master
            .derive_keyring(&cluster)
            .map_err(|error| CliError::Startup(format!("key derivation failed: {error}")))?,
    );
    let signing = SigningKey::load_or_create(&cluster)
        .map_err(|error| CliError::Startup(format!("identity: {error}")))?;
    let client_id = signing.client_id();
    let signing = Arc::new(signing);

    let config = ClientConfig::new(endpoint, args.mountpoint.clone(), client_id)
        .map(|config| config.with_allow_empty_view(args.allow_empty_view))
        .map_err(|error| CliError::Startup(format!("configuration: {error}")))?;
    let mount_id = config.mount_id.clone();

    tracing::info!(
        event = "starting",
        mode = "client",
        mount_id = %mount_id,
        mountpoint = %args.mountpoint.display(),
        cluster = %cluster,
        allow_other = args.allow_other,
        allow_empty_view = args.allow_empty_view,
        "starting syncmount client"
    );

    let client = Client::new(config)
        .with_cluster(cluster)
        .with_allow_other(args.allow_other)
        .with_join_auth(Arc::new(master), Arc::clone(&signing))
        // Build the relay cache and tree from the root `mount_fuse` opens
        // after the stale-mount cleanup; a pre-cleanup descriptor could point
        // at a stale mount.
        .with_relay(true);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| CliError::Startup(format!("cannot start the async runtime: {error}")))?;

    let code = runtime
        .block_on(client.run_with_identity(ring, signing))
        .map_err(|error| CliError::Startup(error.to_string()))?;

    if code == 0 {
        Ok(())
    } else {
        Err(CliError::Exit(u8::try_from(code).unwrap_or(EXIT_STARTUP)))
    }
}

/// Domain separator shared by every cluster-id derivation.
const CLUSTER_DOMAIN: &[u8] = b"sm/v1/cluster\0";

/// Derive the legacy 16-byte cluster id from the normalised endpoint.
///
/// Clients no longer use this id: they all use [`default_cluster`], so the
/// URL spelling is only a connection target. The function is kept for
/// `debug-manifest-diff --url`, which reads caches written before the
/// fixed-identity cutover.
pub fn cluster_for(endpoint: &ClientEndpoint) -> ClusterId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CLUSTER_DOMAIN);
    hasher.update(endpoint.scheme.as_str().as_bytes());
    hasher.update(b"://");
    hasher.update(endpoint.authority().as_bytes());
    hasher.update(endpoint.prefix.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; ClusterId::LEN];
    bytes.copy_from_slice(&digest.as_bytes()[..ClusterId::LEN]);
    ClusterId::from_bytes(bytes)
}

/// The one cluster identity every client uses.
///
/// `BLAKE3("sm/v1/cluster\0" ‖ "default")[0..16]`: no URL component enters
/// the hash, so the key-derivation salt is fixed and the URL only chooses the
/// connection target. The server still uses the URL path as its namespace.
pub fn default_cluster() -> ClusterId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CLUSTER_DOMAIN);
    hasher.update(b"default");
    let digest = hasher.finalize();
    let mut bytes = [0u8; ClusterId::LEN];
    bytes.copy_from_slice(&digest.as_bytes()[..ClusterId::LEN]);
    ClusterId::from_bytes(bytes)
}

#[cfg(feature = "fuse")]
fn load_master(cluster: &ClusterId, key_file: Option<&Path>) -> Result<MasterKey, CliError> {
    if let Some(path) = key_file {
        let password = read_password_file(path)?;
        return MasterKey::derive_from_password(&password, cluster)
            .map_err(|error| CliError::Startup(format!("master password: {error}")));
    }

    // The environment file is re-checked here even though the secret module
    // also reads it: a world-readable credential file must fail before any
    // key material exists (39 §2.7).
    if std::env::var_os(crate::client::config::ENV_MASTER_PASSWORD).is_none() {
        if let Some(path) = std::env::var_os(crate::client::config::ENV_MASTER_PASSWORD_FILE) {
            let path = PathBuf::from(path);
            check_password_file(&path)?;
        }
    }

    if !has_password_source() {
        return Err(CliError::Startup(format!(
            "no master password source: set {}, {} (mode 0600), or run on a terminal",
            crate::client::config::ENV_MASTER_PASSWORD,
            crate::client::config::ENV_MASTER_PASSWORD_FILE
        )));
    }

    MasterKey::load(cluster).map_err(|error| CliError::Startup(format!("master password: {error}")))
}

#[cfg(feature = "fuse")]
fn has_password_source() -> bool {
    if std::env::var_os(crate::client::config::ENV_MASTER_PASSWORD).is_some()
        || std::env::var_os(crate::client::config::ENV_MASTER_PASSWORD_FILE).is_some()
    {
        return true;
    }
    std::io::stdin().is_terminal() || fs::OpenOptions::new().read(true).open("/dev/tty").is_ok()
}

#[cfg(feature = "fuse")]
fn check_password_file(path: &Path) -> Result<(), CliError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        CliError::Startup(format!(
            "cannot read master password file {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.file_type().is_file() {
        return Err(CliError::Startup(format!(
            "master password file {} is not a regular file",
            path.display()
        )));
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(CliError::Startup(format!(
            "master password file {} has mode {:o}; require 0600",
            path.display(),
            metadata.mode() & 0o777
        )));
    }
    if metadata.uid() != rustix::process::geteuid().as_raw() {
        return Err(CliError::Startup(format!(
            "master password file {} is not owned by the current user",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(feature = "fuse")]
fn read_password_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, CliError> {
    check_password_file(path)?;
    let mut bytes = Zeroizing::new(fs::read(path).map_err(|error| {
        CliError::Startup(format!(
            "cannot read master password file {}: {error}",
            path.display()
        ))
    })?);
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    if bytes.is_empty() {
        return Err(CliError::Startup(format!(
            "master password file {} is empty",
            path.display()
        )));
    }
    Ok(bytes)
}

#[cfg(feature = "fuse")]
fn check_fuse_prerequisites(allow_other: bool) -> Result<(), CliError> {
    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(FUSE_DEVICE)
        .map_err(|error| {
            CliError::Startup(format!(
                "cannot open {FUSE_DEVICE}: {error}; load the `fuse` kernel module and \
                 grant the device to the mounting user"
            ))
        })?;

    if fusermount_path().is_none() {
        return Err(CliError::Startup(
            "`fusermount3` was not found in PATH; install fuse3".to_owned(),
        ));
    }

    if allow_other && !user_allow_other() {
        return Err(CliError::Startup(format!(
            "`--allow-other` requires `user_allow_other` in {FUSE_CONF}"
        )));
    }
    Ok(())
}

#[cfg(feature = "fuse")]
fn fusermount_path() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("FUSERMOUNT_PATH") {
        return Some(PathBuf::from(path));
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|directory| directory.join("fusermount3"))
        .find(|candidate| candidate.is_file())
}

#[cfg(feature = "fuse")]
fn user_allow_other() -> bool {
    fs::read_to_string(FUSE_CONF)
        .map(|text| {
            text.lines()
                .map(str::trim)
                .any(|line| line == "user_allow_other")
        })
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// server
// ---------------------------------------------------------------------------

fn run_server(args: ServerArgs) -> Result<(), CliError> {
    let endpoint = ClientEndpoint::parse(&args.url)
        .map_err(|error| CliError::Usage(format!("invalid URL `{}`: {error}", args.url)))?;

    let listen = resolve_listen(args.listen.as_deref(), args.port)?;
    let mut config = ServeConfig::new(listen);
    config.namespace = if endpoint.prefix.is_empty() {
        "/".to_owned()
    } else {
        endpoint.prefix.clone()
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| CliError::Startup(format!("cannot start the async runtime: {error}")))?;

    runtime.block_on(async move {
        let server = Server::bind(config.clone())
            .await
            .map_err(|error| CliError::Startup(format!("cannot bind {listen}: {error}")))?;
        let addr = server.local_addr().map_err(|error| {
            CliError::Startup(format!("cannot read the listen address: {error}"))
        })?;

        tracing::info!(
            event = "listening",
            addr = %addr,
            namespace = %config.namespace,
            "syncmount server listening"
        );

        server.run_with_shutdown(shutdown_signal()).await;
        tracing::info!(event = "stopped", "syncmount server stopped");
        Ok(())
    })
}

fn resolve_listen(listen: Option<&str>, port: Option<u16>) -> Result<SocketAddr, CliError> {
    let text = match (listen, port) {
        (Some(text), _) => text.to_owned(),
        (None, Some(port)) => format!("127.0.0.1:{port}"),
        (None, None) => DEFAULT_LISTEN.to_owned(),
    };
    if let Ok(addr) = text.parse::<SocketAddr>() {
        return Ok(addr);
    }
    text.to_socket_addrs()
        .map_err(|error| CliError::Usage(format!("invalid listen address `{text}`: {error}")))?
        .next()
        .ok_or_else(|| CliError::Usage(format!("listen address `{text}` resolved to nothing")))
}

async fn shutdown_signal() {
    let interrupt = tokio::signal::ctrl_c();
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    tokio::select! {
        _ = interrupt => {}
        _ = terminate => {}
    }
}

// ---------------------------------------------------------------------------
// status and debug
// ---------------------------------------------------------------------------

/// One published status document.
#[derive(Debug)]
struct Instance {
    mount_id: String,
    document: Value,
}

fn run_status(args: StatusArgs) -> Result<(), CliError> {
    let instances = read_instances(args.mount_id.as_deref())?;
    if instances.is_empty() {
        return Err(CliError::Unavailable(match args.mount_id {
            Some(id) => format!(
                "no status file for mount id `{id}` under {}",
                base_dir().display()
            ),
            None => format!("no running syncmount client under {}", base_dir().display()),
        }));
    }

    if args.json {
        let documents: Vec<&Value> = instances
            .iter()
            .map(|instance| &instance.document)
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&documents)
                .map_err(|error| CliError::Startup(format!("cannot encode status: {error}")))?
        );
        return Ok(());
    }

    for instance in &instances {
        let doc = &instance.document;
        let state = string_at(doc, &["state"]).unwrap_or("UNKNOWN");
        let applied = number_at(doc, &["applied_seq"]).unwrap_or(0);
        let epoch = number_at(doc, &["epoch"]).unwrap_or(0);
        let outbox_ops = number_at(doc, &["outbox", "ops"]).unwrap_or(0);
        let outbox_bytes = number_at(doc, &["outbox", "bytes"]).unwrap_or(0);
        let pending = number_at(doc, &["replay", "pending"]).unwrap_or(0);
        let resyncs = number_at(doc, &["replay", "resyncs"]).unwrap_or(0);
        let diverged = doc
            .get("replay")
            .and_then(|value| value.get("diverged"))
            .and_then(Value::as_bool)
            .unwrap_or(false);

        println!(
            "{:<16} state={:<10} applied_seq={:<12} epoch={} outbox={}ops/{}B pending={} resyncs={} diverged={}",
            instance.mount_id,
            state,
            applied,
            epoch,
            outbox_ops,
            outbox_bytes,
            pending,
            resyncs,
            diverged
        );
    }
    Ok(())
}

fn run_debug_state(args: DebugArgs) -> Result<(), CliError> {
    let instances = read_instances(args.mount_id.as_deref())?;
    if instances.is_empty() {
        return Err(CliError::Unavailable(format!(
            "no running syncmount client under {}",
            base_dir().display()
        )));
    }
    for instance in &instances {
        if !args.json {
            println!("## {}", instance.mount_id);
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&instance.document)
                .map_err(|error| CliError::Startup(format!("cannot encode state: {error}")))?
        );
    }
    Ok(())
}

fn run_conntrace(args: ConntraceArgs) -> Result<(), CliError> {
    let instances = read_instances(args.mount_id.as_deref())?;
    if instances.is_empty() {
        return Err(CliError::Unavailable(format!(
            "no running syncmount client under {}",
            base_dir().display()
        )));
    }
    for instance in &instances {
        println!("## {}", instance.mount_id);
        let entries = instance
            .document
            .get("conntrace")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let start = entries.len().saturating_sub(args.limit);
        for entry in &entries[start..] {
            println!(
                "{} {:>4} {:<12} {:>6}B seq={}",
                entry.get("at_us").and_then(Value::as_i64).unwrap_or(0),
                entry.get("dir").and_then(Value::as_str).unwrap_or("?"),
                entry.get("kind").and_then(Value::as_str).unwrap_or("?"),
                entry.get("bytes").and_then(Value::as_u64).unwrap_or(0),
                entry.get("seq").and_then(Value::as_u64).unwrap_or(0),
            );
        }
    }
    Ok(())
}

fn run_seq_gaps(args: DebugArgs) -> Result<(), CliError> {
    let instances = read_instances(args.mount_id.as_deref())?;
    if instances.is_empty() {
        return Err(CliError::Unavailable(format!(
            "no running syncmount client under {}",
            base_dir().display()
        )));
    }

    let mut reports = Vec::new();
    for instance in &instances {
        let applied = number_at(&instance.document, &["applied_seq"]).unwrap_or(0);
        let mut seqs: Vec<u64> = instance
            .document
            .get("conntrace")
            .and_then(Value::as_array)
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(|entry| entry.get("seq").and_then(Value::as_u64))
                    .filter(|seq| *seq != 0)
                    .collect()
            })
            .unwrap_or_default();
        seqs.sort_unstable();
        seqs.dedup();

        let mut gaps: Vec<(u64, u64)> = Vec::new();
        for pair in seqs.windows(2) {
            if pair[1] > pair[0] + 1 {
                gaps.push((pair[0] + 1, pair[1] - 1));
            }
        }
        let gap_count: u64 = gaps.iter().map(|(first, last)| last - first + 1).sum();
        reports.push(serde_json::json!({
            "mount_id": instance.mount_id,
            "applied_seq": applied,
            "observed_frames": seqs.len(),
            "first_gap": gaps.first().map(|(first, _)| *first),
            "last_gap": gaps.last().map(|(_, last)| *last),
            "gap_count": gap_count,
            "gaps": gaps,
        }));
    }

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&reports)
                .map_err(|error| CliError::Startup(format!("cannot encode gaps: {error}")))?
        );
    } else {
        for report in &reports {
            let mount_id = report["mount_id"].as_str().unwrap_or("?");
            let gap_count = report["gap_count"].as_u64().unwrap_or(0);
            if gap_count == 0 {
                println!("{mount_id}: no seq gaps in the connection trace");
            } else {
                println!(
                    "{mount_id}: {} missing seq(s), first_gap={} last_gap={}",
                    gap_count, report["first_gap"], report["last_gap"]
                );
            }
        }
    }
    Ok(())
}

fn run_manifest_diff(args: ManifestDiffArgs) -> Result<(), CliError> {
    let cluster = match (args.cluster.as_deref(), args.url.as_deref()) {
        (Some(text), _) => parse_cluster_hex(text)?,
        (None, Some(url)) => {
            let endpoint = ClientEndpoint::parse(url)
                .map_err(|error| CliError::Usage(format!("invalid URL `{url}`: {error}")))?;
            cluster_for(&endpoint)
        }
        (None, None) => {
            return Err(CliError::Usage(
                "debug-manifest-diff needs --url URL or --cluster HEX to identify the cluster"
                    .to_owned(),
            ));
        }
    };

    let left = load_manifest(&args.mountpoint, cluster)?;
    if let Some(other) = &args.other {
        let right = load_manifest(other, cluster)?;
        print_manifest_diff(&left, &right);
    } else {
        println!(
            "{}: entries={} at_seq={} epoch={} cluster={}",
            args.mountpoint.display(),
            left.manifest.len(),
            left.at_seq.get(),
            left.epoch,
            left.cluster_id
        );
    }
    Ok(())
}

fn parse_cluster_hex(text: &str) -> Result<ClusterId, CliError> {
    let bytes = hex::decode(text)
        .map_err(|error| CliError::Usage(format!("invalid --cluster `{text}`: {error}")))?;
    let bytes: [u8; ClusterId::LEN] = bytes.try_into().map_err(|_| {
        CliError::Usage(format!(
            "invalid --cluster `{text}`: require {} hex characters",
            ClusterId::LEN * 2
        ))
    })?;
    Ok(ClusterId::from_bytes(bytes))
}

fn load_manifest(mountpoint: &Path, cluster: ClusterId) -> Result<LocalManifest, CliError> {
    let root = RootFd::open_before_mount(mountpoint).map_err(|error| {
        CliError::Startup(format!("cannot open {}: {error}", mountpoint.display()))
    })?;
    LocalManifest::load(&root, cluster).ok_or_else(|| {
        CliError::Unavailable(format!(
            "no local manifest cache at {} for cluster {cluster}; the client writes it after a JOIN",
            mountpoint.display()
        ))
    })
}

fn print_manifest_diff(left: &LocalManifest, right: &LocalManifest) {
    use std::collections::BTreeMap;

    let left_entries: BTreeMap<&str, _> = left
        .manifest
        .entries()
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect();
    let right_entries: BTreeMap<&str, _> = right
        .manifest
        .entries()
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect();

    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut changed = Vec::new();
    for (path, entry) in &right_entries {
        match left_entries.get(*path) {
            None => added.push(*path),
            Some(old) if *old != *entry => changed.push(*path),
            Some(_) => {}
        }
    }
    for path in left_entries.keys() {
        if !right_entries.contains_key(*path) {
            removed.push(*path);
        }
    }

    println!(
        "added={} removed={} changed={} (left at_seq={} right at_seq={})",
        added.len(),
        removed.len(),
        changed.len(),
        left.at_seq.get(),
        right.at_seq.get()
    );
    print_paths("added", &added);
    print_paths("removed", &removed);
    print_paths("changed", &changed);
}

fn print_paths(label: &str, paths: &[&str]) {
    const LIMIT: usize = 20;
    for path in paths.iter().take(LIMIT) {
        println!("{label}\t{path}");
    }
    if paths.len() > LIMIT {
        println!("{label}\t… {} more", paths.len() - LIMIT);
    }
}

fn read_instances(filter: Option<&str>) -> Result<Vec<Instance>, CliError> {
    let base = base_dir();
    let entries = match fs::read_dir(&base) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(CliError::Startup(format!(
                "cannot read {}: {error}",
                base.display()
            )));
        }
    };

    let mut instances = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(_) => continue,
        };
        if !file_type.is_dir() {
            continue;
        }
        let Some(mount_id) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if filter.is_some_and(|wanted| wanted != mount_id) {
            continue;
        }

        let path = entry.path().join(runtime_dir::STATUS_FILE);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        if metadata.mode() & 0o777 != 0o600 {
            eprintln!(
                "syncmount: ignoring {}: mode {:o}, require 0600",
                path.display(),
                metadata.mode() & 0o777
            );
            continue;
        }
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) => {
                eprintln!("syncmount: ignoring {}: {error}", path.display());
                continue;
            }
        };
        match serde_json::from_slice::<Value>(&bytes) {
            Ok(document) => instances.push(Instance { mount_id, document }),
            Err(error) => {
                eprintln!("syncmount: ignoring {}: {error}", path.display());
            }
        }
    }
    instances.sort_by(|a, b| a.mount_id.cmp(&b.mount_id));
    Ok(instances)
}

fn base_dir() -> PathBuf {
    RuntimeDir::base()
}

fn string_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_str()
}

fn number_at(value: &Value, path: &[&str]) -> Option<u64> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_u64()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn argv(items: &[&str]) -> Vec<OsString> {
        items.iter().map(OsString::from).collect()
    }

    #[test]
    fn u_implicit_client_alias() {
        let mut args = argv(&["syncmount", "http://127.0.0.1:8080/sync", "/mnt/x"]);
        normalize_args(&mut args);
        assert_eq!(args[1], "client");
        assert_eq!(args[2], "http://127.0.0.1:8080/sync");
    }

    #[test]
    fn u_implicit_server_alias() {
        let mut args = argv(&["syncmount", "http://127.0.0.1:8080/sync"]);
        normalize_args(&mut args);
        assert_eq!(args[1], "server");
    }

    #[test]
    fn u_implicit_alias_skips_flag_values() {
        let mut args = argv(&[
            "syncmount",
            "--log-level",
            "debug",
            "http://127.0.0.1:8080/sync",
            "/mnt/x",
        ]);
        normalize_args(&mut args);
        assert_eq!(args[1], "--log-level");
        assert_eq!(args[3], "client");
    }

    #[test]
    fn u_explicit_subcommand_is_untouched() {
        let mut args = argv(&["syncmount", "status", "--json"]);
        normalize_args(&mut args);
        assert_eq!(args[1], "status");
    }

    #[test]
    fn u_legacy_cluster_id_is_stable_and_url_scoped() {
        let first = ClientEndpoint::parse("http://127.0.0.1:8080/sync").unwrap();
        let same = ClientEndpoint::parse("http://127.0.0.1:8080/sync").unwrap();
        let other = ClientEndpoint::parse("http://127.0.0.1:8080/other").unwrap();
        assert_eq!(cluster_for(&first), cluster_for(&same));
        assert_ne!(cluster_for(&first), cluster_for(&other));
    }

    /// Every client uses one fixed id: no URL component enters the hash, so
    /// scheme, host, port, and prefix only pick the connection target. The
    /// value is pinned because any change would silently move every existing
    /// cluster to a new identity.
    #[test]
    fn u_default_cluster_is_fixed_and_url_independent() {
        assert_eq!(
            default_cluster().to_string(),
            "60ce80b3c33bdf8b763af7464ad131da"
        );
        let plain = ClientEndpoint::parse("http://127.0.0.1:8080/sync").unwrap();
        let tls = ClientEndpoint::parse("https://edge.example:8443/other").unwrap();
        // The legacy derivation still tracks the URL, which is why the client
        // no longer uses it.
        assert_ne!(cluster_for(&plain), cluster_for(&tls));
        assert_ne!(default_cluster(), cluster_for(&plain));
    }

    /// The URL-derived id survives only for `debug-manifest-diff --url`,
    /// which reads caches written before the fixed-identity cutover.
    #[test]
    fn u_legacy_cluster_for_is_pinned() {
        let endpoint = ClientEndpoint::parse("http://127.0.0.1:8080/sync").unwrap();
        assert_eq!(
            cluster_for(&endpoint).to_string(),
            "208d2aa1f256c95fcfa7e455337b46dc"
        );
    }

    #[test]
    fn u_cluster_name_flag_is_rejected() {
        let parsed = Cli::try_parse_from(argv(&[
            "syncmount",
            "client",
            "--cluster-name",
            "prod",
            "http://127.0.0.1:8080/sync",
            "/mnt/x",
        ]));
        assert!(parsed.is_err());
    }

    #[test]
    fn u_listen_resolution() {
        assert_eq!(
            resolve_listen(Some("0.0.0.0:9000"), None).unwrap(),
            "0.0.0.0:9000".parse().unwrap()
        );
        assert_eq!(
            resolve_listen(None, Some(9100)).unwrap(),
            "127.0.0.1:9100".parse().unwrap()
        );
        assert_eq!(
            resolve_listen(None, None).unwrap(),
            DEFAULT_LISTEN.parse().unwrap()
        );
    }
}
