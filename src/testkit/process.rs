//! 进程级测试编排：真实子进程、FUSE 预检与挂载守卫。
//!
//! 本模块只做三件事：
//!
//! 1. [`fuse_probe`] / [`require_fuse`]：按 45 §5.1 的顺序探测 FUSE 环境；
//! 2. [`ProcessCluster`]：启动真实 `syncmount server` 与若干 `syncmount client`
//!    子进程，用 `/proc/mounts` + `status.json` 判定就绪；
//! 3. [`MountGuard`]：单个挂载的 RAII 守卫，Drop 时按 SIGTERM →
//!    `fusermount3 -u` → `-uz` → `umount -l` 的顺序清理。
//!
//! # 归属约定
//!
//! `tokio::process` 与 `tokio::fs` 未启用，因此全部使用 `std::process` /
//! `std::fs`。等待用带截止时间的轮询，固定 sleep 从不充当同步原语。
//! [`ProcessCluster`] 保存每个客户端的 pid，并用 `waitpid(WNOHANG)` 收尸；
//! [`MountedClient`] 里的 `Child` 只是调用方观察用的句柄，**不要**对它调用
//! `wait`/`try_wait`——那会与集群的收尸竞争。反过来，集群的 `unmount` 返回
//! 真实的退出状态，不需要调用方再等一次。
//!
//! # 就绪判定
//!
//! server：JSON 日志出现 `event=listening` 的 `addr`；client：挂载点出现在
//! `/proc/mounts`，且运行目录里的 `status.json` 为 `STEADY`。超时错误带上
//! 日志尾部，避免“绿但没跑”与“红了不知为何”。
//!
//! # 已知取舍
//!
//! * `fuse` feature 关闭时无法构造最小 fuser 会话，探测只做结构性检查；
//!   `cfg!(test)` 的单元测试构建同样跳过试挂载（单元测试不得挂载 FUSE）。
//! * [`MountGuard`] 额外保存 `run_dir`/`log` 两个私有字段，`wait_steady`
//!   与错误信息需要它们；公开字段与契约一致。

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::net::SocketAddr;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::client::config::{ENV_MASTER_PASSWORD, ENV_RUN_DIR};

/// server 打印 `listening` 的等待上限。
const SERVER_READY: Duration = Duration::from_secs(10);
/// client 进入 STEADY 的等待上限。
const CLIENT_READY: Duration = Duration::from_secs(20);
/// 轮询间隔。
const POLL: Duration = Duration::from_millis(20);
/// 显式卸载时等待进程退出的宽限。
const UNMOUNT_GRACE: Duration = Duration::from_secs(5);
/// Drop 中等待进程退出的宽限（45 §5.3：SIGTERM 后最多等 5s）。
const DROP_GRACE: Duration = Duration::from_secs(5);
/// 状态文件名（与 `store::runtime_dir` 一致）。
const STATUS_FILE: &str = "status.json";
/// 生命周期稳态名。
const STEADY: &str = "STEADY";
/// 首选卸载工具。
const FUSERMOUNT: &str = "fusermount3";
/// 覆盖 `fusermount3` 路径的环境变量。
const ENV_FUSERMOUNT: &str = "FUSERMOUNT_PATH";
/// 置 1 时，FUSE 不可用即失败而不是跳过。
const ENV_REQUIRE_FUSE: &str = "SYNCMOUNT_REQUIRE_FUSE";
/// skip 记录文件（相对 crate 根）。
const SKIP_ARTIFACT: &str = "target/test-artifacts/fuse-skips.jsonl";
/// 日志尾部最多回显的字节数。
const LOG_TAIL_BYTES: usize = 4096;

// ---------------------------------------------------------------------------
// FUSE 预检
// ---------------------------------------------------------------------------

/// FUSE 不可用的原因。
#[derive(Debug)]
pub enum FuseSkip {
    /// 非 Linux。
    NotLinux,
    /// `/dev/fuse` 缺失或不是字符设备。
    NoDevFuse,
    /// `/dev/fuse` 存在但打不开（EACCES/ENOENT/…）。
    DevFuseUnopenable(std::io::Error),
    /// 找不到可执行的 `fusermount3`。
    NoFusermount,
    /// `fusermount3` 没有 setuid 位，且当前用户不是 root。
    FusermountNotSetuid,
    /// 结构性检查通过，但试挂载失败（AppArmor/seccomp/内核拒绝）。
    ProbeMountFailed(String),
}

impl std::fmt::Display for FuseSkip {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotLinux => write!(f, "not Linux"),
            Self::NoDevFuse => write!(f, "/dev/fuse is missing or not a character device"),
            Self::DevFuseUnopenable(err) => write!(f, "/dev/fuse cannot be opened: {err}"),
            Self::NoFusermount => write!(f, "fusermount3 not found or not executable"),
            Self::FusermountNotSetuid => write!(
                f,
                "fusermount3 is not setuid and mount(2) needs CAP_SYS_ADMIN"
            ),
            Self::ProbeMountFailed(reason) => write!(f, "probe mount failed: {reason}"),
        }
    }
}

impl std::error::Error for FuseSkip {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::DevFuseUnopenable(err) => Some(err),
            _ => None,
        }
    }
}

/// 探测通过后交给测试的路径。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuseReady {
    /// `fusermount3` 可执行文件。
    pub fusermount: PathBuf,
    /// `/dev/fuse`。
    pub dev_fuse: PathBuf,
}

/// 一次探测的缓存结果：成功路径或（原因类别, 说明）。
#[derive(Debug)]
struct ProbeOutcome {
    ready: Option<FuseReady>,
    skip: Option<(&'static str, String)>,
}

/// 探测 FUSE 环境；同一进程只探测一次。
///
/// 顺序（短路）：Linux → `/dev/fuse` 字符设备且可读写打开 → `fusermount3`
/// 可执行 → setuid（或 root）→ 试挂载。任何一步失败都给出具体原因。
pub fn fuse_probe() -> Result<FuseReady, FuseSkip> {
    static PROBE: LazyLock<ProbeOutcome> = LazyLock::new(probe_once);
    let outcome = &*PROBE;
    if let Some(ready) = &outcome.ready {
        return Ok(ready.clone());
    }
    match &outcome.skip {
        Some((kind, message)) => Err(skip_from(kind, message.clone())),
        None => Err(FuseSkip::ProbeMountFailed(
            "probe produced no outcome".to_owned(),
        )),
    }
}

fn probe_once() -> ProbeOutcome {
    match probe() {
        Ok(ready) => ProbeOutcome {
            ready: Some(ready),
            skip: None,
        },
        Err(skip) => ProbeOutcome {
            ready: None,
            skip: Some((skip_kind(&skip), skip.to_string())),
        },
    }
}

fn probe() -> Result<FuseReady, FuseSkip> {
    if !cfg!(target_os = "linux") {
        return Err(FuseSkip::NotLinux);
    }
    let dev_fuse = PathBuf::from("/dev/fuse");
    let metadata = fs::metadata(&dev_fuse).map_err(|_| FuseSkip::NoDevFuse)?;
    if !metadata.file_type().is_char_device() {
        return Err(FuseSkip::NoDevFuse);
    }
    let _device = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&dev_fuse)
        .map_err(FuseSkip::DevFuseUnopenable)?;

    let fusermount = find_fusermount().ok_or(FuseSkip::NoFusermount)?;
    let metadata = fs::metadata(&fusermount).map_err(|_| FuseSkip::NoFusermount)?;
    if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err(FuseSkip::NoFusermount);
    }
    let setuid = metadata.permissions().mode() & 0o4000 != 0;
    if !setuid && !is_root() {
        return Err(FuseSkip::FusermountNotSetuid);
    }

    probe_mount()?;
    Ok(FuseReady {
        fusermount,
        dev_fuse,
    })
}

fn skip_kind(skip: &FuseSkip) -> &'static str {
    match skip {
        FuseSkip::NotLinux => "NotLinux",
        FuseSkip::NoDevFuse => "NoDevFuse",
        FuseSkip::DevFuseUnopenable(_) => "DevFuseUnopenable",
        FuseSkip::NoFusermount => "NoFusermount",
        FuseSkip::FusermountNotSetuid => "FusermountNotSetuid",
        FuseSkip::ProbeMountFailed(_) => "ProbeMountFailed",
    }
}

fn skip_from(kind: &str, message: String) -> FuseSkip {
    match kind {
        "NotLinux" => FuseSkip::NotLinux,
        "NoDevFuse" => FuseSkip::NoDevFuse,
        "DevFuseUnopenable" => FuseSkip::DevFuseUnopenable(io::Error::other(message)),
        "NoFusermount" => FuseSkip::NoFusermount,
        "FusermountNotSetuid" => FuseSkip::FusermountNotSetuid,
        _ => FuseSkip::ProbeMountFailed(message),
    }
}

fn is_root() -> bool {
    rustix::process::geteuid().as_raw() == 0
}

/// 找 `fusermount3`：`FUSERMOUNT_PATH` 优先，其次 `PATH`。
fn find_fusermount() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os(ENV_FUSERMOUNT) {
        let path = PathBuf::from(path);
        return path.is_file().then_some(path);
    }
    let path = std::env::var_os("PATH")?;
    for directory in std::env::split_paths(&path) {
        let candidate = directory.join(FUSERMOUNT);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// 用最小 fuser 会话试挂载一次，成功后立即卸载。
///
/// 单元测试构建（`cfg!(test)`）不挂载任何东西：45 §5.4 要求单元测试无
/// FUSE 副作用，而集成测试构建会走完整探测。
#[cfg(feature = "fuse")]
fn probe_mount() -> Result<(), FuseSkip> {
    if cfg!(test) {
        return Ok(());
    }
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(run_probe_mount());
    });
    match rx.recv_timeout(Duration::from_secs(5)) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(reason)) => Err(FuseSkip::ProbeMountFailed(reason)),
        Err(_) => Err(FuseSkip::ProbeMountFailed(
            "probe mount timed out after 5s".to_owned(),
        )),
    }
}

/// 没有 `fuse` feature 时没有 fuser 适配层，无法构造最小会话；只做结构性
/// 检查。FUSE 测试本身需要 `fuse-tests`（含 `fuse`），因此不损失覆盖面。
#[cfg(not(feature = "fuse"))]
fn probe_mount() -> Result<(), FuseSkip> {
    Ok(())
}

#[cfg(feature = "fuse")]
fn run_probe_mount() -> Result<(), String> {
    struct ProbeFs;

    impl fuser::Filesystem for ProbeFs {}

    let dir = tempfile::TempDir::new().map_err(|err| format!("tempdir: {err}"))?;
    let mut config = fuser::Config::default();
    config.mount_options = vec![
        fuser::MountOption::FSName("syncmount-probe".to_owned()),
        fuser::MountOption::RO,
        fuser::MountOption::NoDev,
        fuser::MountOption::NoSuid,
    ];
    config.acl = fuser::SessionACL::Owner;
    config.n_threads = Some(1);

    let session = fuser::spawn_mount(ProbeFs, dir.path(), &config)
        .map_err(|err| format!("mount {}: {err}", dir.path().display()))?;
    drop(session);

    let deadline = Instant::now() + Duration::from_secs(2);
    while mounted(dir.path()) && Instant::now() < deadline {
        std::thread::sleep(POLL);
    }
    if mounted(dir.path()) {
        let _ = force_unmount_sync(dir.path());
    }
    if mounted(dir.path()) {
        return Err(format!(
            "{} stayed mounted after the probe",
            dir.path().display()
        ));
    }
    Ok(())
}

/// 探测失败时的统一出口：`SYNCMOUNT_REQUIRE_FUSE=1` 失败，否则打印 SKIP、
/// 记录到 `target/test-artifacts/fuse-skips.jsonl` 并返回 `None`。
pub fn require_fuse() -> Option<FuseReady> {
    match fuse_probe() {
        Ok(ready) => Some(ready),
        Err(reason) => {
            if std::env::var(ENV_REQUIRE_FUSE).ok().as_deref() == Some("1") {
                panic!("FUSE required but unavailable: {reason}");
            }
            eprintln!("SKIP[FUSE] {reason}");
            record_skip(&reason);
            None
        }
    }
}

fn record_skip(reason: &FuseSkip) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(SKIP_ARTIFACT);
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let line = serde_json::json!({
        "kind": skip_kind(reason),
        "reason": reason.to_string(),
        "pid": std::process::id(),
        "unix_seconds": unix_seconds(),
    });
    let Ok(mut text) = serde_json::to_string(&line) else {
        return;
    };
    text.push('\n');
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&path) {
        let _ = file.write_all(text.as_bytes());
    }
}

fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// /proc/mounts
// ---------------------------------------------------------------------------

/// 解析 `/proc/mounts`，返回 `(挂载点, 文件系统类型)`。
///
/// 内核用 `\040`（空格）、`\011`（制表）、`\012`（换行）、`\134`（反斜杠）
/// 转义字段，因此按空白切分是安全的；任何 `\NNN` 八进制转义都还原。
pub fn parse_proc_mounts(text: &str) -> Vec<(PathBuf, String)> {
    let mut mounts = Vec::new();
    for line in text.lines() {
        let mut fields = line.split_ascii_whitespace();
        let Some(_source) = fields.next() else {
            continue;
        };
        let Some(mountpoint) = fields.next() else {
            continue;
        };
        let Some(fstype) = fields.next() else {
            continue;
        };
        mounts.push((
            PathBuf::from(unescape_mount_field(mountpoint)),
            fstype.to_owned(),
        ));
    }
    mounts
}

fn unescape_mount_field(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' && index + 3 < bytes.len() {
            let digits = &bytes[index + 1..index + 4];
            if digits.iter().all(|byte| (b'0'..=b'7').contains(byte)) {
                let value = digits
                    .iter()
                    .fold(0u32, |acc, byte| acc * 8 + u32::from(byte - b'0'));
                if let Ok(byte) = u8::try_from(value) {
                    out.push(byte);
                    index += 4;
                    continue;
                }
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// 路径当前是否是一个挂载点。
pub fn mounted(path: &Path) -> bool {
    let Ok(text) = fs::read_to_string("/proc/mounts") else {
        return false;
    };
    let canonical = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    parse_proc_mounts(&text)
        .into_iter()
        .any(|(mountpoint, _)| mountpoint.as_path() == path || mountpoint == canonical)
}

/// 断言路径不是挂载点；显式测试用，Drop 不用它。
pub fn assert_not_mounted(path: &Path) -> Result<(), ProcessError> {
    if mounted(path) {
        return Err(ProcessError::StillMounted(path.to_path_buf()));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 错误
// ---------------------------------------------------------------------------

/// 进程编排失败。
#[derive(Debug, thiserror::Error)]
pub enum ProcessError {
    /// 文件系统或系统调用失败。
    #[error("{context}: {source}")]
    Io {
        /// 失败的动作与对象。
        context: String,
        /// 底层错误。
        #[source]
        source: io::Error,
    },
    /// 子进程无法启动。
    #[error("cannot spawn `{program}`: {source}")]
    Spawn {
        /// 可执行文件。
        program: String,
        /// 底层错误。
        #[source]
        source: io::Error,
    },
    /// server 没有在截止时间内打印 `listening`。
    #[error("server did not report `listening` within {deadline:?}; log tail:\n{tail}")]
    ServerNotReady {
        /// 等待上限。
        deadline: Duration,
        /// 日志尾部。
        tail: String,
    },
    /// client 没有在截止时间内进入 STEADY。
    #[error("client `{name}` did not reach STEADY within {deadline:?}; log tail:\n{tail}")]
    ClientNotReady {
        /// 客户端名。
        name: String,
        /// 等待上限。
        deadline: Duration,
        /// 日志尾部。
        tail: String,
    },
    /// 集群里没有这个客户端。
    #[error("unknown client `{0}`")]
    UnknownClient(String),
    /// 同名客户端已经挂载。
    #[error("client `{0}` is already mounted")]
    AlreadyMounted(String),
    /// `status.json` 未在截止时间内满足谓词。
    #[error(
        "status for client `{name}` did not match within {deadline:?}; last={last:?}; \
         server log tail:\n{tail}"
    )]
    StatusNotReady {
        /// 客户端名。
        name: String,
        /// 等待上限。
        deadline: Duration,
        /// 最后一次读到的文档（JSON 文本）。
        last: Option<String>,
        /// server 日志尾部。
        tail: String,
    },
    /// 等待超时。
    #[error("timed out waiting for {what} after {deadline:?}")]
    Timeout {
        /// 等待对象。
        what: String,
        /// 等待上限。
        deadline: Duration,
    },
    /// 挂载点仍然存在。
    #[error("mountpoint `{0}` is still mounted")]
    StillMounted(PathBuf),
    /// 子进程已被集群之外的代码收尸。
    #[error("process {pid} was already reaped outside the harness")]
    Reaped {
        /// 进程号。
        pid: u32,
    },
    /// 阻塞任务失败。
    #[error("blocking task failed: {0}")]
    Task(String),
    /// server 日志里的监听地址无法解析。
    #[error("invalid listen address in the server log: `{0}`")]
    BadAddr(String),
}

fn io_error(context: impl Into<String>, source: io::Error) -> ProcessError {
    ProcessError::Io {
        context: context.into(),
        source,
    }
}

fn path_error(action: &str, path: &Path, source: io::Error) -> ProcessError {
    io_error(format!("{action} {}", path.display()), source)
}

// ---------------------------------------------------------------------------
// 进程编排
// ---------------------------------------------------------------------------

/// 集群启动参数。
pub struct ProcessSpec {
    /// 集群 URL。只有 scheme 与路径前缀参与客户端连接；主机与端口由 boot
    /// 解析到的实际监听地址替换。
    pub url: String,
    /// 所有临时目录与日志的根。
    pub run_root: PathBuf,
    /// 客户端主密码（测试夹具，不落盘）。
    pub master_password: String,
    /// `syncmount` 可执行文件。
    pub server_bin: PathBuf,
    /// 日志级别（同时写入 `--log-level` 与 `RUST_LOG`）。
    pub log_level: String,
    /// server 监听地址；`None` 表示 `127.0.0.1:0`（内核分配）。
    ///
    /// 固定端口用于“重启后仍是同一地址”的测试；随机端口避免并行测试冲突。
    pub listen: Option<SocketAddr>,
}

impl std::fmt::Debug for ProcessSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProcessSpec")
            .field("url", &self.url)
            .field("run_root", &self.run_root)
            .field("master_password", &"<redacted>")
            .field("server_bin", &self.server_bin)
            .field("log_level", &self.log_level)
            .field("listen", &self.listen)
            .finish()
    }
}

/// 集群里一个客户端的簿记；`Child` 交给调用方，这里只留 pid。
#[derive(Debug)]
struct ClientSlot {
    pid: u32,
    mountpoint: PathBuf,
    status: Option<ExitStatus>,
}

/// 一个已挂载的客户端。
#[derive(Debug)]
pub struct MountedClient {
    /// 客户端名（集群内唯一）。
    pub name: String,
    /// FUSE 挂载点，同时是本地 backing 根（45 §3.7）。
    pub mountpoint: PathBuf,
    /// 与 `mountpoint` 相同：卸载后就是普通目录。
    pub local_root: PathBuf,
    /// 子进程句柄；收尸由集群负责，见模块文档。
    pub child: Child,
    /// `SYNCMOUNT_RUN_DIR` 基目录。
    pub run_dir: PathBuf,
}

/// 真实 server + N 个真实 client 的进程集群。
pub struct ProcessCluster {
    url: String,
    run_root: PathBuf,
    binary: PathBuf,
    master_password: String,
    log_level: String,
    server: Child,
    server_addr: SocketAddr,
    server_log: PathBuf,
    listen: SocketAddr,
    server_generation: u32,
    clients: HashMap<String, ClientSlot>,
    failed_exits: HashMap<String, ExitStatus>,
    failed_status: HashMap<String, Value>,
}

impl std::fmt::Debug for ProcessCluster {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProcessCluster")
            .field("url", &self.url)
            .field("run_root", &self.run_root)
            .field("binary", &self.binary)
            .field("master_password", &"<redacted>")
            .field("log_level", &self.log_level)
            .field("server", &self.server)
            .field("server_addr", &self.server_addr)
            .field("server_log", &self.server_log)
            .field("listen", &self.listen)
            .field("clients", &self.clients)
            .finish()
    }
}

impl ProcessCluster {
    /// 启动 server 并等待它报告监听地址。
    pub async fn boot(spec: ProcessSpec) -> Result<Self, ProcessError> {
        let run_root = spec.run_root.clone();
        fs::create_dir_all(&run_root)
            .map_err(|err| path_error("create run root", &run_root, err))?;
        let server_dir = run_root.join("server");
        fs::create_dir_all(&server_dir)
            .map_err(|err| path_error("create server directory", &server_dir, err))?;
        let server_log = server_dir.join("server.log");

        let (scheme, prefix) = split_url(&spec.url);
        let listen = spec
            .listen
            .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 0)));
        let mut server = spawn_server(
            &spec.server_bin,
            &spec.url,
            listen,
            &server_log,
            &spec.log_level,
            &run_root,
        )?;

        let server_addr = match wait_server(&mut server, &server_log, SERVER_READY).await {
            Ok(addr) => addr,
            Err(err) => {
                stop_child_async(&mut server, DROP_GRACE).await;
                return Err(err);
            }
        };

        let url = format!("{scheme}://{server_addr}{prefix}");
        Ok(Self {
            url,
            run_root,
            binary: spec.server_bin,
            master_password: spec.master_password,
            log_level: spec.log_level,
            server,
            server_addr,
            server_log,
            listen,
            server_generation: 0,
            clients: HashMap::new(),
            failed_exits: HashMap::new(),
            failed_status: HashMap::new(),
        })
    }

    /// 启动并等待一个客户端进入 STEADY。
    pub async fn mount_client(&mut self, name: &str) -> Result<MountedClient, ProcessError> {
        self.mount_client_with_deadline(name, CLIENT_READY).await
    }

    /// [`ProcessCluster::mount_client`] 带显式就绪上限。
    ///
    /// JOIN 在 `current_seq > 0` 且没有视图时会按 1/2/4/8/16 s 重试，
    /// 31 s 后才拒绝；失败路径测试必须给足这个预算。
    pub async fn mount_client_with_deadline(
        &mut self,
        name: &str,
        deadline: Duration,
    ) -> Result<MountedClient, ProcessError> {
        if self.clients.contains_key(name) {
            return Err(ProcessError::AlreadyMounted(name.to_owned()));
        }
        let dir = self.run_root.join("clients").join(name);
        let mountpoint = dir.join("mnt");
        let run_dir = dir.join("run");
        // 每个客户端独立的 XDG_STATE_HOME：签名密钥按 cluster 落盘，共用
        // 状态目录会让两个客户端拿到同一个 client_id，server 随后以
        // `DuplicateClient` 踢掉先加入者。
        let state_home = dir.join("state");
        for path in [&dir, &mountpoint, &run_dir, &state_home] {
            fs::create_dir_all(path)
                .map_err(|err| path_error("create client directory", path, err))?;
        }
        // 上一轮的生命周期文档可能是 STEADY；清掉它，避免把旧状态当成新进程
        // 的就绪信号。
        clear_status(&run_dir);

        let log = run_dir.join(format!("{name}.log"));
        let mut child = spawn_client(ClientSpawn {
            binary: &self.binary,
            url: &self.url,
            mountpoint: &mountpoint,
            run_dir: &run_dir,
            state_home: &state_home,
            password: &self.master_password,
            log: &log,
            level: &self.log_level,
        })?;

        match wait_client(&mut child, name, &mountpoint, &run_dir, &log, deadline).await {
            Ok(()) => {
                let pid = child.id();
                self.clients.insert(
                    name.to_owned(),
                    ClientSlot {
                        pid,
                        mountpoint: mountpoint.clone(),
                        status: None,
                    },
                );
                Ok(MountedClient {
                    name: name.to_owned(),
                    mountpoint: mountpoint.clone(),
                    local_root: mountpoint,
                    child,
                    run_dir,
                })
            }
            Err(err) => {
                // 先记录证据再清理：`stop_child_async` 会收尸，之后既拿不到
                // 退出码，也可能错过最后一份 status.json。
                if let Some(status) = child.try_wait().ok().flatten() {
                    self.failed_exits.insert(name.to_owned(), status);
                }
                if let Some(document) = self.read_status_at(&mountpoint, name) {
                    self.failed_status.insert(name.to_owned(), document);
                }
                stop_child_async(&mut child, DROP_GRACE).await;
                let _ = wait_unmounted(&mountpoint, DROP_GRACE).await;
                let _ = force_unmount(mountpoint.clone()).await;
                Err(err)
            }
        }
    }

    /// SIGTERM → 等退出 → 必要时 SIGKILL → 强制卸载；返回真实退出状态。
    pub async fn unmount(&mut self, name: &str) -> Result<ExitStatus, ProcessError> {
        let (pid, mountpoint, recorded) = {
            let slot = self
                .clients
                .get(name)
                .ok_or_else(|| ProcessError::UnknownClient(name.to_owned()))?;
            (slot.pid, slot.mountpoint.clone(), slot.status)
        };

        let status = match recorded {
            Some(status) => status,
            None => {
                let status = match reap(pid)? {
                    // 已经退出：直接收尸，避免对可能被复用的 pid 发信号。
                    Reap::Status(status) => status,
                    Reap::Gone => return Err(ProcessError::Reaped { pid }),
                    Reap::Running => {
                        signal(pid, "-TERM");
                        match wait_pid(pid, UNMOUNT_GRACE).await? {
                            Some(status) => status,
                            None => {
                                signal(pid, "-KILL");
                                match wait_pid(pid, UNMOUNT_GRACE).await? {
                                    Some(status) => status,
                                    None => {
                                        return Err(ProcessError::Timeout {
                                            what: format!("client `{name}` to exit"),
                                            deadline: UNMOUNT_GRACE,
                                        });
                                    }
                                }
                            }
                        }
                    }
                };
                if let Some(slot) = self.clients.get_mut(name) {
                    slot.status = Some(status);
                }
                status
            }
        };

        wait_unmounted(&mountpoint, UNMOUNT_GRACE).await;
        force_unmount(mountpoint.clone()).await?;
        self.clients.remove(name);
        Ok(status)
    }

    /// SIGKILL 一个客户端并等待挂载消失。
    pub async fn kill9(&mut self, name: &str) -> Result<(), ProcessError> {
        let (pid, mountpoint, recorded) = {
            let slot = self
                .clients
                .get(name)
                .ok_or_else(|| ProcessError::UnknownClient(name.to_owned()))?;
            (slot.pid, slot.mountpoint.clone(), slot.status)
        };

        if recorded.is_none() {
            let status = match reap(pid)? {
                Reap::Status(status) => status,
                Reap::Gone => return Err(ProcessError::Reaped { pid }),
                Reap::Running => {
                    signal(pid, "-KILL");
                    wait_pid(pid, UNMOUNT_GRACE)
                        .await?
                        .ok_or_else(|| ProcessError::Timeout {
                            what: format!("client `{name}` to die"),
                            deadline: UNMOUNT_GRACE,
                        })?
                }
            };
            if let Some(slot) = self.clients.get_mut(name) {
                slot.status = Some(status);
            }
        }

        wait_unmounted(&mountpoint, UNMOUNT_GRACE).await;
        force_unmount(mountpoint).await?;
        Ok(())
    }

    /// 卸载后重新挂载（同一挂载点、同一 client_id、新会话）。
    ///
    /// 旧的 [`MountedClient`] 随卸载失效，调用方应丢弃它；集群只按 pid
    /// 管理进程，不会复活旧连接（S1：重连 = 重新挂载）。
    pub async fn remount(&mut self, name: &str) -> Result<MountedClient, ProcessError> {
        if self.clients.contains_key(name) {
            self.unmount(name).await?;
        }
        self.mount_client(name).await
    }

    /// 该客户端当前的 `status.json`；文件缺失或无法解析时为 `None`。
    pub fn read_status(&self, name: &str) -> Option<Value> {
        let mountpoint = self.client_mountpoint(name)?;
        self.read_status_at(&mountpoint, name)
    }

    fn client_mountpoint(&self, name: &str) -> Option<PathBuf> {
        if let Some(slot) = self.clients.get(name) {
            return Some(slot.mountpoint.clone());
        }
        let candidate = self.run_root.join("clients").join(name).join("mnt");
        candidate.is_dir().then_some(candidate)
    }

    fn read_status_at(&self, mountpoint: &Path, name: &str) -> Option<Value> {
        let path = self
            .run_root
            .join("clients")
            .join(name)
            .join("run")
            .join(crate::client::config::mount_id_for(mountpoint))
            .join(STATUS_FILE);
        let bytes = fs::read(path).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    /// 轮询 `status.json`，直到谓词成立或截止。
    pub async fn wait_status(
        &self,
        name: &str,
        deadline: Duration,
        mut predicate: impl FnMut(&Value) -> bool,
    ) -> Result<Value, ProcessError> {
        let start = Instant::now();
        let mut last = None;
        loop {
            if let Some(document) = self.read_status(name) {
                if predicate(&document) {
                    return Ok(document);
                }
                last = Some(document.to_string());
            }
            if start.elapsed() >= deadline {
                return Err(ProcessError::StatusNotReady {
                    name: name.to_owned(),
                    deadline,
                    last,
                    tail: tail(&self.server_log),
                });
            }
            tokio::time::sleep(POLL).await;
        }
    }

    /// 非阻塞查询客户端退出状态；`None` 表示仍在运行。
    pub fn try_exit(&mut self, name: &str) -> Result<Option<ExitStatus>, ProcessError> {
        let (pid, recorded) = {
            let slot = self
                .clients
                .get(name)
                .ok_or_else(|| ProcessError::UnknownClient(name.to_owned()))?;
            (slot.pid, slot.status)
        };
        if let Some(status) = recorded {
            return Ok(Some(status));
        }
        let status = match reap(pid)? {
            Reap::Status(status) => Some(status),
            Reap::Running => None,
            Reap::Gone => return Err(ProcessError::Reaped { pid }),
        };
        if let Some(status) = status {
            if let Some(slot) = self.clients.get_mut(name) {
                slot.status = Some(status);
            }
        }
        Ok(status)
    }

    /// `mount_client` 失败时记录的退出状态（进程已退出时）。
    pub fn failed_exit(&self, name: &str) -> Option<ExitStatus> {
        self.failed_exits.get(name).copied()
    }

    /// `mount_client` 失败时记录的最后一份 `status.json`。
    pub fn failed_status(&self, name: &str) -> Option<&Value> {
        self.failed_status.get(name)
    }

    /// server 当前（或最近一次重启）的日志文件。
    pub fn server_log(&self) -> &Path {
        &self.server_log
    }

    /// 用同一监听地址重启 server；客户端进程保留，由调用方观察断连或重挂载。
    pub async fn restart_server(&mut self) -> Result<(), ProcessError> {
        stop_child_async(&mut self.server, DROP_GRACE).await;
        self.server_generation = self.server_generation.saturating_add(1);
        let log = self
            .run_root
            .join("server")
            .join(format!("server-{}.log", self.server_generation));
        let (scheme, prefix) = split_url(&self.url);
        let mut child = spawn_server(
            &self.binary,
            &self.url,
            self.listen,
            &log,
            &self.log_level,
            &self.run_root,
        )?;
        let addr = match wait_server(&mut child, &log, SERVER_READY).await {
            Ok(addr) => addr,
            Err(err) => {
                stop_child_async(&mut child, DROP_GRACE).await;
                return Err(err);
            }
        };
        self.server = child;
        self.server_addr = addr;
        self.server_log = log;
        self.url = format!("{scheme}://{addr}{prefix}");
        Ok(())
    }

    /// server 实际监听地址。
    pub fn server_addr(&self) -> SocketAddr {
        self.server_addr
    }

    /// 所有临时目录的根。
    pub fn run_root(&self) -> &Path {
        &self.run_root
    }
}

impl Drop for ProcessCluster {
    fn drop(&mut self) {
        let names: Vec<String> = self.clients.keys().cloned().collect();
        for name in names {
            let Some(slot) = self.clients.get(&name) else {
                continue;
            };
            if slot.status.is_none() {
                signal(slot.pid, "-TERM");
                let deadline = Instant::now() + DROP_GRACE;
                loop {
                    match reap(slot.pid) {
                        Ok(Reap::Running) if Instant::now() < deadline => {
                            std::thread::sleep(POLL);
                        }
                        _ => break,
                    }
                }
                if matches!(reap(slot.pid), Ok(Reap::Running)) {
                    signal(slot.pid, "-KILL");
                    let deadline = Instant::now() + DROP_GRACE;
                    while matches!(reap(slot.pid), Ok(Reap::Running)) && Instant::now() < deadline {
                        std::thread::sleep(POLL);
                    }
                }
            }
            if let Err(err) = force_unmount_sync(&slot.mountpoint) {
                eprintln!("ProcessCluster drop: {err}");
            }
        }

        if matches!(self.server.try_wait(), Ok(None)) {
            signal(self.server.id(), "-TERM");
            let deadline = Instant::now() + DROP_GRACE;
            while matches!(self.server.try_wait(), Ok(None)) && Instant::now() < deadline {
                std::thread::sleep(POLL);
            }
            if matches!(self.server.try_wait(), Ok(None)) {
                let _ = self.server.kill();
                let _ = self.server.try_wait();
            }
        }
    }
}

// ---------------------------------------------------------------------------
// MountGuard
// ---------------------------------------------------------------------------

/// 启动一个 `syncmount server` 子进程；stdout/stderr 落到 `log`。
fn spawn_server(
    binary: &Path,
    url: &str,
    listen: SocketAddr,
    log: &Path,
    level: &str,
    cwd: &Path,
) -> Result<Child, ProcessError> {
    let (stdout, stderr) = log_stdio(log, true)?;
    let mut command = Command::new(binary);
    command
        .arg("server")
        .arg(url)
        .arg("--listen")
        .arg(listen.to_string())
        .arg("--log-format")
        .arg("json")
        .current_dir(cwd)
        .env("RUST_LOG", rust_log(level))
        .stdin(Stdio::null());
    if !level.is_empty() {
        command.arg("--log-level").arg(level);
    }
    command.stdout(stdout).stderr(stderr);
    command.spawn().map_err(|err| ProcessError::Spawn {
        program: binary.display().to_string(),
        source: err,
    })
}

/// 一次挂载的配置。
pub struct MountCfg {
    /// `syncmount` 可执行文件。
    pub binary: PathBuf,
    /// 集群 URL。
    pub url: String,
    /// 挂载点。
    pub mountpoint: PathBuf,
    /// `SYNCMOUNT_RUN_DIR` 基目录。
    pub run_dir: PathBuf,
    /// 主密码。
    pub master_password: String,
}

impl std::fmt::Debug for MountCfg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MountCfg")
            .field("binary", &self.binary)
            .field("url", &self.url)
            .field("mountpoint", &self.mountpoint)
            .field("run_dir", &self.run_dir)
            .field("master_password", &"<redacted>")
            .finish()
    }
}

/// 单个挂载的 RAII 守卫。
#[derive(Debug)]
pub struct MountGuard {
    /// 挂载点。
    pub mnt: PathBuf,
    /// 子进程。
    pub child: Child,
    mounted: bool,
    run_dir: PathBuf,
    log: PathBuf,
}

impl MountGuard {
    /// 启动客户端并等待 STEADY。
    pub async fn mount(cfg: MountCfg) -> Result<Self, ProcessError> {
        fs::create_dir_all(&cfg.mountpoint)
            .map_err(|err| path_error("create mountpoint", &cfg.mountpoint, err))?;
        fs::create_dir_all(&cfg.run_dir)
            .map_err(|err| path_error("create run directory", &cfg.run_dir, err))?;
        clear_status(&cfg.run_dir);
        let log = cfg.run_dir.join("client.log");
        // 与 ProcessCluster 相同：单挂载也要隔离签名密钥目录。
        let state_home = cfg.run_dir.join("state");
        fs::create_dir_all(&state_home)
            .map_err(|err| path_error("create state home", &state_home, err))?;
        let mut child = spawn_client(ClientSpawn {
            binary: &cfg.binary,
            url: &cfg.url,
            mountpoint: &cfg.mountpoint,
            run_dir: &cfg.run_dir,
            state_home: &state_home,
            password: &cfg.master_password,
            log: &log,
            level: "info",
        })?;
        match wait_client(
            &mut child,
            "mount-guard",
            &cfg.mountpoint,
            &cfg.run_dir,
            &log,
            CLIENT_READY,
        )
        .await
        {
            Ok(()) => Ok(Self {
                mnt: cfg.mountpoint,
                child,
                mounted: true,
                run_dir: cfg.run_dir,
                log,
            }),
            Err(err) => {
                stop_child_async(&mut child, DROP_GRACE).await;
                let _ = wait_unmounted(&cfg.mountpoint, DROP_GRACE).await;
                let _ = force_unmount(cfg.mountpoint.clone()).await;
                Err(err)
            }
        }
    }

    /// 再次确认挂载可见且状态为 STEADY。
    pub async fn wait_steady(&self, deadline: Duration) -> Result<(), ProcessError> {
        let start = Instant::now();
        loop {
            if mounted(&self.mnt) && status_state(&self.run_dir).as_deref() == Some(STEADY) {
                return Ok(());
            }
            if start.elapsed() >= deadline {
                return Err(ProcessError::ClientNotReady {
                    name: "mount-guard".to_owned(),
                    deadline,
                    tail: tail(&self.log),
                });
            }
            tokio::time::sleep(POLL).await;
        }
    }

    /// SIGTERM → 等退出 → 必要时 SIGKILL → 强制卸载；返回真实退出状态。
    pub async fn unmount(&mut self) -> Result<ExitStatus, ProcessError> {
        let status = match self
            .child
            .try_wait()
            .map_err(|err| io_error(format!("wait for {}", self.mnt.display()), err))?
        {
            Some(status) => status,
            None => {
                signal(self.child.id(), "-TERM");
                match wait_child_exit(&mut self.child, UNMOUNT_GRACE).await {
                    Some(status) => status,
                    None => {
                        let _ = self.child.kill();
                        match wait_child_exit(&mut self.child, UNMOUNT_GRACE).await {
                            Some(status) => status,
                            None => {
                                return Err(ProcessError::Timeout {
                                    what: format!("mount `{}` to exit", self.mnt.display()),
                                    deadline: UNMOUNT_GRACE,
                                });
                            }
                        }
                    }
                }
            }
        };

        wait_unmounted(&self.mnt, UNMOUNT_GRACE).await;
        force_unmount(self.mnt.clone()).await?;
        self.mounted = false;
        Ok(status)
    }

    /// SIGKILL 并等待挂载消失。
    pub async fn kill9(&mut self) -> Result<(), ProcessError> {
        let _ = self.child.kill();
        let _ = wait_child_exit(&mut self.child, UNMOUNT_GRACE).await;
        wait_unmounted(&self.mnt, UNMOUNT_GRACE).await;
        force_unmount(self.mnt.clone()).await?;
        self.mounted = false;
        Ok(())
    }
}

impl Drop for MountGuard {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            signal(self.child.id(), "-TERM");
            let deadline = Instant::now() + DROP_GRACE;
            loop {
                match self.child.try_wait() {
                    Ok(Some(_)) => break,
                    Ok(None) if Instant::now() < deadline => std::thread::sleep(POLL),
                    _ => break,
                }
            }
            if matches!(self.child.try_wait(), Ok(None)) {
                let _ = self.child.kill();
                let deadline = Instant::now() + DROP_GRACE;
                while matches!(self.child.try_wait(), Ok(None)) && Instant::now() < deadline {
                    std::thread::sleep(POLL);
                }
            }
        }
        if self.mounted || mounted(&self.mnt) {
            if let Err(err) = force_unmount_sync(&self.mnt) {
                eprintln!("MountGuard drop: {err}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 子进程辅助
// ---------------------------------------------------------------------------

/// 一个客户端子进程的全部输入。
struct ClientSpawn<'a> {
    binary: &'a Path,
    url: &'a str,
    mountpoint: &'a Path,
    run_dir: &'a Path,
    state_home: &'a Path,
    password: &'a str,
    log: &'a Path,
    level: &'a str,
}

fn spawn_client(spec: ClientSpawn<'_>) -> Result<Child, ProcessError> {
    let ClientSpawn {
        binary,
        url,
        mountpoint,
        run_dir,
        state_home,
        password,
        log,
        level,
    } = spec;
    let (stdout, stderr) = log_stdio(log, false)?;
    let mut command = Command::new(binary);
    command
        .arg("client")
        .arg(url)
        .arg(mountpoint)
        .arg("--log-format")
        .arg("json")
        .env(ENV_MASTER_PASSWORD, password)
        .env(ENV_RUN_DIR, run_dir)
        .env("XDG_STATE_HOME", state_home)
        .env("RUST_LOG", rust_log(level))
        .current_dir(run_dir)
        .stdin(Stdio::null());
    if !level.is_empty() {
        command.arg("--log-level").arg(level);
    }
    command.stdout(stdout).stderr(stderr);
    command.spawn().map_err(|err| ProcessError::Spawn {
        program: binary.display().to_string(),
        source: err,
    })
}

fn log_stdio(path: &Path, truncate: bool) -> Result<(Stdio, Stdio), ProcessError> {
    let mut options = OpenOptions::new();
    options.create(true).write(true);
    if truncate {
        options.truncate(true);
    } else {
        options.append(true);
    }
    let file = options
        .open(path)
        .map_err(|err| path_error("open log", path, err))?;
    let clone = file
        .try_clone()
        .map_err(|err| path_error("clone log handle", path, err))?;
    Ok((Stdio::from(file), Stdio::from(clone)))
}

/// 空级别回落到 `info`：空 `RUST_LOG` 是合法但无意义的过滤器。
fn rust_log(level: &str) -> &str {
    if level.is_empty() { "info" } else { level }
}

fn split_url(url: &str) -> (String, String) {
    match url.find("://") {
        Some(index) => {
            let scheme = url[..index].to_owned();
            let rest = &url[index + 3..];
            let prefix = match rest.find('/') {
                Some(slash) => rest[slash..].to_owned(),
                None => String::new(),
            };
            (scheme, prefix)
        }
        None if url.starts_with('/') => ("http".to_owned(), url.to_owned()),
        None => ("http".to_owned(), String::new()),
    }
}

async fn wait_server(
    child: &mut Child,
    log: &Path,
    deadline: Duration,
) -> Result<SocketAddr, ProcessError> {
    let start = Instant::now();
    loop {
        if let Some(addr) = read_listen_addr(log)? {
            return Ok(addr);
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|err| io_error("wait for the server", err))?
        {
            return Err(ProcessError::ServerNotReady {
                deadline,
                tail: format!("server exited with {status}\n{}", tail(log)),
            });
        }
        if start.elapsed() >= deadline {
            return Err(ProcessError::ServerNotReady {
                deadline,
                tail: tail(log),
            });
        }
        tokio::time::sleep(POLL).await;
    }
}

async fn wait_client(
    child: &mut Child,
    name: &str,
    mountpoint: &Path,
    run_dir: &Path,
    log: &Path,
    deadline: Duration,
) -> Result<(), ProcessError> {
    let start = Instant::now();
    loop {
        let visible = mounted(mountpoint);
        let state = status_state(run_dir);
        if visible && state.as_deref() == Some(STEADY) {
            return Ok(());
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|err| io_error("wait for the client", err))?
        {
            return Err(ProcessError::ClientNotReady {
                name: name.to_owned(),
                deadline,
                tail: format!("client exited with {status}\n{}", tail(log)),
            });
        }
        if start.elapsed() >= deadline {
            return Err(ProcessError::ClientNotReady {
                name: name.to_owned(),
                deadline,
                tail: format!("mounted={visible} state={state:?}\n{}", tail(log)),
            });
        }
        tokio::time::sleep(POLL).await;
    }
}

async fn wait_child_exit(child: &mut Child, deadline: Duration) -> Option<ExitStatus> {
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => {}
            Err(_) => return None,
        }
        if start.elapsed() >= deadline {
            return None;
        }
        tokio::time::sleep(POLL).await;
    }
}

async fn stop_child_async(child: &mut Child, grace: Duration) {
    match child.try_wait() {
        Ok(Some(_)) => return,
        Ok(None) => {}
        // 已被别人收尸：不能再按 pid 发信号，pid 可能已被复用。
        Err(_) => return,
    }
    signal(child.id(), "-TERM");
    if wait_child_exit(child, grace).await.is_some() {
        return;
    }
    let _ = child.kill();
    let _ = wait_child_exit(child, grace).await;
}

/// `kill` 走 PATH；信号失败不致命（进程可能已经消失）。
fn signal(pid: u32, signal: &str) {
    let _ = Command::new("kill")
        .arg(signal)
        .arg(pid.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

#[derive(Debug)]
enum Reap {
    Status(ExitStatus),
    Running,
    Gone,
}

fn reap(pid: u32) -> Result<Reap, ProcessError> {
    let raw = i32::try_from(pid).map_err(|_| {
        io_error(
            format!("pid {pid} is out of range"),
            io::Error::other("invalid pid"),
        )
    })?;
    let Some(pid) = rustix::process::Pid::from_raw(raw) else {
        return Ok(Reap::Gone);
    };
    match rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::NOHANG) {
        Ok(Some((_pid, status))) => Ok(Reap::Status(ExitStatus::from_raw(status.as_raw()))),
        Ok(None) => Ok(Reap::Running),
        Err(err) if err == rustix::io::Errno::CHILD => Ok(Reap::Gone),
        Err(err) => Err(io_error(format!("waitpid({raw})"), err.into())),
    }
}

async fn wait_pid(pid: u32, deadline: Duration) -> Result<Option<ExitStatus>, ProcessError> {
    let start = Instant::now();
    loop {
        match reap(pid)? {
            Reap::Status(status) => return Ok(Some(status)),
            Reap::Gone => return Err(ProcessError::Reaped { pid }),
            Reap::Running => {}
        }
        if start.elapsed() >= deadline {
            return Ok(None);
        }
        tokio::time::sleep(POLL).await;
    }
}

async fn wait_unmounted(mountpoint: &Path, deadline: Duration) -> bool {
    let start = Instant::now();
    loop {
        if !mounted(mountpoint) {
            return true;
        }
        if start.elapsed() >= deadline {
            return false;
        }
        tokio::time::sleep(POLL).await;
    }
}

async fn force_unmount(mountpoint: PathBuf) -> Result<(), ProcessError> {
    tokio::task::spawn_blocking(move || force_unmount_sync(&mountpoint))
        .await
        .map_err(|err| ProcessError::Task(err.to_string()))?
}

/// 依次尝试 `fusermount3 -u`、`-uz`、`umount -l`，最后核对 `/proc/mounts`。
fn force_unmount_sync(mountpoint: &Path) -> Result<(), ProcessError> {
    if !mounted(mountpoint) {
        return Ok(());
    }
    if let Some(fusermount) = find_fusermount() {
        let _ = Command::new(&fusermount)
            .arg("-u")
            .arg(mountpoint)
            .stdin(Stdio::null())
            .status();
        if !mounted(mountpoint) {
            return Ok(());
        }
        let _ = Command::new(&fusermount)
            .arg("-uz")
            .arg(mountpoint)
            .stdin(Stdio::null())
            .status();
        if !mounted(mountpoint) {
            return Ok(());
        }
    }
    let _ = Command::new("umount")
        .arg("-l")
        .arg(mountpoint)
        .stdin(Stdio::null())
        .status();
    if mounted(mountpoint) {
        return Err(ProcessError::StillMounted(mountpoint.to_path_buf()));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 日志与状态
// ---------------------------------------------------------------------------

fn read_listen_addr(log: &Path) -> Result<Option<SocketAddr>, ProcessError> {
    let text = match fs::read_to_string(log) {
        Ok(text) => text,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(path_error("read server log", log, err)),
    };
    for line in text.lines() {
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if json_str(&value, "event") != Some("listening") {
            continue;
        }
        let Some(addr) = json_str(&value, "addr") else {
            continue;
        };
        return addr
            .parse::<SocketAddr>()
            .map(Some)
            .map_err(|_| ProcessError::BadAddr(addr.to_owned()));
    }
    Ok(None)
}

/// tracing 的 JSON 格式把事件字段放在 `fields` 下；兼容平铺写法。
fn json_str<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str).or_else(|| {
        value
            .get("fields")
            .and_then(|fields| fields.get(key))
            .and_then(Value::as_str)
    })
}

/// 运行目录下任一 `status.json` 的 `state`。
///
/// 每个客户端使用独立运行目录，且挂载前会清掉旧文档，因此这里取第一份
/// 可解析的文档即可。
fn status_state(run_dir: &Path) -> Option<String> {
    let entries = fs::read_dir(run_dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Ok(text) = fs::read_to_string(path.join(STATUS_FILE)) else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        if let Some(state) = value.get("state").and_then(Value::as_str) {
            return Some(state.to_owned());
        }
    }
    None
}

/// 删除运行目录下所有旧的 `status.json`，避免把上一轮 STEADY 当成新进程就绪。
fn clear_status(run_dir: &Path) {
    let Ok(entries) = fs::read_dir(run_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let _ = fs::remove_file(path.join(STATUS_FILE));
    }
}

fn tail(path: &Path) -> String {
    match fs::read(path) {
        Ok(bytes) => {
            let start = bytes.len().saturating_sub(LOG_TAIL_BYTES);
            String::from_utf8_lossy(&bytes[start..]).into_owned()
        }
        Err(err) => format!("<cannot read {}: {err}>", path.display()),
    }
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use std::fs;
    use std::io;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::{Duration, Instant};
    use tempfile::TempDir;

    fn tempdir() -> TempDir {
        TempDir::new().expect("tempdir")
    }

    /// 45 §5.3：八进制转义、空格、根挂载点。
    #[test]
    fn u_testkit_process_parse_proc_mounts() {
        let text = "\
sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
/dev/sda1 / ext4 rw,relatime 0 0
/dev/sdb1 /mnt/with\\040space ext4 rw 0 0
tmpfs /mnt/tab\\011here tmpfs rw 0 0
tmpfs /mnt/line\\012break tmpfs rw 0 0
tmpfs /mnt/back\\134slash tmpfs rw 0 0
malformed
";
        let mounts = parse_proc_mounts(text);
        assert_eq!(mounts.len(), 6, "malformed line must be skipped");
        assert!(mounts.contains(&(PathBuf::from("/sys"), "sysfs".to_owned())));
        assert!(mounts.contains(&(PathBuf::from("/"), "ext4".to_owned())));
        assert!(mounts.contains(&(PathBuf::from("/mnt/with space"), "ext4".to_owned())));
        assert!(mounts.contains(&(PathBuf::from("/mnt/tab\there"), "tmpfs".to_owned())));
        assert!(mounts.contains(&(PathBuf::from("/mnt/line\nbreak"), "tmpfs".to_owned())));
        assert!(mounts.contains(&(PathBuf::from("/mnt/back\\slash"), "tmpfs".to_owned())));
    }

    /// `/proc/mounts` 的读路径与显式断言。
    #[test]
    fn u_testkit_process_mounted_root_and_tempdir() {
        assert!(mounted(Path::new("/")), "root must appear in /proc/mounts");

        let tmp = tempdir();
        let plain = tmp.path().join("not-a-mountpoint");
        fs::create_dir(&plain).expect("mkdir");
        assert!(!mounted(&plain));
        assert_not_mounted(&plain).expect("a plain directory is not mounted");

        match assert_not_mounted(Path::new("/")) {
            Err(ProcessError::StillMounted(path)) => assert_eq!(path, PathBuf::from("/")),
            other => panic!("expected StillMounted, got {other:?}"),
        }

        // /tmp 是否独立挂载取决于宿主；只要求不 panic。
        let _ = mounted(Path::new("/tmp"));
    }

    /// server 就绪日志的两种 tracing 字段布局都能解析。
    #[test]
    fn u_testkit_process_listen_addr_log() {
        let tmp = tempdir();
        let log = tmp.path().join("server.log");
        fs::write(
            &log,
            concat!(
                "{\"event\":\"listening\",\"addr\":\"127.0.0.1:4100\"}\n",
                "{\"fields\":{\"event\":\"listening\",\"addr\":\"127.0.0.1:4200\"}}\n",
            ),
        )
        .expect("write log");
        let addr = read_listen_addr(&log).expect("parse log").expect("addr");
        assert_eq!(addr.port(), 4100);

        fs::write(
            &log,
            "{\"event\":\"listening\",\"addr\":\"127.0.0.1:4300\"}\n",
        )
        .expect("rewrite log");
        let addr = read_listen_addr(&log).expect("parse log").expect("addr");
        assert_eq!(addr.port(), 4300);

        fs::write(&log, "not json\n").expect("write bad log");
        assert!(read_listen_addr(&log).expect("no error").is_none());
    }

    /// URL 只保留 scheme 与 namespace 前缀，主机/端口由实际监听地址替换。
    #[test]
    fn u_testkit_process_split_url() {
        assert_eq!(
            split_url("http://127.0.0.1:0/team/sync"),
            ("http".to_owned(), "/team/sync".to_owned())
        );
        assert_eq!(
            split_url("https://example.test"),
            ("https".to_owned(), String::new())
        );
        assert_eq!(
            split_url("/prefix"),
            ("http".to_owned(), "/prefix".to_owned())
        );
    }

    /// 状态扫描：取运行目录下 `status.json` 的 `state`。
    #[test]
    fn u_testkit_process_status_state_scan() {
        let tmp = tempdir();
        assert_eq!(status_state(tmp.path()), None);

        let mount_id = tmp.path().join("0123456789abcdef");
        fs::create_dir(&mount_id).expect("mkdir");
        fs::write(mount_id.join(STATUS_FILE), br#"{"state":"JOINING"}"#).expect("write");
        assert_eq!(status_state(tmp.path()).as_deref(), Some("JOINING"));

        fs::write(mount_id.join(STATUS_FILE), br#"{"state":"STEADY"}"#).expect("write");
        assert_eq!(status_state(tmp.path()).as_deref(), Some("STEADY"));

        fs::write(mount_id.join(STATUS_FILE), b"not json").expect("write");
        assert_eq!(status_state(tmp.path()), None);

        clear_status(tmp.path());
        assert!(!mount_id.join(STATUS_FILE).exists());
    }

    /// 45 §5.1：探测只允许返回“就绪”或“跳过”，不得 panic。
    #[test]
    fn u_testkit_process_fuse_probe_shape() {
        match fuse_probe() {
            Ok(ready) => {
                assert!(
                    ready.dev_fuse.exists(),
                    "ready must name an existing device"
                );
                assert!(ready.fusermount.is_file(), "ready must name a real binary");
                assert_eq!(
                    fuse_probe().expect("cached probe").fusermount,
                    ready.fusermount
                );
            }
            Err(skip) => {
                assert!(!skip.to_string().is_empty());
                assert!(!format!("{skip:?}").is_empty());
            }
        }
        if std::env::var(ENV_REQUIRE_FUSE).ok().as_deref() != Some("1") {
            let _ = require_fuse();
        }
    }

    /// 每个 skip 原因都有可读说明。
    #[test]
    fn u_testkit_process_fuse_skip_display() {
        let reasons = [
            FuseSkip::NotLinux,
            FuseSkip::NoDevFuse,
            FuseSkip::DevFuseUnopenable(io::Error::other("denied")),
            FuseSkip::NoFusermount,
            FuseSkip::FusermountNotSetuid,
            FuseSkip::ProbeMountFailed("apparmor".to_owned()),
        ];
        for reason in reasons {
            assert!(!reason.to_string().is_empty(), "{reason:?}");
        }
    }

    /// Drop 在“已卸载”的临时目录上是无操作，且不 panic。
    #[test]
    fn u_testkit_process_mount_guard_drop_clean() {
        let tmp = tempdir();
        let child = Command::new("true").spawn().expect("spawn true");
        let guard = MountGuard {
            mnt: tmp.path().to_path_buf(),
            child,
            mounted: false,
            run_dir: tmp.path().to_path_buf(),
            log: tmp.path().join("client.log"),
        };
        drop(guard);
        assert_not_mounted(tmp.path()).expect("temp dir must not be a mountpoint");
    }

    /// Drop 必须停掉还活着的子进程并完成收尸。
    #[test]
    fn u_testkit_process_mount_guard_drop_stops_child() {
        let tmp = tempdir();
        let child = Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let pid = child.id();
        let guard = MountGuard {
            mnt: tmp.path().to_path_buf(),
            child,
            mounted: true,
            run_dir: tmp.path().to_path_buf(),
            log: tmp.path().join("client.log"),
        };
        drop(guard);

        let alive = || {
            Command::new("kill")
                .arg("-0")
                .arg(pid.to_string())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map(|status| status.success())
                .unwrap_or(false)
        };
        let deadline = Instant::now() + Duration::from_secs(2);
        while alive() && Instant::now() < deadline {
            std::thread::sleep(POLL);
        }
        assert!(!alive(), "child {pid} survived MountGuard::drop");
    }

    /// 错误消息带上下文，测试失败时无需再翻代码。
    #[test]
    fn u_testkit_process_error_display() {
        let unknown = ProcessError::UnknownClient("a".to_owned());
        assert!(unknown.to_string().contains("unknown client `a`"));

        let still = ProcessError::StillMounted(PathBuf::from("/mnt/x"));
        assert!(still.to_string().contains("/mnt/x"));

        let client = ProcessError::ClientNotReady {
            name: "a".to_owned(),
            deadline: Duration::from_secs(20),
            tail: "boom".to_owned(),
        };
        assert!(client.to_string().contains("STEADY"));
        assert!(client.to_string().contains("boom"));

        let server = ProcessError::ServerNotReady {
            deadline: Duration::from_secs(10),
            tail: "x".to_owned(),
        };
        assert!(server.to_string().contains("listening"));

        let io = ProcessError::Io {
            context: "read status".to_owned(),
            source: io::Error::other("nope"),
        };
        assert!(io.to_string().contains("read status"));
    }
}
