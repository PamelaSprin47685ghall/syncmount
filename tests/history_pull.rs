//! 历史拉取端到端验收（P7）：真实 server + 两个真实 CLI client 进程。
//!
//! 运行：
//!
//! ```text
//! SYNCMOUNT_REQUIRE_FUSE=1 \
//!   cargo test --locked --features fuse-tests --test history_pull \
//!   -- --nocapture --test-threads=1
//! ```
//!
//! 覆盖：
//!
//! * `hp_1_two_clients_history`：A 挂载空集群并写 7 个文件（1,371,795 B），
//!   B 后加入，必须自动看到全部内容；A 不得重写历史（`healthz.seq` 不变）。
//! * `hp_2_empty_cluster_mount`：空集群挂载、写入、`applied_seq` 与 server
//!   `seq` 一致。它是 harness 的冒烟闸门。
//! * `hp_3_join_failure_keeps_local`：holder 离线时 B 的 JOIN 不得静默删除
//!   本地哨兵；失败形状必须是退出 2/10 或 `DEGRADED_RO`，不能是“删完再
//!   STEADY”。
//! * `hp_4_single_client_restart`：单客户端干净停止后按同一 name /
//!   mountpoint 重新挂载，必须回到 `STEADY`，epoch 不变，内容逐字节一致。
//!
//! 在 manifest-only 历史拉取、`JoinProofResponder` 与 self
//! view 落地后，hp_1..hp_4 应当全绿；若变红，失败信息按层给出证据
//! （view / holder / manifest / blockmap / JOIN_PROOF），直接指向
//! 断链环节。

#![cfg(feature = "fuse-tests")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::Value;
use sha2::{Digest, Sha256};
use syncmount::testkit::{
    MountedClient, ProcessCluster, ProcessSpec, assert_not_mounted, require_fuse,
};
use tempfile::TempDir;

const POLL: Duration = Duration::from_millis(20);
const STATUS_SETTLE: Duration = Duration::from_secs(12);
const CONVERGE: Duration = Duration::from_secs(90);
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// 7 个文件，合计 1,371,795 B。
const FILES: [(&str, usize); 7] = [
    ("readme.txt", 4_096),
    ("small-a.bin", 32_768),
    ("small-b.bin", 65_536),
    ("mid.bin", 262_144),
    ("big.bin", 786_432),
    ("nested/one.txt", 102_400),
    ("nested/two.txt", 118_419),
];

const TOTAL_BYTES: usize = 1_371_795;

fn spec(run_root: &Path) -> ProcessSpec {
    ProcessSpec {
        url: "http://127.0.0.1:0/sync".to_owned(),
        run_root: run_root.to_path_buf(),
        master_password: "history-pull-master".to_owned(),
        server_bin: PathBuf::from(env!("CARGO_BIN_EXE_syncmount")),
        log_level: "info".to_owned(),
        listen: None,
    }
}

fn log_path(client: &MountedClient) -> PathBuf {
    client.run_dir.join(format!("{}.log", client.name))
}

fn tail(path: &Path, bytes: usize) -> String {
    match fs::read(path) {
        Ok(data) => {
            let start = data.len().saturating_sub(bytes);
            String::from_utf8_lossy(&data[start..]).into_owned()
        }
        Err(error) => format!("<cannot read {}: {error}>", path.display()),
    }
}

/// server 的 `healthz`：`/__syncmount/healthz` 是绝对路径，字段见
/// `src/server/metrics.rs`。
fn healthz(addr: SocketAddr) -> Result<Value, String> {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2))
        .map_err(|error| format!("connect {addr}: {error}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
    stream
        .write_all(b"GET /__syncmount/healthz HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
        .map_err(|error| error.to_string())?;
    let mut text = String::new();
    stream
        .read_to_string(&mut text)
        .map_err(|error| error.to_string())?;
    let body = text
        .split("\r\n\r\n")
        .nth(1)
        .ok_or_else(|| "healthz has no body".to_owned())?;
    serde_json::from_str(body).map_err(|error| error.to_string())
}

async fn wait_clients(cluster: &ProcessCluster, expected: u64, deadline: Duration) {
    let start = Instant::now();
    loop {
        if let Ok(document) = healthz(cluster.server_addr()) {
            if document["clients"].as_u64() == Some(expected) {
                return;
            }
        }
        if start.elapsed() >= deadline {
            panic!(
                "server clients did not reach {expected}: {:?}",
                healthz(cluster.server_addr())
            );
        }
        tokio::time::sleep(POLL).await;
    }
}

/// 等某个客户端的 `applied_seq` 追上 server 的 `seq`。
///
/// 单次相等不够：FUSE 写一个文件会产生多个 ORDERED，`applied == seq` 会在
/// 写入过程中瞬时成立。这里要求同一对值在 2 s 后仍然相等，才算静止；返回
/// 稳定窗口确认时的 `seq`，调用方不要再去读一次 healthz（那会引入竞态）。
async fn wait_at_server_watermark(
    cluster: &ProcessCluster,
    name: &str,
    minimum: u64,
    deadline: Duration,
) -> (Value, u64) {
    let start = Instant::now();
    let mut last = String::from("<no status>");
    let mut stable: Option<(u64, u64)> = None;
    loop {
        let server_seq = healthz(cluster.server_addr())
            .ok()
            .and_then(|document| document["seq"].as_u64());
        if let Some(document) = cluster.read_status(name) {
            let applied = document["applied_seq"].as_u64().unwrap_or(0);
            last = format!("applied_seq={applied} server_seq={server_seq:?}");
            if applied >= minimum && server_seq == Some(applied) {
                let current = (applied, server_seq.unwrap_or(0));
                if stable == Some(current) {
                    return (document, current.1);
                }
                stable = Some(current);
            } else {
                stable = None;
            }
        }
        if start.elapsed() >= deadline {
            panic!("`{name}` did not reach the server watermark: {last}");
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// 写入 7 个文件，返回 rel -> (len, sha256)。
fn write_fixture(root: &Path) -> BTreeMap<String, (usize, [u8; 32])> {
    let mut out = BTreeMap::new();
    for (index, (rel, len)) in FILES.iter().enumerate() {
        let path = root.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("fixture parent");
        }
        let bytes: Vec<u8> = (0..*len)
            .map(|offset| ((offset + index * 31) % 251) as u8)
            .collect();
        fs::write(&path, &bytes).expect("fixture write");
        out.insert((*rel).to_owned(), (*len, sha256(&bytes)));
    }
    out
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// FUSE 慢读：只对瞬时错误重试；显式路径，不做整树遍历。
async fn read_retry(path: &Path, deadline: Duration) -> Result<Vec<u8>, String> {
    let start = Instant::now();
    loop {
        match fs::read(path) {
            Ok(bytes) => return Ok(bytes),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound
                        | std::io::ErrorKind::Interrupted
                        | std::io::ErrorKind::WouldBlock
                ) && start.elapsed() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(error) => return Err(format!("read {}: {error}", path.display())),
        }
    }
}

// ---------------------------------------------------------------------------
// hp_1：A 先写，B 后加入
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hp_1_two_clients_history() {
    if require_fuse().is_none() {
        return;
    }
    let root = TempDir::new().expect("run root");
    let mut cluster = ProcessCluster::boot(spec(root.path()))
        .await
        .expect("server boot");
    let addr = cluster.server_addr();

    let h0 = healthz(addr).expect("healthz");
    assert_eq!(h0["seq"].as_u64(), Some(0), "fresh server sequence");
    assert_eq!(h0["clients"].as_u64(), Some(0), "fresh server clients");

    let a = cluster.mount_client("a").await.expect("A mounts");
    let a_doc = cluster
        .wait_status("a", STATUS_SETTLE, |document| document["state"] == "STEADY")
        .await
        .expect("A steady");
    assert_eq!(a_doc["applied_seq"].as_u64(), Some(0), "empty cluster");
    let epoch = a_doc["epoch"].as_u64().expect("A epoch");

    let expected = write_fixture(&a.mountpoint);
    let (a_doc, server_seq) =
        wait_at_server_watermark(&cluster, "a", 7, Duration::from_secs(30)).await;
    let a_seq = a_doc["applied_seq"].as_u64().expect("A applied_seq");
    let a_ops = a_doc["counters"]["ops_applied"]
        .as_u64()
        .expect("A ops_applied");
    let a_bytes = a_doc["counters"]["bytes_written"]
        .as_u64()
        .expect("A bytes_written");
    // `counters.bytes_written` 只统计 replay 引擎应用的远程写；A 自己写的
    // 回显走 pending 跳过，因此 A 的该计数保持 0。写入是否成功由下面的
    // A 读回与 SHA-256 证明。
    for (rel, (len, hash)) in &expected {
        let bytes = fs::read(a.mountpoint.join(rel))
            .unwrap_or_else(|error| panic!("A cannot read back {rel}: {error}"));
        assert_eq!(bytes.len(), *len, "A length mismatch for {rel}");
        assert_eq!(sha256(&bytes), *hash, "A content mismatch for {rel}");
    }

    // B 的挂载点由 ProcessCluster 创建为 <run_root>/clients/b/mnt；挂载前必须为空。
    let b_mnt = root.path().join("clients").join("b").join("mnt");
    assert!(
        !b_mnt.exists() || fs::read_dir(&b_mnt).expect("read B mnt").next().is_none(),
        "B backing must start empty"
    );

    // JOIN 在 current_seq > 0 且没有视图时按 1/2/4/8/16 s 重试，31 s 后才
    // 拒绝；必须给足预算，否则会把“仍在重试”误判成最终失败。
    let b = match cluster
        .mount_client_with_deadline("b", Duration::from_secs(60))
        .await
    {
        Ok(client) => client,
        Err(error) => panic!(
            "B failed to join: {error}\nA status: {a_doc}\nA log tail:\n{}",
            tail(&log_path(&a), 4096)
        ),
    };

    let b_doc = cluster
        .wait_status("b", CONVERGE, |document| {
            document["state"] == "STEADY" && document["applied_seq"].as_u64().unwrap_or(0) >= a_seq
        })
        .await
        .unwrap_or_else(|error| {
            panic!(
                "B did not catch up: {error}\nA status: {:?}\nB status: {:?}\nhealthz: {:?}\n\
                 A log tail:\n{}\nB log tail:\n{}",
                cluster.read_status("a"),
                cluster.read_status("b"),
                healthz(addr),
                tail(&log_path(&a), 4096),
                tail(&log_path(&b), 4096),
            )
        });
    assert_eq!(b_doc["state"], "STEADY", "B state");
    assert_eq!(b_doc["epoch"].as_u64(), Some(epoch), "B epoch");
    assert!(
        b_doc["replay"]["resyncs"].as_u64().unwrap_or(0) <= 3,
        "B entered a resync loop: {b_doc}"
    );
    assert_eq!(b_doc["replay"]["diverged"], false, "B diverged");

    for (rel, (len, hash)) in &expected {
        let bytes = read_retry(&b.mountpoint.join(rel), READ_TIMEOUT)
            .await
            .unwrap_or_else(|error| panic!("{error}\nB status: {b_doc}"));
        assert_eq!(bytes.len(), *len, "length mismatch for {rel}");
        assert_eq!(sha256(&bytes), *hash, "content mismatch for {rel}");
    }

    // 老客户端不得重写历史：server 的 seq 在 B 加入前后不变。
    let h2 = healthz(addr).expect("healthz after B");
    assert_eq!(
        h2["seq"].as_u64(),
        Some(server_seq),
        "server sequence moved while B joined: an old client rewrote history"
    );
    assert_eq!(
        h2["clients"].as_u64(),
        Some(2),
        "both sessions must coexist"
    );

    // A 的写入计数不得因 B 加入而增长（frames_out 可以增长：A 可能在服务 relay）。
    let a_after = cluster.read_status("a").expect("A status after B");
    assert_eq!(
        a_after["applied_seq"].as_u64(),
        Some(a_seq),
        "A applied_seq moved after B joined"
    );
    assert_eq!(
        a_after["counters"]["ops_applied"].as_u64(),
        Some(a_ops),
        "A ops_applied moved after B joined"
    );
    assert_eq!(
        a_after["counters"]["bytes_written"].as_u64(),
        Some(a_bytes),
        "A bytes_written moved after B joined"
    );

    // 空视图 fallback 的唯一痕迹；出现即证明 snapshot_ref 为 None。
    let b_log = fs::read_to_string(log_path(&b)).unwrap_or_default();
    assert!(
        !b_log.contains("joining with an empty view and no history replay"),
        "B joined with an empty view: {b_doc}"
    );

    let b_code = cluster.unmount("b").await.expect("unmount B");
    let a_code = cluster.unmount("a").await.expect("unmount A");
    assert_eq!(a_code.code(), Some(0), "A exit code");
    assert_eq!(b_code.code(), Some(0), "B exit code");
    assert_not_mounted(&a.mountpoint).expect("A unmounted");
    assert_not_mounted(&b.mountpoint).expect("B unmounted");

    println!(
        "HP evidence: hp_1 pass a_seq={a_seq} b_seq={} server_seq={server_seq} epoch={epoch} \
         resyncs={} files={} bytes={TOTAL_BYTES} a_bytes_written={a_bytes}",
        b_doc["applied_seq"],
        b_doc["replay"]["resyncs"],
        expected.len(),
    );
}

// ---------------------------------------------------------------------------
// hp_2：空集群挂载与写入
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hp_2_empty_cluster_mount() {
    if require_fuse().is_none() {
        return;
    }
    let root = TempDir::new().expect("run root");
    let mut cluster = ProcessCluster::boot(spec(root.path()))
        .await
        .expect("server boot");

    let a = cluster.mount_client("a").await.expect("A mounts");
    let a_doc = cluster
        .wait_status("a", STATUS_SETTLE, |document| document["state"] == "STEADY")
        .await
        .expect("A steady");
    assert_eq!(a_doc["applied_seq"].as_u64(), Some(0), "empty cluster");
    assert_eq!(
        healthz(cluster.server_addr())
            .expect("healthz")
            .get("seq")
            .and_then(Value::as_u64),
        Some(0),
        "server sequence"
    );

    fs::write(a.mountpoint.join("first.txt"), b"hello").expect("write");
    let (a_doc, server_seq) =
        wait_at_server_watermark(&cluster, "a", 1, Duration::from_secs(15)).await;
    assert!(
        a_doc["counters"]["ops_applied"].as_u64().unwrap_or(0) >= 1,
        "A did not apply its write: {a_doc}"
    );

    let code = cluster.unmount("a").await.expect("unmount A");
    assert_eq!(code.code(), Some(0), "A exit code");
    assert_not_mounted(&a.mountpoint).expect("A unmounted");

    println!(
        "HP evidence: hp_2 pass applied_seq={} server_seq={server_seq}",
        a_doc["applied_seq"],
    );
}

// ---------------------------------------------------------------------------
// hp_3：holder 离线时 B 不得静默删除本地文件
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hp_3_join_failure_keeps_local() {
    if require_fuse().is_none() {
        return;
    }
    let root = TempDir::new().expect("run root");
    let mut cluster = ProcessCluster::boot(spec(root.path()))
        .await
        .expect("server boot");

    let a = cluster.mount_client("a").await.expect("A mounts");
    write_fixture(&a.mountpoint);
    let _ = wait_at_server_watermark(&cluster, "a", 7, Duration::from_secs(30)).await;

    // holder 崩溃；等 server 的会话表清空，relay 的候选集才为空。
    cluster.kill9("a").await.expect("kill A");
    wait_clients(&cluster, 0, Duration::from_secs(20)).await;

    let b_mnt = root.path().join("clients").join("b").join("mnt");
    fs::create_dir_all(&b_mnt).expect("B mountpoint");
    fs::write(b_mnt.join("sentinel.txt"), b"keep me").expect("sentinel");

    // JOIN 在 current_seq > 0 且没有视图时按 1/2/4/8/16 s 重试，31 s 后才
    // 拒绝；20 s 的就绪上限会把它误判成“还在 JOINING”。
    match cluster
        .mount_client_with_deadline("b", Duration::from_secs(60))
        .await
    {
        Ok(b) => {
            let document = cluster.read_status("b").unwrap_or(Value::Null);
            let sentinel = fs::read(b.mountpoint.join("sentinel.txt"));
            assert_eq!(
                sentinel.as_deref().ok(),
                Some(b"keep me".as_slice()),
                "JOIN deleted B's local file silently: state={} applied_seq={} log=\n{}",
                document["state"],
                document["applied_seq"],
                tail(&log_path(&b), 4096)
            );
            println!(
                "HP evidence: hp_3 JOIN completed with sentinel preserved: state={} applied_seq={}",
                document["state"], document["applied_seq"]
            );
            let _ = cluster.unmount("b").await;
        }
        Err(error) => {
            let sentinel = fs::read(b_mnt.join("sentinel.txt"));
            assert_eq!(
                sentinel.as_deref().ok(),
                Some(b"keep me".as_slice()),
                "JOIN failure removed the local file: {error}"
            );
            let code = cluster.failed_exit("b").and_then(|status| status.code());
            let state = cluster
                .failed_status("b")
                .and_then(|document| document["state"].as_str())
                .unwrap_or("<none>")
                .to_owned();
            match (code, state.as_str()) {
                (Some(2), _) | (Some(10), _) => {
                    println!("HP evidence: hp_3 JOIN refused: exit={code:?} state={state}");
                }
                (_, "DEGRADED_RO") => {
                    println!("HP evidence: hp_3 unmount failed, client stayed degraded: {state}");
                }
                other => panic!(
                    "unexpected JOIN failure shape {other:?}: {error}\nB status: {:?}",
                    cluster.failed_status("b")
                ),
            }
        }
    }

    let _ = cluster.unmount("a").await;
    assert_not_mounted(&a.mountpoint).expect("A unmounted");
    assert_not_mounted(&b_mnt).expect("B not mounted");
}

// ---------------------------------------------------------------------------
// hp_4：单客户端干净停止后重新挂载
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hp_4_single_client_restart() {
    if require_fuse().is_none() {
        return;
    }
    let root = TempDir::new().expect("run root");
    let mut cluster = ProcessCluster::boot(spec(root.path()))
        .await
        .expect("server boot");

    let a = cluster.mount_client("a").await.expect("A mounts");
    let expected = write_fixture(&a.mountpoint);
    let (a_doc, _) = wait_at_server_watermark(&cluster, "a", 7, Duration::from_secs(30)).await;
    assert_eq!(a_doc["state"], "STEADY", "A steady before restart");
    let epoch = a_doc["epoch"].as_u64().expect("A epoch");

    // 干净停止：SIGTERM -> exit 0。
    let stop = cluster.unmount("a").await.expect("clean stop");
    assert_eq!(stop.code(), Some(0), "clean stop must exit 0");
    assert_not_mounted(&a.mountpoint).expect("A unmounted");

    // 同一 name / mountpoint / run_dir / XDG_STATE_HOME 重新启动。
    let a2 = match cluster
        .mount_client_with_deadline("a", Duration::from_secs(60))
        .await
    {
        Ok(client) => client,
        Err(error) => {
            let code = cluster.failed_exit("a").and_then(|status| status.code());
            let state = cluster
                .failed_status("a")
                .and_then(|document| document["state"].as_str())
                .unwrap_or("<none>")
                .to_owned();
            panic!(
                "restart failed: {error}\nclient exit={code:?} state={state}\nlog tail:\n{}",
                tail(&log_path(&a), 4096)
            );
        }
    };
    let a2_doc = cluster
        .wait_status("a", Duration::from_secs(60), |document| {
            document["state"] == "STEADY"
        })
        .await
        .unwrap_or_else(|error| {
            panic!(
                "restart did not reach STEADY: {error}\nstatus: {:?}\nlog tail:\n{}",
                cluster.read_status("a"),
                tail(&log_path(&a2), 4096)
            )
        });
    assert_eq!(
        a2_doc["epoch"].as_u64(),
        Some(epoch),
        "the same server must keep its epoch"
    );
    let applied = a2_doc["applied_seq"].as_u64().expect("applied_seq");
    let server_seq = healthz(cluster.server_addr())
        .expect("healthz")
        .get("seq")
        .and_then(Value::as_u64)
        .expect("server seq");
    assert_eq!(
        applied, server_seq,
        "applied_seq must equal the server sequence after restart"
    );

    for (rel, (len, hash)) in &expected {
        let bytes = read_retry(&a2.mountpoint.join(rel), READ_TIMEOUT)
            .await
            .unwrap_or_else(|error| panic!("{error}\nstatus: {a2_doc}"));
        assert_eq!(bytes.len(), *len, "length mismatch for {rel}");
        assert_eq!(sha256(&bytes), *hash, "content mismatch for {rel}");
    }

    let stop = cluster.unmount("a").await.expect("final stop");
    assert_eq!(stop.code(), Some(0), "final stop must exit 0");
    assert_not_mounted(&a2.mountpoint).expect("A unmounted after restart");

    println!(
        "HP evidence: hp_4 pass files={} bytes={TOTAL_BYTES} epoch={epoch} \
         applied={applied} server_seq={server_seq}",
        expected.len(),
    );
}
