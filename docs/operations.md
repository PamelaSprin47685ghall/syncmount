# syncmount 1.0.0 运维交接

适用版本：1.0.0（协议 3.0，事件 payload v3）。

本文写操作与判据，不写真实资产。真实主机名、域名、地址、账号和密钥位置见“内部拓扑文档”与密码库。文中的示例统一使用 `example.com`、`192.0.2.0/24`、`2001:db8::/32`、`/home/user` 和角色代号。

角色代号只用于本文：

| 代号 | 角色 |
|---|---|
| S | 服务器主机，运行两个 sequencer 和两个客户端挂载 |
| A | IPv4 客户端，物理接口 `enp18s0`，运行 mihomo 和旧 foreman 管理服务 |
| B | 迷你主机客户端（AMD 7640HS 平台） |
| H | 香港节点 |
| R | frp 管理入口（frps 与 SSH 端口映射） |

## 1. 拓扑

### 1.1 数据面

```text
12 台客户端主机（24 个 client unit）
  │  http://sync[-v4|-v6].example.com/{private,public}
  ▼
Caddy :80（S）
  ├─ /private/*  → 127.0.0.1:8081 → /var/lib/syncmount/private/server.db
  └─ /public/*   → 127.0.0.1:8082 → /var/lib/syncmount/public/server.db
```

- S 上两个 sequencer 进程，一个 namespace 一个：`private` 监听 `127.0.0.1:8081`，`public` 监听 `127.0.0.1:8082`。两个进程共用同一份 master password，但各自持有独立的 `server.db`。
- Caddy 只监听公网 `:80`，纯 HTTP，无 TLS，`auto_https off`。客户端只支持明文 HTTP/1.1；`https://` URL 在拨号阶段就会被拒绝。
- Caddy 必须原样转发 namespace 前缀，不能用 `handle_path`。`/__syncmount/healthz` 是绝对路径，不属于任何一个 namespace，必须单独路由。
- 两条 `/events` 长流要求关闭 Caddy 的 `read_body_idle` 与 `write_idle` 超时；`flush_interval -1` 也必须保留。
- Caddy 的 `admin off` 意味着没有 `caddy reload`；改配置只能 `systemctl restart caddy`。重启会切断两条长流，客户端按设计退出 10，`Restart=always` 会重新拉起。
- 服务端数据库是明文 SQLite；PSK 只保护链路，不保护服务器。磁盘加密和主机访问控制是边界的一部分。

### 1.2 客户端分布

| 项目 | 数量 | 说明 |
|---|---:|---|
| 客户端主机 | 12 | 含服务器主机 S；每台两个挂载点 |
| client unit | 24 | 每台 `private` 与 `public` 各一个 |
| 使用 IPv6 专用 URL 的主机 | 8 | 16 个 unit；URL 主机只有 AAAA |
| 使用 IPv4 专用 URL 的主机 | 4 | 8 个 unit；URL 主机只有 A |
| 双栈 URL | 0 | `sync.example.com` 保留给需要双栈的主机，当前 unit 不使用 |

- 每个客户端主机有两个 `client.db`，分别位于 `~/.local/state/syncmount-private/client.db` 与 `~/.local/state/syncmount-public/client.db`（以 unit 中的 `--db` 为准）。
- 服务器主机 S 自己也运行两个 client unit，因此也计入 12 台和 24 个 unit；S 的两个 unit 使用 IPv4 专用 URL。
- 不要给 IPv6 专用域名添加 A 记录，也不要给 IPv4 专用域名添加 AAAA 记录。地址选择会先尝试错误的地址族，导致拨号超时；需要双栈时使用 `sync.example.com`。
- 每台主机、每个 namespace 使用同一个 master password；密码文件必须是 0600，且属主是运行该 unit 的账户。没有按客户端区分的凭据，也没有轮换或吊销机制。

### 1.3 管理面

- 管理入口是 R 上的 frps 加各客户端的 frpc，提供 SSH 端口映射；它只用于管理，不承载 syncmount 同步流量。
- frp 故障通常不影响已经建立的同步数据面；但主机整体断网时，同步会话和管理入口会一起消失。
- 没有 frp dashboard，也没有公网管理面板。不要为了排障临时把 8081/8082 暴露到公网。
- 真实的管理地址、端口映射和账号见“内部拓扑文档”和密码库，不写入本文。

### 1.4 端口与边界

| 端口 | 绑定 | 用途 |
|---|---|---|
| 80 | 公网 | Caddy → 两个 sequencer |
| 8081 | `127.0.0.1` | `private` sequencer |
| 8082 | `127.0.0.1` | `public` sequencer |
| frp | 管理网络 | SSH 端口映射，不是同步数据面 |

- 只允许 80 对公网开放；8081/8082 必须保持 loopback。
- 同步协议没有 TLS；不要把 `https://` 写进 client unit。
- Caddy 的 catch-all 返回 `404 not found`，用于拒绝未知 Host 和未知路径。

## 2. 已知故障与处置

### 2.1 A 的 frp 物理链路：`enp18s0` carrier loss

现象：

- `enp18s0` 失去 carrier，frpc 断线，经 frp 的 SSH 管理入口不可达。
- A 的两个客户端会话同时断开并以 10 退出；`Restart=always` 会持续重试，日志出现 `reconnect`，预算耗尽后出现 `reconnect budget exhausted`。
- 若 A 仍能通过其他链路访问，`healthz.clients` 会少 1；若整机断网，则两个 namespace 都少 1。

判断与处置：

```sh
ip -br link show enp18s0
ethtool enp18s0
journalctl -u frpc --since '30 min ago' --no-pager
```

- 先查网线、光模块、交换机端口和对端电源；这是物理层故障，不是 syncmount 故障。
- 链路恢复后 frpc 会自动重连；客户端 unit 的 `Restart=always` 会自动重连，不需要手工 `systemctl restart`。
- 只有在链路已恢复而 frpc 仍不重连时，才重启 `frpc`。
- 不要反复重启 syncmount unit 来掩盖 carrier loss；那只会制造更多 exit 10 日志。

### 2.2 B 整机离线或电源故障

现象：

- 两个 namespace 的 `healthz.clients` 各少 1（通常从 12 变成 11），frp 映射端口无监听，SSH 和 ICMP 都不通。
- 这不是 DNS 故障，也不是 sequencer 故障；B 上的客户端 unit 根本没有机会启动。

处置：

- 检查电源适配器、PSU、BIOS/CMOS、机房供电和带外管理；必要时现场重启。
- 回网后先验证解析和拨号，再启动 unit：

```sh
getent ahosts sync-v6.example.com
curl -6 -fsS http://sync-v6.example.com/__syncmount/healthz
```

- 如果 IPv6 链路暂时不可用，可以把 B 的 unit 临时改为 IPv4 专用 URL；改 unit 后执行 `systemctl daemon-reload`，并记录改动，恢复后改回。
- 不要在整机离线期间循环重启 unit 或反复重建客户端数据库。

### 2.3 A 的 mihomo 过滤 AAAA

现象：

- A 上的 mihomo DNS 过滤 AAAA，`sync-v6.example.com` 返回 NODATA；使用 IPv6 专用 URL 的 unit 拨号失败。
- 同一时刻 A 使用 IPv4 专用 URL 正常，其他主机的 IPv6 URL 也正常。

处置：

- A 固定使用 IPv4 专用 URL；不要把它改回 IPv6 URL。
- 排查时先看解析，再看拨号：

```sh
getent ahostsv6 sync-v6.example.com
getent ahostsv4 sync-v4.example.com
curl -4 -fsS http://sync-v4.example.com/__syncmount/healthz
```

- 如果要恢复 A 的 IPv6 能力，先修 mihomo 的 DNS/`ipv6` 配置，确认 `getent ahostsv6` 和 `curl -6` 都成功，再改 unit。
- 不要给 IPv6 专用域名添加 A 记录来“绕过”过滤；那会破坏其他主机的地址选择。

### 2.4 A 上的 foreman 管理服务已 disable

- 旧 foreman 管理服务已经 `disable`，不应作为任何部署、巡检或监控的依赖。
- 它曾经占用本地管理端口并自动拉起；不要为了“恢复旧工具”而直接 `enable`。
- 如需重新启用，先确认端口冲突、资源占用和负责人，再单独评估；当前巡检使用 systemd、journalctl 和 SSH。
- 不要因为 foreman 不在而认为 syncmount 异常；两者没有依赖关系。

### 2.5 H 的 DNS 历史问题

现象：

- H 上域名解析超时或返回失败，但 IP 可达；syncmount 拨号失败，日志表现为解析/连接错误，而不是握手错误。
- 历史原因是 `/etc/resolv.conf` 的上游是 IPv6 DNS，经 HE 隧道到上游超时。

处置：

- 先区分 DNS 与链路：

```sh
cat /etc/resolv.conf
resolvectl status 2>/dev/null || true
getent ahosts sync.example.com
dig sync.example.com A
dig sync.example.com AAAA
```

- 临时改用 IPv4 DNS 或修复 HE 隧道；不要在 DNS 故障时反复重启 sequencer。
- 如果 H 必须继续同步，可临时使用 IPv4 专用 URL；恢复 DNS 后再切回原 URL。
- 这是历史问题，可能复现；巡检时把 H 的解析失败单独归类，不要先怀疑 syncmount。

## 3. 备份与恢复

### 3.1 备份对象与一致性

| 对象 | 文件 | 一致性要求 |
|---|---|---|
| 服务端数据库 | `server.db`、`server.db-wal`、`server.db-shm` | 停服冷备，或 `sqlite3 .backup` 热备 |
| 客户端数据库 | `client.db`、`client.db-wal`、`client.db-shm` | 停客户端冷备；outbox 是唯一不可重建的数据 |
| 树清单 | `tree.meta`、`tree.sha256` | 业务静默、挂载在线时生成 |
| 配置 | unit、Caddyfile、env 文件 | 纯文本；不要把密钥写进去 |
| 密钥 | master password 文件 | 单独保管，不放进普通备份包 |

- **绝不能只复制 `*.db` 而漏掉 `-wal`**。WAL 里有已提交但尚未 checkpoint 的事务；只拿主文件会丢数据。
- `-shm` 是共享内存索引，通常可以重建；但冷备时按“三件套”一起复制，避免混用不同时刻的文件。
- 服务端使用 WAL + `synchronous=FULL`，已确认的事件能承受断电。
- 客户端使用 WAL + `synchronous=NORMAL`（1.0.0 实现；旧文档若写 FULL，以当前代码为准）：正常停止会 flush；突然断电可能丢掉最近一段本地事务（包括 outbox 行）。这是客户端副本的已知取舍，不是备份可以修复的。
- outbox 的 `pending`/`sent` 行在重启后重发；`acked` 行已删除；`failed` 是 tombstone，普通重连不会重发或修复。
- 备份目录必须是 0700，备份文件 0600；异地副本同样按敏感数据处理。

### 3.2 冷备步骤

在维护窗口内执行。先让业务停止写入，确认 outbox 为空、`applied_seq` 已追平，再生成树清单；然后停客户端，最后停服务端。

```sh
TS=$(date -u +%Y%m%dT%H%M%SZ)
BK=/var/backups/syncmount/$TS
install -d -m 0700 "$BK"

manifest() {
  mnt=$1
  out=$2
  ( cd "$mnt" && find . -xdev -mindepth 1 \
      -printf '%y\t%m\t%U:%G\t%n\t%s\t%T@\t%P\t%l\n' \
    | LC_ALL=C sort ) > "$out.meta"
  ( cd "$mnt" && find . -xdev -type f -print0 \
    | LC_ALL=C sort -z \
    | xargs -0 -r sha256sum ) > "$out.sha256"
}

manifest /home/user/private "$BK/tree-private"
manifest /home/user/public  "$BK/tree-public"

# 先停客户端：让 FUSE flush、unmount，outbox 落盘
systemctl stop syncmount-client@private.service syncmount-client@public.service

# 再停服务端：SIGTERM 触发 drain + compaction
systemctl stop syncmount-sequencer@private.service syncmount-sequencer@public.service
```

停服后确认：

```sh
systemctl is-active syncmount-client@private.service syncmount-client@public.service
systemctl is-active syncmount-sequencer@private.service syncmount-sequencer@public.service
journalctl -u syncmount-sequencer@private.service -n 50 --no-pager
journalctl -u syncmount-sequencer@public.service  -n 50 --no-pager
```

服务端日志应出现 `drain complete` 和 `event log compacted`；如果出现 `drain timed out; compacting anyway`，说明还有会话没追上，但压缩仍会完成，需要在恢复服务后查那些客户端。

复制数据库三件套并校验：

```sh
for ns in private public; do
  src=/var/lib/syncmount/$ns
  dst=$BK/server-$ns
  install -d -m 0700 "$dst"
  for f in server.db server.db-wal server.db-shm; do
    [ -e "$src/$f" ] && cp -a "$src/$f" "$dst/"
  done
  sqlite3 "$dst/server.db" 'PRAGMA integrity_check;'
  sqlite3 "$dst/server.db" \
    "SELECT key, quote(value) FROM meta ORDER BY key;" > "$dst/meta.txt"
done

for ns in private public; do
  src=/home/user/.local/state/syncmount-$ns
  dst=$BK/client-$ns
  install -d -m 0700 "$dst"
  for f in client.db client.db-wal client.db-shm; do
    [ -e "$src/$f" ] && cp -a "$src/$f" "$dst/"
  done
  sqlite3 "$dst/client.db" 'PRAGMA integrity_check;'
  sqlite3 "$dst/client.db" \
    "SELECT state, COUNT(*) FROM outbox GROUP BY state ORDER BY state;" \
    > "$dst/outbox.txt"
  sqlite3 "$dst/client.db" \
    "SELECT key, quote(value) FROM meta WHERE key IN \
     ('epoch','applied_seq','state_hash','state_hash_pending', \
      'state_hash_seq','state_hash_at');" > "$dst/meta.txt"
done

( cd "$BK" && find . -type f -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS )
```

`PRAGMA integrity_check` 必须返回 `ok`；任何其他输出都视为备份失败，不要继续升级或恢复。

### 3.3 热备

服务端不能停时，用 SQLite 的在线备份接口生成一致快照：

```sh
sqlite3 /var/lib/syncmount/private/server.db \
  ".backup '$BK/server-private/server.db'"
sqlite3 "$BK/server-private/server.db" 'PRAGMA integrity_check;'
```

- `.backup` 生成的是单文件一致快照，不需要再复制 WAL；但不要用 `cp` 去热复制正在写入的数据库。
- 客户端热备同样可以用 `.backup`，但 outbox 会随时间变化；升级前仍应冷备。
- 热备的 RPO 是快照完成时刻；冷备的 RPO 是停服时刻。

### 3.4 恢复步骤

先停所有客户端，再停服务端。把现有数据库移到一边，不要删除。

```sh
systemctl stop syncmount-client@private.service syncmount-client@public.service
systemctl stop syncmount-sequencer@private.service syncmount-sequencer@public.service

ts=$(date -u +%Y%m%dT%H%M%SZ)
mv /var/lib/syncmount/private/server.db \
   /var/lib/syncmount/private/server.db.bad-$ts
mv /var/lib/syncmount/private/server.db-wal \
   /var/lib/syncmount/private/server.db-wal.bad-$ts 2>/dev/null || true
mv /var/lib/syncmount/private/server.db-shm \
   /var/lib/syncmount/private/server.db-shm.bad-$ts 2>/dev/null || true

for f in server.db server.db-wal server.db-shm; do
  [ -e "$BK/server-private/$f" ] && \
    cp -a "$BK/server-private/$f" /var/lib/syncmount/private/
done
chown -R syncmount:syncmount /var/lib/syncmount/private
chmod 0700 /var/lib/syncmount/private
chmod 0600 /var/lib/syncmount/private/server.db \
            /var/lib/syncmount/private/server.db-wal \
            /var/lib/syncmount/private/server.db-shm 2>/dev/null || true

sqlite3 /var/lib/syncmount/private/server.db 'PRAGMA integrity_check;'
systemctl start syncmount-sequencer@private.service
curl -fsS http://127.0.0.1:8081/__syncmount/healthz
```

`public` 同样处理。两个 namespace 尽量恢复到同一时间点；只恢复一个时，另一个 namespace 的客户端不受影响，但不要混用不同批次的 DB 文件。

恢复客户端：

- 如果客户端数据库也恢复了：启动 unit，按 epoch/applied 规则续传或 fast-forward。
- 如果客户端数据库丢失：先移走旧文件，再启动 unit；它会从服务器全量 replay。outbox 丢失，未确认的本地写入不可恢复。
- 如果服务端数据库丢失且没有备份：不要用“客户端反向 seed”当常规恢复。只有在接受丢失服务端顺序、且客户端持有完整树的前提下，才按 `docs/known-limitations.md` 的 seed 路径重建；这不能替代备份。

恢复后检查：

```sh
for p in 8081 8082; do
  curl -fsS "http://127.0.0.1:$p/__syncmount/healthz"
done
SYNCMOUNT_RUN_DIR=/run/syncmount-private syncmount status --json
```

### 3.5 compaction 前后

服务端每次干净停止都会 drain + compaction：epoch 加一，`seq` 归零后重新写入最小 replay 日志，`replay_floor` 回到 1，`compacted_from_seq` / `compacted_epoch` / `compacted_seq` 更新。

停止前记录：

```sh
sqlite3 /var/lib/syncmount/private/server.db \
  "SELECT key, quote(value) FROM meta WHERE key IN \
   ('epoch','seq','replay_floor','compacted_from_seq', \
    'compacted_epoch','compacted_seq','compacted_at','state_hash');"
```

停止后再次记录同一组值，并对照：

| 键 | 压缩前 | 压缩后 |
|---|---|---|
| `epoch` | `E` | `E+1` |
| `seq` | 旧 `S` | 新 `compacted_seq` |
| `compacted_from_seq` | 上一次的值 | 旧 `S` |
| `compacted_epoch` | 上一次的值 | `E+1` |
| `compacted_seq` | 上一次的值 | 新日志最后一条的 seq |
| `replay_floor` | 1 | 1 |
| `state_hash` | 上一次 checkpoint 的值 | 重新计算；活树不变时必须相同 |

- `meta.state_hash` 只在 compaction 和干净退出时刷新；运行中的值可能是旧的，不要把它当实时值。
- 压缩不重写 object/name 表，活树的 `state_hash` 不应变化。若压缩前后 `state_hash` 不同且期间没有写入，停止升级，保留现场并恢复备份。
- 压缩后日志应出现 `event log compacted`，字段包含 `epoch`、`events`、`objects`。压缩失败会记录 `compaction failed`；不要继续升级。
- 被 drain 到压缩点的客户端在重连时执行 fast-forward：保留本地树，采用新 epoch，`applied_seq` 设为 `compacted_seq`，日志出现 `compaction_fast_forward`。低于压缩点或没有该能力的客户端会清空副本并从 0 重放。

### 3.6 RPO / RTO

| 数据 | 建议频率 | RPO | RTO |
|---|---|---|---|
| `server.db` | 每日 + 每次升级前 | 每日 ≤ 24 h；升级前 0 | 单 namespace ≤ 30 min |
| `client.db` | 每周 + 每次升级前 | 每周 ≤ 7 d；升级前 0 | 单机 ≤ 30 min |
| 树清单 | 每次备份/升级 | 不适用 | 生成/比对 ≤ 15 min |
| 全集群 | 按上述组合 | 以最旧的必要备份为准 | 目标 ≤ 2 h |

- 这是目标值，不是保证；首次恢复演练后按实测校准。
- 客户端 `synchronous=NORMAL`，断电可能丢最近事务；RPO 以“最后一次成功备份”或“最后一次干净停止”中较晚者为准。
- 每季度至少做一次恢复演练：从备份启动一个隔离的 sequencer，挂一个客户端，比对树清单；不要在生产 namespace 上演练。

### 3.7 回滚限制：payload v3

1.0.0 写入事件 payload v3（rename/unlink/rmdir/link 携带 mtime 等目录元数据）。0.1.0 旧二进制只认识 v1/v2；一旦服务端或客户端数据库里出现 v3 事件，旧二进制在 decode 时会报：

```text
event payload version 3 is not supported (current is 2)
```

因此：

- **不能在 1.0.0 已经写入之后只把二进制换回旧版**。服务端 replay、客户端 replay 都会失败。
- 回滚必须同时恢复升级前的 `server.db` 和 `client.db`（含 WAL/SHM），再装回旧二进制。
- 如果只恢复服务端而保留新客户端数据库，客户端仍可能带着 v3 事件；要么恢复客户端数据库，要么移走客户端数据库让它从旧服务器全量 replay（会丢 outbox）。
- 协议仍是 3.0；不要用 major 相同来判断兼容性。真正的硬限制是 payload v3，旧二进制在 decode 阶段拒绝。
- 回滚窗口最好在升级后尚未产生新写入时；一旦有新写入，回滚会丢这些写入，必须先得到业务确认并记录。

## 4. 升级 runbook

### 4.1 前置检查

维护窗口内执行；先通知使用者，再冻结写入。

```sh
syncmount --version
sha256sum /usr/local/bin/syncmount
sha256sum syncmount-1.0.0-<arch>
```

基线检查：

```sh
for p in 8081 8082; do
  curl -fsS "http://127.0.0.1:$p/__syncmount/healthz"
done

SYNCMOUNT_RUN_DIR=/run/syncmount-private syncmount status --json
SYNCMOUNT_RUN_DIR=/run/syncmount-public  syncmount status --json

for db in /home/user/.local/state/syncmount-private/client.db \
          /home/user/.local/state/syncmount-public/client.db; do
  sqlite3 "$db" "SELECT state, COUNT(*) FROM outbox GROUP BY state ORDER BY state;"
done
```

要求：

- 两个 namespace 的 `healthz.status` 都是 `ok`，`clients` 等于当前基线（正常 12；B 离线时为 11）。
- 所有客户端 `state` 为 `STEADY`，`applied_seq` 已追平 `healthz.seq`，`outbox.ops` 为 0，`replay.pending` 为 0，`replay.diverged` 为 false。
- outbox 没有 `failed` 行；有 `failed` 行时先按 known-limitations 处理，不要带着它升级。
- journal 中没有未处理的 `replay_stall`、`chunk_gc` 失败、`compaction failed`。
- 磁盘剩余至少为数据库大小的 2 倍；WAL 没有异常增长。
- 完成 3.2 的冷备和树清单，校验和与 `integrity_check` 都通过。
- 记录两个 namespace 的 `epoch`、`seq`、`state_hash` 和树清单路径。

### 4.2 停服顺序

**停：先客户端，后服务端。启动：先服务端，后客户端。**

```sh
# 所有客户端主机，包括 S 自己
systemctl stop syncmount-client@private.service syncmount-client@public.service

# S
systemctl stop syncmount-sequencer@private.service
systemctl stop syncmount-sequencer@public.service
```

- 客户端收到 SIGTERM 后会 flush、unmount、正常退出 0；`TimeoutStopSec=30s` 足够覆盖 quiesce/flush 预算。
- 如果客户端 30 s 内没有退出，先看 `journalctl -u ...`；必要时 `fusermount3 -uz /home/user/private` 清理残留挂载，再继续。
- 服务端收到 SIGTERM 后 drain 最多 30 s，然后 compaction、退出。不要在 drain 期间 `kill -9`；崩溃会跳过 compaction，下次启动仍可恢复，但会留下更大的事件日志和更慢的 replay。
- 如果日志出现 `drain timed out; compacting anyway`，记录 lagging 会话；升级后重点检查对应客户端。
- 不要先停服务端再停客户端：那会让客户端被 epoch kick，增加 exit 10 和未完成 flush 的风险。

### 4.3 客户端二进制：先换，不启动

按“先客户端、后服务器”的顺序替换二进制，但**所有客户端保持停止**，直到服务端升级完成。原因是 1.0.0 客户端会写 payload v3，旧服务端读不了。

每台客户端：

```sh
install -m 0755 syncmount-1.0.0-<arch> /usr/local/bin/syncmount.new
sha256sum /usr/local/bin/syncmount.new
mv /usr/local/bin/syncmount /usr/local/bin/syncmount.pre-1.0.0
mv /usr/local/bin/syncmount.new /usr/local/bin/syncmount
```

- 保留旧二进制到验收结束，不要覆盖。
- 只替换二进制不需要 `daemon-reload`；如果同时改了 unit，才执行 `systemctl daemon-reload`。
- 替换后不要启动客户端；启动会立刻尝试写 v3。

### 4.4 服务端 cutover

服务端此时已停止，并且已完成 compaction。先记录压缩后的状态：

```sh
for ns in private public; do
  sqlite3 /var/lib/syncmount/$ns/server.db \
    "SELECT key, quote(value) FROM meta WHERE key IN \
     ('epoch','seq','replay_floor','compacted_from_seq', \
      'compacted_epoch','compacted_seq','compacted_at','state_hash');"
done
```

确认：

- `state_hash` 与压缩前活树一致（期间没有写入）。
- `PRAGMA integrity_check` 返回 `ok`。
- 日志有 `event log compacted`，没有 `compaction failed`。

替换服务端二进制：

```sh
install -m 0755 syncmount-1.0.0-<arch> /usr/local/bin/syncmount.new
sha256sum /usr/local/bin/syncmount.new
mv /usr/local/bin/syncmount /usr/local/bin/syncmount.pre-1.0.0
mv /usr/local/bin/syncmount.new /usr/local/bin/syncmount
```

启动服务端：

```sh
systemctl start syncmount-sequencer@private.service
systemctl start syncmount-sequencer@public.service

for p in 8081 8082; do
  curl -fsS "http://127.0.0.1:$p/__syncmount/healthz"
done
```

期望：`status=ok`、`clients=0`、`seq` 等于压缩后的 `compacted_seq`、`epoch` 为新 epoch。此时客户端还没启动，`clients=0` 是正常的。

Caddy 不需要因为 syncmount 升级而重启；只有改 Caddyfile 才重启。若必须重启，放在客户端启动之前，避免二次断流。

### 4.5 启动与验证

按主机逐台启动客户端，先 `private` 再 `public`，或两个一起；不要 12 台同时启动，避免瞬时 replay 争抢。

```sh
systemctl start syncmount-client@private.service
systemctl start syncmount-client@public.service
```

每台等待 `STEADY`，再启动下一台。重点看：

```sh
journalctl -u syncmount-client@private.service --since '10 min ago' -o cat \
  | grep -E 'compaction_fast_forward|replay_stall|reconnect|resync|state_hash'
```

期望：

- 升级前已追平并在压缩点的客户端出现 `compaction_fast_forward`，`applied_seq` 直接跳到新的 `compacted_seq`，不重放整棵树。
- 低于压缩点的客户端会清空副本并从 0 replay；日志出现 `resync` / `replay_progress`，没有 `replay_stall`。
- 全量 replay 会清空副本，但 outbox 的 `pending`/`sent` 行保留；replay 追上后按原顺序重发。
- `replay_stall` 表示 10 s 没有进展，客户端会从 durable cursor 重连；连续出现时检查服务端、网络和磁盘，不要盲目重启。

全量验证：

（下面的 `manifest` 复用 3.2 中的函数定义。）

```sh
# 1) healthz：两个 namespace 的 clients 等于基线
for p in 8081 8082; do
  curl -fsS "http://127.0.0.1:$p/__syncmount/healthz"
done

# 2) 客户端状态：STEADY、applied 追平、outbox 为空
SYNCMOUNT_RUN_DIR=/run/syncmount-private syncmount status --json
SYNCMOUNT_RUN_DIR=/run/syncmount-public  syncmount status --json

# 3) outbox：没有 pending/sent/failed
for db in /home/user/.local/state/syncmount-private/client.db \
          /home/user/.local/state/syncmount-public/client.db; do
  sqlite3 "$db" "SELECT state, COUNT(*) FROM outbox GROUP BY state ORDER BY state;"
done

# 4) state_hash：服务端与客户端在 checkpoint 后比较
sqlite3 /var/lib/syncmount/private/server.db \
  "SELECT lower(hex(value)) FROM meta WHERE key='state_hash';"
sqlite3 /home/user/.local/state/syncmount-private/client.db \
  "SELECT key, quote(value) FROM meta WHERE key IN \
   ('state_hash','state_hash_pending','state_hash_seq','applied_seq');"

# 5) 树清单：重新生成并与备份比对
manifest /home/user/private /tmp/tree-private
diff -u /var/backups/syncmount/<TS>/tree-private.meta   /tmp/tree-private.meta
diff -u /var/backups/syncmount/<TS>/tree-private.sha256 /tmp/tree-private.sha256
```

判据：

- `healthz.clients` 回到基线，`status=ok`。
- 所有客户端 `state=STEADY`，`applied_seq` 等于对应 namespace 的 `healthz.seq`（允许短暂追平窗口），`outbox.ops=0`，`replay.pending=0`，`replay.diverged=false`。
- 客户端 `state_hash_pending=0` 后再比较 `state_hash`。`state_hash` 是本地诊断值，不是跨集群共识；同一批次导入的副本应一致，独立导入的副本可能不同。
- 树清单 `diff` 无输出；任何差异都视为升级失败，按 4.6 回滚。
- 做一次跨主机写读测试：在一台创建小文件，等待 1–2 s，在另一台读取并比对 SHA-256；删除后再确认两端消失。

### 4.6 回滚条件与步骤

出现以下任一情况，停止继续升级，评估回滚：

- compaction 日志出现 `compaction failed`，或压缩前后 `state_hash` 异常变化。
- 服务端启动后 `healthz` 不是 `ok`，或 `seq`/`epoch` 与压缩记录不符。
- 10 min 后 `healthz.clients` 仍低于基线，且不是已知的 B 离线。
- 客户端 `applied_seq` 超过 5 min 不前进，或反复出现 `replay_stall`。
- outbox 出现新的 `failed` 行，或 `replay.diverged=true`。
- 树清单比对出现差异，或跨主机写读测试不一致。
- 日志出现 `event payload version 3 is not supported`。

回滚步骤：

1. 停所有客户端。
2. 停两个 sequencer。
3. 把当前 DB 移到 `.bad-<TS>`，恢复升级前的 `server.db` 三件套和 `client.db` 三件套。
4. 装回 `syncmount.pre-1.0.0`。
5. 先启动 sequencer，确认 `healthz` 和 `integrity_check`；再启动客户端。
6. 重新生成树清单并比对；确认 outbox 和 applied 状态。
7. 记录回滚原因、丢失的写入和时间点。

如果升级后已经产生新写入，回滚会丢失这些写入；没有备份时不要只换二进制，应该修 forward 或从备份重建。

## 5. 监控与巡检

### 5.1 healthz

```sh
# 本机直连，绕过 Caddy
curl -fsS http://127.0.0.1:8081/__syncmount/healthz
curl -fsS http://127.0.0.1:8082/__syncmount/healthz

# 经 Caddy，验证 Host 路由和转发
curl -fsS http://sync.example.com/__syncmount/healthz
```

字段：

| 字段 | 含义 | 正常/告警 |
|---|---|---|
| `status` | `ok` 或 `degraded` | 正常 `ok`；`degraded` 只在会话数超过 8000 时出现，12 台集群不应触发 |
| `version` | 二进制版本 | 升级后应为 `1.0.0` |
| `mode` | `serve` | 固定 |
| `clients` | 当前附着的会话数 | 每个 namespace 等于基线（正常 12） |
| `uptime_s` | 进程运行秒数 | 突然变小说明重启 |
| `seq` | 当前序列 | 单调递增；压缩后从新日志重新计数 |
| `epoch` | 当前 epoch，十六进制 | 只在 compaction 后变化 |
| `sync_sessions` | relay 会话数 | 正常 0；非 0 时查 relay 使用 |

- `healthz` 由 acceptor 的同步闭包直接返回，不经过 sequencer actor；探针不会排队。
- 两个 namespace 要分别探测；一个 8081 的响应不能代表 8082。
- Caddy 自身每 30 s 也会探测上游 `health_uri`；探针失败会标记上游不健康，但不会改变 `healthz.clients`。

### 5.2 客户端 status

```sh
SYNCMOUNT_RUN_DIR=/run/syncmount-private syncmount status --json
SYNCMOUNT_RUN_DIR=/run/syncmount-public  syncmount status --json
```

重点字段：

- `state`：必须是 `STEADY`；`JOINING` 表示还在 replay，`DEGRADED_RO` 表示卸载失败、只读驻留。
- `applied_seq`：应等于服务端 `healthz.seq`；落后时看 `replay.pending` 和 journal。
- `epoch`：应与服务端一致；epoch 变化后短暂不一致是正常的。
- `outbox.ops` / `outbox.bytes`：正常为 0；持续增长说明上行受阻。
- `replay.pending` / `replay.reorder`：正常为 0；持续非 0 说明 replay 有洞或慢。
- `replay.resyncs`：本次运行的重连次数；短时间快速增长要查网络/服务端。
- `replay.diverged`：必须为 false；true 表示看到未知操作类别，需人工介入。
- `counters.ops_rejected`：语义拒绝计数；持续增长说明有客户端在撞冲突，查 `failed` outbox。

辅助命令：

```sh
syncmount debug-state --json
syncmount debug-seq-gaps --json
syncmount debug-conntrace --limit 50
```

### 5.3 journal 关键词

服务端：

```sh
journalctl -u syncmount-sequencer@private.service --since '1 hour ago' -o cat \
  | grep -E 'drain|compacted|compaction failed|chunk_gc'
```

客户端：

```sh
journalctl -u syncmount-client@private.service --since '1 hour ago' -o cat \
  | grep -E 'compaction_fast_forward|replica_repair|replay_stall|reconnect|state_hash'
```

| 关键词 | 来源 | 含义 | 动作 |
|---|---|---|---|
| `drain complete` | server | 所有会话已追平 | 正常 |
| `drain timed out; compacting anyway` | server | 有会话未在 30 s 内追平 | 记录 lagging 会话，升级后重点查 |
| `event log compacted` | server | 压缩完成 | 记录 `epoch`/`events`/`objects` |
| `compaction failed` | server | 压缩失败 | 不要继续升级；保留现场，恢复备份 |
| `compaction_fast_forward`（compaction fast-forward） | client | 客户端采用压缩点，保留本地树 | 升级后的正常路径 |
| `replica_repair` | client | 启动时修复了副本元数据 | 偶发可接受；反复出现要查损坏来源 |
| `replay_stall` | client | 10 s 无进展，准备从 cursor 重连 | 查服务端/网络/磁盘；连续出现升级失败 |
| `reconnect budget exhausted` | client | 重连预算耗尽，进程以 10 退出 | `Restart=always` 会拉起；反复出现要查根因 |
| `chunk_gc` | server | 孤儿 chunk 回收 | `orphans/deleted/freed_bytes`；warn 级别要查磁盘/权限 |
| `exit 10` / `status=10` | client / systemd | 客户端以 10 退出 | 断连/被 kick；正常应自动重启，频繁出现要告警 |

- `exit 10` 不是崩溃：它表示连接断开或 mount 已释放。`Restart=always` + `RestartPreventExitStatus=2 4` 的语义是：2（启动失败）和 4（认证失败）不重启，10 会重启。
- `status=0` 是正常停止；升级/维护时的 stop 不应产生 `status=10`。
- 用 `systemctl show -p NRestarts -p ExecMainStatus -p ActiveEnterTimestamp` 观察重启趋势，不要只看当前 active。

### 5.4 磁盘、WAL 与 GC

```sh
df -h /var/lib/syncmount /home/user/.local/state
du -sh /var/lib/syncmount/private /var/lib/syncmount/public
for db in /var/lib/syncmount/private/server.db \
          /var/lib/syncmount/public/server.db; do
  ls -lh "$db" "$db-wal" "$db-shm" 2>/dev/null
done
```

- WAL 持续大于 256 MiB 或超过主库大小的 50%：查长事务、读快照、磁盘写满和 checkpoint 失败。不要手工删除 `-wal`/`-shm`。
- 需要主动 checkpoint 时，用 `sqlite3 "$db" 'PRAGMA wal_checkpoint(PASSIVE);'`；不要用 `TRUNCATE` 在忙碌的生产库上强行截断。
- 磁盘剩余低于数据库大小的 2 倍时，先扩容或清理备份；不要等 SQLite 返回 `SQLITE_FULL`。
- `chunk_gc` 的 `reason` 可能是 `startup`、`periodic`、`compaction`；周期性 GC 有 1 小时保留窗口，刚删除的文件不会立刻释放磁盘。
- `freed_bytes` 是逻辑释放量，SQLite 会复用页，主库文件不一定立刻缩小；不要为此频繁 `VACUUM`。需要收缩时在停服备份后单独做。
- 每周在备份副本上跑 `PRAGMA quick_check;`，不要在生产库上跑重检查。

### 5.5 巡检表

| 频率 | 项目 |
|---|---|
| 每日 | 两个 namespace 的 `healthz`（status/clients/seq/epoch）；所有客户端 `STEADY`；outbox 无 pending/failed；journal 无 `replay_stall`/`compaction failed`/`chunk_gc` 失败；磁盘与 WAL |
| 每周 | 备份年龄与异地副本；`integrity_check`/`quick_check` 结果；`NRestarts` 趋势；`state_hash_pending`；树清单抽样比对 |
| 每月 | 恢复演练计划；密钥文件权限（0600、属主正确）；Caddy `validate`；unit `is-enabled`；旧二进制/旧备份清理 |
| 每季度 | 完整恢复演练（隔离环境）；升级/回滚演练；容量与 RTO 校准 |

## 6. systemd 与示例

示例文件在 `deploy/`：

- `deploy/syncmount-client@.service`
- `deploy/syncmount-sequencer@.service`
- `deploy/Caddyfile.example`

示例已去掉真实域名、地址和账号，使用 `example.com`、`192.0.2.0/24`、`2001:db8::/32`、`/home/user`。不要直接覆盖生产 unit；先 diff，再按本机路径调整。

### 6.1 客户端 unit

模板实例 `%i` 取 `private` 或 `public`。关键指令：

| 指令 | 值 | 作用 |
|---|---|---|
| `Restart` | `always` | 断连/exit 10 后自动重连 |
| `RestartPreventExitStatus` | `2 4` | 启动失败、认证失败不重启，避免死循环 |
| `StartLimitIntervalSec` | `0` | 取消启动频率限制，长断网时持续重试 |
| `RestartSec` | `2s` | 重试间隔 |
| `UMask` | `0077` | 数据库和运行时文件默认 0600 |
| `TimeoutStopSec` | `30s` | 覆盖客户端 quiesce/flush 预算 |

注意：旧文档可能写 `RestartPreventExitStatus=10` 或“客户端不自动重连”；1.0.0 生产 unit 使用 `Restart=always` + `RestartPreventExitStatus=2 4`，exit 10 会重启。以实际 unit 为准。

`ExecStartPre=-/usr/bin/fusermount3 -uz /home/user/%i` 用于清理上次残留挂载；前面的 `-` 表示失败不阻塞启动。`RuntimeDirectory` 提供可写的 `/run/syncmount-%i`，`SYNCMOUNT_RUN_DIR` 必须与 `syncmount status` 使用的值一致。

`UMask=0077` 只影响新创建的文件；已有 `client.db`/`-wal`/`-shm` 要单独确认权限为 0600。

开机时若网络尚未就绪，初始 JOIN 失败会以 2 退出，而 `RestartPreventExitStatus=2` 不会自动拉起；确认 `network-online.target` 和 DNS 后手工 `systemctl start`。

安装：

```sh
install -d -m 0755 /home/user/private /home/user/public
install -d -m 0700 /home/user/.config/syncmount
install -m 0600 -o user -g user /dev/null /home/user/.config/syncmount/master.pass
install -m 0644 deploy/syncmount-client@.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now syncmount-client@private.service
systemctl enable --now syncmount-client@public.service
```

`master.pass` 由挂载用户拥有并写入；不要把密码写进 unit 的 `Environment=`。

### 6.2 服务端 unit

模板实例 `%i` 取 `private` 或 `public`。示例通过 `/etc/syncmount/%i.env` 提供 `LISTEN` 和 `DB`：

```sh
# /etc/syncmount/private.env
LISTEN=127.0.0.1:8081
DB=/var/lib/syncmount/private/server.db

# /etc/syncmount/public.env
LISTEN=127.0.0.1:8082
DB=/var/lib/syncmount/public/server.db
```

`*.env` 不含密钥，0644、管理员属主即可；`master.pass` 单独 0600、属主为运行 sequencer 的账户。

关键指令：

| 指令 | 值 | 作用 |
|---|---|---|
| `Restart` | `on-failure` | 正常退出不重启，异常退出重启 |
| `RestartPreventExitStatus` | `1 2 3` | 用法错误、启动失败、审计日志损坏不重启 |
| `StartLimitIntervalSec` | `0` | 取消启动频率限制 |
| `RestartSec` | `2s` | 重试间隔 |
| `UMask` | `0077` | `server.db` 默认 0600 |

服务端 drain 预算 30 s；systemd 默认 `TimeoutStopSec=90s` 足够。如果自定义，设为大于 45 s。示例使用专用账户 `syncmount`；生产若沿用其他账户，按实际调整 `User`/`Group` 和目录属主，但不要放宽 `UMask`。

`UMask=0077` 只影响新文件；已有 `server.db`/`-wal`/`-shm` 要单独 `chmod 0600`。

安装：

```sh
install -d -m 0700 -o syncmount -g syncmount /var/lib/syncmount/private
install -d -m 0700 -o syncmount -g syncmount /var/lib/syncmount/public
install -d -m 0755 /etc/syncmount
install -m 0600 -o syncmount -g syncmount /dev/null /etc/syncmount/master.pass
# 用密码管理器写入密码；不要把密码写进 unit 或 shell 历史
install -m 0644 deploy/syncmount-sequencer@.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now syncmount-sequencer@private.service
systemctl enable --now syncmount-sequencer@public.service
```

### 6.3 Caddy

示例与生产实际配置同构：`:80`、`auto_https off`、`admin off`、`persist_config off`、关闭 idle 超时、`flush_interval -1`、`health_uri /__syncmount/healthz`、上游 HTTP/1.1、catch-all 404。Caddy 2.11.6+ 默认把 idle 设为 1 分钟，所以这两项必须显式关闭；建议使用 2.11.7 或更新版本。

```sh
caddy fmt --overwrite deploy/Caddyfile.example
caddy validate --config deploy/Caddyfile.example --adapter caddyfile
```

上线前把 `sync.example.com`、`sync-v4.example.com`、`sync-v6.example.com` 换成真实 Host；保留三处 `host` matcher 和两处 `path` matcher。不要用 `handle_path`。改完：

```sh
systemctl restart caddy
```

`admin off` 下没有 reload；重启会断开长流，客户端 exit 10 后由 `Restart=always` 拉起。尽量在维护窗口做。

## 7. 敏感信息与边界

- 本文和 `deploy/` 示例不含真实密码、token、主机名、公网 IP、域名或用户名；真实映射见“内部拓扑文档”和密码库。
- master password 只放在 0600 文件或密码管理器中；不要放进 argv、unit 的 `Environment=`、仓库、聊天记录或工单。
- 备份包含明文数据库，按与在线库同等级别保护；异地副本要加密。
- 轮换 master password 等于新 namespace 和新数据库；没有原地轮换。轮换前先备份，按新密码重新导入/seed，再切换客户端。
- 不要为了排障临时关闭 Caddy 的 Host 检查、把 8081/8082 暴露到公网，或把 `auto_https` 打开；客户端没有 TLS 栈，打开 TLS 只会让同步中断。
