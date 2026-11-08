# syncmount 1.1 mm 部署工件

本目录只准备 `--mmap`（1.1 mm）两套 namespace 的部署工件，不部署、不启动、不改生产。
1.0 的 `deploy/Caddyfile.example`、`deploy/syncmount-*@.service` 和两个 1.0 数据库都不动。

## 1. 文件

| 文件 | 用途 |
|---|---|
| `mm-server-private-mm.service` | `private-mm` 服务端，`127.0.0.1:8083` |
| `mm-server-public-mm.service` | `public-mm` 服务端，`127.0.0.1:8084` |
| `mm-client@.service` | 客户端模板，实例 `private-mm` / `public-mm` |
| `Caddyfile.mm.example` | 完整示例：1.0 站点原样 + 两套 mm 路由 |
| `install.sh` | 幂等安装 unit、目录、key；不启动任何服务 |
| `README.md` | 本文件 |

服务端用两个显式 unit：监听端口不能从实例名 `%i` 推导。客户端用一个模板：
URL namespace、挂载点、shadow 目录都能从 `%i` 推导，三者不会漂移。

## 2. 假设与取值

### 2.1 端口

| 端口 | 绑定 | 用途 |
|---:|---|---|
| 80 | 公网 | Caddy，1.0 与 1.1 共用 |
| 8081 / 8082 | `127.0.0.1` | 1.0 `private` / `public` sequencer，不变 |
| 8083 | `127.0.0.1` | 1.1 `private-mm` mm-server |
| 8084 | `127.0.0.1` | 1.1 `public-mm` mm-server |

8083/8084 在当前仓库的文档、示例和 unit 中没有出现；1.0 只占用 8081/8082。
上线前仍用 `ss -ltnp` 确认主机上没有其他进程占用。

### 2.2 路径

| 路径 | 属主/模式 | 说明 |
|---|---|---|
| `/var/lib/syncmount-mm/<ns>/server.db` | `root:root 0600` | 每个 namespace 独立 SQLite |
| `/var/lib/syncmount-mm/<ns>/spool/` | `root:root 0700` | 每批上传的临时文件 |
| `/var/lib/syncmount-mm-client/<ns>/` | `syncmount:syncmount 0700` | mm 客户端 shadow 根 |
| `/private-mm`、`/public-mm` | `syncmount:syncmount 0755` | FUSE 挂载点 |
| `/etc/syncmount/` | `root:root 0755` | 只需可遍历；key 文件本身 0600 |
| `/etc/syncmount/mm.key` | `root:root 0600` | 服务端读 |
| `/etc/syncmount/mm-client.key` | `syncmount:syncmount 0600` | 客户端读 |

`--shadow-dir` 传入的是每个 namespace 的根；代码里的 `ShadowLayout` 会再拼
`mm/<namespace>`，所以实际 shadow 数据在
`/var/lib/syncmount-mm-client/<ns>/mm/<ns>/`。备份时备份整个 `--shadow-dir`。

### 2.3 为什么是两个 key 文件

`src/cli.rs::check_password_file` 同时检查：

- 文件模式必须没有 group/other 位（`0600`）；
- 文件属主必须等于进程 euid。

服务端以 root 运行，客户端以非 root 账户（示例为 `syncmount`）运行，因此同一个文件不可能同时满足两者。
`/etc/syncmount/mm.key` 与 `/etc/syncmount/mm-client.key` 必须保存**相同的 32 字节**，
是同一把密钥的两个视图。`install.sh` 只在缺失时复制，不会轮换；两份不一致时直接报错。
目录本身设为 0755，客户端用户才能穿到自己的 0600 key；目录里没有可读的明文。

密钥格式：32 原始字节，或 64 个十六进制字符（可带一个结尾换行）。
`install.sh` 生成 32 原始字节，并避开首尾 ASCII 空白（二进制的 `parse_mm_key`
会 trim 两端，首尾空白会让长度不足 32）；不打印内容。

### 2.4 URL 与 Host

- 客户端 URL：`http://mst0v6.example.com/<ns>`。示例中的 `mst0v6.example.com`
  是占位符；生产替换为实际 mm 主机名。
- Caddy 的 mm host matcher 是 `mst.example.com mst0v4.example.com mst0v6.example.com`。
  客户端用的 Host 必须在这个列表里，否则落到 catch-all 404。
- 服务端 URL 只用来取 namespace（`ClientEndpoint` 的 prefix），示例写成
  `http://127.0.0.1:8083/private-mm`，host 部分不参与监听。
- Caddy 必须原样转发 `/private-mm`、`/public-mm` 前缀，不能用 `handle_path`。

### 2.5 其他

- 二进制路径固定 `/usr/local/bin/syncmount`；需要带 `fuse` feature 的 1.1 构建。
- 客户端账户必须能打开 `/dev/fuse`，`/usr/bin/fusermount3` 必须是 setuid-root；
  不使用 `--allow-other`，所以不需要 `/etc/fuse.conf` 的 `user_allow_other`。
- 纯 HTTP，无 TLS；链路认证是 SMM1 的 hello/MAC，不依赖 Caddy。
- 客户端实例名同时是 URL namespace 和挂载点，三者不能漂移。

## 3. 部署顺序

以下命令只是 runbook；本目录的准备阶段没有执行它们。

### 3.1 安装二进制

```sh
cargo build --release --features fuse
sudo install -m 0755 target/release/syncmount /usr/local/bin/syncmount
```

### 3.2 备份 Caddy 配置

```sh
sudo install -m 0600 /etc/caddy/Caddyfile "/etc/caddy/Caddyfile.bak-$(date -u +%Y%m%dT%H%M%SZ)"
```

### 3.3 安装 unit、目录、key（不启动）

```sh
sudo deploy/mm/install.sh
```

脚本只写 `mm-server-private-mm.service`、`mm-server-public-mm.service`、
`mm-client@.service`，不碰 1.0 unit；不执行 `systemctl`。
重复运行会覆盖这三个同名 unit；本机差异请用 `systemctl edit` 的 drop-in，
不要直接改 unit 文件。

### 3.4 合并 Caddy 配置

```sh
diff -u /etc/caddy/Caddyfile deploy/mm/Caddyfile.mm.example
```

把 1.1 mm 的两段 `handle` 合并进生产 Caddyfile，保留 1.0 段不变；把三个
`mst*.example.com` 换成真实 Host。然后：

```sh
sudo caddy fmt --diff /etc/caddy/Caddyfile
sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
sudo systemctl restart caddy
```

`admin off` 下没有 reload。重启会切断 1.0 的 `/events` 长流，客户端按设计
exit 10 后由 `Restart=always` 拉起；安排在维护窗口。

### 3.5 启动服务端并检查

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now mm-server-private-mm.service mm-server-public-mm.service
curl -fsS http://127.0.0.1:8083/__syncmount/healthz
curl -fsS http://127.0.0.1:8084/__syncmount/healthz
```

两个 healthz 都返回 200 后再继续。

### 3.6 启动客户端

```sh
sudo systemctl enable --now mm-client@private-mm.service mm-client@public-mm.service
findmnt -T /private-mm -o TARGET,SOURCE,FSTYPE
findmnt -T /public-mm  -o TARGET,SOURCE,FSTYPE
```

## 4. 验证

### 4.1 unit 与端口

```sh
systemd-analyze verify \
  /etc/systemd/system/mm-server-private-mm.service \
  /etc/systemd/system/mm-server-public-mm.service \
  /etc/systemd/system/mm-client@.service
systemctl cat mm-client@private-mm.service
ss -ltnp | grep -E ':(8083|8084)\b'
```

`systemctl cat` 应看到 `%i` 已展开为 `private-mm`：URL、挂载点、shadow 目录一致。

### 4.2 密钥与目录

```sh
stat -c '%a %U:%G %n' /etc/syncmount/mm.key /etc/syncmount/mm-client.key
namei -l /var/lib/syncmount-mm-client/private-mm
```

期望 `600 root:root`、`600 syncmount:syncmount`；路径每一级对客户端账户可进入。
不要用 `cat` 检查 key 内容。

### 4.3 服务端

```sh
curl -fsS http://127.0.0.1:8083/__syncmount/healthz
curl -fsS http://127.0.0.1:8084/__syncmount/healthz
journalctl -u mm-server-private-mm -u mm-server-public-mm -n 100 --no-pager
```

### 4.4 Caddy 路由

```sh
curl -s -o /dev/null -w '%{http_code}\n' -X POST \
  http://mst.example.com/private-mm/mm/v1/hello
curl -s -o /dev/null -w '%{http_code}\n' \
  http://mst.example.com/private-mm/not-a-route
```

第一条期望 400 或 401（请求体不合法/未认证），**不应是 404**；
第二条期望 404。404 说明 Host 或路径没有匹配到 mm 段；502/503 说明上游
不健康或没有健康的上游。

### 4.5 客户端

```sh
findmnt -T /private-mm -o TARGET,SOURCE,FSTYPE
ls -la /private-mm
journalctl -u mm-client@private-mm -u mm-client@public-mm -n 100 --no-pager
```

挂载后 `/private-mm` 的 root 来自远端空目录；写入验证会真正提交到 mm 数据库，
只在确认是测试 namespace 时做。

## 5. 回滚

顺序：先停客户端，再停服务端，最后回 Caddy。1.0 的 unit 和数据库全程不动。

```sh
sudo systemctl disable --now mm-client@private-mm.service mm-client@public-mm.service
sudo fusermount3 -uz /private-mm || true
sudo fusermount3 -uz /public-mm  || true

sudo systemctl disable --now mm-server-private-mm.service mm-server-public-mm.service

sudo install -m 0600 /etc/caddy/Caddyfile.bak-<TS> /etc/caddy/Caddyfile
sudo systemctl restart caddy
```

- 不要删除 `/var/lib/syncmount-mm-client/<ns>`：shadow 里可能有未提交的 dirty
  buffer/outbox；确认无待提交数据后再清理。
- 不要删除 `/var/lib/syncmount-mm/<ns>/server.db`，除非确定要丢弃该 namespace
  的 mm 树。删除后无法从 1.0 数据库恢复。
- 回滚 Caddy 也会断开 1.0 长流，按维护窗口处理。

## 6. 风险

1. **单 writer**：每个 namespace 一个 SQLite writer；大 batch 提交会阻塞同
   namespace 其他目录的提交，WAL 可能增长。1.1 没有跨目录 group commit。
2. **last-writer-wins**：锁只串行上传，不阻止基于旧 checkout 的编辑；后提交者
   的显式 delete 会覆盖前者。
3. **key 分裂**：两份 key 必须同字节；轮换没有原子流程。改 key 等于同时改
   服务端和所有客户端，且没有吊销机制。
4. **Host 不匹配**：Caddy 的 mm host 列表与客户端 URL 不一致时静默 404；
   这是最常见的“服务正常但同步不通”原因。
5. **端口暴露**：8083/8084 必须保持 loopback；不要为了排障把它们暴露到公网，
   也不要打开 `auto_https`（客户端没有 TLS）。
6. **启动即失败**：`RestartPreventExitStatus=2 4` 下，挂载点或 shadow 目录缺失
   会以 2 退出且不重启。先跑 `install.sh`。开机时 `network-online.target`
   已到但 DNS/上游仍不可用也可能以 2 退出；确认网络后手工
   `systemctl start mm-client@<ns>.service`。
7. **沙箱路径**：服务端 `ProtectSystem=strict` + `ReadWritePaths=-…`；目录缺失时
   沙箱仍能建立，但 mm-server 会以 2 退出，`RestartPreventExitStatus` 阻止重启。
   unit 不会自动重建目录，先跑 `install.sh`。
8. **spool 磁盘**：设计上限单 batch 64 GiB；监控 `/var/lib/syncmount-mm` 所在
   文件系统。磁盘满会使上传失败，服务端树保持不变，客户端保留 dirty 状态。
9. **shadow 布局**：`--shadow-dir` 下还有 `mm/<ns>` 一层；只备份/迁移最外层
   会漏数据。
10. **`-shm` 与硬链接**：`-shm` 按 opaque 普通文件处理；硬链接不在 1.1 保证范围。
11. **Caddy 重启代价**：`admin off` 只能重启；1.0 长流会短暂断开。

## 7. 敏感信息

示例统一使用 `example.com`、`127.0.0.1` 和 `/home/syncmount`。没有真实域名、
公网 IP、密码或 token；密钥只由 `install.sh` 生成到 0600 文件，不进入 argv、
unit 的 `Environment=`、仓库或日志。客户端账户 `syncmount` 是占位符：
`install.sh` 读取 `CLIENT_USER`/`CLIENT_GROUP`，按该账户渲染
`mm-client@.service` 的 `User=`、`Group=` 和 `HOME=`。

`server.db`、`spool/` 和客户端 shadow 都是明文；它们和备份按与在线数据同等级别
保护。密钥文件不要放进普通备份包。
