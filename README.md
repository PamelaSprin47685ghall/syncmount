# syncmount

End-to-end encrypted, eventually consistent FUSE filesystem for Linux.

One binary is both the client and the server. A client mounts a remote
namespace as a local directory, acknowledges local writes immediately, and
synchronises encrypted operations in the background. The server is a stateless
sequencer: it assigns a total order to ciphertext and holds no key, no disk and
no replay window. Every client replays the same order and reaches the same
state.

```
client A ── FUSE ── local backing
   │  POST {prefix}/rpc        (chunked, encrypted frames)
   │  GET  {prefix}/events     (chunked, encrypted frames)
   ▼
sequencer ── assign seq (total order) ── broadcast ciphertext
   ▲
   │  same two streams
client B ── FUSE ── local backing
```

The server sees a frame header, a routing or control prefix and an opaque
ciphertext body. It never derives, receives or stores a key, and it neither
sees nor verifies Ed25519 signatures: each receiving client verifies every
ordered operation against its own key directory. All payloads — data, paths,
operation arguments, manifests and chunk contents — are sealed with
ChaCha8-Poly1305 under the cluster key; a build may select ChaCha20-Poly1305.
Control frames (`KICK`, `LEAVE`, `WELCOME`, `PONG`) are plaintext hints.

## Status

v0.1.0. The protocol, crypto, store, client, sync, FUSE and server modules are
implemented; the CLI, man page, examples, install script and release workflow
are part of this release. The test suite covers the frame/crypto golden
vectors, deterministic replay, join/rsync, FUSE write/read, two-client
convergence and the server watermark.

## Quick start

Requirements: Linux, `/dev/fuse`, setuid `fusermount3` (package `fuse3`), and a
host C compiler only if blake3 uses its asm backend.

```bash
export SYNCMOUNT_MASTER_PASSWORD='correct horse battery staple'

# Sequencer (foreground)
syncmount server http://127.0.0.1:8080/sync --listen 127.0.0.1:8080

# Client (second terminal)
mkdir -p /mnt/share
syncmount client http://127.0.0.1:8080/sync /mnt/share

# The implicit aliases are equivalent:
#   syncmount URL MOUNTPOINT   -> client
#   syncmount URL              -> server
```

Data writes return before the cluster sees them. A second client mounted with
the same URL and password converges to the same tree.

The client speaks plain HTTP/1.1 only. An `https://` URL is rejected at dial
with `TlsUnsupported`; keep the URL `http://` and, if the path needs transport
protection, use a local tunnel that accepts plain HTTP on loopback.

### Cluster identity

The 16-byte cluster id is derived from the normalised URL
(`scheme://host:port/prefix`) with the domain separator `sm/v1/cluster`, and it
is the Argon2id salt. **Every client of one cluster must use the same URL
spelling.** Changing the host, port or prefix derives a different key and a
different cluster. The scheme is part of that spelling: `http://host/prefix`
and `https://host/prefix` are different clusters, and the client rejects the
latter.

The master password comes from one of:

- `--key-file PATH` (mode 0600, owned by the user);
- `SYNCMOUNT_MASTER_PASSWORD`;
- `SYNCMOUNT_MASTER_PASSWORD_FILE` (mode 0600, owned by the user);
- an interactive terminal prompt when none is configured.

`--key-file` is used when given; otherwise exactly one of the two environment
variables must be set, and setting both is an error. `--key` is refused: a
password in argv is visible in `ps` and shell history. The server needs no
password at all.

## Deployment

The reference deployment serves plain HTTP on port 80. Caddy fronts two
sequencers on loopback: `http://sync.example.com/private` and
`http://sync.example.com/public`. Every client URL in this deployment is
`http://`; the client has no TLS stack and rejects `https://` with
`TlsUnsupported`.

Caddy must forward the prefix unchanged. The URL path is the namespace prefix
and part of the cluster id (and Argon2id salt); `handle_path` strips it and
would break both routing and identity. Keep `/private` and `/public` on the
upstream request.

```caddyfile
{
	servers {
		timeouts {
			read_body_idle -1s
			write_idle -1s
		}
	}
}

http://sync.example.com {
	handle /__syncmount/healthz {
		reverse_proxy 127.0.0.1:8081
	}
	handle /private/* {
		reverse_proxy 127.0.0.1:8081
	}
	handle /public/* {
		reverse_proxy 127.0.0.1:8082
	}
}
```

`healthz` is an absolute path, not below either namespace prefix; route it
explicitly. The response describes the one sequencer it reaches, so a
two-sequencer deployment cannot report both through one health check. Start
each sequencer with its prefix:

```bash
syncmount server http://127.0.0.1:8081/private --listen 127.0.0.1:8081
syncmount server http://127.0.0.1:8082/public  --listen 127.0.0.1:8082
```

Caddy 2.11.6 and later default `read_body_idle` and `write_idle` to one
minute. syncmount keeps two long-lived chunked streams open, so disable both
for these routes as shown. Caddy 2.11.6 also cut some streams after a minute;
that regression is fixed in 2.11.7, so prefer 2.11.7 or later.

A system-level client unit runs as the mounting user:

```ini
[Unit]
Description=syncmount private client

[Service]
Type=simple
User=user
RuntimeDirectory=syncmount-private
Environment=XDG_STATE_HOME=/home/user/.local/state/private
Environment=SYNCMOUNT_RUN_DIR=/run/syncmount-private
Environment=SYNCMOUNT_MASTER_PASSWORD_FILE=/etc/syncmount/master-password
ExecStart=/usr/local/bin/syncmount client http://sync.example.com/private /home/user/private
Restart=on-failure
RestartPreventExitStatus=10

[Install]
WantedBy=multi-user.target
```

`RuntimeDirectory` gives the unit a writable `/run/syncmount-private`;
`XDG_STATE_HOME` holds the Ed25519 identity under
`$XDG_STATE_HOME/syncmount/keys/<cluster>/ed25519.key`. The password file must
be mode 0600, owned by and readable by `User=`. `RestartPreventExitStatus=10`
makes a disconnect final: the unit does not reconnect on its own, so start it
again after the network or the sequencer returns. The `/public` cluster uses
the same shape with `syncmount-public`, `/run/syncmount-public`, its own state
home, mountpoint and unit name. Set the same `SYNCMOUNT_RUN_DIR` when running
`syncmount status`.

## Commands

| Command | Purpose |
|---|---|
| `syncmount client URL MOUNTPOINT` | Mount and run until the transport fails or a signal arrives. |
| `syncmount server URL` | Run the sequencer; `--listen`/`--port` choose the bind address. |
| `syncmount status [--json]` | Read the per-mount status file under the runtime base (default `/run/syncmount`) for every running client. |
| `syncmount debug-state` | Print the full published status document. |
| `syncmount debug-manifest-diff MNT [OTHER] (--url URL \| --cluster HEX)` | Compare local manifest caches. |
| `syncmount debug-seq-gaps [--json]` | Report gaps in the connection trace. |
| `syncmount debug-conntrace [--limit N]` | Print recent frame events. |

Global options: `--log-level FILTER`, `--log-format text|json`, `--foreground`
(a no-op; both modes already run in the foreground), `-h/--help`, `-V/--version`.

Client options: `--allow-other` (requires `user_allow_other` in
`/etc/fuse.conf`), `--allow-empty-view` (accept a JOIN with no view above
sequence zero; cluster-wins then deletes local-only paths), `--key-file PATH`.

Server options: `--listen ADDR` (default `127.0.0.1:8080`), `--port PORT`
(conflicts with `--listen`). Only the path of the server URL is used, as the
namespace prefix; its host and port are ignored.

Exit status: `0` success, `1` usage or a second instance, `2` startup failure,
`3` corrupt audit log, `10` disconnected or kicked after the mount was
released. A systemd unit that restarts on failure must list `10` in
`RestartPreventExitStatus`; see the SYSTEMD section of `man/syncmount.1`.

## Consistency and durability

Data writes, `truncate`, `setattr` and `xattr` are applied to the local backing
tree first and queued in an in-memory outbox. The sequencer orders them later;
reads always use the local tree. The cluster converges by deterministic replay.

Admission is also gated by a replay-backlog window: the client counts local
operations whose echo has not been applied, closes the window at 256 in flight
and reopens it at 128. While it is closed, `write`, `truncate`, `setattr`,
`xattr` and namespace calls return `ENOSPC` before the disk or the sequencer is
touched, and the uplink sends nothing new. `ENOSPC` here means
**backpressure, not data loss**: retry after a pause or lower the write rate.
One client sustains about 1,024 4 KiB random writes per second (4 MiB/s) on
btrfs with zstd, and more on tmpfs; above that rate fio sees `ENOSPC` while the
mount and the client process stay alive. The window protects the producer
only: the server still kicks a consumer whose downlink backlog exceeds its
8 MiB / 512-frame budget with `QueueOverflow`, including an idle peer that
cannot apply the broadcast stream fast enough. That kick unmounts the client
with status 10; remounting recovers. See
[`docs/known-limitations.md`](docs/known-limitations.md) §1.1 and §3.

Namespace operations (`mkdir`, `rmdir`, `unlink`, `rename`, `symlink`, `link`,
`O_CREAT|O_EXCL`) and `fcntl` lock changes use L2 synchronous arbitration: the
callback queues the operation and waits for its own replay verdict, and the
replay engine applies the local change. A concurrent loser gets the losing
errno and its tree is untouched. The wait costs one sequencer round trip and
answers `ENOTCONN` on disconnect or after 10 s; the operation may still be
applied later. See [`docs/known-limitations.md`](docs/known-limitations.md)
§1.1 and §2.5.

`flock` is local to one mount and never crosses clients. `fcntl` record locks
are cross-client and strongly ordered: a cluster mount negotiates
`FUSE_POSIX_LOCKS`, every `getlk`/`setlk` reaches the deterministic byte-range
table, every lock change is an ordered operation, and the caller waits for its
replay verdict. `F_GETLK` returns the first conflicting lock held by another
client, and a conflicting `F_SETLK` returns `EAGAIN`. The owner is the mount,
not the process (`l_pid` is 0), and blocking `F_SETLKW` returns `EOPNOTSUPP`.
A departed holder's locks are released by a signed `LEAVE` or by lease expiry,
not by a server hint; a crashed holder's locks are not reclaimed immediately.

`fsync`/`fdatasync` flush the local disk and ask the uplink to flush the
coalescer; they do not wait for a cluster acknowledgement. The outbox is not
durable: a crash, disconnect or kick loses operations that were not broadcast.
A remount is cluster-wins and can delete or replace local-only work.

### Content addressing

A content chunk has two identifiers. `chunk_id = BLAKE3(plaintext, at most
256 KiB)` is the logical identity used by the manifest, `DataMap`, `BLOCK_REQ`
and the local chunk cache. `blob_id = BLAKE3(ciphertext)` is the
physical-integrity identifier. Deduplication happens before encryption, by
`chunk_id`. Each 64 KiB envelope of a chunk is sealed with a fresh random
nonce, so equal plaintext produces different ciphertext. This is plaintext
addressing: no key and no nonce are derived from the content. A cluster member
who holds the index can tell whether two blocks are byte-identical; the server
sees neither identifier. See
[`docs/known-limitations.md`](docs/known-limitations.md) §4.3.

## History pull

A JOIN above sequence zero needs a view of the current tree. The server names
one online holder in `WELCOME`; the joiner opens a relay session to that
holder and pulls the holder's manifest at the declared sequence, the blockmap,
and the blocks its diff needs. The local cluster-wins step then deletes
local-only paths and replaces differing content. This path is manifest-only:
it has no snapshot transfer and no replay log.

The holder must be another client, `Online`, with both outbox channels open,
and it must report `applied_seq == current_seq`; among eligible holders the
smallest `client_id` wins. A holder that is even one operation behind cannot
serve.

A solo member can recover from its own disk. The server grants a self view
when the client reports the current epoch and has applied `current_seq`, or is
one `LEAVE` behind, and no other identity is attached. The client loads its
persisted local manifest and refuses the view unless it covers the accepted
watermark and describes the disk exactly: any transfer or local-only path
aborts the JOIN before a byte is deleted or pulled.

By default, if no holder and no self view is available above sequence zero,
the client retries after 1, 2, 4, 8 and 16 seconds and exits 2. Cluster-wins
has not run at that point, so local files are not deleted. A multi-member
cluster cannot use a self view; if no member is exactly caught up, the JOIN
fails the same way. At sequence zero the empty view is exact and the JOIN
proceeds without a holder.

See [`docs/known-limitations.md`](docs/known-limitations.md) §1.8 for the
exact conditions and failure semantics.

## Limitations

This is the short list. The normative list, including v0.1.0 implementation
gaps, is [`docs/known-limitations.md`](docs/known-limitations.md); the
adversary model is [`docs/threat-model.md`](docs/threat-model.md).

- **Disconnect means unmount.** A transport failure, heartbeat timeout, kick or
  protocol violation quiesces the mount, flushes for at most two seconds,
  unmounts and exits 10. There is no offline mode, no pending-operation replay,
  no durable outbox and no grace period.
- **No automatic reconnect.** Status 10 is final. A systemd unit must list it
  in `RestartPreventExitStatus`, so the mount stays down after a disconnect;
  start the unit again once the network or the sequencer is back. This
  deployment uses exactly that setting.
- **No built-in TLS.** The client speaks plain HTTP/1.1 and rejects an
  `https://` URL with `TlsUnsupported` before mounting. This deployment is
  plain HTTP on port 80 behind Caddy; a conventional TLS-terminating reverse
  proxy cannot be dialed by the client.
- **Remount is cluster-wins.** Local-only paths are deleted and differing
  content and attributes are replaced. There is no merge, no confirmation and
  no `--force`; the audit log records the counts.
- **Reads are local, and JOIN is readable.** Reads can serve stale data during
  the convergence window (about 0.1 s on a LAN, about 1 s on a public network).
  Writes return `EROFS` during `JOINING`, but reads are allowed, so a reader can
  see a mixed tree while cluster-wins is replacing entries.
- **Empty-local is the only full transfer.** A JOIN otherwise pulls the
  holder's manifest and uses manifest and rsync differences. A local tree with
  no non-empty file and no usable baseline is classified `empty-local` and
  transfers everything. The v0.1.0 status document does not yet expose the
  `empty-local full sync` marker.
- **`fsync` is local only.** It flushes the backing disk and asks the uplink to
  flush the coalescer; it does not wait for the cluster. A crash or disconnect
  loses operations that were not broadcast.
- **`ENOSPC` can mean backpressure.** When replay falls behind, the outbox
  window closes and mutations return `ENOSPC` before anything is written or
  queued; retry after a pause or slow down. The ceiling for 4 KiB random
  writes from one client is about 1,024 ops/s on btrfs (more on tmpfs). A
  consumer that cannot keep up with the broadcast stream — even an idle peer —
  can be kicked by the server with `QueueOverflow`, which unmounts it with
  status 10; remounting recovers.
- **Weak POSIX surface.** `mmap(MAP_SHARED)`, device nodes, Unix sockets,
  FIFOs and `O_APPEND` are best effort: they are accepted and do not fail
  because of the weak cross-client semantics. Shared mappings write back
  through the ordinary write path and participate in last-writer-wins, but
  `msync` is local only, a remote invalidation can raise `SIGBUS`, and
  concurrent mappings on two clients are an uncontrolled race. `O_APPEND`
  anchors at the local EOF and can interleave across clients. A device node
  and a Unix socket are local kernel endpoints whose metadata may be
  broadcast; the endpoint is not shared across hosts. FIFO writes do not
  cross clients. Only regular files, directories and symbolic links have real
  cross-client semantics. atime is not synchronized; ctime is assigned at
  apply time from the server order and is consistent across clients; uid/gid
  are not mapped; mtime is client-supplied; `ioctl` supports only a small
  `FS_IOC_GETFLAGS`/`SETFLAGS` subset and returns `ENOTTY` for other
  commands; `RENAME_EXCHANGE` returns `EOPNOTSUPP`.
- **Locks.** `flock` is local to one mount and never crosses clients. `fcntl`
  record locks are cross-client and strongly ordered: every lock
  change is an ordered operation, and the caller waits for its replay verdict.
  A conflicting `F_SETLK` returns `EAGAIN`; `F_GETLK` reads the table at the
  client's applied sequence, so it can be stale by the convergence window.
  The owner is the mount rather than the process (`l_pid` is 0), blocking
  `F_SETLKW` returns `EOPNOTSUPP`, and a departed holder's locks are released
  by a signed `LEAVE` or a lease, not by a server hint. Namespace conflicts
  (`mkdir`, `rename`, `O_EXCL`) are resolved at replay and the caller waits
  for the verdict.
- **One sequencer, no HA.** A restart resets the sequence to zero, draws a new
  epoch, disconnects every client with status 10 and forces a resynchronise.
  The server can rewrite `seq`, delay, drop, duplicate or reorder frames;
  clients detect their own gaps and epoch changes, but cannot prove a
  cross-client reorder. There is no second sequencer or failover.
- **One identity per running mount.** Two mounts on one host must use distinct
  `XDG_STATE_HOME` values; the server treats a second session with the same
  `client_id` as a duplicate and kicks the older one.
- **Scale.** No hard limit, but the design point is about 20 online clients,
  one million files and 4 GiB per file. Larger deployments are not promised.
  rsync uses 16 MiB segments; each segment boundary can lose one block match
  (about 0.4% of a 4 GiB file at 64 KiB blocks). The `librsync_oxide` backend
  is a new, pinned dependency.
- **One shared master password.** Every client uses the same password; there
  is no per-client credential, rotation or revocation. A leak decrypts past
  and future traffic and requires rebuilding the cluster.
- **Security.** No perfect forward secrecy. Every `ORDERED` operation is
  signed with a random per-client Ed25519 key and verified by every receiving
  client; the server neither sees nor verifies the signature, and a PSK holder
  cannot forge another member's operation without that member's private key.
  Keys are distributed by peers through `JOIN_PROOF`/`JOIN_ACCEPT`, so the
  exchange forms a star: a cluster of three or more clients is not stable
  until every pair has exchanged keys.
  A cluster with no online member trusts its first client without
  verification, so a wrong password is accepted there and creates an isolated
  cluster. The server sees frame headers, routing and control prefixes,
  sizes, timing, connection pairs and client ids, not payloads or paths.
  Control frames (`KICK`, `LEAVE`, `WELCOME`, `PONG`) are hints, not
  authority; the plaintext `LEAVE` is ignored, so it cannot release a lock.
- **No independent fsck, broadcast log, multi-tenant routing or P2P.** Content
  verification is deferred; the watermark health check plus a remount are the
  recovery path. One process serves one cluster. All sync traffic goes through
  the sequencer.
- **No Prometheus listener, config file, `--daemon`, keyring or `genkey`.**
  Configuration is CLI flag > environment > default. The client listens on no
  port.
- **Linux only.** The host needs `/dev/fuse` and a setuid `fusermount3`
  (package `fuse3`). The musl binary is static, but FUSE is not; a container
  also needs `/etc/resolv.conf` for DNS.

## Build

```bash
rustup toolchain install 1.85.0
rustup target add x86_64-unknown-linux-musl
cargo build --locked --release
cargo test --locked --features testkit
```

Static release binary:

```bash
cargo build --locked --profile dist --target x86_64-unknown-linux-musl
file target/x86_64-unknown-linux-musl/dist/syncmount   # static-pie linked
```

The release profile uses fat LTO, one codegen unit and symbol stripping; the
CI asserts a size below 15 MiB and no `NEEDED` entries. See
[`docs/build.md`](docs/build.md) for the full build and release procedure.

## Install

```bash
./install.sh                      # latest release into ~/.local/bin
./install.sh --version 0.1.0 --prefix /usr/local
```

The script downloads the tarball, verifies its sha256, installs the binary and
man page, and reports missing `/dev/fuse` or `fusermount3`.

## Examples

- [`examples/mount-demo.sh`](examples/mount-demo.sh) — one sequencer, one
  mount, write/read round trip.
- [`examples/two-clients.sh`](examples/two-clients.sh) — two mounts, eventual
  convergence and last-writer-wins.
- [`examples/offline-remount.sh`](examples/offline-remount.sh) — transport
  loss unmounts with status 10; a remount is cluster-wins.

Each script uses a private runtime and state directory and cleans up after
itself.

## Documentation

- `man/syncmount.1` — every command, option, environment variable and exit
  status.
- `docs/build.md` — toolchain, musl static build, release assets.
- `docs/known-limitations.md` — the normative semantic boundary: volatile
  writes, locks, JOIN behaviour, scale, security limits and v0.1.0 gaps.
- `docs/threat-model.md` — adversaries, protections, residual risks and key
  lifecycle.
- `docs/contracts/` — frozen contract ledger.
- Acceptance transcripts are internal records and are not published with
  this repository.

## Licences

MIT OR Apache-2.0. See `LICENSE-MIT` and `LICENSE-APACHE`.
