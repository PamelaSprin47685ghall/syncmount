# syncmount

Server-authoritative, eventually consistent FUSE filesystem backed by SQLite.

One binary is both the client and the server. A client mounts a namespace as a
local directory, buffers each write in memory and returns, and synchronises
through a durable outbox. A background writer wakes on the first buffered write
and commits the buffer to its own SQLite database and the outbox within 100 ms,
or sooner on flush, fsync, close or a namespace operation; an idle buffer does
not poll. The server owns the authoritative tree, assigns one total order,
appends an event log and streams that log to every client. A client's
mountpoint is a view over its replica database; it is not a backing directory.

**This is not end-to-end encryption.** The server holds the master password,
decrypts every operation, applies it to a plaintext SQLite database and serves
plaintext chunks to joining clients. The shared key protects the link against
an eavesdropper who does not know the password. It does not protect the data
from the server. See [`docs/threat-model.md`](docs/threat-model.md).

```
client A ── FUSE ── client.db (SQLite, plaintext)
   │                  └── outbox (pending / sent / acked / failed)
   │  POST {prefix}/rpc       sealed frames
   │  GET  {prefix}/events    ordered event stream
   ▼
server ── SQLite (authoritative, plaintext) ── seq + epoch + event log
   ▲
   │  same two streams
client B ── FUSE ── client.db (SQLite, plaintext)
```

The server derives the same PSK as every client from the master password
(Argon2id, then HKDF-SHA256), decrypts each operation, plans it against the
authoritative state, commits the object/name/chunk rows and one event in a
single SQLite transaction, and only then broadcasts. A semantic rejection
consumes no sequence and goes back to the author alone. Clients replay events
in `seq` order; an epoch change normally clears the replica and replays from
zero, except for a drained client that adopts the compaction point.

The client has no backing tree. Every FUSE callback reads a SQLite read transaction or
runs one local-first `BEGIN IMMEDIATE` transaction that updates the replica and
appends the matching outbox row in the same commit. A write returns after it
enters the memory buffer, not after a local commit and not after a network
round trip. The outbox is durable: a crash, disconnect or kick keeps the rows,
and the next session resends them.

## Status

v1.1.2, protocol 3.0, payload v3. The 1.0 wire protocol, schema and
`/private` and `/public` behaviour are unchanged; 1.1 adds the independent
`--mmap` namespaces (`/private-mm`, `/public-mm`) served by `mm-server` and
mounted by `mm-client` over a local shadow tree. 1.0 and 1.1 can share a host
and one reverse proxy because they use different paths, ports and databases.
Within the 1.0 core, protocol 3.0 is a clean break from every earlier release:
there is no supported mixed-version cluster. Protocol 1.0 and 2.0 peers are
rejected during negotiation. Payload v1 and v2 records remain decodable, but
an older binary cannot read a v3 record.

The current implementation covers the shared SQLite store, the server
sequencer and event log, the PSK handshake, the FUSE-over-SQLite client, the
durable outbox, deterministic replay, import, drain/compaction and the 12-host
reference deployment. The 1.1 mmap path adds an independent mm schema, the
SMM1 protocol, rsync deltas, per-directory upload locks, a streaming upload
spool and a FUSE-over-shadow client; it does not read or write the 1.0
databases.

## Upgrade to 1.0.0

1.0.0 is **not compatible** with any earlier release. A mixed cluster is
unsupported: finish the upgrade with every client and the server on 1.0.0. The
wire protocol is 3.0 and events use payload v3.

Replace every client binary first, then the server, but keep the clients
stopped until the server is upgraded. These steps assume the old server already
speaks protocol 3.0; from an older protocol major, stop the cluster and rebuild
or re-import under 1.0.0. The authoritative runbook is `docs/operations.md`
§3.2 and §4.2.

1. Freeze writes and confirm every client has `applied_seq == server.seq` and
   an empty outbox. Generate the tree manifests while the mounts are online.
   If a rollback to the old binary must remain possible, take a hot
   `sqlite3 .backup` of `server.db` now, before SIGTERM: the cold copy taken
   after step 2 is already compacted and cannot be read by an old binary.
2. **Keep the clients running.** Send SIGTERM to the old server. Drain waits
   until every online client has applied `current_seq`; compaction then bumps
   the epoch and writes the minimal replay log. Each online client receives an
   `EpochMismatch` KICK, which does not inject a LEAVE event.
3. Stop each client (it may already have exited 10 after the KICK), and back up
   `client.db` with `client.db-wal` plus the stopped server's `server.db` with
   `server.db-wal`.
4. Replace every client binary and keep the clients stopped. A 1.0.0 client
   sends payload v3 in its operations, which the old server cannot decode.
5. Replace the server binary and start the 1.0.0 server. It starts in the
   compacted epoch; new operations write payload v3 immediately.
6. Start the clients. A client that was online at compaction and applied
   exactly `compacted_from_seq` fast-forwards: it keeps its tree, adopts the
   new epoch, and sets `applied_seq = compacted_seq`. Its journal shows
   `compaction_fast_forward` and no `epoch_reset`.

**Do not stop the clients first.** A normal client stop makes the server
commit a LEAVE event. `compacted_from_seq` then includes that LEAVE, the
client's `applied_seq` sits one event behind the compaction point, and
`CompactionState::admits` fails: the client replays the whole tree
(`epoch_reset`) instead of fast-forwarding. A client that was offline during
compaction, or whose watermark is below the compaction point, also replays
from zero.

Verify per client: `compaction_fast_forward` in the journal, zero
`epoch_reset` lines, and `meta.applied_seq` equal to the server's
`meta.compacted_seq` with matching `epoch`. An `epoch_reset` means the client
was not drained to the compaction point.

Do not run an old client against a 1.0.0 server. The server writes every new
event as payload v3, which an old binary cannot decode; the client exits 10 at
the first such event. A pre-3.0 client may instead fail negotiation and report
exit 4. A v3 record is unreadable by every older binary, so a rollback after
the new server has written one fails unless the backups above are restored.

Existing databases are readable: payload v1 and v2 decode, and the schema is
unchanged. A clean rebuild or re-import is still the safer path across this
boundary, because it also removes replicas that were already divergent. After
a graceful compaction, a client that was online and drained at the compaction
point (`epoch = compacted_epoch - 1`, `applied_seq = compacted_from_seq`,
non-empty tree, fast-forward capability negotiated) adopts the new epoch
without replaying; every other client replays from zero.

Keep the service alive with the systemd settings below: `Restart=always`,
`RestartPreventExitStatus=2 4`, and `StartLimitIntervalSec=0`.

## Quick start

Requirements: Linux, `/dev/fuse`, setuid `fusermount3` (package `fuse3`), and a
host C compiler only if blake3 uses its asm backend.

```bash
export SYNCMOUNT_MASTER_PASSWORD='correct horse battery staple'

# Server (foreground). The URL path is the namespace; the database is a file.
syncmount server http://127.0.0.1:8080/sync \
  --listen 127.0.0.1:8080 \
  --db /var/lib/syncmount/sync.db

# Client (second terminal). The database defaults to the state directory.
mkdir -p /mnt/share
syncmount client http://127.0.0.1:8080/sync /mnt/share \
  --db /var/lib/syncmount/client.db

# The implicit aliases are equivalent:
#   syncmount URL MOUNTPOINT   -> client
#   syncmount URL              -> server
```

The first client to reach an empty server (`seq == 0`) with a non-empty local
database seeds the cluster from that database. Import an existing tree before
that first start rather than copying it through FUSE:

```bash
syncmount import --from /srv/data --db /var/lib/syncmount/client.db --seed
```

The client speaks plain HTTP/1.1 only. An `https://` URL is rejected at dial
with `TlsUnsupported`; keep the URL `http://` and, if the path needs transport
protection, use a local tunnel that accepts plain HTTP on loopback.

### Password and namespace identity

The master password comes from one of, in order:

1. `--key-file PATH`;
2. `SYNCMOUNT_MASTER_PASSWORD`;
3. `SYNCMOUNT_MASTER_PASSWORD_FILE`;
4. an interactive terminal prompt.

`--key` is refused: a password in argv is visible in `ps` and shell history.
A password file must be a regular file, owned by the current effective user,
with mode 0600 or stricter. Violations are a startup error (exit 2).

The 16-byte namespace id is `BLAKE3("sm/v2/namespace\0" ‖ PSK)[..16]`. It is
derived from the password, not from the URL. The URL only chooses the
connection target and the HTTP namespace prefix. Every client and the server
must use the same password; a wrong password derives a different key and fails
at the sealed `AUTH` inside `HELLO` (exit 4). The client database also records
the namespace id and refuses to open under a different password.

The handshake is one round trip: `HELLO` (plain body carrying a sealed `AUTH`)
→ `WELCOME` (plain body carrying a server proof and a sealed `ACCEPT`).
`AUTH` and `ACCEPT` are sealed sub-bodies, not frame types; steady-state frames
are sealed with a per-session key derived from the PSK. There is no perfect
forward secrecy and no in-band rotation: a new password means a new namespace
id and new databases.

## Commands

| Command | Purpose |
|---|---|
| `syncmount client URL MOUNTPOINT` | Mount the replica and run until unmounted, a signal arrives, or the reconnect budget is exhausted. |
| `syncmount server URL` | Run the authoritative sequencer; `--listen`/`--port` choose the bind address. |
| `syncmount mm-client URL MOUNTPOINT` | Mount one 1.1 mmap namespace over a local shadow tree. |
| `syncmount mm-server URL` | Run one 1.1 mmap namespace server (separate database and spool). |
| `syncmount import --from DIR` | Import a POSIX tree into a client database without mounting it. |
| `syncmount status [--json]` | Read the per-mount status file under the runtime base (default `/run/syncmount`). |
| `syncmount debug-state` | Print the full published status document. |
| `syncmount debug-seq-gaps` | Report gaps in the connection trace. |
| `syncmount debug-conntrace [--limit N]` | Print recent frame events. |

Global options: `--log-level FILTER`, `--log-format text|json`, `--foreground`
(a no-op; both modes already run in the foreground), `-h/--help`, `-V/--version`.

Client options: `--allow-other` (requires `user_allow_other` in
`/etc/fuse.conf`), `--db PATH` (overrides `SYNCMOUNT_DB`), `--key-file PATH`.

Server options: `--listen ADDR` (default `127.0.0.1:8080`), `--port PORT`
(conflicts with `--listen`), `--db PATH` (default `SYNCMOUNT_SERVER_DB`, else
`syncmount-server.db`), `--key-file PATH`. Only the path of the server URL is
used, as the namespace prefix; its host and port are ignored.

Import options: `--from DIR`, `--db PATH` (default `SYNCMOUNT_DB`, otherwise
the client state directory plus the namespace), `--namespace NAME` (default
`root`, used only for the default database path), `--replace` (clear the
existing tree, outbox and chunks first), `--seed` (generate the deterministic
seed outbox events now), and `--key-file PATH`. An import is idempotent; run it
on a quiescent tree before the first client start, then let that client seed
the empty server. All clients of one namespace must import the same tree.

mm-client options: `--shadow-dir DIR` (required; local object and metadata
store), `--key-file PATH` (raw 32-byte or 64-hex mm key; else
`SYNCMOUNT_MM_KEY`), `--allow-other`. The URL prefix must be `/private-mm` or
`/public-mm`; the client rejects `/private` and `/public`, because those are
1.0 namespaces. An empty prefix selects `/private-mm`.

mm-server options: `--listen ADDR` (default `127.0.0.1:8080`, or
`SYNCMOUNT_MM_LISTEN`), `--db PATH` (default `mm-server.db`, or
`SYNCMOUNT_MM_DB`), `--spool-dir DIR` (default `mm-spool`, or
`SYNCMOUNT_MM_SPOOL`), `--key-file PATH`. The URL path is the namespace and
must match the clients; its host and port are ignored. Run one process,
database and spool directory per namespace.

Exit status: `0` success, `1` usage error detected by syncmount (the refused
`--key`, an invalid URL or listen address), `2` argument parsing failure (for
example an unknown option or missing value; clap exits 2) or startup failure,
`3` reserved (a corrupt audit journal; no audit journal exists in 1.0.0), `4`
authentication failure (wrong master password), `10` disconnected after the
reconnect budget was exhausted or after a terminal kick. A systemd unit should
use `Restart=always`, list `2` and `4` in `RestartPreventExitStatus`, and set
`StartLimitIntervalSec=0`; see the SYSTEMD section of `man/syncmount.1`.

## mmap namespaces (1.1)

`mm-server` and `mm-client` are a second, independent path. They use their own
SQLite schema, the SMM1 protocol and a local shadow tree; they never read or
write a 1.0 database, event log or mountpoint. Both paths can run on the same
host and share one reverse proxy.

```bash
syncmount mm-server http://127.0.0.1:8083/private-mm \
  --listen 127.0.0.1:8083 --db /var/lib/syncmount-mm/private-mm/server.db \
  --spool-dir /var/lib/syncmount-mm/private-mm/spool \
  --key-file /etc/syncmount/mm.key

syncmount mm-client http://sync.example.com/private-mm /private-mm \
  --shadow-dir /var/lib/syncmount-mm-client/private-mm \
  --key-file /etc/syncmount/mm-client.key
```

The key is 32 raw bytes or 64 hex characters; the server and every client of
one namespace must hold the same bytes. The URL prefix is the namespace and
must be `/private-mm` or `/public-mm` (an empty prefix means `/private-mm`);
`/private` and `/public` are refused because they belong to 1.0. Both
processes speak plain HTTP, so terminate TLS in front of the listener. The
server needs `--spool-dir` for per-batch uploads. The client keeps objects,
versions and upload state under `--shadow-dir` and needs an existing absolute
mountpoint.

A checkout returns the `(epoch, dir_seq, dir_version)` base plus the direct
entries of one directory. A write stays local. `fsync` acquires the
per-directory upload lock, asks for rsync signatures, sends COPY/LITERAL
instructions and commits the whole directory batch in one server transaction.
A `409` (base changed) or `423` (lock held, lost or expired) maps to `EAGAIN`,
keeps the dirty generations, and is retried on the next `fsync` or close.
`flush` does not upload. The final `close` of a dirty inode commits its
directory chain from the root down to the owning directory, and commits the
owning directory last; a conflict or transport error there is logged and the
dirty generations survive for the next close or `fsync`. With a live `mmap`,
the kernel delays the final release until the last mapping is gone; an
explicit `fsync` can commit new writes in between.

Limitations specific to the mm path:

- **One uploader per directory.** Uploads of one canonical directory are
  serialised by a server lock. Different directories can proceed in parallel,
  but the single SQLite writer serialises their commits.
- **No hard links.** `link` returns `EOPNOTSUPP`; each inode has one name.
- **No cross-directory rename.** A rename between directories returns
  `EXDEV`. A rename inside one directory, including replace, is supported;
  `RENAME_EXCHANGE` returns `EOPNOTSUPP`.
- **UTF-8 names only.** A non-UTF-8 name returns `EINVAL`. The 255-byte
  component and 4096-byte path limits of 1.0 still apply.
- **No xattrs.** `setxattr` and `removexattr` return `EOPNOTSUPP`.
- **Conflicts are retried later.** A `409` or `423` is not retried inside the
  failing call. The dirty state survives and the next `fsync` or close
  retries it.
- **1.0 is untouched.** `/private`, `/public`, their units, databases and
  options keep their 1.0 behaviour; the mm path is opt-in by command name.

## Deployment

The reference deployment has 12 Linux hosts: one server host that also runs a
client, and 11 client hosts. Names are generic here; a real deployment picks
its own.

| Role | Hosts | Notes |
|---|---|---|
| Server + client | `node-a` | Two server units on loopback: `127.0.0.1:8081` for `/private` and `127.0.0.1:8082` for `/public`, with `/var/lib/syncmount/private/server.db` and `/var/lib/syncmount/public/server.db`. Also runs one client with both mounts. |
| Clients | `node-b` … `node-l` | Each mounts both `/private` and `/public`. `node-b` is `aarch64`; the other hosts are `x86_64`. |

All 12 hosts use the same master password and the same two URLs. Each client
mounts two namespaces, so each host has two `client.db` files and two FUSE
mounts. The server keeps `/etc/syncmount/master.pass` (0600, root). A client
running as a non-root user cannot read that file because the password file
must be owned by the effective user; give each mount user its own 0600 file
(for example `~/.config/syncmount/master.pass`). A backup from an earlier
migration is kept at `$HOME/syncmount-backup-pre-v2-<timestamp>` with checksum
and size inventories; it is not deleted automatically.

Caddy fronts the two server processes. The sync URL stays plain HTTP; the
client has no TLS stack. The public tree may also be published read-only over
HTTPS by a separate Caddy file-server route; that route is a web view, not the
sync protocol.

Caddy must forward the prefix unchanged. The URL path is the namespace prefix;
`handle_path` strips it and would break routing.

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
two-sequencer deployment needs one probe per namespace. Start each sequencer
with its prefix and an explicit database:

```bash
syncmount server http://127.0.0.1:8081/private --listen 127.0.0.1:8081 \
  --db /var/lib/syncmount/private/server.db --key-file /etc/syncmount/master.pass
syncmount server http://127.0.0.1:8082/public --listen 127.0.0.1:8082 \
  --db /var/lib/syncmount/public/server.db --key-file /etc/syncmount/master.pass
```

Caddy 2.11.6 and later default `read_body_idle` and `write_idle` to one
minute. syncmount keeps two long-lived chunked streams open, so disable both
for these routes as shown. Prefer Caddy 2.11.7 or later.

A system-level client unit runs as the mounting user:

```ini
[Unit]
Description=syncmount private client
StartLimitIntervalSec=0

[Service]
Type=simple
User=user
UMask=0077
RuntimeDirectory=syncmount-private
Environment=SYNCMOUNT_RUN_DIR=/run/syncmount-private
Environment=SYNCMOUNT_STATE_DIR=/home/user/.local/state/private
Environment=SYNCMOUNT_MASTER_PASSWORD_FILE=/home/user/.config/syncmount/master.pass
ExecStart=/usr/local/bin/syncmount client http://sync.example.com/private /home/user/private
Restart=always
RestartPreventExitStatus=2 4

[Install]
WantedBy=multi-user.target
```

`RuntimeDirectory` gives the unit a writable `/run/syncmount-private`;
`SYNCMOUNT_STATE_DIR` holds the client database at
`$SYNCMOUNT_STATE_DIR/<namespace>/client.db`. The password file must be mode
0600, owned by and readable by `User=`. The client reconnects in-process after
a transport close, a `QueueOverflow` or `Stalled` kick, or a replay stall; it
exits 10 only when the bounded budget is exhausted or a terminal kick arrives.
`Restart=always` then starts a fresh process, which resends the outbox.
Statuses 2 (argument or startup failure) and 4 (wrong password) are
configuration errors and stop the unit until fixed. `StartLimitIntervalSec=0`
removes the start-rate limit so repeated restarts are not throttled. The
`/public` cluster uses the same shape with `syncmount-public`,
`/run/syncmount-public`, its own state directory, mountpoint and unit name. Set
the same `SYNCMOUNT_RUN_DIR` when running `syncmount status`.

## Consistency and durability

Every mutation is local-first. A `write` appends to a per-inode memory
buffer and returns; the bytes are visible to local reads at once, but SQLite
has not seen them yet. A background writer wakes on the first buffered write
and commits each dirty inode as one SQLite transaction that updates the object
row, the full chunk list, the size and the matching outbox row, at a 100 ms
deadline or earlier when the soft buffer cap forces it. It waits on a
condition variable while the buffer is idle, so there is no fixed polling
tick. `flush`, `release` (close), `fsync`, `truncate`, a size-changing
`setattr`, `unlink` and `rename` commit the affected buffer synchronously
first; `create`, `mkdir`, `symlink`, `link` and `rmdir` commit before
returning. There is no synchronous arbitration round trip. Reads use the
local replica plus the uncommitted buffer.

Operation boundaries are explicit. One FUSE write request is inserted
atomically; coalesced requests may share a transaction, but each request is
fully in it or absent. `create`, `mkdir`, `symlink`, `link`, `rmdir`,
`unlink`, `rename`, `truncate` and `setattr` each use one SQLite transaction.
`rename`/`unlink` first commit the related inode's buffered content in a
separate transaction, then change names and objects in one transaction. A
size-changing `setattr` is one `SETATTR` operation: the client commits the
new chunk list, the metadata and one outbox row in one transaction, and the
server applies the size and metadata as one change set in one transaction. A
crash therefore leaves each operation either fully visible or completely
absent; it cannot leave a committed size with half its chunks, or a renamed
name without its content.

The buffer is volatile. A process crash loses every write that has not been
committed: at most the current flush interval under normal load, or more if
the soft cap is exceeded and the synchronous commit fails. A normal exit
commits the buffer. The soft cap defaults to 64 MiB and only forces an early
commit; it never turns a local write into `ENOSPC`. The outbox row is created
at commit, so its sequence order matches the SQLite transaction and a
namespace operation always follows the writes it covers.

The I/O paths are event driven. The outbox uplink wakes when a commit publishes
a notifier permit, when a control frame arrives, or when the one-second
PING/fallback deadline expires; it sends at most one page of 64 rows per pass
and flushes a coalesced write aggregate at the page boundary, so no aggregate
waits for a timer. The downlink applies at most 64 events or 4 MiB per
transaction and arms one 2 ms quiet-window timer only while a batch is pending.
An idle client wakes about once a second.

The outbox row moves through four states:

| State | Meaning |
|---|---|
| `pending` | Not yet handed to the uplink. |
| `sent` | Written to the socket; no acknowledgement yet. A `sent` row is not retried within the same session. |
| `acked` | The server's event for this `op_id` was applied; the row is deleted. |
| `failed` | The server rejected the operation; the errno is kept for diagnostics. |

A new session resets `sent` back to `pending` and resends it. The server
deduplicates by `op_id`, so a resend after a lost acknowledgement receives the
original sequence and does not create a second event. The client's own data
echo is matched by `op_id` and only acknowledges the outbox row; it never
re-applies the payload, so an older echo cannot shrink a file that newer local
writes have extended. A rename or link echo is applied: the server resolves
paths, so its event may name a different inode than the optimistic local
operation. A rejection does not roll back unrelated local work. The outbox row
becomes a `failed` tombstone with the server's errno, and later pending
operations on the same inode are tombstoned too, so they cannot recreate the
lost race. The ERROR detail carries the server's authoritative state for
the affected path when it fits the 512-byte budget; the client replaces that
path locally. A state payload that does not fit becomes a resync marker: the
client records the tombstone, reconnects and replays the server log. Other
paths and pending operations are untouched. Writes to an existing path are
last-writer-wins and do converge.

`fsync`/`fdatasync` first commit every buffered write, then fsync the client
WAL file. They do not run `wal_checkpoint(TRUNCATE)`: a background thread
copies WAL pages back with a PASSIVE checkpoint, which never blocks the writer
or waits for a long read. The client database uses WAL and
`synchronous=NORMAL`; the server database uses `synchronous=FULL`, because a
confirmed event must survive a power loss. `fsync` makes the local WAL
durable; it does not wait for the cluster. Closing a file (`flush`/`release`)
commits that file but does not checkpoint the WAL.

A transport close, a `QueueOverflow` or `Stalled` kick, or a replay stall
reconnects in-process from `applied_seq` with a bounded backoff; a session that
applies events, or lives 10 seconds, resets the budget. If the budget is
exhausted, the process exits with status 10. Every other kick (for example
`Regression`, `Overclaim`, `EpochMismatch` or `ServerShutdown`), a protocol
violation or a fatal local error unmounts the client and exits 10. There is no
offline mode. The outbox survives a restart, so pending and previously sent
operations are resent. An epoch change normally clears the replica tables and
replays the compacted stream from zero; pending outbox rows survive that reset
too. A drained client that applied exactly the sequence immediately before the
compaction is the exception: it keeps its tree and adopts the new epoch
without a replay (see below).

Both ends enable TCP keepalive (60 s idle, 10 s probe interval, 3 probes), and
the client sends a sealed `PING` every second carrying its `applied_seq`. The
server uses that watermark for drain, regression/overclaim checks and lag
diagnostics; a session that stops reporting progress is eventually kicked as
`Stalled`.

A client whose replica is behind replays the server's event log from
`applied_seq + 1`. Writes return `EROFS` during `JOINING`, but reads are
allowed, so a reader can see a mixed tree while replay is filling it. The
write gate opens at `STEADY`.

The server has a per-session outbound budget of 32 MiB and 512 data frames. A
sequenced frame that does not fit ends the session with `QueueOverflow` instead
of being dropped, so a client's `ORDERED` stream never contains a hole; the
client reconnects and replays from `applied_seq`. Unsequenced relay frames are
dropped unless the queue has stopped draining. A watermark
that regresses or exceeds the server's `current_seq` is kicked as `Regression`
or `Overclaim`. Lag diagnostics are not a kick: a slow but progressing client
may stay slow. See [`docs/known-limitations.md`](docs/known-limitations.md).

`meta.state_hash` is a BLAKE3 digest of the object table, including inode ids.
On the server it is a checkpoint digest written at compaction and at clean
shutdown. On a client it is a diagnostic value: replay refreshes it after 4096
events or 300 seconds, and a smaller batch marks it pending for the background
checkpoint thread, which drains it within 60 seconds. It is not a
cross-cluster consensus value, and replicas built from different imports need
not agree.

Orphan chunks are collected at server startup, at most every 3600 seconds,
and immediately after compaction. A periodic pass deletes only when the last
compaction is at least 3600 seconds old; compaction itself has already dropped
every event that could reference an orphan, so it collects without delay.
Collection deletes chunk rows only. `VACUUM` is not run automatically; freed
pages are reused by later writes.

## Drain, compaction and epoch

`SIGTERM` or `SIGINT` stops the accept loop and starts a graceful shutdown:

1. **Drain.** Wait up to 30 seconds for every attached session's reported
   applied watermark to reach `current_seq`. A session that is already caught
   up does not delay the shutdown. On timeout the server logs the lagging
   sessions and compacts anyway.
2. **Compact.** In one transaction: clear `events`, `event_chunks`, `op_ids`
   and the `replay_wire` sidecar; advance `epoch` by one; reset `seq` to 0 and
   `replay_floor` to 1; emit a minimal replayable log for the live tree (one
   `create_*` per object in path order, a `write` carrying the current chunk
   list for non-empty files, a full `setattr`, and a `link` for every extra
   hard-link name); record `compacted_from_seq` (the old `seq`),
   `compacted_epoch` (the new epoch) and `compacted_seq` (the synthetic log's
   final sequence); refresh chunk refcounts and `meta.state_hash`. Compaction
   then collects chunks that no object, event or replay frame references. The
   object and name tables are not rewritten, so the state digest is unchanged.
3. **Kick.** Every session receives `EpochMismatch` and stops. Clients exit 10.

A crash skips compaction. The next start resumes `epoch` and `seq` from
`meta`, replays the existing event log, and clients continue from their
`applied_seq + 1`.

`WELCOME` carries the three compaction watermarks. A client whose durable
epoch is `compacted_epoch - 1` and whose `applied_seq` equals
`compacted_from_seq` already holds the tree the synthetic log describes: it
keeps its objects, names and chunks, adopts the new epoch and sets
`applied_seq` to `compacted_seq`. The server skips the synthetic log for that
session, so only events written after the compaction are replayed. The
decision uses the applied watermark and epoch alone; inode ids differ between
replicas, and a tree built from an independent import may carry different
timestamps, so no state hash is compared.

A client below `compacted_from_seq`, an empty or damaged replica, or a client
that did not negotiate the capability clears its replica, resets
`applied_seq` to zero and replays the new log from the beginning. A new
client with an empty database always takes this path. The first client to
reach an empty server (`seq == 0`) with a non-empty, never-synced database
seeds the cluster from that database; this is the only path that uploads a
whole local tree.

`replay_floor` is the oldest sequence still replayable. Compaction always
leaves it at 1 because the synthetic log starts at 1.

## Content and import

Content is chunked at 64 KiB and addressed by `BLAKE3(plaintext)`. The server
stores the plaintext chunk bytes in `chunks`; clients store the same bytes in
their replica. A `write` event carries chunk references, not content. The
client coalesces adjacent writes into one wire operation of at most 4 MiB, and
one event payload is capped at 4 MiB. The server buffers the whole
post-operation file for `PWRITE`/`TRUNCATE` and refuses a result above 4 GiB.

`syncmount import` walks a directory without following symbolic links and
writes `objects`, `names`, `chunks` and `object_chunks` directly. It preserves
directories, regular files, symbolic links, hard links, mode, uid, gid and
mtime. Inodes are deterministic:
`ino = BLAKE3("sm/v2/import\0" ‖ path)[..16]`, so importing the same tree on
several machines yields the same ids and re-running an import is a no-op.
Names used by the old daemon (`.syncmount*`, `.audit.log`) are skipped, and
special files are refused.

## Limitations

This is the short list. The normative list is
[`docs/known-limitations.md`](docs/known-limitations.md); the adversary model
is [`docs/threat-model.md`](docs/threat-model.md).

- **Not end-to-end encrypted.** The server holds the master password, decrypts
  every operation, stores plaintext file data and can read or modify
  everything. The PSK protects the link against an eavesdropper, not the data
  from the server.
- **One shared password.** Every client and the server use the same password.
  There is no per-client credential, rotation, revocation or forward secrecy.
  A leaked password is a full compromise; recovery means new databases under a
  new password.
- **SQLite is the only state.** The client mountpoint is a view over
  `client.db`; the server's `server.db` is authoritative. Both are plaintext.
  The client creates its database 0600; the server database follows the
  process umask, so set `UMask=0077` in the unit and keep both in a 0700
  directory. Use full-disk or volume encryption if the host disk is not
  trusted.
- **One writer per database.** SQLite allows one writer at a time. The client
  serialises FUSE writers through one connection; the server runs one store
  thread. A second process on the same client database fails at startup (exit 2).
- **Drain is bounded at 30 seconds.** A session that does not reach the
  watermark in time is disconnected when the server compacts and kicks.
- **`sent` is not retried within a session.** There is no acknowledgement
  timeout or in-session retransmit. A row marked `sent` is resent only when the
  next session resets it to `pending`.
- **No non-UTF-8 names.** A file name must be valid UTF-8, at most 255 bytes
  and free of `/` and NUL; otherwise the operation returns `EINVAL` or
  `ENAMETOOLONG`. Paths are capped at 4096 bytes.
- **No ACLs or xattrs.** `getxattr` returns `ENODATA`, `listxattr` returns an
  empty list, `setxattr` and `removexattr` return `ENOTSUP`, and POSIX ACLs
  are not stored. `fcntl` record locks return `ENOSYS`; `flock` is local to one
  mount.
- **4 MiB payload and 4 GiB file ceilings.** One wire write aggregate and one
  event payload are capped at 4 MiB; the server refuses a file larger than
  4 GiB. Larger files must be split by the application.
- **Reads can be stale and JOIN is readable.** The convergence window is about
  0.1 s on a LAN and about 1 s on a public network. A joining client allows
  reads while it replays.
- **A rejection repairs only the affected path.** The outbox row becomes a
  `failed` tombstone with the server's errno, and later operations on the same
  inode are tombstoned too. The server's state replaces the affected path
  locally when it fits the 512-byte detail budget; otherwise the client
  records a resync marker, reconnects and replays the server log. Other paths
  and pending operations are untouched. Writes to an existing path converge by
  last-writer-wins.
- **No HA, no multi-tenant routing, no P2P.** One process serves one
  namespace, and one SQLite file is the only authoritative state; there is no
  failover, leader election or multi-server replication. All traffic goes
  through the server. There is no independent fsck, broadcast log or content
  verification pass; a full replay is the recovery path.
- **Linux only.** The host needs `/dev/fuse` and a setuid `fusermount3`. The
  musl binary is static, but FUSE is not; a container also needs
  `/etc/resolv.conf` for DNS.

## Build

```bash
rustup toolchain install 1.85.0
rustup target add x86_64-unknown-linux-musl
cargo build --locked --release
cargo test --locked
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
./install.sh --version 1.1.2 --prefix /usr/local
```

The script downloads the tarball, verifies its sha256, installs the binary and
man page, and reports missing `/dev/fuse` or `fusermount3`.

## Examples

- [`examples/mount-demo.sh`](examples/mount-demo.sh) — one server, one mount,
  write/read round trip.
- [`examples/two-clients.sh`](examples/two-clients.sh) — two mounts, eventual
  convergence and last-writer-wins.
- [`examples/offline-remount.sh`](examples/offline-remount.sh) — transport loss
  triggers in-process reconnects; once the budget is exhausted the client
  unmounts with status 10 and the durable outbox is resent on the next start.

Each script uses a private runtime and state directory and cleans up after
itself.

## Documentation

- `man/syncmount.1` — every command, option, environment variable and exit
  status.
- `docs/build.md` — toolchain, musl static build, release assets.
- `docs/known-limitations.md` — the normative semantic boundary: local-first
  writes, the durable outbox, replay and epoch rules, POSIX gaps, scale and
  security limits.
- `docs/threat-model.md` — adversaries, the plaintext-server boundary,
  password lifecycle and residual risks.
- `docs/contracts/` — frozen contract ledger.

## Licences

MIT OR Apache-2.0. See `LICENSE-MIT` and `LICENSE-APACHE`.
