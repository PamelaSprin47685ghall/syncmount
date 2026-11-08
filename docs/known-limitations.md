# Known limitations

Status: normative design boundary for syncmount v2 (protocol 3.0). This
document states the guarantees the design makes, the guarantees it weakens,
and the behaviour it refuses. It describes the design, not a particular build.

Where this document says **best effort**, the operation is accepted and does
not fail because of the weak semantics. The result is whatever local execution
and convergence produce. A limitation is a deliberate trade-off, not a bug.

Related documents: [`threat-model.md`](threat-model.md),
[`../README.md`](../README.md) and `man/syncmount.1`.

## 1. Consistency, durability and recovery

### 1.1 The server is authoritative

The server owns the authoritative tree. It decrypts each accepted operation,
plans it against the in-memory mirror, commits the object/name/chunk rows and
one event in a single SQLite transaction, and only then broadcasts the event.
Every client replays the same `seq` order and converges to the server's tree.

The server is the only writer of its database. A semantic rejection consumes
no sequence and is sent to the author alone; the client marks the outbox row
`failed`. A duplicate `op_id` receives the original sequence and does not
create a second event.

This is eventual consistency, not POSIX or ACID. There is no multi-file
transaction, no cluster-wide commit point and no rollback. Atomicity is per
operation. A large write may be split into several wire operations.

### 1.2 Every mutation is local-first

A `write` appends to a per-inode memory buffer and returns. The bytes are
visible to local reads immediately, but they are volatile until the buffer is
committed. A background thread commits the buffer as one client SQLite
transaction that updates the replica and appends the matching outbox row,
every 100 ms and whenever the soft buffer cap forces it. `flush`, `release`
(close), `fsync`, `truncate`, a size-changing `setattr`, `unlink` and `rename`
commit the affected buffer synchronously first; `create`, `mkdir`, `symlink`,
`link`, `rmdir` and the namespace part of `unlink`/`rename` commit before the
FUSE callback returns. The network is not consulted on the write path. There
is no synchronous arbitration round trip.

A crash loses every buffered write that was not committed. The window is at
most one flush interval under normal load, or longer if the soft cap is
exceeded and the synchronous commit fails. The cap defaults to 64 MiB, logs
one warning when crossed and never returns `ENOSPC`. A normal process exit
commits the buffer. Reads consult the buffer before SQLite, so read-after-write
is consistent inside the window; `stat` reports the buffered size.

Operation boundaries are explicit. One FUSE write request is inserted
atomically; coalesced requests may share a transaction, but each request is
fully in it or absent. `create`, `mkdir`, `symlink`, `link`, `rmdir`,
`unlink`, `rename`, `truncate` and `setattr` each use one client transaction.
`rename`/`unlink` first commit the related inode's buffered content in a
separate transaction, then change names and objects in one transaction. A
size-changing `setattr` is one `SETATTR` operation carrying `F_LENGTH` and the
metadata fields, one outbox row and one `setattr` event. The server plans the
new chunk list and the metadata change as one change set in one transaction,
so a crash cannot leave the new size with the old mode. A client crash leaves
an operation fully visible or completely absent; it cannot leave a committed
size with a partial chunk list. The client's own
data echo is acknowledgement-only and never
re-applies the payload, so it cannot roll back a newer local write. A rename or
link echo is applied: the server resolves paths, so its event may name a
different inode than the optimistic local operation, and skipping the echo
would leave this replica permanently split.

Reads use the local replica only. During the convergence window a reader can
see old data, an old directory listing or old attributes. The design target is
about 100 ms on a LAN and about 1 s on a public network; no latency is
guaranteed.

Concurrent writes to the same offset are resolved by last-writer-wins in
server sequence order. The write-back buffer merges the ranges of one inode
into one event. Its chunk list is contiguous: holes between the first and the
last touched chunk are filled with zero chunks, so every chunk keeps its server
offset in the uplink stream. (The coalescer only joins adjacent ranges.)

A server rejection does **not** roll back unrelated local work. The outbox row
stays in the local database as a `failed` tombstone with the server's errno;
the server never applies it, and ordinary reconnects do not resend it. The
affected path is repaired from the server: the ERROR detail carries the
server's snapshot when it fits the 512-byte detail budget, and a larger
snapshot falls back to a resync marker, so the client records the tombstone,
reconnects and replays the server log. Other paths and pending operations are
untouched. Writes to an existing path are last-writer-wins and do converge.

### 1.3 The outbox is durable

The outbox lives in `client.db`, in the same transaction as the local effect.
It has four states:

| State | Meaning |
|---|---|
| `pending` | Not yet handed to the uplink. |
| `sent` | Written to the socket; no acknowledgement yet. |
| `acked` | The server's event for this `op_id` was applied; the row is deleted. |
| `failed` | The server rejected the operation; the errno is kept. |

A new session resets `sent` back to `pending` and resends it. A `sent` row is
**not** retried within the same session: there is no acknowledgement timeout
and no in-session retransmit. A lost frame is recovered only after the
connection ends and the next session resets the row.

The server deduplicates by `op_id`. A resend after a lost acknowledgement
receives the original sequence; the client applies its own echo, marks the row
`acked` and does not apply the local effect a second time.

The outbox has a soft resident-memory budget of 1 GiB and one million
operations. Crossing it logs one warning and admission continues. A lagging
replay or a stalled network never turns a local write into `ENOSPC`; `ENOSPC`
means the client's SQLite disk is full.

### 1.4 `fsync` is local only

`fsync(2)` and `fdatasync(2)` run `PRAGMA wal_checkpoint(TRUNCATE)` on the
client database. They make the local SQLite file durable; they do not wait for
a cluster acknowledgement and do not make the data visible to other clients.
The remote copy becomes visible when the server commits and broadcasts the
event.

The client database uses WAL and `synchronous=FULL`, so a committed
transaction survives a crash even before the checkpoint. `syncfs(2)` is not a
cluster barrier.

### 1.5 Disconnect, remount and replay

A transport failure, kick or protocol violation unmounts the client and exits
with status 10. There is no in-process reconnect and no offline mode. The
replica and the outbox stay in `client.db`; the next start resends pending and
previously sent operations.

A reconnect above `applied_seq == 0` replays the server's event log from
`applied_seq + 1`. A different epoch normally clears the replica tables,
resets `applied_seq` to zero and replays the compacted log from the beginning;
pending outbox rows survive the reset and are sent after the replay.

The exception is a drained client whose durable epoch is the one before the
compaction and whose `applied_seq` equals the pre-compaction sequence. Its
tree already equals the state the compacted log describes, so it keeps the
replica and adopts the new epoch with `applied_seq` set to the synthetic log's
final sequence. Only events written after the compaction are replayed. The
server makes the same decision from the reported watermark, so it does not
resend the synthetic log. An empty replica, a watermark below the compaction
point, or a client without the capability takes the full replay.

A JOIN is a pure event-log replay; the v1 join and identity machinery has
been removed.

Writes return `EROFS` while the client is `JOINING`, but reads are allowed.
A reader can therefore see a mixed tree while replay is filling it. The write
gate opens at `STEADY`.

The first client to reach an empty server (`seq == 0`) with a non-empty,
never-synced database seeds the cluster from that database. This is the only
path that uploads a whole local tree. A later client replays the resulting
events; it does not receive a bulk tree image.

### 1.6 Watermarks, kicks and health

The client sends a sealed `PING` every second carrying its `applied_seq`. The
server uses that watermark for drain, for regression/overclaim checks and for
diagnostics.

The server kicks a session when:

- its outbound queue cannot take a sequenced frame (32 MiB or 512 data
  frames) (`QueueOverflow`); dropping the frame would leave a sequence hole,
  so the session ends instead;
- its reported watermark goes backwards (`Regression`);
- its reported watermark exceeds `current_seq` (`Overclaim`);
- the server compacts or shuts down (`EpochMismatch` or `ServerShutdown`).

A `QueueOverflow` kick does not unmount: the client reconnects from its
durable `applied_seq` with a bounded backoff, and a session that applies
events resets that budget. Only a client that makes no progress across
several attempts exits with status 10. Any other kick unmounts and exits 10.
Lag diagnostics are not a kick: a slow but progressing client may stay slow
for as long as it keeps making progress.

Watermarks prove liveness and replay position, not content correctness. There
is no independent fsck and no content-level verification pass. A client can be
healthy while its local tree is wrong; a full replay is the recovery path.

The server can delay, drop, duplicate or reorder frames. A client detects its
own sequence gap, reconnects from `applied_seq` and replays the hole; an epoch
change clears the replica and replays from zero, unless the client was drained
at the compaction point and fast-forwards. Neither proves a cross-client
reorder:
the server can put B's operation before A's as long as each client's own
stream stays monotonic.

### 1.7 Drain, compaction and epoch

`SIGTERM` or `SIGINT` stops the accept loop and starts a graceful shutdown:

1. **Drain.** Wait up to 30 seconds for every attached session's applied
   watermark to reach `current_seq`. A caught-up session does not delay the
   shutdown. On timeout the server logs the lagging sessions and compacts
   anyway.
2. **Compact.** In one transaction: clear `events`, `event_chunks`, `op_ids`
   and the `replay_wire` sidecar; advance `epoch` by one; reset `seq` to 0 and
   `replay_floor` to 1; emit a minimal replayable log for the live tree (one
   `create_*` per object in path order, a `write` carrying the current chunk
   list for non-empty files, a full `setattr`, and a `link` for every extra
   hard-link name); record `compacted_from_seq`, `compacted_epoch` and
   `compacted_seq`; refresh chunk refcounts and `meta.state_hash`. Compaction
   then collects chunks that no object, event or replay frame references. The
   object and name tables are not rewritten, so the state digest is unchanged.
3. **Kick.** Every session receives `EpochMismatch` and stops. Clients exit 10.

A crash skips compaction. The next start resumes `epoch` and `seq` from
`meta`, replays the existing event log, and clients continue from their
`applied_seq + 1`. Compaction is idempotent for the live tree: running it twice
produces the same state digest.

`WELCOME` carries the three compaction watermarks. A client at
`(compacted_epoch - 1, compacted_from_seq)` adopts `compacted_epoch` and
`compacted_seq` without replaying; the server starts that session after the
synthetic log. Live create, remove, rename and link events carry the timestamp
they write to the affected object and its parents (payload version 3), so two
replicas that applied the same history agree on directory mtimes as well as
content; a fast-forwarding replica therefore keeps the metadata it already
has. The test uses only the epoch and the applied watermark: inode ids differ
between replicas, and a tree built from an independent import may carry
different timestamps, so no state hash is compared. A rolled-back compaction
leaves the metadata unchanged, and a client that already adopted a watermark
it cannot prove falls back to a full replay.

`replay_floor` is the oldest sequence still replayable. Compaction always
leaves it at 1 because the synthetic log starts at 1. There is no bulk tree
transfer: a client that has been offline replays every event after its
watermark, and a client that returns after a compaction either fast-forwards
from the pre-compaction point or replays the synthetic log from the beginning.

### 1.8 State hashes are local diagnostics

`state_hash` is a BLAKE3 digest of the object table, including the 128-bit
inode ids. The server writes it on compaction and on a clean shutdown. The
client refreshes it from replay: a batch that moves `applied_seq` rewrites the
digest after 4096 events or 300 seconds, and otherwise marks
`meta.state_hash_pending`, which the background checkpoint thread drains
within a minute. It is useful for comparing two databases that were built
from the same import, but it is not a cross-cluster consensus value and two
independently written databases need not agree.

## 2. POSIX surface

### 2.1 Names and paths

File names must be valid UTF-8, at most 255 bytes, and free of `/` and NUL.
A non-UTF-8 name is refused with `EINVAL`; an over-long name returns
`ENAMETOOLONG`. The whole path is capped at 4096 bytes. There is no encoding
translation: a name that is not UTF-8 cannot be stored or synchronized.

### 2.2 Supported object types

Regular files, directories, symbolic links and hard links have real
cross-client semantics. `mknod` accepts only regular files; character devices,
block devices, FIFOs and Unix sockets are refused with `EPERM`. A hard link is
a second name for one inode id, and `nlink` is maintained by replay.

### 2.3 Extended attributes and ACLs

Extended attributes are not stored. `getxattr` returns `ENODATA`, `listxattr`
returns an empty list, and `setxattr`/`removexattr` return `ENOTSUP`. POSIX
ACLs are xattr-based and are therefore not supported either. Tools that
depend on `system.posix_acl_*` or `security.*` xattrs will not preserve them.

### 2.4 Locks

`flock(2)` is handled by the local kernel and is local to one mount. Two
clients do not exclude each other through `flock`.

`fcntl(2)` record locks are not implemented: `getlk` and `setlk` return
`ENOSYS`. There is no cross-client byte-range lock table and no lock lease.
Applications that need a distributed mutex must build it at the application
layer.

### 2.5 `mmap`, `O_APPEND` and special I/O

Files are opened with `FOPEN_DIRECT_IO` and reads use the SQLite chunk table.
There is no page-cache coherence protocol. `mmap(MAP_SHARED)` is not a
supported path: on most kernels a direct-I/O file cannot be mapped, and a
mapping that does succeed has no cross-client invalidation. Use
`pread`/`pwrite` for shared data.

`O_APPEND` is anchored at the local EOF by the kernel and then applied as an
ordinary write at that offset. Two clients appending concurrently can
interleave or overwrite each other; POSIX's atomic append is not preserved
across clients.

`ioctl(2)` is not implemented. `fallocate` accepts only mode 0 or
`FALLOC_FL_KEEP_SIZE`; `PUNCH_HOLE`, `COLLAPSE_RANGE`, `INSERT_RANGE` and
`UNSHARE_RANGE` return `ENOTSUP`. `copy_file_range` falls back to
read/write. `lseek` reports `SEEK_DATA`/`SEEK_HOLE` from the stored size, not
from a sparse extent map.

### 2.6 Attributes and time

Only `mode`, `uid`, `gid`, `mtime` and `size` are stored. `atime` and `ctime`
are reported as `mtime`; birth time is the Unix epoch. There is no separate
`ctime` assigned by the server.

`uid` and `gid` are metadata labels, not a cross-host permission model. The
mount ACL (`RootAndOwner` by default, `All` with `--allow-other`) controls
local access. If two machines use different uid/gid assignments, `ls -l` shows
the raw numbers.

### 2.7 Other deviations

- `rename` supports `RENAME_NOREPLACE`; `RENAME_EXCHANGE` returns
  `EOPNOTSUPP`.
- `statvfs` reports the SQLite filesystem's capacity, not a cluster quota.
- `readdir` and `seekdir` use the local replica; a replay can shift directory
  offsets between calls.
- `inotify` reports local VFS events at the time the replica changes, not the
  source client's event time.
- `fanotify` is not supported.

## 3. Scale and performance envelope

There is no hard file-count or client-count limit. The following constraints
set the practical envelope.

| Constraint | Effect |
|---|---|
| Server outbound bandwidth × online clients | The hard bottleneck. The server sends every event to every client, so aggregate write throughput is roughly link bandwidth / (N−1). |
| Full local copy | Every client keeps the full tree and chunk bytes in `client.db`; the server keeps the same data plus the event log. Plan disk for both. |
| Join replay | A new client replays every event after its watermark. After compaction the log is minimal but still one create, one write and one setattr per live object. A large tree takes time to join; there is no bulk tree transfer. |
| SQLite single writer | The client serialises FUSE writers through one connection; the server runs one store thread. Commit latency is dominated by `synchronous=FULL` fsync. |
| Event log growth | Events accumulate until a graceful shutdown compacts them. A long-running server needs disk headroom for the log plus the live tree. |
| Whole-file buffering | `PWRITE` and `TRUNCATE` need the complete post-operation file bytes. The server refuses a result above 4 GiB. |
| Payload ceiling | One wire write aggregate and one event payload are capped at 4 MiB. A larger write is split by the client. |
| Coalescing | Adjacent writes are merged up to 128 KiB immediately, a 2 ms quiet window, or a 5 ms hard ceiling. Without coalescing, small random writes can saturate one HTTP/1.1 connection. |
| Path depth | `PATH_MAX` (4096 bytes) is the real limit; deep-tree optimisation is not attempted. |

The reference deployment has 12 clients and a design point of about one
million files and 4 GiB per file. Larger deployments are not promised.
Degradation beyond the design point is a physical bandwidth, memory and
SQLite consequence, not a bug.

## 4. Security limits

The full adversary model is in [`threat-model.md`](threat-model.md). This
section states the limits that users and operators must plan for.

### 4.1 The server holds the password and reads plaintext

The server requires the master password. It derives the PSK, decrypts every
operation, plans it against the authoritative state and stores plaintext file
data in `server.db`. It can read, modify or delete everything, and it can forge
events or kicks. The PSK protects the link against an eavesdropper who does not
know the password; it does not make the server unable to read the data.

This is not end-to-end encryption and not a zero-knowledge design.

### 4.2 A leaked password is a full compromise

A leaked PSK or master password lets an attacker decrypt recorded traffic,
open both server and client databases, join as a new client, send valid
operations and deny service. There is no per-client credential, no ACL, no
role and no read restriction: every password holder is equal.

There is no perfect forward secrecy. A leaked password decrypts past and
future traffic. ChaCha8-Poly1305 (default) and ChaCha20-Poly1305 (selectable)
both have this property.

There is no in-band password rotation and no revocation list. Changing the
password derives a new namespace id, so existing client databases refuse to
open and the cluster must be rebuilt or re-imported under the new password.
Old recordings remain decryptable with the old password.

### 4.3 Plaintext at rest

Both `client.db` and `server.db` contain plaintext paths, file data, chunk
bytes and metadata. The client creates its database with mode 0600 in a
directory set to 0700. The server database is created by SQLite under the
process umask, so a server unit must set `UMask=0077` (or pre-create the file
0600) and keep it in a 0700 directory. File permissions are not encryption: a
local user who can read the file, a backup, a disk image or a volume image can
read everything.

Use full-disk or volume encryption when the host disk is not trusted. Protect
backups at least as strictly as the live database. There is no separate
client key file in v2; the password file and the databases are equivalent
secrets.

### 4.4 The link

The client speaks plain HTTP/1.1 and rejects an `https://` URL with
`TlsUnsupported`. Without a TLS tunnel, a network attacker sees frame headers,
frame sizes, timing, connection pairs and the number of clients. Paths and
payloads are sealed, so the attacker cannot read them without the PSK. The
attacker can drop, delay, duplicate or inject garbage; AEAD and the handshake
proof reject modified or forged frames.

If transport protection is required, terminate TLS in a local tunnel that
accepts plain HTTP on loopback. TLS protects the wire metadata; it does not
change the server's trust status, because the server already holds the
password.

### 4.5 Denial of service

The server accepts unauthenticated connections; garbage is dropped at AEAD
decryption or at the handshake proof. Rate limiting, connection quotas and a
reverse proxy are operational controls, not protocol guarantees.

A queue overflow, a watermark regression/overclaim or a server shutdown kicks
a client. A malicious server can force an unmount; that affects availability,
not the stored data.

### 4.6 Local users and the mount

The default mount ACL is `RootAndOwner`; `--allow-other` widens it to every
local user and requires `user_allow_other` in `/etc/fuse.conf`. The password
file must be owned by the effective user and mode 0600 or stricter. A local
user who can read the password file or the database has the same access as the
mount owner.

## 5. Compatibility and deployment

- Linux only. The client depends on `/dev/fuse`, Linux VFS semantics and the
  Linux syscall surface. macOS and Windows are not supported.
- A non-root mount needs a setuid `fusermount3` (package `fuse3`). Without it,
  only root can mount.
- `/dev/fuse` must exist and be readable/writable by the user. Containers need
  `--device /dev/fuse` (and usually `--cap-add SYS_ADMIN` for the mount).
- One process per client database. Two mounts on one host need distinct
  `--db` paths or distinct `SYNCMOUNT_STATE_DIR` values. The client takes an
  exclusive `flock` on the database file; a second process fails at startup.
- One server process per namespace. There is no leader election, no failover
  and no multi-server consensus. A graceful shutdown compacts and kicks every
  client; a crash resumes `epoch` and `seq` from the database.
- The reference deployment runs two namespaces on one host, on loopback ports
  8081 and 8082, with separate server databases and one shared password file.
  Caddy must forward the namespace prefix unchanged and must disable
  `read_body_idle`/`write_idle` for the two long-lived streams.
- The server database defaults to `syncmount-server.db` in the current
  directory. A unit should pass an absolute `--db`, set `UMask=0077` and keep
  the file in a 0700 directory.
- The client database path defaults to
  `SYNCMOUNT_STATE_DIR/<namespace>/client.db`, then
  `XDG_DATA_HOME/syncmount/<namespace>/client.db`, then
  `$HOME/.local/share/syncmount/<namespace>/client.db`.
- The password file must be a regular file, owned by the effective user, mode
  0600 or stricter. A root-owned `/etc/syncmount/master.pass` cannot be read by
  a non-root client; give the mount user its own file.
- The SQLite schema is versioned (`user_version` and `meta.schema_version`).
  A build that does not understand the schema refuses to open the database
  rather than migrating silently.

## 6. Explicitly not in v2

These are scope exclusions, not bugs and not promises:

- end-to-end encryption, a zero-knowledge server or server-side opacity;
- perfect forward secrecy, password rotation, revocation or per-client
  credentials;
- per-client ACLs, roles or read restrictions;
- the v1 join and identity machinery (removed);
- delta transfer, bulk tree install and incremental catch-up
  beyond the event log;
- offline mode, local-wins merge, journal replay or pending-operation replay;
- independent fsck or content-level verification tools;
- multi-tenant or multi-cluster routing (one process, one namespace);
- peer-to-peer data transfer (all traffic goes through the server);
- multi-server consensus, leader election or op-log replication;
- built-in TLS termination;
- Prometheus metrics listener, `readyz`, config file, `--daemon`, `--verbose`
  or `genkey`;
- keyring or any credential cache; a password in argv is refused;
- xattrs, POSIX ACLs, `fcntl` record locks, device nodes, FIFOs, Unix sockets
  or non-UTF-8 names;
- files above 4 GiB or wire payloads above 4 MiB;
- built-in encryption at rest.

## 7. User notice

> syncmount is a server-authoritative, eventually consistent filesystem, not
> a POSIX filesystem, not an ACID store and not an end-to-end encrypted
> system.
>
> The server holds the master password, decrypts every operation and stores
> plaintext file data. A leaked password is a full compromise: it opens the
> databases, decrypts recorded traffic and allows new clients to join. There is
> no forward secrecy, no rotation and no revocation. Use full-disk encryption
> when the host disk is not trusted.
>
> Every write commits to the local SQLite database and the durable outbox
> before it returns. A crash or disconnect keeps the outbox; the next session
> resends it. `fsync` only guarantees the local SQLite file, not that other
> clients have the data. A row marked `sent` is not retried until the next
> session resets it to `pending`.
>
> Other clients see changes after a convergence delay (about 0.1 s on a LAN,
> about 1 s on a public network); reads during that window can return old
> data. A JOIN allows reads while it replays, so a reader can see a stale or
> mixed tree; writes return `EROFS` until the replay completes.
>
> A server rejection marks the outbox row `failed` but does not roll back
> unrelated local work. The row stays as a tombstone with the server's errno;
> the server never applies it, and ordinary reconnects do not resend it. The
> affected path is repaired from the server snapshot or by a full replay when
> the snapshot exceeds the ERROR detail budget; writes to an existing path
> converge by last-writer-wins.
>
> Names must be valid UTF-8 and at most 255 bytes. xattrs, POSIX ACLs, `fcntl`
> record locks, device nodes, FIFOs and Unix sockets are not supported.
> `flock` is local to one mount. `mmap(MAP_SHARED)` is not a supported path.
> One wire write and one event payload are capped at 4 MiB; the server refuses
> a file above 4 GiB.
>
> The server can delay, drop, duplicate or reorder frames; clients detect their
> own gaps and epoch changes but cannot prove a cross-client reorder. A
> graceful shutdown drains for at most 30 seconds, compacts the event log,
> advances the epoch and kicks every client; a drained client then adopts the
> new epoch without replaying, while a lagging or new client clears its
> replica and replays from zero. A crash resumes the previous epoch and
> sequence.
>
> The client speaks plain HTTP/1.1 and rejects `https://`. Without a TLS
> tunnel, the link metadata is visible to the network. The PSK hides paths and
> payloads from an eavesdropper, not from the server.
>
> Only Linux is supported. The reference deployment has 12 clients and two
> namespaces; the design point is about one million files and 4 GiB per file.
