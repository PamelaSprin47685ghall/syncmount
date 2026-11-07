# Known limitations

Status: normative design boundary for syncmount v1. This document states the
guarantees the design makes, the guarantees it weakens, and the behaviour it
refuses. It describes the design, not a particular build; implementation
status belongs in release notes.

Where this document says **best effort**, the operation is accepted and does
not fail because of the weak semantics. The result is whatever local execution
and convergence produce. A limitation is a deliberate trade-off, not a bug.

Related documents: [`threat-model.md`](threat-model.md),
[`../README.md`](../README.md), `man/syncmount.1`, and the design records
`39-s1-spec.md`, `49-arbitration-list.md`, `50-client-signing.md` and
`36-known-limitations.md`.

## 1. Consistency, durability and recovery

### 1.1 Eventual consistency, not POSIX or ACID

syncmount is an eventually consistent distributed filesystem. The sequencer
assigns a total order to encrypted operations; every client replays that order
and converges to the same tree. It is not a POSIX filesystem and not an ACID
store.

- A data write, `truncate`, `setattr` and `xattr` change is applied to the
  local backing tree first and queued in an in-memory outbox. The call returns
  before the sequencer has assigned a sequence number.
- Reads use the local backing tree only. During the convergence window a
  reader can see old data, an old directory listing or old attributes. The
  design target is about 100 ms on a LAN and about 1 s on a public network;
  no latency is guaranteed.
- Concurrent writes to the same offset are resolved by last-writer-wins in
  sequence order. Concurrent writes to non-overlapping ranges are merged.
- Namespace operations (`mkdir`, `rmdir`, `unlink`, `rename`, `symlink`,
  `link`, `O_CREAT|O_EXCL`) and `fcntl` lock changes are the exception: they
  are ordered operations, and the caller waits for the sequencer's verdict
  before the callback returns (one round trip). A client that loses such a
  race receives the losing errno (`EEXIST`, `ENOENT`, `EAGAIN`) and its local
  tree is not changed.
- There is no multi-file transaction, no cluster-wide commit point and no
  rollback. Atomicity is per operation, and a large write may be split into
  several operations. Durability is the local backing filesystem.

### 1.2 `fsync` and `fdatasync` are local only

`fsync(2)` and `fdatasync(2)` flush the local backing file and ask the uplink
to flush the coalescer for that inode. They do **not** wait for a cluster
acknowledgement and do not make the data visible to other clients. The remote
copy remains volatile until the sequencer broadcasts it.

There is no durable outbox. The outbox and coalescer live in memory. If the
client process crashes, is killed, loses its transport or is kicked,
operations that were queued but not yet broadcast are lost, even if the
application had already received a successful return from `write(2)` or
`fsync(2)`. The bytes that reached the local backing file remain on local
disk, but a later remount is cluster-wins and may delete or replace them.

`syncfs(2)` is not a cluster barrier. It flushes the local backing filesystem
only.

### 1.3 Disconnect means unmount

A transport failure, heartbeat timeout, protocol violation or kick moves the
client through unmounting: it quiesces the mount, flushes local state for at
most two seconds, unmounts and exits with status 10. There is no offline mode,
no grace period, no pending-operation replay and no durable outbox. Network
recovery does not resume the session; the user must mount again.

If every unmount attempt fails, the client enters a read-only degraded mode:
reads keep working and writes return `EROFS`. This is fail-safe, not fail-stop:
a dead session must not keep accepting writes.

### 1.4 Remount is cluster-wins

A remount reconciles the local tree against the cluster in one direction:

- a path present in the cluster but absent locally is fetched;
- a path present locally but absent in the cluster is deleted;
- differing content is replaced by the cluster version;
- differing attributes are replaced by the cluster version.

There is no merge, no confirmation prompt, no `--force` and no local-wins
option. The audit log records the manifest snapshot and the
`discarded_local_only` / `overwritten` counts. Local-only work that was never
broadcast is therefore lost by design.

### 1.5 JOIN reads can be stale

Writes are refused with `EROFS` while the client is joining, but reads are not
blocked. The cluster-wins step deletes and replaces entries in place before
the write gate opens. A reader during this window can therefore observe a mix
of pre-JOIN local files and cluster content, or a path that disappears and
reappears. Each file is replaced atomically, but the tree as a whole may be
old or mixed. The window ends when the lifecycle publishes `STEADY`.

Blocking reads instead would make a large JOIN look like a hung mount. The
design accepts a read-only, possibly stale view.

Above sequence zero, a JOIN pulls the current manifest from an online holder
and uses a manifest diff plus an rsync difference pass. The only case in which
every file is transferred is a local tree with no non-empty file and no usable
baseline; there is no baseline to diff against. A single missing file is still
a normal rsync difference: that file is transferred in full, but the rest of
the tree is not. See §1.8 for the holder and self-view conditions.

### 1.6 Watermark health is not content verification

The server's watermark check answers liveness and trust questions: is
`applied_seq` advancing, did it go backwards, is it beyond `current_seq`, is
the client still sending heartbeats. It does **not** verify file content,
block hashes or replay correctness. A client can be healthy while its local
tree is stale or wrong.

The accepted recovery path is a remount and a full cluster-wins
resynchronisation. There is no independent fsck tool and no content-level
verification pass in v1.

### 1.7 Server order, restart and reordering

The server assigns `seq`; it is the only total order. Client clocks do not
participate in ordering, and a client clock that is wrong cannot change an
arbitration result.

The server can rewrite `seq`, delay, drop, duplicate or reorder frames. Clients
detect their own `local_seq` gaps, rollback and epoch changes. They cannot
prove a cross-client reorder: the server can put one client's operation before
another's as long as each client's own sequence is monotonic. Preventing that
requires client-to-client consensus or a global hash chain, which v1 does not
have.

The server keeps no durable state. A server restart draws a new epoch and
resets the sequence. Every client is disconnected, unmounts and exits 10; it
must resynchronise on the next mount, and frames from the old epoch are
rejected. There is one sequencer, no leader election and no high availability.

### 1.8 Manifest-only JOIN and self view

Above sequence zero a JOIN needs a view of the current tree. The v1 path is
manifest-only: the server names one online holder in `WELCOME`, the joiner
opens a relay session to that holder, and pulls the holder's manifest at the
declared sequence, the blockmap, and the blocks its diff needs. The local
cluster-wins step then deletes local-only paths and replaces differing content.
There is no snapshot transfer, no replay log and no server-side history on
this path.

Both endpoints must advertise `VIEW_SOURCE` for the server to name a view; a
self view additionally requires `VIEW_SELF` on both sides.

A holder is eligible only when it is another client, `Online`, has both outbox
channels open, and reports `applied_seq == current_seq`. Among eligible
holders the smallest `client_id` wins, so the choice is deterministic. A
holder that is even one operation behind cannot serve.

A self view is the solo-member recovery path. The server grants it only when:

- `current_seq` is sequenced;
- the client reports the current epoch;
- the client's applied watermark is `current_seq`, or one behind it and the
  missing sequence is a `LEAVE` pseudo-operation, not an `ORDERED` operation;
- no other identity is attached to the cluster;
- both endpoints advertised `VIEW_SELF`.

The one-sequence gap is the `LEAVE` that a disconnect while `Online` injects;
it consumes a sequence but carries no content.

The client then loads its persisted local manifest and requires it to cover
the accepted watermark (`current_seq`, or the one-behind `LEAVE` gap) and to
describe the disk exactly. A manifest with any transfer or local-only path is
refused before a byte is deleted or pulled.

By default, if no holder and no self view is available above sequence zero,
the client retries the JOIN after 1, 2, 4, 8 and 16 seconds and then exits 2.
Cluster-wins has not run at that point, so no local file is deleted. A
multi-member cluster cannot use a self view: as soon as another identity is
attached, only a caught-up holder can serve, and a cluster with no such holder
fails the same way.

Sequence zero has its own path. The first identity on an empty cluster is
offered a bootstrap view (`F_VIEW_BOOTSTRAP`, `0x5D`, an optional `u8` in
`WELCOME`) when both endpoints advertise `VIEW_SOURCE`, the server's watermark
is zero, and no other identity is attached. The client then scans its own
disk, uses that manifest and blockmap as the sequence-zero cluster view, and
becomes the holder for later joiners through the normal manifest-only path.
No server state is added: the bootstrap decision is derived from the current
online table and is recomputed on every reconnect.

A non-empty disk is adopted only when it carries a valid
`.syncmount-manifest`. A missing cache means "new mount"; a cache that does
not decode means "damaged state". Both are refused with exit 2 and the disk
is left byte-for-byte unchanged. An empty disk proceeds with an exact empty
view. `--allow-empty-view` is the explicit opt-in to the loss: at sequence
zero it accepts the empty view for a non-empty disk, and cluster-wins then
deletes local-only paths.

The bootstrap source lives only as long as the server process. The server
keeps no durable state, so a restart draws a new epoch and a new sequence
zero. If the bootstrap client is offline when another client connects, that
client becomes the new bootstrap source; when the original returns it sees a
cluster whose initial content is already defined and its local-only paths are
deleted. The first client to connect therefore defines the cluster's initial
content. That is the same trust-on-first-use boundary as key bootstrapping
(§4.6), not a separate authorization.

An old client ignores the unknown `0x5D` field and still takes its old
sequence-zero empty-view path, which deletes local-only files. No protocol
change can repair that client; the protection exists only in clients that
understand the flag.

The limits follow: a new client cannot recover history while every holder is
offline or behind; a solo restart recovers only from a manifest that matches
the disk; and a holder disconnect invalidates its view route, so the joiner
must retry against a new holder.

## 2. POSIX surface

### 2.1 Locks

**`flock(2)` is local to one mount.** The client does not negotiate
`FUSE_FLOCK_LOCKS`, so the kernel handles `flock` locally. Two clients do not
exclude each other, and a lock is not visible in any cluster state. This is
the intended v1 behaviour, not a bug.

**`fcntl` record locks are cross-client.** A cluster mount negotiates
`FUSE_POSIX_LOCKS`; `getlk` and `setlk` reach the adapter. Every lock change is
an ordered `FCNTL_LOCK` operation, every client replays it into the same
deterministic byte-range table, and the caller waits for its own verdict.
`F_GETLK` returns the first conflicting lock held by another client, and
`F_SETLK` returns `EAGAIN` when the replay verdict rejects the range.
`F_GETLK` reads the table at the client's applied sequence, so it can be stale
by the convergence window.

Lock release is part of the security boundary. The server's plaintext `LEAVE`
is only a hint; it must not release a lock. A lock is released by a signed
client `LEAVE` operation or by lease expiry. The exact lease rule is an open
v1 design point (`50-client-signing.md` §11.5), so reclamation of a crashed
holder's locks is not guaranteed to be immediate.

Locks are advisory and depend on all participants being online and replayed.
Do not use them as the only defence for a distributed mutex.

### 2.2 `mmap`, device nodes, sockets, FIFOs and `O_APPEND`

These operations are **best effort**: they are allowed and do not fail because
of the weak cross-client semantics. Their results converge like any other
operation, but the runtime semantics are weaker than on a local filesystem.

**`mmap(MAP_SHARED)` writes.** Shared writable mappings are allowed. Dirty
pages are written back through the ordinary WRITE path and participate in LWW.
The semantics are weak:

- the kernel chooses the writeback time; the application has no flush point;
- `msync(2)` only triggers local writeback, not a cluster acknowledgement;
- a remote invalidation can raise `SIGBUS` in the mapping;
- concurrent mapping writes on two clients are an uncontrolled LWW race;
- a read-only mapping can serve stale pages during the convergence window.

Programs that depend on `MAP_SHARED` (some databases, JVM heaps) can run, but
they get weaker durability and coherence than on a local filesystem. For
critical data, use `pread`/`pwrite` plus `fsync`.

**Device nodes.** `mknod` may create a character or block device node, and its
metadata may be broadcast. The endpoint is always a local kernel object: the
same path on two clients does not refer to the same device, and access remains
subject to the local mount policy. A device node is not a cross-host device
passthrough.

**Unix sockets.** `bind(2)` may create a socket node, and its metadata may be
broadcast. The socket endpoint belongs to the local network stack; two clients
bind their own local sockets and do not interoperate through the shared path.

**FIFOs.** `mkfifo` creates a local kernel object; metadata may be broadcast,
but writes do not cross clients. Two clients see two independent FIFOs.

Only regular files, directories and symbolic links have real cross-client
semantics.

**`O_APPEND`.** `O_APPEND` is allowed and does not fail because of the weak
cross-client semantics. The daemon anchors the write at the local EOF even if
the kernel supplies offset 0, so a single client sees normal append behaviour.
Across clients the EOF is a moving target: two appends can interleave or
overwrite each other, and POSIX's "atomic seek to EOF plus write" is not
preserved. Use explicit offsets and application-level coordination when
appending from multiple clients.

### 2.3 Hard links are strongly consistent

Hard links are not best effort. `link(2)`/`linkat(2)` create a directory entry
that references an existing global inode id. `nlink` is maintained
deterministically by sequence order, and the operation is ordered and
synchronous: the caller waits for the replay verdict. A concurrent unlink that
wins at replay returns `ENOENT` to the caller instead of leaving a link that is
later removed.

All clients converge to the same inode identity, the same directory entries
and the same link count. There is no cross-device refusal for a link within the
cluster.

### 2.4 atime, ctime, mtime, uid, gid and birth time

- **atime** is not part of the synchronized metadata. The mount requests
  `noatime`; the daemon never broadcasts an atime change and never uses atime
  in conflict resolution. A local read can still update the local backing
  filesystem's atime, but no other client sees it. POSIX atime semantics are
  therefore lost.
- **ctime** is written by the state machine at apply time from the server's
  order time. It is consistent across clients and cannot be supplied by a
  client.
- **mtime** is carried in the operation payload and is client-supplied. A
  client can set an arbitrary mtime with `utimensat(2)`; LWW uses the
  sequencer's sequence number, not mtime, so a forged mtime cannot win an
  arbitration by itself. mtime is display and diff metadata, not a trusted
  clock. It reflects the author machine's clock and can look inconsistent with
  ctime if that clock is wrong.
- **uid/gid** are carried as metadata and are not mapped between hosts. If two
  machines use different uid/gid assignments, `ls -l` shows the raw numbers and
  can look wrong. Permission checks are not based on these values: the FUSE
  mount uses the daemon's local credentials and the mount ACL (`RootAndOwner`
  by default, `All` with `--allow-other`). Treat uid/gid as author labels, not
  access control. When the replay engine applies a `SETATTR`, the backing file
  takes the local client's effective uid/gid; the author's uid/gid remain
  manifest metadata.
- **birth time** is not provided. `statx` `STATX_BTIME` is absent from the FUSE
  `getattr` surface.

### 2.5 Other POSIX deviations

- `rename` is one ordered operation. The calling client waits for its verdict,
  so it sees either success or the errno. Other clients apply it when it
  reaches them, so during the convergence window they see the old name or the
  new name, never a half-renamed entry.
- `readdir` and `seekdir` use the local tree. A remote change can arrive
  between two calls and shift directory offsets.
- `statvfs` reports the local backing filesystem's capacity, not a cluster
  quota or a globally accurate free-space figure.
- `O_CREAT|O_EXCL` and `mkdir`-EEXIST are arbitrated at replay and the caller
  waits for the verdict. This costs one sequencer round trip; a loser sees
  `EEXIST`.
- `RENAME_NOREPLACE` is supported. `RENAME_EXCHANGE` is not supported.
- `ioctl(2)` supports only a small `FS_IOC_GETFLAGS`/`SETFLAGS` subset mapped
  to setattr; other commands and `FICLONE` are not supported.
- `fallocate` `COLLAPSE_RANGE`, `INSERT_RANGE` and `UNSHARE_RANGE` are not
  supported. `PUNCH_HOLE`/`ZERO_RANGE` are passed to the backing filesystem, so
  their guarantees are the backing filesystem's, not syncmount's.
- `copy_file_range`, `sendfile` and `splice` fall back to read/write when the
  backing filesystem cannot do the operation.
- `fanotify` is not supported. `inotify` reports local VFS events at the time
  the local view changes, not the source client's event time; it is not a
  cross-client event order or audit log.

## 3. Scale and performance envelope

There is no hard file-count or client-count limit. The following constraints
set the practical envelope.

| Constraint | Effect |
|---|---|
| Server outbound bandwidth × online clients | The hard bottleneck. Aggregate write throughput is roughly link bandwidth / (N−1). 1 Gbps with 20 clients is about 6 MB/s; 20 MB/s with 20 clients needs about 4 Gbps. |
| Manifest memory | About 80–150 bytes per file. One million files is roughly 100–300 MB; five million is roughly 0.5–1 GB. The server keeps only routing state; each client holds its manifest. |
| Full-sync time | A 1 TiB tree at 1 Gbps is about 2.4 hours on one stream; 100 Mbps public is about 24 hours. New large nodes take hours. There is no incremental replay log; a join pulls the holder's manifest and uses rsync differences. |
| Small-message overhead | Coalescing (128 KiB or a 2–5 ms window, forced by `fsync`) is required. Without it, 4 KiB random writes can saturate one HTTP/1.1 connection. |
| Path depth | `PATH_MAX` (4096 bytes) is the real limit; deep-tree optimisation is not attempted. |
| Local full copy | Every client keeps a full local copy. Disk space equal to the dataset is required before mounting. |
| Signature overhead | Every `ORDERED` carries a 75-byte Ed25519 AUTH block; an inline public key adds 32 bytes on the first frame and at least every 64 frames. At 2,000 signed operations per second the sign-and-verify cost is roughly 0.15–0.25 of one modern x86_64 core. For a 200-byte operation the relative overhead is about 37%. |

The v1 design point is about 20 online clients, one million files and 4 GiB per
file. Larger deployments are not promised. Degradation beyond the design point
is a physical bandwidth and memory consequence, not a bug.

### 3.1 `librsync_oxide` and 16 MiB segments

The rsync difference engine uses `librsync_oxide` 0.3.0 (Apache-2.0, pure Rust,
librsync 2.2.1 wire format). The crate has a full-memory API, so every call is
bounded to a 16 MiB segment. The segment size is also the inline threshold:
`RSYNC_INLINE_MAX = RSYNC_SEGMENT = 16 MiB`. Peak memory is about 48 MiB per
worker (basis, new file and delta); four workers is about 192 MiB. A join
checks available memory before starting.

Rolling matching works inside a segment, not across a segment boundary. Each
boundary can lose at most one block match. For a 4 GiB file with 64 KiB rsync
blocks that is at most 256 blocks, about 16 MiB or 0.4% of the file,
transferred as literal data. The loss is bounded and accepted; it does not
change correctness.

The crate is new: a single published version and low download volume. The
project pins it and locks the wire format with fixed golden vectors; it does
not use the C `librsync` library as a test oracle. If the crate turns out to be
incompatible or unmaintained, the allowed remedies are to replace the backend
or accept whole-block transfer. Re-implementing the rolling matcher is not an
option.

If a segment fails (parse error, memory limit, timeout), that file falls back
to a full transfer with a recorded reason. The fallback still uses `chunk_id`
deduplication and the file-level `file_root` verification.

## 4. Security limits

The full adversary model is in [`threat-model.md`](threat-model.md). This
section states the limits that users and operators must plan for.

### 4.1 No forward secrecy and no revocation

The master key is derived from a fixed password and cluster id. A leaked
password decrypts all recorded traffic, past and future. The default wire
cipher is ChaCha8-Poly1305; ChaCha20-Poly1305 can be selected, but neither adds
forward secrecy.

There is no in-band password rotation, no per-client key revocation and no
revocation list. Changing the password derives a new cluster key and requires
every client to change it; it is not a rolling rotation. Deleting a client's
Ed25519 key file creates a new identity (`client_id` changes); v1 does not
rotate a key under one id.

A leaked PSK is a full compromise: the attacker can decrypt all traffic, join
as a new client, send its own operations, replay within the dedup window and
refuse to serve snapshot data. The only remedy is to rebuild the cluster with a
new password. There is no per-client permission model; every PSK holder is
equal.

### 4.2 The server can rewrite `seq` and reorder

The server is the ordering authority. It can rewrite `seq`, delay, drop,
duplicate or reorder frames. Signatures deliberately exclude `seq` because the
sender does not know it when signing and the server must be able to assign it.

Clients detect their own sequence gaps, rollback and epoch changes. They cannot
prove a cross-client reorder. The server can put B's operation before A's as
long as each client's own `local_seq` is monotonic; no client can distinguish
that from a legitimate arrival order. Preventing it requires client-to-client
consensus or a global hash chain, which v1 does not have.

The server can also inject plaintext `WELCOME`, `PONG`, `KICK`, `ERROR`,
`FLOW`, `SYNC_END` and `LEAVE` frames. These are hints, not authority. A forged
`KICK` can force an unmount (availability denial); a forged `LEAVE` cannot
release a lock. State changes require a signed `ORDERED` operation. A signed
client `LEAVE` is the authoritative release for that client's locks.

### 4.3 Plaintext chunk index equality leak

Content chunks are addressed by `chunk_id = BLAKE3(256 KiB plaintext)`. The
manifest, `DataMap`, `BLOCK_REQ` and the local chunk cache are keyed by this
plaintext hash. A peer that holds the index can therefore tell whether two
blocks are byte-identical, including blocks in different files or snapshots,
and can confirm a guessed block by hashing it.

The server does not see `chunk_id`: it is inside the encrypted WCP payload.
The leak is limited to cluster members, who already hold the PSK and can
decrypt the payloads. It is the inherent cost of plaintext addressing, not an
implementation defect.

Each 64 KiB envelope of a chunk is sealed with a fresh random nonce, so equal
plaintext produces different ciphertext. Deduplication happens before
encryption, by `chunk_id`; the design does not use deterministic or
content-derived nonces. `blob_id = BLAKE3(ciphertext)` is a separate
physical-integrity identifier and does not replace `chunk_id` as the logical
identity.

### 4.4 Signature boundary

Every `ORDERED` operation is signed by its author with Ed25519. The signature
covers `client_id`, `op_id` (`iid` and `local_seq`), `op_class`, `epoch`,
frame type, flags and a BLAKE3 hash of the plaintext payload. It does **not**
cover `seq`, `req_id`, `len`, the nonce, the ciphertext or the tag.

The signature therefore proves who wrote an operation and what it contains. It
does not prove where the server placed it in the order. Replay protection is
stateful: `op_id` deduplication, the per-client `local_seq` window, the epoch
check and snapshot watermarks. The server neither sees nor verifies the
signature. A stolen client key allows impersonation of that `client_id` if the
attacker also has the PSK; there is no revocation, so the only global response
is to rebuild the cluster.

A signature failure is fail-closed: the frame is dropped, it is not applied,
and `applied_seq` does not advance. An authorized member can therefore use
invalid signatures to stall a receiver. This is an accepted denial-of-service
risk, not a confidentiality or integrity break.

### 4.5 Traffic analysis and transport

The server and network see frame headers, frame sizes, timing, connection
pairs, client identifiers and the number of clients. The frame header is 21
bytes; a routed frame also carries a 25-byte route prefix (`session_id`,
`stream`, `chunk_index`, `total_chunks`), and a control frame carries an
18-byte control prefix. Payloads, paths, operation arguments, manifests and
chunk contents are encrypted. The server holds no key and cannot decrypt or
forge them. No plaintext path hash is sent to the server.

There is no built-in TLS termination, and the client rejects an `https://` URL
with `TlsUnsupported` before mounting. The protocol is HTTP/1.1 with chunked
request and event streams. A conventional TLS-terminating reverse proxy cannot
be dialed by this client; if transport protection is required, use a local
tunnel that accepts plain HTTP on loopback and carries it over TLS. This
deployment is plain HTTP on port 80. TLS protects frame headers, control
frames and traffic metadata on the wire. It is not a trust root: the server is
still not trusted, and TLS does not make its control frames authoritative. The
payload remains end-to-end encrypted even without TLS.

Server-side denial of service is not cryptographically prevented. The server
accepts unauthenticated connections; garbage is dropped at AEAD decryption.
Rate limiting, connection quotas and a reverse proxy are operational controls,
not protocol guarantees.

### 4.6 Bootstrap and key distribution

The first client in an empty cluster has no peer verifier. It bootstraps on its
own self-certified key. A wrong PSK cannot be detected in that state and
creates an isolated cluster; a later correctly-keyed client cannot join while
the wrong-key client is the only online member.

The same first client also defines the cluster's initial file view when it is
the only identity at sequence zero (§1.8). A wrong-key or wrong-content first
client is therefore authoritative until the cluster is rebuilt.

Key distribution is peer-mediated: `JOIN_PROOF`, `JOIN_ACCEPT`, the snapshot
`keys[]` section, inline public keys on ordered frames, and `KEY_REQ`/
`KEY_RESP`. A member that has not learned a peer's key cannot verify that
peer's frames; it drops them and requests the key. The server's key directory,
if one is deployed, is a cache and never authoritative. Trust-on-first-use is
optional and is not a trust root.

### 4.7 Other security limits

- **ChaCha8 margin.** ChaCha8-Poly1305 has no known practical attack and is
  suitable for personal, internal and mid-value data. For high-value or
  long-lived secrets, select ChaCha20-Poly1305. The cipher choice does not add
  forward secrecy.
- **No per-client ACLs or roles.** Every PSK holder can read every path and
  payload, join as a new client, send valid operations, replay within the dedup
  window and deny service. The PSK is the tenant boundary.
- **Control frames are not authoritative.** `WELCOME`, `PONG`, `KICK`,
  `ERROR`, `FLOW`, `SYNC_END` and the server's `LEAVE` are plaintext and
  unauthenticated. They may affect availability; they do not change locks,
  membership or file state.
- **A `client_id` claim in `HELLO` is not a credential.** A malicious client
  can claim another `client_id` and trigger the duplicate-session kick against
  the real owner. This is a denial of service, not impersonation of signed
  operations.
- **Snapshot providers are members.** A malicious provider can withhold data
  or supply a bad baseline, causing a denial of service or a wrong starting
  point. Snapshot content is content-addressed and the ordered replay still
  converges; a provider cannot forge a signed operation.

## 5. Compatibility and deployment

- Linux only. The client depends on `/dev/fuse`, Linux VFS semantics and the
  Linux syscall surface. macOS and Windows are not supported.
- A non-root mount needs a setuid `fusermount3` (package `fuse3`). Without it,
  only root can mount.
- `/dev/fuse` must exist and be readable/writable by the user. Containers need
  `--device /dev/fuse` (and usually `--cap-add SYS_ADMIN` for the mount).
- The FUSE adapter negotiates `DO_READDIRPLUS` and `PARALLEL_DIROPS`. A
  cluster mount also negotiates `POSIX_LOCKS`; `FLOCK_LOCKS`, writeback cache,
  direct I/O and passthrough are never negotiated. Kernels without a requested
  opcode degrade the corresponding feature.
- The release binary can be static musl, but FUSE is not: the host still needs
  `fusermount3` and `/dev/fuse`. A scratch container also needs
  `/etc/resolv.conf` and `/etc/hosts` for DNS.
- One identity per running mount. Two mounts on one host need distinct
  `XDG_STATE_HOME` values; the server treats a second session with the same
  `client_id` as a duplicate and kicks the older one.
- One sequencer, no leader election and no HA. A server restart draws a new
  epoch and resets the sequence to zero; every client is disconnected, exits
  10 and must resynchronise on the next mount.

## 6. Explicitly not in v1

These are scope exclusions, not bugs and not promises:

- offline mode, local-wins merge, journal replay or pending-operation replay;
- a durable outbox, broadcast log, replay buffer or incremental catch-up;
- independent fsck or content-level verification tools;
- multi-tenant or multi-cluster routing (one process, one cluster);
- peer-to-peer data transfer (all sync traffic goes through the sequencer);
- multi-server consensus, leader election or op-log replication;
- built-in TLS termination;
- Prometheus metrics listener, `readyz`, config file, `--daemon`, `--verbose`
  or `genkey`;
- keyring or any credential cache; a password in argv is refused;
- server-side opaque block cache, zstd compression or payload padding;
- per-client ACLs or roles (every PSK holder is equal).

## 7. User notice

> syncmount is eventually consistent, not a POSIX filesystem and not an ACID
> store.
>
> A write returns after it reaches the local disk and the in-memory outbox; a
> crash, disconnect or kick loses operations that were not broadcast. `fsync`
> only guarantees the local disk, not that other devices have the data. A
> remount is cluster-wins: local-only paths are deleted and differing content
> is replaced.
>
> Other clients see changes after a convergence delay (about 0.1 s on a LAN,
> about 1 s on a public network); reads during that window can return old
> data. A JOIN allows reads while it replaces the tree, so a reader can see a
> stale or mixed tree; writes return `EROFS` until the JOIN completes.
>
> `mmap(MAP_SHARED)`, device nodes, Unix sockets, FIFOs and `O_APPEND` are best
> effort: they are accepted but their cross-client semantics are weak. `flock`
> is local to one mount. `fcntl` record locks are cross-client, but a departed
> holder's locks are released by a signed `LEAVE` or a lease, not by a server
> hint. Hard links are strongly consistent. atime is not synchronized; uid/gid
> are not mapped.
>
> The server sees ciphertext and traffic shape, not payloads or paths. It can
> rewrite sequence numbers, delay, drop or reorder frames; clients detect their
> own gaps but cannot prove cross-client reordering. Do not treat server
> control frames as authority. Use TLS in front of the sequencer on an
> untrusted network.
>
> The encryption has no forward secrecy and no key revocation. A leaked
> password requires rebuilding the cluster. A leaked client private key allows
> impersonation of that client if the attacker also has the password.
>
> A plaintext chunk index lets a cluster member tell whether two blocks are
> identical. The server does not see the index. This is the accepted cost of
> plaintext addressing.
>
> Only Linux is supported. The design point is about 20 online clients, one
> million files and 4 GiB per file; larger deployments are not promised. rsync
> uses 16 MiB segments, so a segment boundary can lose one block match.
