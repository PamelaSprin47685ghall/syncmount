# Changelog

## 1.1.3 — 2026-11-09

The wire protocol, the commands, the server and the 1.0 path are unchanged.
The mmap schema is unchanged.

### Fixed

- **`rmdir` commits pending child deletions first.** When a directory known
  to the server still holds locally deleted entries, `rmdir` commits the
  child directory as an empty batch before the parent batch removes it; the
  server refuses to remove a non-empty directory, so the child must go first.
  If that child checkin fails with `409`, `423` or a transport error, `rmdir`
  returns the error (`EAGAIN` for `409` and `423`), keeps the directory and
  its dirty generations in place, and the next `rmdir` or `fsync` retries. A
  full snapshot taken during the child checkin can expose new live entries;
  `rmdir` then returns `ENOTEMPTY` instead of deleting them. A local-only
  directory skips the child batch and is removed locally.
- **`DIR_NOT_EMPTY` maps to `ENOTEMPTY`.** A `DIR_NOT_EMPTY` server rejection
  no longer becomes the generic batch conflict. It maps to
  `RemoteError::DirNotEmpty(detail)` and the FUSE errno `ENOTEMPTY`, is not
  classified as a retryable conflict, and keeps the server detail in the error
  text and in the `close_checkin` warning log.
- **Close after a local `rmdir` still commits the parent chain.** Closing the
  last descriptor of an entry whose owning directory was removed locally
  commits the surviving parent chain, walking from the root and falling back
  to the root when the owning directory is gone. A committed tombstone version
  also has its dirty generation cleared, so it becomes collectable.

### Changed

- **A checkin that proves nothing changed uploads nothing.** `fsync`,
  `fsyncdir` and the final `close` of a dirty inode first compare every dirty
  direct entry of the directory with the clean checkout baseline: the base
  kept in `mm_base` and the baseline content hash of each regular file. When
  all of them match, the upload is suppressed. No batch is created, no lock,
  checkout revalidation, signature, `begin` or `commit` request is sent, and
  `snapshot_seq` does not advance; only the local dirty bookkeeping is
  cleared. A `noop_checkin` tracing event at debug level records the
  directory, the dirty count and the elapsed time.
- **The comparison is metadata first.** A regular file is compared on size,
  mode, uid, gid and `mtime_ns`; only a full metadata match hashes the bytes,
  with BLAKE3, and only for files that are dirty. A differing hash is a real
  change and is uploaded. A symlink compares its target and
  mode/uid/gid/`mtime_ns`. A directory compares existence and
  mode/uid/gid/`mtime_ns`; a child write never changes the parent `mtime`, so
  clean children are not scanned. A deletion is a real change only when the
  baseline contained the entry. The cost is one metadata comparison per direct
  entry plus BLAKE3 over the dirty regular files; a clean file body is never
  read, and a hash computed by the check is reused by a following upload of
  the same checkin.
- **`mtime` is strict.** Changing only `mtime` is a real change and is
  uploaded. `ino`, `atime` and `ctime` are ignored. A missing baseline content
  hash, from an older shadow database or a collected version, uploads
  conservatively. A concurrent write that changes the directory dirty
  generation during the check abandons the no-op and falls through to the
  normal upload, so no write is lost. `flush` still never uploads, and a
  conflict keeps the dirty state for the next `fsync` or close as before.

## 1.1.2 — 2026-11-09

The wire protocol, commands, the 1.0 path and the mmap schema are unchanged.

### Fixed

- **Close commits the final dirty state.** The last `close` of a dirty inode
  now commits the directory chain from the root down to the owning directory
  and commits the owning directory last, so `fsync` is no longer required to
  publish a file. `flush` still never uploads.
- **Parent snapshots keep local-only child directories.** A full snapshot
  taken during an upload revalidation used to treat a locally created child
  directory as a clean removal and tombstone it before the manifest was
  built. Such a child is now dirty until its parent batch commits.
- **Close keeps the dirty state on error.** A `409`, `423` or transport error
  during the close-triggered checkin is logged; close still succeeds and
  leaves the dirty generations and batch id for the next close or explicit
  `fsync`.

### Changed

- Version string and man page report 1.1.2.

## 1.1.1 — 2026-11-09

The wire protocol, commands and the 1.0 path are unchanged. The shadow schema
gains one additive column (`snapshot_gen`), created on open and defaulted to 0
for existing databases.

### Fixed

- **Shadow restart adopts committed batches.** On mount, the mm client scans
  the batch ids persisted in the shadow database and asks `mm-server` for each
  status. A batch that committed before the crash is adopted locally (base
  version, `snapshot_seq`, cleanup of dirty generations up to the frozen
  snapshot) without uploading again. An open batch is kept for the next
  `fsync`; an aborted or unknown batch is cleared and stays dirty; a network
  or `401` error leaves the state untouched and does not block the mount. A
  batch is adopted at most once, and an older commit never rolls back a newer
  checkout.

### Changed

- Version string and man page report 1.1.1.

## 1.1.0 — 2026-11-09

The 1.0 wire protocol, schema, `/private` and `/public` paths, options and
units are unchanged. 1.1 adds a second, independent path: `--mmap` namespaces
served by `mm-server` and mounted by `mm-client`. Both paths can run on one
host and behind one reverse proxy.

### Added

- **mmap foundation.** An independent SQLite schema and database role, base
  versions `(epoch, dir_seq, dir_version)`, canonical directory manifests,
  BLAKE3 file roots, and a 1.1 store that never touches the 1.0 tables.
- **Two namespaces.** `/private-mm` and `/public-mm`, with a single namespace
  conversion point between URL, SMM1 and shadow paths. `/private` and
  `/public` remain 1.0 namespaces and are refused by the mm client.
- **SMM1 protocol and authentication.** 24-byte frame header, streaming
  payloads, hello/proof with a raw 32-byte key, per-request session MAC,
  strictly increasing sequence numbers, nonce replay guard and idle/absolute
  session expiry.
- **`mm-server`.** checkout, file read, signatures, upload begin/commit/abort,
  lock acquire/renew/release, batch status and version endpoints; one
  `BEGIN IMMEDIATE` atomic commit per directory batch with full rollback; a
  per-batch spool; idempotent begin/commit and `409 BATCH_COMMITTED` replay
  protection.
- **`mm-client` and FUSE-over-shadow.** A local shadow tree of objects,
  versions and per-directory hard links; `mmap(MAP_SHARED)` writeback;
  checkout, fetch-on-miss, dirty generations and `fsync` uploads. `flush` and
  `close` do not upload.
- **rsync deltas.** Per-block weak and strong-128 signatures, COPY, LITERAL,
  UNCHANGED and END_FILE instructions, exact-length streaming reconstruction,
  whole-file BLAKE3 and 64 KiB chunk `file_root` verification on the server.
  A 64 MiB file with one 4 KiB patch moves about 0.5 MiB end to end.
- **Per-directory upload locks.** Key `(namespace, canonical dir_path)`, owner
  by client, 60 s TTL, idempotent acquire, renew and release; `423` for held,
  lost or expired locks; subtree prefix checks on directory rename/remove; a
  5 s sweeper and startup cleanup of stale locks and aborted uploads.
- **Event-driven I/O.** The 2 ms idle outbox poll is gone. A commit notifies
  the uplink through a `Notify` permit; the downlink applies one batch per
  transaction and arms one 2 ms quiet-window timer only while a batch is
  pending; the writeback thread waits on a condition variable until the first
  dirty write. An idle client now wakes about once a second (PING/fallback)
  instead of 500 times a second.
- **Upload recovery.** A batch id is persisted before BEGIN. A lost BEGIN or
  COMMIT response is resolved with `GET batch/{id}`; committed adopts the
  result, open resends once, aborted starts a new batch on the next `fsync`.
- **Deployment artifacts.** `deploy/mm/` units, a Caddy example and an
  idempotent `install.sh`. They are prepared only; nothing is enabled,
  installed or started by this release.

### Changed

- Version string and man page report 1.1.0.
- README, man page and `docs/known-limitations.md` document the mm commands,
  the two namespaces, and the mm limits (no hard links, no cross-directory
  rename, UTF-8 names only, one uploader per directory, `409`/`423` retried on
  the next `fsync`).

### Limits

- Hard links return `EOPNOTSUPP`; cross-directory rename returns `EXDEV`;
  non-UTF-8 names return `EINVAL`; xattrs return `EOPNOTSUPP`.
- One file is capped at 4 GiB, one batch at 64 GiB and 100,000 entries, one
  meta frame at 16 MiB and one read range at 8 MiB.
- Plain HTTP only; terminate TLS in front of the listener. One process and one
  SQLite writer per namespace.

## 1.0.0

Clean break from earlier releases: protocol 3.0, payload v3, server-authoritative
SQLite store, durable outbox, deterministic replay, import, drain/compaction and
the FUSE-over-SQLite client. No mixed-version cluster is supported.
