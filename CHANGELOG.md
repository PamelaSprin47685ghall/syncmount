# Changelog

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
