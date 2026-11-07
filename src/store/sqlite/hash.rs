//! Content and state hashes.
//!
//! # Contracts
//!
//! * `chunks.hash = BLAKE3(chunk data)`.
//! * A file's `file_root` commits to its ordered chunk list, not to the bytes:
//!
//! ```text
//! file_root = BLAKE3("sm/v1/fileroot64"
//!                    || block_count_le64
//!                    || concat(chunk_no_le32 || chunk_hash))
//! ```
//!
//! * `state_hash` commits to every live object, sorted by canonical path:
//!
//! ```text
//! state_hash = BLAKE3("sm/v1/state\0" || for each live object:
//!     path || 0x00 || ino || kind_tag:u8
//!          || mode_le32 || uid_le32 || gid_le32
//!          || mtime_ns_le64 || size_le64 || file_root || nlink_le32)
//! ```
//!
//! `kind_tag` is [`ObjectKind::tag`]. A variable-length kind text would make
//! the concatenation ambiguous against the following fixed-width fields.
//! `path` is the smallest `names.path` for the inode; the root's path is `/`.

use rusqlite::{Connection, OptionalExtension};

use super::schema::ROOT_INO;
use super::types::{ChunkRef, ObjectKind};
use super::{Result, StoreError, read_blob16, read_blob32, read_u32, read_u64};

/// BLAKE3 of one chunk's plaintext.
pub fn chunk_hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// Compute the file-level Merkle root for an object.
///
/// `chunks` must be the object's ordered chunk list (`chunk_no` 0..n with no
/// gaps). For a symlink, `target` is the link body. Special files have no
/// content but still get a distinct root.
pub fn file_root(kind: ObjectKind, target: Option<&[u8]>, chunks: &[ChunkRef]) -> [u8; 32] {
    match kind {
        ObjectKind::File => {
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"sm/v1/fileroot64");
            hasher.update(&(chunks.len() as u64).to_le_bytes());
            for chunk in chunks {
                hasher.update(&chunk.chunk_no.to_le_bytes());
                hasher.update(&chunk.hash);
            }
            *hasher.finalize().as_bytes()
        }
        ObjectKind::Dir => *blake3::hash(b"sm/v1/dir").as_bytes(),
        ObjectKind::Symlink => {
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"sm/v1/symlink");
            hasher.update(target.unwrap_or_default());
            *hasher.finalize().as_bytes()
        }
        other => {
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"sm/v1/special");
            hasher.update(other.as_str().as_bytes());
            *hasher.finalize().as_bytes()
        }
    }
}

const STATE_SQL: &str = r#"
SELECT path, ino, kind, mode, uid, gid, mtime_ns, size, file_root, nlink
FROM (
    SELECT MIN(n.path) AS path,
           o.ino AS ino,
           o.kind AS kind,
           o.mode AS mode,
           o.uid AS uid,
           o.gid AS gid,
           o.mtime_ns AS mtime_ns,
           o.size AS size,
           o.file_root AS file_root,
           o.nlink AS nlink
    FROM objects o
    JOIN names n ON n.ino = o.ino
    WHERE o.deleted = 0
    GROUP BY o.ino
    UNION ALL
    SELECT '/',
           o.ino, o.kind, o.mode, o.uid, o.gid, o.mtime_ns, o.size,
           o.file_root, o.nlink
    FROM objects o
    WHERE o.ino = ?1 AND o.deleted = 0
)
ORDER BY path
"#;

/// Digest of the authoritative object/name tree.
///
/// Reads `objects` and `names` only. A live object without a name (other than
/// the root) is a broken invariant and is reported instead of being silently
/// skipped, because skipping it would make two different trees hash alike.
pub fn state_hash(conn: &Connection) -> Result<[u8; 32]> {
    ensure_live_root(conn)?;

    let mut hasher = blake3::Hasher::new();
    hasher.update(b"sm/v1/state\0");

    let mut stmt = conn.prepare(STATE_SQL)?;
    let mut rows = stmt.query([ROOT_INO.as_slice()])?;
    let mut seen: usize = 0;
    let mut previous: Option<String> = None;

    while let Some(row) = rows.next()? {
        let path: String = row.get(0)?;
        if path.as_bytes().contains(&0) {
            return Err(StoreError::InvalidPath("contains NUL"));
        }
        if let Some(prev) = &previous {
            if prev.as_str() >= path.as_str() {
                return Err(StoreError::Corrupt("state hash path order"));
            }
        }

        let ino = read_blob16(row, 1)?;
        let kind_text: String = row.get(2)?;
        let kind =
            ObjectKind::parse(&kind_text).ok_or(StoreError::Corrupt("unknown object kind"))?;
        let mode = read_u32(row, 3)?;
        let uid = read_u32(row, 4)?;
        let gid = read_u32(row, 5)?;
        let mtime_ns: i64 = row.get(6)?;
        if mtime_ns < 0 {
            return Err(StoreError::Corrupt("negative mtime"));
        }
        let size = read_u64(row, 7)?;
        let root = read_blob32(row, 8)?;
        let nlink = read_u32(row, 9)?;

        hasher.update(path.as_bytes());
        hasher.update(&[0]);
        hasher.update(&ino);
        hasher.update(&[kind.tag()]);
        hasher.update(&mode.to_le_bytes());
        hasher.update(&uid.to_le_bytes());
        hasher.update(&gid.to_le_bytes());
        hasher.update(&(mtime_ns as u64).to_le_bytes());
        hasher.update(&size.to_le_bytes());
        hasher.update(&root);
        hasher.update(&nlink.to_le_bytes());

        previous = Some(path);
        seen += 1;
    }

    let live: i64 = conn.query_row(
        "SELECT COUNT(*) FROM objects WHERE deleted = 0",
        [],
        |row| row.get(0),
    )?;
    let live = usize::try_from(live).map_err(|_| StoreError::Corrupt("negative object count"))?;
    if live != seen {
        return Err(StoreError::Corrupt("live object without a name"));
    }

    Ok(*hasher.finalize().as_bytes())
}

/// The root is the one live object allowed to have no `names` row. It is also
/// the anchor of every path, so a digest computed without it would silently
/// describe a different tree.
pub(crate) fn ensure_live_root(conn: &Connection) -> Result<()> {
    let row = conn
        .query_row(
            "SELECT kind, deleted FROM objects WHERE ino = ?1",
            [ROOT_INO.as_slice()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()?;
    match row {
        Some((kind, 0)) if kind == ObjectKind::Dir.as_str() => Ok(()),
        _ => Err(StoreError::Corrupt(
            "root object is missing or not a live directory",
        )),
    }
}
