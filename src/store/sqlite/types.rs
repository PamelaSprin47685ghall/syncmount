//! Plain value types exchanged with the SQLite store.
//!
//! These mirror table rows one-to-one. They deliberately carry no SQL logic:
//! validation and binding live in [`super`], so the types stay usable by the
//! event codec and by tests.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::StoreError;

/// Object kind, stored as the `objects.kind` text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ObjectKind {
    File,
    Dir,
    Symlink,
    Char,
    Block,
    Fifo,
    Socket,
}

impl ObjectKind {
    /// The exact text stored in `objects.kind`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Dir => "dir",
            Self::Symlink => "symlink",
            Self::Char => "char",
            Self::Block => "block",
            Self::Fifo => "fifo",
            Self::Socket => "socket",
        }
    }

    /// Parse the `objects.kind` text.
    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "file" => Self::File,
            "dir" => Self::Dir,
            "symlink" => Self::Symlink,
            "char" => Self::Char,
            "block" => Self::Block,
            "fifo" => Self::Fifo,
            "socket" => Self::Socket,
            _ => return None,
        })
    }

    /// One-byte tag used by [`super::hash::state_hash`].
    ///
    /// The state hash must be injective, so a variable-length text kind would
    /// be ambiguous against the following fixed-width fields. This tag is part
    /// of the hash contract; never renumber it.
    pub const fn tag(self) -> u8 {
        match self {
            Self::File => 1,
            Self::Dir => 2,
            Self::Symlink => 3,
            Self::Char => 4,
            Self::Block => 5,
            Self::Fifo => 6,
            Self::Socket => 7,
        }
    }

    /// True for directories.
    pub const fn is_dir(self) -> bool {
        matches!(self, Self::Dir)
    }

    /// True for regular files.
    pub const fn is_file(self) -> bool {
        matches!(self, Self::File)
    }
}

impl fmt::Display for ObjectKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A row of `objects`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Object {
    pub ino: [u8; 16],
    pub kind: ObjectKind,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime_ns: i64,
    pub size: u64,
    pub file_root: [u8; 32],
    pub block_count: u32,
    pub target: Option<Vec<u8>>,
    pub nlink: u32,
    pub deleted: bool,
    pub created_seq: i64,
    pub updated_seq: i64,
}

/// One entry of a file's ordered chunk list.
///
/// `offset` is redundant with `chunk_no` (`offset = chunk_no * 64 KiB`) but is
/// stored and carried on the wire so a reader never has to re-derive it.
/// The server's authoritative state for one rejected path.
///
/// A rejection is point-to-point: the author receives this snapshot in the
/// ERROR detail and replaces the affected path locally. Other clients never
/// see it and it consumes no sequence number.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejectState {
    pub path: String,
    pub object: Option<Object>,
    pub chunks: Vec<ChunkRef>,
    /// Plaintext for each chunk, aligned with `chunks`. Empty when the
    /// server could not read a chunk.
    pub data: Vec<Vec<u8>>,
    pub parent: Option<[u8; 16]>,
    pub name: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkRef {
    pub chunk_no: u32,
    pub hash: [u8; 32],
    pub offset: u64,
    pub len: u32,
}

/// A row of `chunks`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Chunk {
    pub hash: [u8; 32],
    pub len: u32,
    /// `None` on a client means "known hash, bytes not cached".
    pub data: Option<Vec<u8>>,
    pub refcount: u32,
}

/// A row of `names`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Name {
    pub parent: [u8; 16],
    pub name: String,
    pub ino: [u8; 16],
    pub path: String,
}

/// A row of the server-only `op_ids` table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpId {
    pub op_id: [u8; 16],
    pub payload_hash: [u8; 32],
    pub first_seq: i64,
    pub seen_at: i64,
}

/// A `meta.value`. The column is `ANY NOT NULL`; `NULL` is not representable.
#[derive(Clone, Debug, PartialEq)]
pub enum MetaValue {
    Integer(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}

impl MetaValue {
    /// The storage class name, used in type-mismatch errors.
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::Integer(_) => "integer",
            Self::Real(_) => "real",
            Self::Text(_) => "text",
            Self::Blob(_) => "blob",
        }
    }
}

impl From<i64> for MetaValue {
    fn from(value: i64) -> Self {
        Self::Integer(value)
    }
}

impl From<String> for MetaValue {
    fn from(value: String) -> Self {
        Self::Text(value)
    }
}

impl From<&str> for MetaValue {
    fn from(value: &str) -> Self {
        Self::Text(value.to_owned())
    }
}

impl From<Vec<u8>> for MetaValue {
    fn from(value: Vec<u8>) -> Self {
        Self::Blob(value)
    }
}

impl From<MetaValue> for rusqlite::types::Value {
    fn from(value: MetaValue) -> Self {
        match value {
            MetaValue::Integer(value) => Self::Integer(value),
            MetaValue::Real(value) => Self::Real(value),
            MetaValue::Text(value) => Self::Text(value),
            MetaValue::Blob(value) => Self::Blob(value),
        }
    }
}

impl TryFrom<rusqlite::types::Value> for MetaValue {
    type Error = StoreError;

    fn try_from(value: rusqlite::types::Value) -> Result<Self, Self::Error> {
        match value {
            rusqlite::types::Value::Integer(value) => Ok(Self::Integer(value)),
            rusqlite::types::Value::Real(value) => Ok(Self::Real(value)),
            rusqlite::types::Value::Text(value) => Ok(Self::Text(value)),
            rusqlite::types::Value::Blob(value) => Ok(Self::Blob(value)),
            rusqlite::types::Value::Null => Err(StoreError::Corrupt("meta value is NULL")),
        }
    }
}
