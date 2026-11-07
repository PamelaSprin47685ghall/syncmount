//! Inode identity and the in-memory name/path index.
//!
//! [`InodeId`] is a client-generated UUIDv4 frozen into the op payload; it
//! survives `rename` and `link` and is the only identity the replay engine and
//! the sync layer exchange. [`NodeTable`] maps that id to:
//!
//! * one stable kernel inode number (`u64`) for the lifetime of the mount;
//! * every `(parent, name)` directory entry that references it (hard links);
//! * a cached path relative to the backing root (invalidated on every rename).
//!
//! It is an index, never a source of truth: the disk is authoritative, and a
//! failed table update must never fail an already-completed syscall.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::store::{Errno, Kind, Result, is_reserved_name};

/// The kernel inode number reserved for the backing root.
pub const ROOT_INO: u64 = 1;

/// Maximum parent-chain length accepted while building a path.
const MAX_DEPTH: usize = 256;

/// Path cache entries kept before the cache is dropped wholesale.
const PATH_CACHE_LIMIT: usize = 4096;

/// Directory descriptors kept before the oldest one is dropped.
const DIRFD_CACHE_LIMIT: usize = 256;

/// A globally unique inode identity.
///
/// The wire format is a UUIDv4 (128 bit, stored as a `u128`); the all-zero
/// value is reserved for the backing root, which has no on-wire identity.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InodeId(pub u128);

impl InodeId {
    /// The backing root.
    pub const ROOT: Self = Self(0);

    /// Generate a fresh UUIDv4.
    pub fn new_v4() -> Self {
        Self(uuid::Uuid::new_v4().as_u128())
    }

    /// True for the backing root.
    pub fn is_root(self) -> bool {
        self.0 == 0
    }

    /// Lowercase 32-digit hex, suitable for logs and `status`.
    pub fn to_hex(self) -> String {
        format!("{:032x}", self.0)
    }

    /// Reconstruct an id from its 16-byte big-endian wire form.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(u128::from_be_bytes(bytes))
    }

    /// The 16-byte big-endian wire form.
    pub const fn to_bytes(self) -> [u8; 16] {
        self.0.to_be_bytes()
    }

    /// The underlying UUID.
    pub const fn as_uuid(self) -> uuid::Uuid {
        uuid::Uuid::from_u128(self.0)
    }

    /// Wrap a UUID.
    pub const fn from_uuid(id: uuid::Uuid) -> Self {
        Self(id.as_u128())
    }

    /// True when the id carries the UUIDv4 version and RFC 4122 variant bits.
    pub fn is_uuid_v4(self) -> bool {
        let bytes = self.to_bytes();
        bytes[6] >> 4 == 4 && bytes[8] & 0xc0 == 0x80
    }
}

impl fmt::Debug for InodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "InodeId({:032x})", self.0)
    }
}

impl fmt::Display for InodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:032x}", self.0)
    }
}

/// One inode known to the mount.
#[derive(Clone, Debug)]
pub struct Node {
    /// Global identity.
    pub id: InodeId,
    /// Stable kernel inode number.
    pub ino: u64,
    /// File type.
    pub kind: Kind,
    /// Kernel lookup count (`FUSE_FORGET` decrements it).
    pub nlookup: u64,
    dirfd: Option<Arc<OwnedFd>>,
}

impl Node {
    /// A cached directory descriptor, if one was retained.
    pub fn dirfd(&self) -> Option<&Arc<OwnedFd>> {
        self.dirfd.as_ref()
    }

    /// Replace the cached directory descriptor.
    pub fn set_dirfd(&mut self, fd: Option<Arc<OwnedFd>>) {
        self.dirfd = fd;
    }
}

#[derive(Debug)]
struct Inner {
    by_ino: HashMap<u64, InodeId>,
    by_id: HashMap<InodeId, Node>,
    /// `(parent, name) -> inode`: the authoritative directory entries.
    names: BTreeMap<(InodeId, OsString), InodeId>,
    /// `inode -> {(parent, name)}`: one entry per hard link.
    links: BTreeMap<InodeId, BTreeSet<(InodeId, OsString)>>,
    /// Insertion order for cached directory descriptors (FIFO eviction).
    dirfd_order: VecDeque<InodeId>,
    next_ino: u64,
    rename_epoch: u64,
}

impl Inner {
    fn new() -> Self {
        let root = Node {
            id: InodeId::ROOT,
            ino: ROOT_INO,
            kind: Kind::Dir,
            nlookup: 1,
            dirfd: None,
        };
        let mut by_ino = HashMap::new();
        by_ino.insert(ROOT_INO, InodeId::ROOT);
        let mut by_id = HashMap::new();
        by_id.insert(InodeId::ROOT, root);
        Self {
            by_ino,
            by_id,
            names: BTreeMap::new(),
            links: BTreeMap::new(),
            dirfd_order: VecDeque::new(),
            next_ino: ROOT_INO + 1,
            rename_epoch: 0,
        }
    }

    fn alloc_ino(&mut self) -> u64 {
        let ino = self.next_ino;
        self.next_ino += 1;
        ino
    }

    fn drop_subtree(&mut self, id: InodeId) {
        let mut stack = vec![id];
        let mut removed = BTreeSet::new();
        while let Some(current) = stack.pop() {
            let children: Vec<(InodeId, OsString)> = self
                .names
                .range((current, OsString::new())..)
                .take_while(|((parent, _), _)| *parent == current)
                .map(|(key, _)| key.clone())
                .collect();
            for key in children {
                if let Some(child) = self.names.remove(&key) {
                    self.links.remove(&child);
                    stack.push(child);
                }
            }
            if let Some(node) = self.by_id.remove(&current) {
                self.by_ino.remove(&node.ino);
            }
            self.links.remove(&current);
            removed.insert(current);
        }
        if !removed.is_empty() {
            self.dirfd_order.retain(|cached| !removed.contains(cached));
        }
    }

    /// True if `node` is `ancestor` or lies below it.
    fn is_within(&self, mut node: InodeId, ancestor: InodeId) -> bool {
        let mut depth = 0usize;
        loop {
            if node == ancestor {
                return true;
            }
            if node.is_root() {
                return false;
            }
            let Some(link) = self.links.get(&node).and_then(|set| set.iter().next()) else {
                return false;
            };
            node = link.0;
            depth += 1;
            if depth > MAX_DEPTH {
                return false;
            }
        }
    }
}

#[derive(Debug, Default)]
struct PathCache {
    map: HashMap<(u64, InodeId), PathBuf>,
}

/// The inode / directory-entry index for one mounted backing tree.
///
/// All methods are thread-safe. Lock poisoning is recovered rather than
/// propagated: a panic in one FUSE worker must not brick the namespace.
pub struct NodeTable {
    inner: RwLock<Inner>,
    cache: Mutex<PathCache>,
}

impl fmt::Debug for NodeTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inner = self.read();
        f.debug_struct("NodeTable")
            .field("nodes", &inner.by_id.len())
            .field("names", &inner.names.len())
            .field("rename_epoch", &inner.rename_epoch)
            .finish()
    }
}

impl Default for NodeTable {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeTable {
    /// A table containing only the backing root.
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(Inner::new()),
            cache: Mutex::new(PathCache::default()),
        }
    }

    fn read(&self) -> RwLockReadGuard<'_, Inner> {
        self.inner
            .read()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    fn write(&self) -> RwLockWriteGuard<'_, Inner> {
        self.inner
            .write()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    /// Register `(parent, name) -> id`, creating the inode if needed.
    ///
    /// A second call with the same id and a different name is a hard link.
    pub fn insert_link(
        &self,
        id: InodeId,
        parent: InodeId,
        name: &OsStr,
        kind: Kind,
    ) -> Result<()> {
        validate_name(name)?;
        if is_reserved_name(name) {
            return Err(Errno::EEXIST);
        }
        if id.is_root() {
            return Err(Errno::EINVAL);
        }
        let mut inner = self.write();
        let Some(parent_node) = inner.by_id.get(&parent) else {
            return Err(Errno::ENOENT);
        };
        if !parent_node.kind.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        let key = (parent, name.to_os_string());
        if let Some(existing) = inner.names.get(&key) {
            if *existing != id {
                return Err(Errno::EEXIST);
            }
        }
        match inner.by_id.get(&id) {
            Some(node) if node.kind != kind => return Err(Errno::EINVAL),
            Some(_) => {}
            None => {
                let ino = inner.alloc_ino();
                inner.by_ino.insert(ino, id);
                inner.by_id.insert(
                    id,
                    Node {
                        id,
                        ino,
                        kind,
                        nlookup: 0,
                        dirfd: None,
                    },
                );
            }
        }
        inner.names.insert(key.clone(), id);
        inner.links.entry(id).or_default().insert(key);
        inner.rename_epoch += 1;
        Ok(())
    }

    /// Remove one directory entry. The inode is dropped when its last link
    /// disappears; a directory subtree is dropped with it.
    pub fn remove_name(&self, parent: InodeId, name: &OsStr) -> Option<InodeId> {
        if is_reserved_name(name) {
            return None;
        }
        let mut inner = self.write();
        let key = (parent, name.to_os_string());
        let id = inner.names.remove(&key)?;
        if let Some(links) = inner.links.get_mut(&id) {
            links.remove(&key);
        }
        let last_link = inner
            .links
            .get(&id)
            .map(|links| links.is_empty())
            .unwrap_or(true);
        if last_link {
            inner.links.remove(&id);
            inner.drop_subtree(id);
        }
        inner.rename_epoch += 1;
        Some(id)
    }

    /// Move one directory entry, replacing the target if it exists.
    pub fn rename_name(
        &self,
        old_parent: InodeId,
        old_name: &OsStr,
        new_parent: InodeId,
        new_name: &OsStr,
    ) -> Result<InodeId> {
        validate_name(old_name)?;
        validate_name(new_name)?;
        if is_reserved_name(old_name) {
            return Err(Errno::ENOENT);
        }
        if is_reserved_name(new_name) {
            return Err(Errno::EEXIST);
        }
        let mut inner = self.write();
        let old_key = (old_parent, old_name.to_os_string());
        let Some(&id) = inner.names.get(&old_key) else {
            return Err(Errno::ENOENT);
        };
        let Some(new_parent_node) = inner.by_id.get(&new_parent) else {
            return Err(Errno::ENOENT);
        };
        if !new_parent_node.kind.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        if inner.is_within(new_parent, id) {
            return Err(Errno::EINVAL);
        }
        let new_key = (new_parent, new_name.to_os_string());
        if let Some(&existing) = inner.names.get(&new_key) {
            if existing != id {
                inner.names.remove(&new_key);
                if let Some(links) = inner.links.get_mut(&existing) {
                    links.remove(&new_key);
                }
                let last_link = inner
                    .links
                    .get(&existing)
                    .map(|links| links.is_empty())
                    .unwrap_or(true);
                if last_link {
                    inner.links.remove(&existing);
                    inner.drop_subtree(existing);
                }
            }
        }
        inner.names.remove(&old_key);
        if let Some(links) = inner.links.get_mut(&id) {
            links.remove(&old_key);
            links.insert(new_key.clone());
        }
        inner.names.insert(new_key, id);
        inner.rename_epoch += 1;
        Ok(id)
    }

    /// Exchange two directory entries (`RENAME_EXCHANGE`).
    pub fn swap_names(&self, first: (InodeId, &OsStr), second: (InodeId, &OsStr)) -> Result<()> {
        validate_name(first.1)?;
        validate_name(second.1)?;
        if is_reserved_name(first.1) || is_reserved_name(second.1) {
            return Err(Errno::EEXIST);
        }
        let mut inner = self.write();
        let first_key = (first.0, first.1.to_os_string());
        let second_key = (second.0, second.1.to_os_string());
        let first_id = *inner.names.get(&first_key).ok_or(Errno::ENOENT)?;
        let second_id = *inner.names.get(&second_key).ok_or(Errno::ENOENT)?;
        inner.names.insert(first_key.clone(), second_id);
        inner.names.insert(second_key.clone(), first_id);
        if let Some(links) = inner.links.get_mut(&first_id) {
            links.remove(&first_key);
            links.insert(second_key.clone());
        }
        if let Some(links) = inner.links.get_mut(&second_id) {
            links.remove(&second_key);
            links.insert(first_key);
        }
        inner.rename_epoch += 1;
        Ok(())
    }

    /// Resolve one directory entry.
    pub fn lookup(&self, parent: InodeId, name: &OsStr) -> Option<InodeId> {
        if is_reserved_name(name) {
            return None;
        }
        self.read()
            .names
            .get(&(parent, name.to_os_string()))
            .copied()
    }

    /// The inode's first directory entry, by deterministic key order.
    pub fn first_name(&self, id: InodeId) -> Option<(InodeId, OsString)> {
        self.read()
            .links
            .get(&id)
            .and_then(|links| links.iter().next().cloned())
    }

    /// All directory entries that reference `id`.
    pub fn names_of(&self, id: InodeId) -> Vec<(InodeId, OsString)> {
        self.read()
            .links
            .get(&id)
            .map(|links| links.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// All children of a directory, sorted by name.
    pub fn children_of(&self, dir: InodeId) -> Vec<(OsString, InodeId)> {
        let inner = self.read();
        inner
            .names
            .range((dir, OsString::new())..)
            .take_while(|((parent, _), _)| *parent == dir)
            .map(|((_, name), id)| (name.clone(), *id))
            .collect()
    }

    /// Path relative to the backing root; empty for the root itself.
    pub fn path_of(&self, id: InodeId) -> Option<PathBuf> {
        if id.is_root() {
            return Some(PathBuf::new());
        }
        let epoch = {
            let inner = self.read();
            if !inner.by_id.contains_key(&id) {
                return None;
            }
            inner.rename_epoch
        };
        {
            let cache = self
                .cache
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            if let Some(path) = cache.map.get(&(epoch, id)) {
                return Some(path.clone());
            }
        }
        let path = {
            let inner = self.read();
            let mut parts: Vec<OsString> = Vec::new();
            let mut current = id;
            let mut depth = 0usize;
            while !current.is_root() {
                let link = inner.links.get(&current)?.iter().next()?.clone();
                parts.push(link.1);
                current = link.0;
                depth += 1;
                if depth > MAX_DEPTH {
                    return None;
                }
            }
            parts.reverse();
            let mut path = PathBuf::new();
            for part in parts {
                path.push(part);
            }
            path
        };
        let mut cache = self
            .cache
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if cache.map.len() >= PATH_CACHE_LIMIT {
            cache.map.clear();
        }
        cache.map.insert((epoch, id), path.clone());
        Some(path)
    }

    /// Stable kernel inode number.
    pub fn ino_of(&self, id: InodeId) -> Option<u64> {
        self.read().by_id.get(&id).map(|node| node.ino)
    }

    /// Reverse lookup from the kernel inode number.
    pub fn id_of(&self, ino: u64) -> Option<InodeId> {
        self.read().by_ino.get(&ino).copied()
    }

    /// File type, if known.
    pub fn kind_of(&self, id: InodeId) -> Option<Kind> {
        self.read().by_id.get(&id).map(|node| node.kind)
    }

    /// POSIX link count derived from the directory entries.
    pub fn nlink(&self, id: InodeId) -> u32 {
        let inner = self.read();
        match inner.by_id.get(&id) {
            Some(node) if node.kind.is_dir() => {
                let subdirs = inner
                    .names
                    .range((id, OsString::new())..)
                    .take_while(|((parent, _), _)| *parent == id)
                    .filter(|(_, child)| {
                        inner
                            .by_id
                            .get(child)
                            .map(|node| node.kind.is_dir())
                            .unwrap_or(false)
                    })
                    .count();
                (2 + subdirs) as u32
            }
            Some(_) => inner
                .links
                .get(&id)
                .map(|links| links.len() as u32)
                .unwrap_or(0),
            None => 0,
        }
    }

    /// Increment the kernel lookup count.
    pub fn touch_lookup(&self, id: InodeId) -> u64 {
        let mut inner = self.write();
        match inner.by_id.get_mut(&id) {
            Some(node) => {
                node.nlookup += 1;
                node.nlookup
            }
            None => 0,
        }
    }

    /// Decrement the kernel lookup count, dropping an unreferenced inode.
    pub fn forget(&self, id: InodeId, count: u64) {
        if id.is_root() {
            return;
        }
        let mut inner = self.write();
        let remove = match inner.by_id.get_mut(&id) {
            Some(node) => {
                node.nlookup = node.nlookup.saturating_sub(count);
                node.nlookup == 0
                    && inner
                        .links
                        .get(&id)
                        .map(|links| links.is_empty())
                        .unwrap_or(true)
            }
            None => false,
        };
        if remove {
            inner.drop_subtree(id);
        }
    }

    /// Cache a directory descriptor for `id`.
    pub fn set_dirfd(&self, id: InodeId, fd: Option<Arc<OwnedFd>>) {
        let mut inner = self.write();
        let present = fd.is_some();
        let newly_cached = {
            let Some(node) = inner.by_id.get_mut(&id) else {
                return;
            };
            let newly_cached = node.dirfd.is_none() && present;
            node.dirfd = fd;
            newly_cached
        };
        if !present {
            inner.dirfd_order.retain(|cached| *cached != id);
            return;
        }
        if !newly_cached {
            return;
        }
        inner.dirfd_order.push_back(id);
        while inner.dirfd_order.len() > DIRFD_CACHE_LIMIT {
            let Some(evicted) = inner.dirfd_order.pop_front() else {
                break;
            };
            if evicted == id {
                continue;
            }
            if let Some(node) = inner.by_id.get_mut(&evicted) {
                node.dirfd = None;
            }
        }
    }

    /// The cached directory descriptor for `id`.
    pub fn dirfd(&self, id: InodeId) -> Option<Arc<OwnedFd>> {
        self.read()
            .by_id
            .get(&id)
            .and_then(|node| node.dirfd.clone())
    }

    /// Number of known inodes, including the root.
    pub fn len(&self) -> usize {
        self.read().by_id.len()
    }

    /// True when only the root is known.
    pub fn is_empty(&self) -> bool {
        self.len() <= 1
    }

    /// The current rename generation, used to invalidate cached paths.
    pub fn rename_epoch(&self) -> u64 {
        self.read().rename_epoch
    }

    /// Drop every inode except the root.
    pub fn clear(&self) {
        let mut inner = self.write();
        *inner = Inner::new();
        let mut cache = self
            .cache
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        cache.map.clear();
    }
}

pub(crate) fn validate_name(name: &OsStr) -> Result<()> {
    let bytes = name.as_bytes();
    if bytes.is_empty()
        || bytes == b"."
        || bytes == b".."
        || bytes.contains(&b'/')
        || bytes.contains(&0)
    {
        return Err(Errno::EINVAL);
    }
    if bytes.len() > 255 {
        return Err(Errno::ENAMETOOLONG);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok<T>(result: Result<T>) -> T {
        result.unwrap_or_else(|err| panic!("unexpected error: {err:?}"))
    }

    fn err<T: fmt::Debug>(result: Result<T>) -> Errno {
        match result {
            Ok(value) => panic!("expected an error, got {value:?}"),
            Err(err) => err,
        }
    }

    fn table_with_dir() -> (NodeTable, InodeId) {
        let table = NodeTable::new();
        let dir = InodeId::new_v4();
        ok(table.insert_link(dir, InodeId::ROOT, OsStr::new("d"), Kind::Dir));
        (table, dir)
    }

    /// 31:M1-2
    #[test]
    fn u_store_node_table_insert_lookup_path() {
        let table = NodeTable::new();
        let dir = InodeId::new_v4();
        ok(table.insert_link(dir, InodeId::ROOT, OsStr::new("d"), Kind::Dir));
        let file = InodeId::new_v4();
        ok(table.insert_link(file, dir, OsStr::new("f"), Kind::File));
        assert_eq!(table.lookup(InodeId::ROOT, OsStr::new("d")), Some(dir));
        assert_eq!(
            table
                .path_of(file)
                .unwrap_or_else(|| panic!("path missing")),
            PathBuf::from("d/f")
        );
        assert_eq!(table.ino_of(dir), Some(2));
        assert_eq!(table.id_of(2), Some(dir));
        assert_eq!(table.kind_of(file), Some(Kind::File));
        assert_eq!(table.children_of(InodeId::ROOT), vec![("d".into(), dir)]);
    }

    /// 31:M1-2
    #[test]
    fn u_store_node_table_rejects_bad_names() {
        let table = NodeTable::new();
        let id = InodeId::new_v4();
        for name in ["", ".", "..", "a/b"] {
            assert_eq!(
                err(table.insert_link(id, InodeId::ROOT, OsStr::new(name), Kind::File)),
                Errno::EINVAL
            );
        }
        ok(table.insert_link(id, InodeId::ROOT, OsStr::new("ok"), Kind::File));
        assert_eq!(
            err(table.insert_link(id, InodeId::ROOT, OsStr::new("ok"), Kind::Dir)),
            Errno::EINVAL
        );
    }

    /// 31:M1-2
    #[test]
    fn u_store_node_table_hardlinks() {
        let (table, dir) = table_with_dir();
        let file = InodeId::new_v4();
        ok(table.insert_link(file, dir, OsStr::new("a"), Kind::File));
        ok(table.insert_link(file, dir, OsStr::new("b"), Kind::File));
        assert_eq!(table.nlink(file), 2);
        assert_eq!(
            table
                .path_of(file)
                .unwrap_or_else(|| panic!("path missing")),
            PathBuf::from("d/a")
        );
        table.remove_name(dir, OsStr::new("a"));
        assert_eq!(table.nlink(file), 1);
        assert_eq!(
            table
                .path_of(file)
                .unwrap_or_else(|| panic!("path missing")),
            PathBuf::from("d/b")
        );
        table.remove_name(dir, OsStr::new("b"));
        assert_eq!(table.path_of(file), None);
    }

    /// 31:M1-2
    #[test]
    fn u_store_node_table_rename_updates_paths() {
        let (table, dir) = table_with_dir();
        let file = InodeId::new_v4();
        ok(table.insert_link(file, dir, OsStr::new("f"), Kind::File));
        ok(table.rename_name(dir, OsStr::new("f"), InodeId::ROOT, OsStr::new("g")));
        assert_eq!(
            table
                .path_of(file)
                .unwrap_or_else(|| panic!("path missing")),
            PathBuf::from("g")
        );

        let sub = InodeId::new_v4();
        ok(table.insert_link(sub, dir, OsStr::new("sub"), Kind::Dir));
        let leaf = InodeId::new_v4();
        ok(table.insert_link(leaf, sub, OsStr::new("leaf"), Kind::File));
        ok(table.rename_name(
            InodeId::ROOT,
            OsStr::new("d"),
            InodeId::ROOT,
            OsStr::new("e"),
        ));
        assert_eq!(
            table
                .path_of(leaf)
                .unwrap_or_else(|| panic!("path missing")),
            PathBuf::from("e/sub/leaf")
        );
        assert_eq!(
            table.path_of(sub).unwrap_or_else(|| panic!("path missing")),
            PathBuf::from("e/sub")
        );
    }

    /// 31:M1-2
    #[test]
    fn u_store_node_table_swap_names() {
        let (table, dir) = table_with_dir();
        let first = InodeId::new_v4();
        let second = InodeId::new_v4();
        ok(table.insert_link(first, dir, OsStr::new("a"), Kind::File));
        ok(table.insert_link(second, dir, OsStr::new("b"), Kind::File));
        ok(table.swap_names((dir, OsStr::new("a")), (dir, OsStr::new("b"))));
        assert_eq!(table.lookup(dir, OsStr::new("a")), Some(second));
        assert_eq!(table.lookup(dir, OsStr::new("b")), Some(first));
    }

    /// 31:M1-2
    #[test]
    fn u_store_node_table_rejects_cycle() {
        let (table, dir) = table_with_dir();
        let sub = InodeId::new_v4();
        ok(table.insert_link(sub, dir, OsStr::new("sub"), Kind::Dir));
        assert_eq!(
            err(table.rename_name(InodeId::ROOT, OsStr::new("d"), sub, OsStr::new("d"))),
            Errno::EINVAL
        );
    }

    /// 31:M1-2
    #[test]
    fn u_store_node_table_remove_subtree() {
        let (table, dir) = table_with_dir();
        let file = InodeId::new_v4();
        ok(table.insert_link(file, dir, OsStr::new("f"), Kind::File));
        table.remove_name(InodeId::ROOT, OsStr::new("d"));
        assert_eq!(table.path_of(file), None);
        assert_eq!(table.lookup(dir, OsStr::new("f")), None);
        assert_eq!(table.len(), 1);
        assert!(table.is_empty());
    }

    /// 31:M1-2
    #[test]
    fn u_store_node_table_ino_is_stable() {
        let (table, dir) = table_with_dir();
        let ino = table.ino_of(dir).unwrap_or_else(|| panic!("ino missing"));
        ok(table.rename_name(
            InodeId::ROOT,
            OsStr::new("d"),
            InodeId::ROOT,
            OsStr::new("d2"),
        ));
        assert_eq!(table.ino_of(dir), Some(ino));
        let file = InodeId::new_v4();
        ok(table.insert_link(file, InodeId::ROOT, OsStr::new("x"), Kind::File));
        assert!(table.ino_of(file).unwrap_or_else(|| panic!("ino missing")) > ino);
    }

    /// 31:M1-2
    #[test]
    fn u_store_node_table_dirfd_cache() {
        let (table, dir) = table_with_dir();
        assert!(table.dirfd(dir).is_none());
        let fd: OwnedFd = std::fs::OpenOptions::new()
            .read(true)
            .open("/dev/null")
            .unwrap_or_else(|err| panic!("open /dev/null: {err}"))
            .into();
        table.set_dirfd(dir, Some(Arc::new(fd)));
        assert!(table.dirfd(dir).is_some());
        table.set_dirfd(dir, None);
        assert!(table.dirfd(dir).is_none());
    }

    /// 31:M1-3
    #[test]
    fn u_store_node_table_dir_nlink() {
        let (table, dir) = table_with_dir();
        assert_eq!(table.nlink(InodeId::ROOT), 3);
        assert_eq!(table.nlink(dir), 2);
        let sub = InodeId::new_v4();
        ok(table.insert_link(sub, dir, OsStr::new("sub"), Kind::Dir));
        assert_eq!(table.nlink(dir), 3);
    }

    /// 41 §2.1 / 51 D-24: `InodeId` is a 16-byte UUIDv4.
    #[test]
    fn u_store_inode_id_is_uuid_v4() {
        assert_eq!(std::mem::size_of::<InodeId>(), 16);
        let id = InodeId::new_v4();
        let bytes = id.to_bytes();
        assert_eq!(bytes[6] >> 4, 4, "version nibble");
        assert_eq!(bytes[8] & 0xc0, 0x80, "RFC 4122 variant");
        assert!(id.is_uuid_v4());
        assert_eq!(InodeId::from_bytes(bytes), id);
        assert_eq!(InodeId::from_uuid(id.as_uuid()), id);
        assert_eq!(id.to_hex(), id.as_uuid().simple().to_string());
        assert_eq!(InodeId::ROOT.to_bytes(), [0u8; 16]);
        assert!(!InodeId::ROOT.is_uuid_v4());

        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..256 {
            assert!(seen.insert(InodeId::new_v4().to_bytes()));
        }
    }

    /// C-10 / 43 §6.1: reserved names never enter the index.
    #[test]
    fn u_store_node_table_reserved_names_are_shadowed() {
        let table = NodeTable::new();
        let id = InodeId::new_v4();
        for name in [".syncmount-staging", ".syncmount-manifest", ".audit.log"] {
            assert_eq!(
                err(table.insert_link(id, InodeId::ROOT, OsStr::new(name), Kind::File)),
                Errno::EEXIST
            );
            assert_eq!(table.lookup(InodeId::ROOT, OsStr::new(name)), None);
        }
        ok(table.insert_link(id, InodeId::ROOT, OsStr::new("ok"), Kind::File));
        assert_eq!(
            err(table.rename_name(
                InodeId::ROOT,
                OsStr::new("ok"),
                InodeId::ROOT,
                OsStr::new(".audit.log"),
            )),
            Errno::EEXIST
        );
        assert_eq!(
            err(table.rename_name(
                InodeId::ROOT,
                OsStr::new(".audit.log"),
                InodeId::ROOT,
                OsStr::new("x"),
            )),
            Errno::ENOENT
        );
        assert_eq!(
            err(table.swap_names(
                (InodeId::ROOT, OsStr::new("ok")),
                (InodeId::ROOT, OsStr::new(".syncmount-staging")),
            )),
            Errno::EEXIST
        );
    }

    /// 41 §2.3: the directory descriptor cache is bounded.
    #[test]
    fn u_store_node_table_dirfd_cache_is_bounded() {
        let table = NodeTable::new();
        let mut ids = Vec::new();
        for index in 0..=DIRFD_CACHE_LIMIT {
            let id = InodeId::new_v4();
            let name = format!("d{index}");
            ok(table.insert_link(id, InodeId::ROOT, OsStr::new(&name), Kind::Dir));
            ids.push(id);
        }
        for &id in &ids {
            let fd: OwnedFd = std::fs::OpenOptions::new()
                .read(true)
                .open("/dev/null")
                .unwrap_or_else(|err| panic!("open /dev/null: {err}"))
                .into();
            table.set_dirfd(id, Some(Arc::new(fd)));
        }
        assert!(table.dirfd(ids[0]).is_none(), "oldest entry is evicted");
        assert!(table.dirfd(ids[1]).is_some());

        // The oldest surviving entry is the next victim.
        let extra = InodeId::new_v4();
        ok(table.insert_link(extra, InodeId::ROOT, OsStr::new("extra"), Kind::Dir));
        let fd: OwnedFd = std::fs::OpenOptions::new()
            .read(true)
            .open("/dev/null")
            .unwrap_or_else(|err| panic!("open /dev/null: {err}"))
            .into();
        table.set_dirfd(extra, Some(Arc::new(fd)));
        assert!(table.dirfd(ids[1]).is_none());
        assert!(table.dirfd(ids[2]).is_some());
    }
}
