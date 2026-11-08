//! 1.0 compatibility and schema-isolation tests.
//!
//! The 1.1 mm database must never be adopted by the 1.0 store, and the 1.0
//! database must never be adopted as an mm database. They share the SQLite
//! file format and both use `PRAGMA user_version = 1`, so the numeric version
//! alone is not an identity check; each side must reject the other's schema.
//!
//! A second point is namespace isolation. The namespace id in 1.0 is derived
//! from the master password only, so `/private`, `/public`, `/private-mm` and
//! `/public-mm` share it. Tests must prove isolation with separate database
//! files and processes, never with the namespace id.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod mmap_harness;

use mmap_harness::MmapEnv;

use rusqlite::Connection;

use syncmount::mmap::{MmDb, MmRole, MmTx, ROOT_INO};
use syncmount::store::sqlite::{Db, Role, SCHEMA_VERSION};

const NAMESPACE: &str = "/private-mm";

#[test]
fn legacy_and_mm_schemas_refuse_each_other() {
    let env = MmapEnv::new();
    let legacy_path = env.path("server-1.0-private.db");
    let mm_path = env.path("server-private-mm.db");

    {
        let db = Db::open(&legacy_path, Role::Server).unwrap();
        assert_eq!(db.schema_version().unwrap(), SCHEMA_VERSION);
    }
    {
        let mut db = MmDb::open(&mm_path, MmRole::Server, NAMESPACE).unwrap();
        assert_eq!(db.schema_version().unwrap(), 1);
        let tx = db.write().unwrap();
        assert_eq!(tx.next_mm_seq().unwrap().get(), 1);
        tx.commit().unwrap();
    }

    let mm_error = MmDb::open(&legacy_path, MmRole::Server, NAMESPACE).unwrap_err();
    assert!(
        format!("{mm_error}").contains("mm_meta")
            || matches!(mm_error, syncmount::mmap::MmError::Sqlite(_)),
        "unexpected mm-open error on a 1.0 database: {mm_error:?}"
    );
    let legacy_error = Db::open(&mm_path, Role::Server).unwrap_err();
    assert!(
        format!("{legacy_error}").contains("meta")
            || format!("{legacy_error}").contains("no such table"),
        "unexpected 1.0-open error on an mm database: {legacy_error:?}"
    );

    // Reopening each database still works, which proves neither rejection
    // path left a destructive migration behind.
    let legacy = Db::open(&legacy_path, Role::Server).unwrap();
    assert_eq!(legacy.schema_version().unwrap(), SCHEMA_VERSION);
    drop(legacy);
    let mm = MmDb::open(&mm_path, MmRole::Server, NAMESPACE).unwrap();
    assert_eq!(mm.mm_seq().unwrap().get(), 1);

    assert!(table_exists(&legacy_path, "meta"));
    assert!(!table_exists(&legacy_path, "mm_meta"));
    assert!(!table_exists(&mm_path, "meta"));
    assert!(table_exists(&mm_path, "mm_meta"));
}

#[test]
fn two_mm_databases_with_one_namespace_do_not_share_state() {
    let env = MmapEnv::new();
    let first_path = env.path("server-private-mm-a.db");
    let second_path = env.path("server-private-mm-b.db");
    let mut first = MmDb::open(&first_path, MmRole::Server, NAMESPACE).unwrap();
    let second = MmDb::open(&second_path, MmRole::Server, NAMESPACE).unwrap();

    {
        let tx = first.write().unwrap();
        assert_eq!(tx.next_mm_seq().unwrap().get(), 1);
        tx.bump_dir(ROOT_INO).unwrap();
        tx.commit().unwrap();
    }

    assert_eq!(first.mm_seq().unwrap().get(), 1);
    assert_eq!(second.mm_seq().unwrap().get(), 0);
    assert_ne!(
        first.read().unwrap().dir_seq(ROOT_INO).unwrap(),
        second.read().unwrap().dir_seq(ROOT_INO).unwrap()
    );

    // A namespace label is metadata, not an isolation key. The two files have
    // the same label and the same (password-derived) namespace id; only the
    // path separates them.
    assert_eq!(first.namespace(), second.namespace());
    assert_ne!(first.path(), second.path());
}

#[test]
fn a_shared_namespace_label_does_not_merge_roles() {
    let env = MmapEnv::new();
    let server_path = env.path("server.db");
    let client_path = env.path("client.db");
    let server = MmDb::open(&server_path, MmRole::Server, NAMESPACE).unwrap();
    let client = MmDb::open(&client_path, MmRole::Client, NAMESPACE).unwrap();

    // Same namespace, different role, different file: opening the server file
    // as a client must fail rather than silently mixing the two row sets.
    let error = MmDb::open(&server_path, MmRole::Client, NAMESPACE).unwrap_err();
    assert!(matches!(
        error,
        syncmount::mmap::MmError::RoleMismatch { .. }
    ));
    assert_eq!(server.role(), MmRole::Server);
    assert_eq!(client.role(), MmRole::Client);
    assert_ne!(server.path(), client.path());
}

fn table_exists(path: &std::path::Path, table: &str) -> bool {
    let conn = Connection::open(path).unwrap();
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [table],
            |row| row.get(0),
        )
        .unwrap();
    count != 0
}
