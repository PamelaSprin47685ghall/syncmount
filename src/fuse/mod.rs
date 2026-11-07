//! FUSE view over the client SQLite database.
//!
//! The mountpoint holds no file tree. [`sqlite::SqliteFs`] answers every
//! callback from `client.db`: reads take a WAL snapshot, mutations run one
//! local-first transaction and append to the durable outbox.

pub mod sqlite;

pub use sqlite::SqliteFs;

use fuser::{Config, MountOption, SessionACL};

/// Mount configuration for a local syncmount session.
///
/// `AutoUnmount` covers a crashed process; fuser requires an ACL other than
/// `Owner` for it, and this host's `/etc/fuse.conf` enables
/// `user_allow_other`. The mount is still limited to the owner and root by
/// `RootAndOwner`.
///
/// Eight worker threads and `clone_fd` keep a blocking callback from stalling
/// the whole session.
pub fn mount_config() -> Config {
    mount_config_with(false)
}

/// Mount configuration with an explicit `allow_other` choice.
pub fn mount_config_with(allow_other: bool) -> Config {
    let mut config = Config::default();
    config.mount_options = vec![
        MountOption::FSName("syncmount".to_string()),
        MountOption::Subtype("syncmount".to_string()),
        MountOption::AutoUnmount,
        MountOption::NoDev,
        MountOption::NoSuid,
    ];
    config.acl = if allow_other {
        SessionACL::All
    } else {
        SessionACL::RootAndOwner
    };
    config.n_threads = Some(8);
    config.clone_fd = true;
    config
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_config_is_local_and_auto_unmounting() {
        let config = mount_config();
        assert!(config.mount_options.contains(&MountOption::AutoUnmount));
        assert!(config
            .mount_options
            .contains(&MountOption::FSName("syncmount".to_string())));
        assert!(matches!(config.acl, SessionACL::RootAndOwner));
        assert_eq!(config.n_threads, Some(8));
        assert!(config.clone_fd);
    }

    #[test]
    fn allow_other_widens_the_acl() {
        assert!(matches!(mount_config_with(true).acl, SessionACL::All));
    }
}
