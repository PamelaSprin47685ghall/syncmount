//! 命名故障注入点。
//!
//! 只在 `testkit` feature 下编译；生产构建不含本模块、不含任何符号。
//!
//! 两种触发方式：
//! 1. 进程内：`FailPoint::set(name, Action)` 或 [`FailPointGuard`]。
//! 2. 进程级：环境变量 `SYNCMOUNT_FAILPOINT=name[,name...]`（命中即 panic）。
//!
//! 名称集中在 [`names`]；调用点禁止散落字符串。

use std::collections::BTreeMap;
use std::sync::{LazyLock, Mutex, MutexGuard};
use std::time::Duration;

/// 进程级 failpoint 环境变量；逗号分隔。
pub const ENV_VAR: &str = "SYNCMOUNT_FAILPOINT";

/// 全部已定义的 failpoint 名称（45 §2.2）。
pub mod names {
    pub const AFTER_LOCAL_WRITE_BEFORE_ENQUEUE: &str = "after_local_write_before_enqueue";
    pub const AFTER_ENQUEUE_BEFORE_SEND: &str = "after_enqueue_before_send";
    pub const AFTER_SEND_BEFORE_ACK: &str = "after_send_before_ack";
    pub const JOIN_AFTER_MANIFEST: &str = "join_after_manifest";
    pub const JOIN_AFTER_STAGE_FSYNC: &str = "join_after_stage_fsync";
    pub const JOIN_BEFORE_RENAME1: &str = "join_before_rename1";
    pub const JOIN_BEFORE_RENAME2: &str = "join_before_rename2";
    pub const JOIN_BEFORE_RENAME3: &str = "join_before_rename3";
    pub const UNMOUNT_AFTER_QUIESCE: &str = "unmount_after_quiesce";
    pub const UNMOUNT_AFTER_FLUSH: &str = "unmount_after_flush";
    pub const SNAPSHOT_BEFORE_FINALIZE: &str = "snapshot_before_finalize";
    pub const SERVER_BEFORE_BROADCAST: &str = "server_before_broadcast";

    /// 名称表；供唯一性检查与进程级 harness 使用。
    pub const ALL: &[&str] = &[
        AFTER_LOCAL_WRITE_BEFORE_ENQUEUE,
        AFTER_ENQUEUE_BEFORE_SEND,
        AFTER_SEND_BEFORE_ACK,
        JOIN_AFTER_MANIFEST,
        JOIN_AFTER_STAGE_FSYNC,
        JOIN_BEFORE_RENAME1,
        JOIN_BEFORE_RENAME2,
        JOIN_BEFORE_RENAME3,
        UNMOUNT_AFTER_QUIESCE,
        UNMOUNT_AFTER_FLUSH,
        SNAPSHOT_BEFORE_FINALIZE,
        SERVER_BEFORE_BROADCAST,
    ];
}

/// 命中 failpoint 时执行的动作。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// panic，用于断言调用点之前的原子性。
    Panic,
    /// 以给定退出码终止进程，模拟崩溃。
    Exit(i32),
    /// 阻塞给定时间，用于放大竞态窗口。
    Sleep(Duration),
}

type Registry = BTreeMap<&'static str, Action>;

static REGISTRY: LazyLock<Mutex<Registry>> = LazyLock::new(|| Mutex::new(BTreeMap::new()));

fn lock_registry() -> MutexGuard<'static, Registry> {
    REGISTRY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// 进程内 failpoint 注册表。
#[derive(Debug, Clone, Copy)]
pub struct FailPoint;

impl FailPoint {
    /// 注册或覆盖；返回旧动作。
    pub fn set(name: &'static str, action: Action) -> Option<Action> {
        lock_registry().insert(name, action)
    }

    /// 读取当前动作。
    pub fn get(name: &str) -> Option<Action> {
        lock_registry().get(name).cloned()
    }

    /// 移除并返回旧动作。
    pub fn clear(name: &str) -> Option<Action> {
        lock_registry().remove(name)
    }

    /// 清空全部注册项。只应在测试收尾时调用。
    pub fn clear_all() {
        lock_registry().clear();
    }

    pub fn is_set(name: &str) -> bool {
        lock_registry().contains_key(name)
    }

    /// 命中则执行动作；未注册且环境变量未列出时为空操作。
    pub fn trigger(name: &str) {
        let action = lock_registry().get(name).cloned();
        match action {
            Some(action) => execute(name, &action),
            None => {
                if env_mentions(name) {
                    execute(name, &Action::Panic);
                }
            }
        }
    }

    /// 创建 RAII guard；Drop 时恢复之前的值。
    pub fn guard(name: &'static str, action: Action) -> FailPointGuard {
        FailPointGuard::set(name, action)
    }
}

/// RAII failpoint：Drop 时恢复设置前的状态。
#[derive(Debug)]
pub struct FailPointGuard {
    name: &'static str,
    previous: Option<Action>,
}

impl FailPointGuard {
    pub fn set(name: &'static str, action: Action) -> Self {
        let previous = FailPoint::set(name, action);
        Self { name, previous }
    }
}

impl Drop for FailPointGuard {
    fn drop(&mut self) {
        let mut registry = lock_registry();
        match self.previous.take() {
            Some(previous) => {
                registry.insert(self.name, previous);
            }
            None => {
                registry.remove(self.name);
            }
        }
    }
}

fn execute(name: &str, action: &Action) {
    match action {
        Action::Panic => panic!("failpoint triggered: {name}"),
        Action::Exit(code) => std::process::exit(*code),
        Action::Sleep(duration) => std::thread::sleep(*duration),
    }
}

fn env_mentions(name: &str) -> bool {
    match std::env::var(ENV_VAR) {
        Ok(value) => value.split(',').any(|candidate| candidate.trim() == name),
        Err(_) => false,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// W18: a registered Panic failpoint triggers.
    #[test]
    fn u_testkit_failpoint_triggers_panic() {
        let _guard = FailPointGuard::set(names::AFTER_LOCAL_WRITE_BEFORE_ENQUEUE, Action::Panic);
        let outcome = std::panic::catch_unwind(|| {
            FailPoint::trigger(names::AFTER_LOCAL_WRITE_BEFORE_ENQUEUE)
        });
        assert!(outcome.is_err());
    }

    /// W18: clear removes the action; unknown names are no-ops.
    #[test]
    fn u_testkit_failpoint_clear_and_unknown() {
        let action = Action::Sleep(Duration::from_millis(1));
        assert_eq!(
            FailPoint::set(names::JOIN_AFTER_MANIFEST, action.clone()),
            None
        );
        assert!(FailPoint::is_set(names::JOIN_AFTER_MANIFEST));
        assert_eq!(FailPoint::clear(names::JOIN_AFTER_MANIFEST), Some(action));
        assert!(!FailPoint::is_set(names::JOIN_AFTER_MANIFEST));

        FailPoint::trigger("no_such_failpoint");
        assert!(!FailPoint::is_set("no_such_failpoint"));
    }

    /// W18: the guard restores the previous value on drop.
    #[test]
    fn u_testkit_failpoint_guard_restores() {
        let original = Action::Sleep(Duration::ZERO);
        FailPoint::set(names::SNAPSHOT_BEFORE_FINALIZE, original.clone());
        {
            let _guard = FailPointGuard::set(names::SNAPSHOT_BEFORE_FINALIZE, Action::Exit(9));
            assert_eq!(
                FailPoint::get(names::SNAPSHOT_BEFORE_FINALIZE),
                Some(Action::Exit(9))
            );
        }
        assert_eq!(
            FailPoint::get(names::SNAPSHOT_BEFORE_FINALIZE),
            Some(original)
        );
        FailPoint::clear(names::SNAPSHOT_BEFORE_FINALIZE);
    }

    /// W18: a Sleep action returns instead of aborting the test process.
    #[test]
    fn u_testkit_failpoint_sleep_returns() {
        let _guard = FailPointGuard::set(
            names::SERVER_BEFORE_BROADCAST,
            Action::Sleep(Duration::from_millis(1)),
        );
        FailPoint::trigger(names::SERVER_BEFORE_BROADCAST);
    }

    /// W18: the name table is non-empty and unique.
    #[test]
    fn u_testkit_failpoint_names_unique() {
        assert_eq!(names::ALL.len(), 12);
        let mut sorted = names::ALL.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), names::ALL.len());
        assert!(names::ALL.iter().all(|name| !name.is_empty()));
    }
}
