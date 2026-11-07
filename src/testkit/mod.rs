//! 测试基建（仅 `testkit` feature 编译）。
//!
//! | 模块 | 职责 |
//! |---|---|
//! | [`memnet`] | 进程内字节传输：有界队列、确定性延迟、partition/heal |
//! | [`faults`] | 确定性故障决策引擎与帧级 `FaultyTransport` |
//! | [`clock`] | 暂停时钟与超时常数 |
//! | [`cluster`] | 进程内多客户端 harness（真实 Sequencer + MemNet） |
//! | [`process`] | 进程级 harness、FUSE 预检与 `MountGuard` |
//! | [`failpoints`] | 命名故障注入点 |
//!
//! 生产代码不得引用本模块；`cargo build --release` 不含任何 testkit 符号。
//! 集成测试只依赖本 façade，不直接摸私有模块。

pub mod clock;
pub mod cluster;
pub mod failpoints;
pub mod faults;
pub mod memnet;
pub mod process;

pub use clock::{SystemClock, TestClock, Timeouts, WallClock};
pub use cluster::{
    ClientHandle, ClientSpec, ClientState, Cluster, ClusterError, ClusterSpec, ClusterStats,
    QuiesceReport,
};
pub use failpoints::{
    Action as FailPointAction, FailPoint, FailPointGuard, names as failpoint_names,
};
pub use faults::{
    Action as FaultAction, AppliedFault, Direction, FaultEngine, FaultError, FaultRule,
    FaultScript, FaultTrace, FaultyTransport, FrameMeta, RuleDecision, Selector, SplitMix64,
    TraceEntry,
};
pub use memnet::{HubConfig, HubStats, InMemoryHub, InMemoryTransport, MemNet};
pub use process::{
    FuseReady, FuseSkip, MountCfg, MountGuard, MountedClient, ProcessCluster, ProcessError,
    ProcessSpec, assert_not_mounted, fuse_probe, mounted, parse_proc_mounts, require_fuse,
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// W18: the testkit facade re-exports every module's public surface.
    #[test]
    fn u_testkit_facade_exports() {
        let clock: std::sync::Arc<TestClock> = TestClock::new(0);
        clock.advance(Duration::from_micros(1));
        assert_eq!(WallClock::now_us(&*clock), 1);

        let engine = FaultEngine::new(FaultScript::new(1).with_rule(FaultRule::new(
            Direction::Up,
            Selector::Any,
            FaultAction::Drop,
        )));
        assert_eq!(engine.seed(), 1);

        assert_eq!(failpoint_names::ALL.len(), 12);
        let _ = FailPoint::is_set(failpoint_names::ALL[0]);
        let _: Timeouts = Timeouts::for_tests();
        let _: HubConfig = HubConfig::default();
    }
}
