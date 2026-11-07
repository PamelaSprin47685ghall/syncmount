//! 测试时钟与超时常数。
//!
//! 排序只用 `seq`；`WallClock` 只服务超时、mtime 与审计时间，不参与排序。
//! `TestClock` 是暂停时钟：测试显式 `advance`/`rollback`，不读真实时间。

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// 挂钟端口。生产用 [`SystemClock`]，测试用 [`TestClock`]。
pub trait WallClock: Send + Sync {
    /// 当前时间，Unix 纪元起的微秒数。
    fn now_us(&self) -> i64;
}

/// 真实系统时钟。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SystemClock;

impl WallClock for SystemClock {
    fn now_us(&self) -> i64 {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(elapsed) => duration_to_us(elapsed),
            Err(err) => duration_to_us(err.duration()).saturating_neg(),
        }
    }
}

/// 暂停时钟：只有显式 `set`/`advance`/`rollback` 才改变。
///
/// 所有方法接收 `&self`，因此可被 `Arc` 共享给多个 actor。
#[derive(Debug)]
pub struct TestClock {
    now_us: AtomicI64,
}

impl TestClock {
    /// 以 `start_us`（Unix 微秒）创建共享时钟。
    pub fn new(start_us: i64) -> Arc<Self> {
        Arc::new(Self {
            now_us: AtomicI64::new(start_us),
        })
    }

    /// 从 Unix 纪元开始。
    pub fn at_epoch() -> Arc<Self> {
        Self::new(0)
    }

    /// 当前时间，Unix 微秒。
    pub fn now_us(&self) -> i64 {
        self.now_us.load(Ordering::SeqCst)
    }

    /// 直接设置时间。
    pub fn set(&self, us: i64) {
        self.now_us.store(us, Ordering::SeqCst);
    }

    /// 前进 `d`。
    pub fn advance(&self, d: Duration) {
        self.advance_us(duration_to_us(d));
    }

    /// 回拨 `d`。
    pub fn rollback(&self, d: Duration) {
        self.advance_us(duration_to_us(d).saturating_neg());
    }

    /// 前进（正）或回拨（负）`delta_us`；饱和于 `i64` 边界。
    pub fn advance_us(&self, delta_us: i64) {
        let mut current = self.now_us.load(Ordering::SeqCst);
        loop {
            let next = current.saturating_add(delta_us);
            match self.now_us.compare_exchange_weak(
                current,
                next,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return,
                Err(observed) => current = observed,
            }
        }
    }
}

impl WallClock for TestClock {
    fn now_us(&self) -> i64 {
        TestClock::now_us(self)
    }
}

/// 把 `Duration` 饱和转换为微秒。
fn duration_to_us(d: Duration) -> i64 {
    i64::try_from(d.as_micros()).unwrap_or(i64::MAX)
}

/// 超时与常数集合。
///
/// [`Timeouts::production`] 是生产默认值；[`Timeouts::for_tests`] 只缩小时间，
/// 不改变任何语义比例，且不是生产配置。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    pub unmount_flush: Duration,
    pub join: Duration,
    pub rtt_window: usize,
    pub rtt_default: Duration,
    pub stall_cap: Duration,
    /// 保守吞吐，字节/秒。
    pub min_throughput: u64,
    pub op_apply: Duration,
}

impl Timeouts {
    /// 生产默认值（39/41/42 的冻结常数）。
    pub const fn production() -> Self {
        Self {
            unmount_flush: Duration::from_secs(2),
            join: Duration::from_secs(5),
            rtt_window: 60,
            rtt_default: Duration::from_millis(300),
            stall_cap: Duration::from_secs(24 * 60 * 60),
            min_throughput: 1024 * 1024,
            op_apply: Duration::from_millis(100),
        }
    }

    /// 测试用缩小值（10–50ms 量级），只用于内存测试。
    pub const fn for_tests() -> Self {
        Self {
            unmount_flush: Duration::from_millis(50),
            join: Duration::from_millis(50),
            rtt_window: 60,
            rtt_default: Duration::from_millis(10),
            stall_cap: Duration::from_secs(60 * 60),
            min_throughput: 1024 * 1024,
            op_apply: Duration::from_millis(5),
        }
    }
}

impl Default for Timeouts {
    fn default() -> Self {
        Self::production()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// W18: TestClock advances and rolls back deterministically.
    #[test]
    fn u_testkit_clock_advance() {
        let clock = TestClock::new(1_000);
        assert_eq!(clock.now_us(), 1_000);

        clock.advance(Duration::from_secs(2));
        assert_eq!(clock.now_us(), 2_001_000);

        clock.rollback(Duration::from_millis(500));
        assert_eq!(clock.now_us(), 1_501_000);

        clock.set(42);
        assert_eq!(clock.now_us(), 42);

        clock.advance_us(-7);
        assert_eq!(clock.now_us(), 35);
    }

    /// W18: TestClock saturates instead of overflowing.
    #[test]
    fn u_testkit_clock_saturates() {
        let high = TestClock::new(i64::MAX);
        high.advance(Duration::from_secs(1));
        assert_eq!(high.now_us(), i64::MAX);

        let low = TestClock::new(i64::MIN);
        low.rollback(Duration::from_secs(1));
        assert_eq!(low.now_us(), i64::MIN);
    }

    /// W18: clones share one clock.
    #[test]
    fn u_testkit_clock_is_shared() {
        let clock = TestClock::at_epoch();
        let clone = Arc::clone(&clock);
        clock.advance(Duration::from_micros(9));
        assert_eq!(clone.now_us(), 9);

        let as_port: &dyn WallClock = &*clone;
        assert_eq!(as_port.now_us(), 9);
    }

    /// W18: production defaults are frozen; test values are strictly smaller.
    #[test]
    fn u_testkit_timeouts_profiles() {
        let production = Timeouts::production();
        assert_eq!(production, Timeouts::default());
        assert_eq!(production.unmount_flush, Duration::from_secs(2));
        assert_eq!(production.rtt_window, 60);
        assert_eq!(production.rtt_default, Duration::from_millis(300));
        assert_eq!(production.stall_cap, Duration::from_secs(24 * 60 * 60));
        assert_eq!(production.min_throughput, 1024 * 1024);

        let test = Timeouts::for_tests();
        assert!(test.unmount_flush < production.unmount_flush);
        assert!(test.join < production.join);
        assert!(test.rtt_default < production.rtt_default);
        assert!(test.op_apply < production.op_apply);
    }
}
