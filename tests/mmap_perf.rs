//! Performance measurements for the 1.1 `--mmap` path.
//!
//! The test is ignored until `src/mmap/{server,client,shadow}` lands, and it
//! also requires `SYNCMOUNT_PERF=1` because it writes a 1 GiB file through a
//! real mount. Assertions are enabled only with `SYNCMOUNT_PERF_ASSERT=1`;
//! without it the test prints samples and always passes.
//!
//! Run with:
//!
//! ```text
//! SYNCMOUNT_PERF=1 cargo test --release --test mmap_perf -- --ignored --nocapture
//! SYNCMOUNT_PERF=1 SYNCMOUNT_PERF_ASSERT=1 \
//!     cargo test --release --test mmap_perf -- --ignored --nocapture
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod mmap_harness;

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::FileExt;
use std::time::{Duration, Instant};

use serial_test::serial;

use mmap_harness::{MmapEnv, skip_without_fuse};

/// Size of one measured I/O.
const BLOCK: usize = 4 << 10;
/// Number of measured 4 KiB writes and reads.
const SAMPLES: usize = 1000;
/// The warm-read file is exactly 1 GiB, read in 1 MiB chunks.
const CHUNK: usize = 1 << 20;
const CHUNKS: usize = 1024;

/// Deterministic bytes, so a failure shows the same payload every run.
fn pattern(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.push((state >> 32) as u8);
    }
    out
}

fn percentile(sorted: &[Duration], fraction: f64) -> Duration {
    assert!(!sorted.is_empty(), "no samples");
    let last = sorted.len() - 1;
    let index = ((last as f64) * fraction).round() as usize;
    sorted[index.min(last)]
}

/// Read 1 GiB from offset zero and return the elapsed time.
fn read_pass(reader: &mut File, buffer: &mut [u8]) -> Duration {
    assert_eq!(buffer.len(), CHUNK);
    reader.seek(SeekFrom::Start(0)).unwrap();
    let started = Instant::now();
    for _ in 0..CHUNKS {
        reader.read_exact(buffer).unwrap();
    }
    started.elapsed()
}

#[test]
#[serial]
#[ignore = "perf: writes 1 GiB; run with SYNCMOUNT_PERF=1"]
fn mmap_read_write_and_fsync_latency() {
    if skip_without_fuse("mmap_read_write_and_fsync_latency") {
        return;
    }
    if std::env::var("SYNCMOUNT_PERF").as_deref() != Ok("1") {
        eprintln!(
            "SKIP mmap_read_write_and_fsync_latency: set SYNCMOUNT_PERF=1 to write 1 GiB \
             through the mount"
        );
        return;
    }
    let assert_perf = std::env::var("SYNCMOUNT_PERF_ASSERT").as_deref() == Ok("1");

    let env = MmapEnv::new();
    let mut server = env.server("/private-mm", "perf");
    let mut client = env.client("/private-mm", "perf", true);
    client.wait_mounted();
    client.wait_steady();

    // --- 4 KiB read/write latency -----------------------------------------
    let small = client.mountpoint.join("perf-4k.bin");
    let file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(&small)
        .unwrap();
    let block = pattern(BLOCK, 11);
    let mut write_samples = Vec::with_capacity(SAMPLES);
    let mut read_samples = Vec::with_capacity(SAMPLES);
    let mut buffer = [0u8; BLOCK];
    for index in 0..SAMPLES {
        let offset = (index as u64) * BLOCK as u64;
        let started = Instant::now();
        file.write_all_at(&block, offset).unwrap();
        write_samples.push(started.elapsed());

        let started = Instant::now();
        file.read_exact_at(&mut buffer, offset).unwrap();
        read_samples.push(started.elapsed());
        assert_eq!(
            &buffer[..],
            &block[..],
            "the read must return the written block"
        );
    }
    file.sync_all().unwrap();

    write_samples.sort();
    read_samples.sort();
    let write_p50 = percentile(&write_samples, 0.50);
    let write_p99 = percentile(&write_samples, 0.99);
    let read_p50 = percentile(&read_samples, 0.50);
    let read_p99 = percentile(&read_samples, 0.99);
    println!("4 KiB write samples (first 10): {:?}", &write_samples[..10]);
    println!("4 KiB read samples (first 10): {:?}", &read_samples[..10]);
    println!(
        "4 KiB through the mount: write p50={write_p50:?} p99={write_p99:?}; \
         read p50={read_p50:?} p99={read_p99:?}"
    );

    // --- 1 GiB warm read throughput ---------------------------------------
    let big = client.mountpoint.join("perf-1g.bin");
    let chunk = pattern(CHUNK, 21);
    {
        let mut writer = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&big)
            .unwrap();
        for _ in 0..CHUNKS {
            writer.write_all(&chunk).unwrap();
        }
        writer.sync_all().unwrap();
    }
    assert_eq!(
        fs::metadata(&big).unwrap().len(),
        (CHUNK * CHUNKS) as u64,
        "the warm-read file is 1 GiB"
    );
    let mut reader = File::open(&big).unwrap();
    let mut read_buffer = vec![0u8; CHUNK];
    let first_pass = read_pass(&mut reader, &mut read_buffer);
    let second_pass = read_pass(&mut reader, &mut read_buffer);
    let throughput_mib_s = 1024.0 / second_pass.as_secs_f64();
    println!(
        "1 GiB warm read: first pass {first_pass:?}, second pass {second_pass:?}, \
         {throughput_mib_s:.1} MiB/s"
    );

    // --- 64 MiB re-fsync wire bytes ---------------------------------------
    // A second client dials the counting proxy, so a one-block change can be
    // measured without counting the initial upload.
    let proxy = env.proxy(server.port);
    let mut wire_client = env.client_at("/private-mm", "perf-wire", true, proxy.port);
    wire_client.wait_mounted();
    wire_client.wait_steady();
    let wire_path = wire_client.mountpoint.join("perf-wire.bin");
    let wire_base = pattern(64 << 20, 0x77);
    fs::write(&wire_path, &wire_base).unwrap();
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(&wire_path)
        .unwrap()
        .sync_all()
        .unwrap();
    let before_delta = proxy.bytes();
    let patch = pattern(4 << 10, 0x78);
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(&wire_path)
        .unwrap()
        .write_all_at(&patch, 8 << 20)
        .unwrap();
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(&wire_path)
        .unwrap()
        .sync_all()
        .unwrap();
    let after_delta = proxy.bytes();
    let wire_delta =
        after_delta.0.saturating_sub(before_delta.0) + after_delta.1.saturating_sub(before_delta.1);
    let wire_budget = (wire_base.len() / 20) as u64;
    println!(
        "64 MiB re-fsync after one 4 KiB change: {wire_delta} bytes through proxy {} \
         (budget {wire_budget}, {:.3}%)",
        proxy.port,
        wire_delta as f64 * 100.0 / wire_base.len() as f64
    );
    assert!(wire_delta > 0, "the second fsync must cross the proxy");

    if assert_perf {
        assert!(
            wire_delta <= wire_budget,
            "one-block delta moved {wire_delta} bytes, budget {wire_budget} (5% of 64 MiB)"
        );
        assert!(
            write_p50 <= Duration::from_millis(20),
            "4 KiB write p50 {write_p50:?} exceeds 20 ms"
        );
        assert!(
            write_p99 <= Duration::from_millis(200),
            "4 KiB write p99 {write_p99:?} exceeds 200 ms"
        );
        assert!(
            read_p50 <= Duration::from_millis(20),
            "4 KiB read p50 {read_p50:?} exceeds 20 ms"
        );
        assert!(
            read_p99 <= Duration::from_millis(200),
            "4 KiB read p99 {read_p99:?} exceeds 200 ms"
        );
        assert!(
            throughput_mib_s >= 20.0,
            "1 GiB warm read throughput {throughput_mib_s:.1} MiB/s is below 20 MiB/s"
        );
    }

    let _ = wire_client.stop_graceful();
    let _ = client.stop_graceful();
    let _ = server.stop_graceful();
}
