//! M3 exit acceptance harness (31:M3-7, decision D13): chunk assembly under
//! out-of-order and duplicate delivery.
//!
//! One 100 MiB deterministic file is cut into 256 KiB chunks, sealed with the
//! content cipher, and delivered in a shuffled order where about 10% of the
//! chunks are sent twice at a later position. Two assemblies must reproduce
//! the source exactly:
//!
//! * the JOIN write path: [`ChunkCipher::open`] then
//!   [`StagingBuild::stage_segment`] at explicit offsets, `finish`, `apply`;
//! * the chunk layer alone: [`ChunkCipher::open`] into a byte buffer at the
//!   chunk's file offset, with duplicate writes overwriting in place.
//!
//! A duplicate delivery carries the same plaintext for the same chunk, so it
//! must be idempotent: no extra bytes and no shifted chunks. Both results are
//! compared byte for byte and by SHA-256.
//!
//! The input is generated with xorshift64* and a fixed seed, so a failure is
//! reproducible. Run:
//!
//! ```text
//! cargo test --test m3_chunks -- --nocapture --test-threads=1
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs::File;
use std::io::{BufReader, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::{Arc, LazyLock};
use std::time::Instant;

use sha2::{Digest, Sha256};
use syncmount::store::{RootFd, STAGING_TREE};
use syncmount::sync::chunk::{CHUNK_BYTES, ChunkCipher, ChunkId, ChunkKind, SealedChunk};
use syncmount::sync::staging::{ApplyItem, StagingBuild, apply};
use tempfile::TempDir;

/// Acceptance file size (100 MiB).
const FILE_BYTES: usize = 100 * 1024 * 1024;
/// 100 MiB / 256 KiB, exact: every chunk is a full chunk.
const CHUNKS: usize = FILE_BYTES / CHUNK_BYTES;
/// Target path relative to the backing root.
const TARGET: &str = "payload.bin";
/// Fixed content key for the acceptance run.
const KEY: [u8; 32] = [0x6d; 32];
/// Seed of the pseudo-random file content.
const DATA_SEED: u64 = 0x4d33_5eed_0000_0001;
/// Seed of the delivery shuffle.
const SHUFFLE_SEED: u64 = 0x0f0f_5eed_0f0f_5eed;
/// Seed of the duplicate insertion positions.
const DUPLICATE_SEED: u64 = 0x1234_5678_9abc_def1;
/// Every tenth delivery repeats one chunk once.
const DUPLICATE_EVERY: usize = 10;

/// xorshift64* (Marsaglia): deterministic input without a PRNG dependency.
struct XorShift64Star {
    state: u64,
}

impl XorShift64Star {
    fn new(seed: u64) -> Self {
        Self { state: seed | 1 }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, bound: usize) -> usize {
        assert!(bound > 0, "bound must be positive");
        (self.next_u64() % bound as u64) as usize
    }
}

/// The 100 MiB source, generated once per test process.
fn source_data() -> &'static [u8] {
    static SOURCE: LazyLock<Vec<u8>> = LazyLock::new(|| {
        let mut rng = XorShift64Star::new(DATA_SEED);
        let mut out = vec![0u8; FILE_BYTES];
        for word in out.chunks_exact_mut(8) {
            word.copy_from_slice(&rng.next_u64().to_le_bytes());
        }
        out
    });
    &SOURCE
}

/// Seal every 256 KiB chunk of `data` in file order.
fn seal_chunks(cipher: &ChunkCipher, data: &[u8]) -> Vec<SealedChunk> {
    data.chunks(CHUNK_BYTES)
        .enumerate()
        .map(|(index, plaintext)| {
            cipher
                .seal(ChunkKind::File, plaintext)
                .unwrap_or_else(|err| panic!("seal chunk {index}: {err}"))
        })
        .collect()
}

/// Deterministic Fisher-Yates permutation of `0..count`.
fn shuffled(count: usize, seed: u64) -> Vec<usize> {
    let mut rng = XorShift64Star::new(seed);
    let mut order: Vec<usize> = (0..count).collect();
    for index in (1..count).rev() {
        let other = rng.below(index + 1);
        order.swap(index, other);
    }
    order
}

/// Repeat every `every`-th chunk once, at an arbitrary later stream position.
///
/// Returns the delivery sequence (chunk indices) and the duplicate count.
fn deliveries(order: &[usize], every: usize, seed: u64) -> (Vec<usize>, usize) {
    let mut rng = XorShift64Star::new(seed);
    let mut stream = order.to_vec();
    let mut duplicates = 0usize;
    for (position, &index) in order.iter().enumerate() {
        if position % every == 0 {
            let at = rng.below(stream.len() + 1);
            stream.insert(at, index);
            duplicates += 1;
        }
    }
    (stream, duplicates)
}

/// Lowercase hex of a digest.
fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(out, "{byte:02x}").expect("write to String");
    }
    out
}

/// SHA-256 of an in-memory buffer.
fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    to_hex(&hasher.finalize())
}

/// Stream `path`, hashing it and comparing every byte with `expected`.
///
/// Returns `(size, sha256_hex)`. A mismatch reports the first differing
/// offset without dumping 100 MiB.
fn hash_and_compare(path: &Path, expected: &[u8]) -> (u64, String) {
    let file = File::open(path).unwrap_or_else(|err| panic!("open {}: {err}", path.display()));
    let mut reader = BufReader::with_capacity(CHUNK_BYTES, file);
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; CHUNK_BYTES];
    let mut offset = 0usize;
    let mut total = 0u64;
    loop {
        let read = reader
            .read(&mut buffer)
            .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        let end = offset + read;
        assert!(
            end <= expected.len() && buffer[..read] == expected[offset..end],
            "installed file differs from the source at byte {offset}"
        );
        offset = end;
        total += read as u64;
    }
    assert_eq!(
        total,
        expected.len() as u64,
        "installed file size must equal the source size"
    );
    (total, to_hex(&hasher.finalize()))
}

/// 31:M3-7 / D13: shuffled segments, 10% delivered twice, assembled through
/// staging and installed with one rename.
#[test]
fn m3_7_staging_out_of_order_duplicate_segments() {
    let started = Instant::now();
    assert_eq!(
        FILE_BYTES % CHUNK_BYTES,
        0,
        "100 MiB is a whole chunk count"
    );

    let data = source_data();
    let cipher = ChunkCipher::new(KEY);
    let chunks = seal_chunks(&cipher, data);
    assert_eq!(chunks.len(), CHUNKS);

    let order = shuffled(chunks.len(), SHUFFLE_SEED);
    let (stream, duplicates) = deliveries(&order, DUPLICATE_EVERY, DUPLICATE_SEED);
    assert_eq!(duplicates, CHUNKS / DUPLICATE_EVERY, "about 10% repeat");
    assert_eq!(stream.len(), CHUNKS + duplicates);
    assert_ne!(
        order,
        (0..CHUNKS).collect::<Vec<_>>(),
        "delivery must be shuffled"
    );

    let temp = TempDir::new().expect("tempdir");
    let mount = temp.path().join("mnt");
    std::fs::create_dir(&mount).expect("create mountpoint");
    let root = Arc::new(RootFd::open_before_mount(&mount).expect("open backing root"));

    let mut build = StagingBuild::new(root.clone()).expect("start staging build");
    for &index in &stream {
        let offset = (index * CHUNK_BYTES) as u64;
        let sealed = &chunks[index];
        let plaintext = cipher
            .open(ChunkKind::File, &sealed.chunk_id, &sealed.blob)
            .unwrap_or_else(|err| panic!("open chunk {index}: {err}"));
        assert_eq!(plaintext.len(), CHUNK_BYTES);
        build
            .stage_segment(Path::new(TARGET), offset, &plaintext, 0o644)
            .unwrap_or_else(|err| panic!("stage chunk {index} at {offset}: {err}"));
    }

    let plan = build.into_plan().expect("finish staging");
    assert_eq!(plan.len(), 1, "one target file");
    let (staging, target) = match &plan.items()[0] {
        ApplyItem::Install { staging, target } => (staging.clone(), target.clone()),
        other => panic!("expected one install, got {other:?}"),
    };
    assert_eq!(target, Path::new(TARGET));
    assert!(
        staging
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(".sm-tmp")),
        "staged name must stay flat: {}",
        staging.display()
    );
    let staged_attr = root.stat_at(&staging, false).expect("stat staged file");
    assert_eq!(
        staged_attr.size, FILE_BYTES as u64,
        "staged file must hold every segment once"
    );

    let report = apply(&root, &plan).expect("apply staged file");
    assert_eq!(report.installed, 1);
    assert_eq!(report.replaced, 0);
    assert!(
        root.list_at(Path::new(STAGING_TREE))
            .expect("list staging tree")
            .is_empty(),
        "staging tree must be empty after apply"
    );

    let target_path = mount.join(TARGET);
    let metadata = std::fs::metadata(&target_path).expect("stat target");
    assert_eq!(metadata.len(), FILE_BYTES as u64);
    assert_eq!(metadata.permissions().mode() & 0o777, 0o644);

    let (size, digest) = hash_and_compare(&target_path, data);
    let expected = sha256_hex(data);
    assert_eq!(digest, expected, "installed sha256 must equal the source");
    assert_eq!(size, FILE_BYTES as u64);

    println!(
        "M3 evidence: M3-7 staging_out_of_order size={FILE_BYTES} chunks={CHUNKS} \
         deliveries={} duplicates={duplicates} sha256={digest} elapsed_ms={}",
        stream.len(),
        started.elapsed().as_millis()
    );
}

/// 31:M3-7 / D13: the chunk layer alone reassembles the file from shuffled
/// `open` calls; repeated chunks overwrite the same offset idempotently.
#[test]
fn m3_7_chunk_layer_out_of_order_open() {
    let started = Instant::now();
    let data = source_data();
    let cipher = ChunkCipher::new(KEY);
    let chunks = seal_chunks(&cipher, data);
    assert_eq!(chunks.len(), CHUNKS);

    let mut index_of: HashMap<ChunkId, usize> = HashMap::with_capacity(CHUNKS);
    for (index, sealed) in chunks.iter().enumerate() {
        assert!(
            index_of.insert(sealed.chunk_id, index).is_none(),
            "chunk ids must be unique"
        );
        let start = index * CHUNK_BYTES;
        assert_eq!(
            sealed.chunk_id,
            ChunkId::of_plaintext(&data[start..start + CHUNK_BYTES]),
            "chunk {index} identity"
        );
    }

    let order = shuffled(chunks.len(), SHUFFLE_SEED ^ 0xa5a5_a5a5_5a5a_5a5a);
    let (stream, duplicates) = deliveries(&order, DUPLICATE_EVERY, DUPLICATE_SEED ^ 0xdead_beef);
    assert_eq!(duplicates, CHUNKS / DUPLICATE_EVERY, "about 10% repeat");
    assert_eq!(stream.len(), CHUNKS + duplicates);
    assert_ne!(
        order,
        (0..CHUNKS).collect::<Vec<_>>(),
        "delivery must be shuffled"
    );

    let mut assembled = vec![0u8; FILE_BYTES];
    let mut written = vec![false; CHUNKS];
    let mut distinct = 0usize;
    let mut overwritten = 0usize;
    for &index in &stream {
        let sealed = &chunks[index];
        let plaintext = cipher
            .open(ChunkKind::File, &sealed.chunk_id, &sealed.blob)
            .unwrap_or_else(|err| panic!("open chunk {index}: {err}"));
        let target_index = *index_of
            .get(&sealed.chunk_id)
            .expect("every opened chunk id is known");
        assert_eq!(target_index, index, "chunk id maps to its file offset");
        let start = index * CHUNK_BYTES;
        let end = start + plaintext.len();
        assert!(end <= FILE_BYTES, "chunk {index} must fit the file");
        if written[index] {
            assert!(
                assembled[start..end] == plaintext[..],
                "duplicate chunk {index} must carry identical bytes"
            );
            overwritten += 1;
        } else {
            written[index] = true;
            distinct += 1;
        }
        assembled[start..end].copy_from_slice(&plaintext);
    }

    assert_eq!(distinct, CHUNKS, "every chunk must arrive at least once");
    assert_eq!(
        overwritten, duplicates,
        "each duplicate must overwrite its own offset"
    );
    assert_eq!(
        assembled.len(),
        FILE_BYTES,
        "duplicates must not append bytes"
    );
    assert!(
        assembled.as_slice() == data,
        "assembled bytes must equal the source"
    );
    let digest = sha256_hex(&assembled);
    assert_eq!(digest, sha256_hex(data), "assembled sha256");

    println!(
        "M3 evidence: M3-7 chunk_layer_out_of_order size={FILE_BYTES} chunks={CHUNKS} \
         deliveries={} duplicates={duplicates} sha256={digest} elapsed_ms={}",
        stream.len(),
        started.elapsed().as_millis()
    );
}
