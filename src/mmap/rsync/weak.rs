//! Standard rsync rolling weak checksum.
//!
//! The window is `n` bytes. The two 16-bit sums are:
//!
//! ```text
//! s1 = sum(x[i]) mod 2^16
//! s2 = sum((n - i) * x[i]) mod 2^16
//! weak = s1 | (s2 << 16)
//! ```
//!
//! Rolling one byte uses `CHAR_OFFSET = 0`:
//!
//! ```text
//! s1' = s1 - x[0] + x[n]
//! s2' = s2 - n * x[0] + s1'
//! ```
//!
//! The weak checksum only filters. A hit must be confirmed with a
//! [`super::strong::strong128`] comparison before it can become a COPY.

/// Rolling state for one window.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WeakState {
    s1: u32,
    s2: u32,
    len: u32,
}

impl WeakState {
    /// Start a state over `bytes`.
    #[must_use]
    pub fn new(bytes: &[u8]) -> Self {
        let mut state = Self::default();
        state.update(bytes);
        state
    }

    /// Add bytes to the state. The caller must only use this to build a
    /// fresh state; rolling uses [`WeakState::rotate`].
    pub fn update(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.s1 = self.s1.wrapping_add(u32::from(byte)) & 0xffff;
            self.s2 = self.s2.wrapping_add(self.s1) & 0xffff;
        }
        self.len = self.len.saturating_add(bytes.len() as u32);
    }

    /// Roll the window by one byte: `out` leaves the front, `inb` enters the
    /// back. The window length does not change.
    pub fn rotate(&mut self, out: u8, inb: u8) {
        let sub = self.len.wrapping_mul(u32::from(out)) & 0xffff;
        self.s1 = (self.s1 + 0x1_0000 - u32::from(out) + u32::from(inb)) & 0xffff;
        self.s2 = (self.s2 + 0x1_0000 - sub + self.s1) & 0xffff;
    }

    /// The packed 32-bit checksum: `s1` in the low half, `s2` in the high.
    #[must_use]
    pub fn weak(&self) -> u32 {
        (self.s2 << 16) | self.s1
    }

    /// Window length used by the rolling update.
    #[must_use]
    pub fn len(&self) -> u32 {
        self.len
    }

    /// True when the window is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// One-shot weak checksum.
#[must_use]
pub fn weak(bytes: &[u8]) -> u32 {
    WeakState::new(bytes).weak()
}

#[cfg(all(test, feature = "mmap-tests"))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn u_rsync_weak_known_vectors() {
        let cases: &[(&[u8], u32)] = &[
            (b"", 0x0000_0000),
            (&[0x00], 0x0000_0000),
            (&[0x01], 0x0001_0001),
            (&[0xff], 0x00ff_00ff),
            (&[0x00, 0x01], 0x0001_0001),
            (&[0x01, 0x00], 0x0002_0001),
            (&[0x01, 0x02, 0x03], 0x000a_0006),
            (&[0xff, 0xff, 0xff, 0xff], 0x09f6_03fc),
            (&[0x00, 0x80], 0x0080_0080),
        ];
        for (input, expected) in cases {
            assert_eq!(weak(input), *expected, "input={input:02x?}");
        }

        let bytes: Vec<u8> = (0..=255).collect();
        assert_eq!(weak(&bytes), 0xaa80_7f80);

        let bytes = vec![0xffu8; 65536];
        assert_eq!(weak(&bytes), 0x8000_0000);
    }

    #[test]
    fn u_rsync_weak_rolling_chain() {
        let mut state = WeakState::new(&[1, 2, 3, 4]);
        assert_eq!((state.s1, state.s2, state.weak()), (10, 20, 0x0014_000a));

        state.rotate(1, 5);
        assert_eq!((state.s1, state.s2, state.weak()), (14, 30, 0x001e_000e));

        state.rotate(2, 6);
        assert_eq!((state.s1, state.s2, state.weak()), (18, 40, 0x0028_0012));

        assert_eq!(state, WeakState::new(&[3, 4, 5, 6]));
    }

    #[test]
    fn u_rsync_weak_rolling_matches_full_recompute() {
        let data: Vec<u8> = (0..4096).map(|index| (index % 251) as u8).collect();
        let window = 64;
        let mut state = WeakState::new(&data[..window]);
        for offset in 0..=data.len() - window - 1 {
            assert_eq!(
                state.weak(),
                weak(&data[offset..offset + window]),
                "offset={offset}"
            );
            state.rotate(data[offset], data[offset + window]);
        }
    }

    #[test]
    fn u_rsync_weak_empty_state() {
        let state = WeakState::default();
        assert!(state.is_empty());
        assert_eq!(state.len(), 0);
        assert_eq!(state.weak(), 0);
    }
}
