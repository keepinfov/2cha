//! # Replay Protection
//!
//! Sliding window for anti-replay attack protection.

/// Number of bits in the replay window. A wider window tolerates more
/// reordering/loss on lossy links (the old 64-packet window dropped legitimate
/// out-of-order packets too eagerly). 1024 bits = 16 × `u64`.
const WINDOW_BITS: u64 = 1024;
const WORDS: usize = (WINDOW_BITS / 64) as usize;

/// Sliding window for replay attack protection.
///
/// Bit `d` of the bitmap records whether the packet with counter
/// `last_counter - d` has been seen; word 0 holds bits 0..=63, with bit 0
/// corresponding to `last_counter` itself.
#[derive(Debug)]
pub struct ReplayWindow {
    last_counter: u64,
    bitmap: [u64; WORDS],
}

impl ReplayWindow {
    /// Create a new replay window
    pub fn new() -> Self {
        ReplayWindow {
            last_counter: 0,
            bitmap: [0; WORDS],
        }
    }

    /// Shift the whole bitmap left by `shift` bits (toward higher words),
    /// dropping bits that fall off the top of the window.
    #[inline]
    fn shift_left(&mut self, shift: u64) {
        if shift == 0 {
            return;
        }
        if shift >= WINDOW_BITS {
            self.bitmap = [0; WORDS];
            return;
        }
        let word_shift = (shift / 64) as usize;
        let bit_shift = (shift % 64) as u32;

        if bit_shift == 0 {
            for i in (0..WORDS).rev() {
                self.bitmap[i] = if i >= word_shift {
                    self.bitmap[i - word_shift]
                } else {
                    0
                };
            }
        } else {
            for i in (0..WORDS).rev() {
                let mut v = 0u64;
                if i >= word_shift {
                    v = self.bitmap[i - word_shift] << bit_shift;
                    if i > word_shift {
                        v |= self.bitmap[i - word_shift - 1] >> (64 - bit_shift);
                    }
                }
                self.bitmap[i] = v;
            }
        }
    }

    /// Check if packet is valid (not a replay)
    /// Returns true if packet should be accepted
    #[inline]
    pub fn check_and_update(&mut self, counter: u64) -> bool {
        if counter == 0 {
            return false;
        }

        if counter > self.last_counter {
            // New packet ahead of window: slide the window forward and record
            // the new high-water mark at bit 0.
            let diff = counter - self.last_counter;
            self.shift_left(diff);
            self.bitmap[0] |= 1;
            self.last_counter = counter;
            return true;
        }

        // Packet within or before window
        let diff = self.last_counter - counter;
        if diff >= WINDOW_BITS {
            return false; // Too old
        }

        let word = (diff / 64) as usize;
        let bit = 1u64 << (diff % 64);
        if self.bitmap[word] & bit != 0 {
            return false; // Replay
        }

        // Mark as seen
        self.bitmap[word] |= bit;
        true
    }

    /// Reset window
    pub fn reset(&mut self) {
        self.last_counter = 0;
        self.bitmap = [0; WORDS];
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replay_window() {
        let mut window = ReplayWindow::new();

        // Sequential packets
        assert!(window.check_and_update(1));
        assert!(window.check_and_update(2));
        assert!(window.check_and_update(3));

        // Replay should fail
        assert!(!window.check_and_update(2));

        // Out of order but within window
        assert!(window.check_and_update(5));
        assert!(window.check_and_update(4));

        // Replay again
        assert!(!window.check_and_update(4));
    }

    #[test]
    fn test_replay_window_jump() {
        let mut window = ReplayWindow::new();

        assert!(window.check_and_update(1));
        assert!(window.check_and_update(100)); // Big jump
        assert!(!window.check_and_update(1)); // Old packet
        assert!(window.check_and_update(99)); // Just within window
    }

    #[test]
    fn test_replay_window_wide() {
        let mut window = ReplayWindow::new();

        // Advance the high-water mark well past a single u64 word.
        assert!(window.check_and_update(2000));

        // A packet 1023 behind the head is still inside the 1024-bit window
        // and crosses several bitmap words.
        assert!(window.check_and_update(2000 - 1023));
        // Replaying it is rejected.
        assert!(!window.check_and_update(2000 - 1023));

        // A packet exactly at the window edge (1024 behind) is too old.
        assert!(!window.check_and_update(2000 - 1024));

        // A packet near the middle of the window is accepted once.
        assert!(window.check_and_update(2000 - 500));
        assert!(!window.check_and_update(2000 - 500));
    }
}
