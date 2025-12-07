//! # Replay Protection
//!
//! Sliding window for anti-replay attack protection.

/// Sliding window for replay attack protection
#[derive(Debug)]
pub struct ReplayWindow {
    last_counter: u64,
    bitmap: u64,
    window_size: u64,
}

impl ReplayWindow {
    /// Create a new replay window
    pub fn new() -> Self {
        ReplayWindow {
            last_counter: 0,
            bitmap: 0,
            window_size: 64,
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
            // New packet ahead of window
            let diff = counter - self.last_counter;
            if diff >= self.window_size {
                self.bitmap = 1;
            } else {
                self.bitmap <<= diff;
                self.bitmap |= 1;
            }
            self.last_counter = counter;
            return true;
        }

        // Packet within or before window
        let diff = self.last_counter - counter;
        if diff >= self.window_size {
            return false; // Too old
        }

        // Check if already seen
        let bit = 1u64 << diff;
        if self.bitmap & bit != 0 {
            return false; // Replay
        }

        // Mark as seen
        self.bitmap |= bit;
        true
    }

    /// Reset window
    pub fn reset(&mut self) {
        self.last_counter = 0;
        self.bitmap = 0;
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
}
