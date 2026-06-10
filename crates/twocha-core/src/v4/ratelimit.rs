//! # Handshake Rate Limiting
//!
//! Per-source-IP token buckets plus a global bucket that flips the server
//! into "under load" mode, at which point unproven sources must complete a
//! cookie challenge before any expensive crypto is done for them.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

/// Handshakes allowed per source IP per second (sustained)
const PER_IP_RATE: f64 = 2.0;
const PER_IP_BURST: f64 = 5.0;
/// Global sustained handshake rate before cookie challenges kick in
const GLOBAL_RATE: f64 = 50.0;
const GLOBAL_BURST: f64 = 100.0;
/// Evict idle per-IP buckets after this many seconds
const GC_AFTER_SECS: u64 = 60;

struct Bucket {
    tokens: f64,
    last: Instant,
}

impl Bucket {
    fn new(burst: f64) -> Self {
        Bucket {
            tokens: burst,
            last: Instant::now(),
        }
    }

    fn take(&mut self, rate: f64, burst: f64) -> bool {
        let now = Instant::now();
        self.tokens = (self.tokens + now.duration_since(self.last).as_secs_f64() * rate).min(burst);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

pub struct RateLimiter {
    per_ip: HashMap<IpAddr, Bucket>,
    global: Bucket,
    last_gc: Instant,
}

impl RateLimiter {
    pub fn new() -> Self {
        RateLimiter {
            per_ip: HashMap::new(),
            global: Bucket::new(GLOBAL_BURST),
            last_gc: Instant::now(),
        }
    }

    /// Whether a handshake attempt from `ip` may proceed at all.
    /// Exceeding the per-IP budget means the datagram is dropped outright.
    pub fn allow(&mut self, ip: IpAddr) -> bool {
        self.maybe_gc();
        self.per_ip
            .entry(ip)
            .or_insert_with(|| Bucket::new(PER_IP_BURST))
            .take(PER_IP_RATE, PER_IP_BURST)
    }

    /// Whether the server should demand cookies (global pressure).
    /// Consumes one global token per handshake attempt.
    pub fn under_load(&mut self) -> bool {
        !self.global.take(GLOBAL_RATE, GLOBAL_BURST)
    }

    fn maybe_gc(&mut self) {
        if self.last_gc.elapsed().as_secs() < GC_AFTER_SECS {
            return;
        }
        self.per_ip
            .retain(|_, b| b.last.elapsed().as_secs() < GC_AFTER_SECS);
        self.last_gc = Instant::now();
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_per_ip_burst_then_block() {
        let mut rl = RateLimiter::new();
        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        let allowed = (0..20).filter(|_| rl.allow(ip)).count();
        assert!((4..=7).contains(&allowed), "allowed={}", allowed);
    }

    #[test]
    fn test_independent_ips() {
        let mut rl = RateLimiter::new();
        let a: IpAddr = "198.51.100.1".parse().unwrap();
        let b: IpAddr = "198.51.100.2".parse().unwrap();
        for _ in 0..10 {
            rl.allow(a);
        }
        assert!(rl.allow(b), "different IP must have its own bucket");
    }

    #[test]
    fn test_global_load_flips() {
        let mut rl = RateLimiter::new();
        let mut flipped = false;
        for _ in 0..200 {
            if rl.under_load() {
                flipped = true;
                break;
            }
        }
        assert!(flipped, "global bucket must eventually signal load");
    }
}
