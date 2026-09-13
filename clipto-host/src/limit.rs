//! The failure limit for one source address.
//!
//! Every node that the access rules allow can reach the port, so a listener
//! must cap what a single address may try. Ten failures inside one minute close
//! the port to that address.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Failures one address may make inside `FAILURE_WINDOW`.
const MAX_FAILURES: u32 = 10;

/// The window the failure count applies to.
const FAILURE_WINDOW: Duration = Duration::from_secs(60);

/// Counts the failed attempts for each source address.
#[derive(Default)]
pub struct Limiter {
    failures: HashMap<IpAddr, (u32, Instant)>,
}

impl Limiter {
    pub fn allow(&mut self, address: IpAddr) -> bool {
        match self.failures.get(&address) {
            Some((count, since)) if *count >= MAX_FAILURES => {
                if since.elapsed() >= FAILURE_WINDOW {
                    self.failures.remove(&address);
                    true
                } else {
                    false
                }
            }
            _ => true,
        }
    }

    pub fn failed(&mut self, address: IpAddr) {
        let entry = self.failures.entry(address).or_insert((0, Instant::now()));
        if entry.1.elapsed() >= FAILURE_WINDOW {
            *entry = (0, Instant::now());
        }
        entry.0 += 1;
    }

    pub fn passed(&mut self, address: IpAddr) {
        self.failures.remove(&address);
    }
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn address() -> IpAddr {
        "100.83.1.13".parse().unwrap()
    }

    #[test]
    fn closes_the_port_after_the_limit() {
        let mut limiter = Limiter::default();
        for _ in 0..MAX_FAILURES {
            assert!(limiter.allow(address()));
            limiter.failed(address());
        }
        assert!(!limiter.allow(address()));
    }

    #[test]
    fn one_success_clears_the_count() {
        let mut limiter = Limiter::default();
        for _ in 0..MAX_FAILURES {
            limiter.failed(address());
        }
        limiter.passed(address());
        assert!(limiter.allow(address()));
    }

    /// The count belongs to one address. A second address must not inherit it.
    #[test]
    fn counts_each_address_on_its_own() {
        let mut limiter = Limiter::default();
        for _ in 0..MAX_FAILURES {
            limiter.failed(address());
        }
        assert!(limiter.allow("100.83.1.14".parse().unwrap()));
    }
}
