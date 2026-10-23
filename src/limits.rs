use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use anyhow::{Result, bail};

use crate::vault::WrongPassphrase;

const MAX_DELAY: Duration = Duration::from_secs(30);

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[derive(Default)]
struct Attempts {
    failures: u32,
    not_before: Option<Instant>,
}

/// Passphrase checks, one at a time per user; after each wrong passphrase the next check
/// waits twice as long as the last, up to half a minute, and a right one resets that.
/// Without it any process of a user could ask the daemon to try passphrases on their
/// vaults as fast as it can run scrypt.
#[derive(Default)]
pub struct Guesses {
    users: Mutex<HashMap<u32, Arc<Mutex<Attempts>>>>,
}

impl Guesses {
    pub fn check<T>(&self, uid: u32, f: impl FnOnce() -> Result<T>) -> Result<T> {
        let slot = lock(&self.users).entry(uid).or_default().clone();
        let mut attempts = lock(&slot);
        if let Some(at) = attempts.not_before {
            let wait = at.saturating_duration_since(Instant::now());
            if !wait.is_zero() {
                bail!(
                    "too many wrong passphrases; try again in {}s",
                    wait.as_secs_f64().ceil() as u64
                );
            }
        }
        let result = f();
        match &result {
            Ok(_) => *attempts = Attempts::default(),
            Err(e) if e.downcast_ref::<WrongPassphrase>().is_some() => {
                attempts.failures += 1;
                attempts.not_before = Some(Instant::now() + delay_after(attempts.failures));
            }
            Err(_) => {}
        }
        result
    }
}

/// How long the next check waits after `failures` wrong passphrases in a row.
fn delay_after(failures: u32) -> Duration {
    Duration::from_secs(1u64 << failures.saturating_sub(1).min(5)).min(MAX_DELAY)
}

static SCRYPT: Mutex<()> = Mutex::new(());

/// Runs a passphrase-strength scrypt computation, one at a time across the daemon: each
/// takes hundreds of megabytes, and anyone may ask for one.
pub fn expensive<T>(f: impl FnOnce() -> T) -> T {
    let _one_at_a_time = lock(&SCRYPT);
    f()
}

/// Caps open connections, in total and per user, so that no one can exhaust the daemon
/// for everyone by holding connections open.
pub struct Connections {
    max_total: usize,
    max_per_user: usize,
    open: Mutex<(usize, HashMap<u32, usize>)>,
}

pub struct Admitted {
    connections: Arc<Connections>,
    uid: u32,
}

impl Connections {
    pub fn new(max_total: usize, max_per_user: usize) -> Arc<Connections> {
        Arc::new(Connections {
            max_total,
            max_per_user,
            open: Mutex::new((0, HashMap::new())),
        })
    }

    pub fn admit(self: &Arc<Self>, uid: u32) -> Option<Admitted> {
        let mut open = lock(&self.open);
        let for_user = open.1.get(&uid).copied().unwrap_or(0);
        if open.0 >= self.max_total || for_user >= self.max_per_user {
            return None;
        }
        open.0 += 1;
        open.1.insert(uid, for_user + 1);
        Some(Admitted {
            connections: self.clone(),
            uid,
        })
    }
}

impl Drop for Admitted {
    fn drop(&mut self) {
        let mut open = lock(&self.connections.open);
        open.0 -= 1;
        if let Some(n) = open.1.get_mut(&self.uid) {
            *n -= 1;
            if *n == 0 {
                open.1.remove(&self.uid);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wrong() -> Result<()> {
        Err(anyhow::Error::new(WrongPassphrase))
    }

    #[test]
    fn a_wrong_passphrase_makes_the_next_check_wait() {
        let guesses = Guesses::default();
        assert!(guesses.check(1, wrong).is_err());
        let err = guesses.check(1, || Ok(())).err().unwrap();
        assert!(format!("{err}").contains("try again in 1s"), "{err}");
        assert!(
            guesses.check(2, || Ok(())).is_ok(),
            "other users are not affected"
        );
    }

    #[test]
    fn the_wait_doubles_up_to_half_a_minute() {
        let waits: Vec<u64> = (1..=8).map(|n| delay_after(n).as_secs()).collect();
        assert_eq!(waits, [1, 2, 4, 8, 16, 30, 30, 30]);
    }

    #[test]
    fn a_right_passphrase_resets_the_count() {
        let guesses = Guesses::default();
        assert!(guesses.check(1, wrong).is_err());
        let slot = lock(&guesses.users).get(&1).unwrap().clone();
        assert_eq!(lock(&slot).failures, 1);
        lock(&slot).not_before = None;
        assert!(guesses.check(1, || Ok(())).is_ok());
        assert_eq!(lock(&slot).failures, 0);
        assert!(lock(&slot).not_before.is_none());
    }

    #[test]
    fn other_errors_cost_no_wait() {
        let guesses = Guesses::default();
        assert!(
            guesses
                .check(1, || -> Result<()> { bail!("no vault") })
                .is_err()
        );
        assert!(guesses.check(1, || Ok(())).is_ok());
    }

    #[test]
    fn connections_are_capped_per_user_and_in_total() {
        let connections = Connections::new(3, 2);
        let a1 = connections.admit(1).unwrap();
        let _a2 = connections.admit(1).unwrap();
        assert!(connections.admit(1).is_none(), "per user");
        let _b1 = connections.admit(2).unwrap();
        assert!(connections.admit(3).is_none(), "in total");
        drop(a1);
        assert!(
            connections.admit(1).is_some(),
            "a closed connection frees its place"
        );
    }
}
