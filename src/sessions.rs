use std::collections::HashMap;
use std::time::Instant;

use crate::procs::Liveness;

const MAX_DEPTH: usize = 4096;

struct Session<H> {
    handle: H,
    expires: Option<Instant>,
}

impl<H: Liveness> Session<H> {
    fn live(&self, now: Instant) -> bool {
        !self.handle.has_exited() && self.expires.is_none_or(|at| now < at)
    }
}

/// Unlocked shells, keyed by pid, each with a handle that detects pid reuse and an
/// optional moment it locks again by itself.
pub struct Sessions<H> {
    shells: HashMap<u32, Session<H>>,
}

impl<H: Liveness> Sessions<H> {
    pub fn new() -> Self {
        Sessions {
            shells: HashMap::new(),
        }
    }

    /// Registering a shell again replaces its expiry, so `unlock` extends or ends a limit.
    pub fn register(&mut self, pid: u32, handle: H, expires: Option<Instant>) {
        self.shells.insert(pid, Session { handle, expires });
    }

    pub fn remove(&mut self, pid: u32) -> bool {
        self.shells.remove(&pid).is_some()
    }

    pub fn clear(&mut self) {
        self.shells.clear();
    }

    pub fn len(&self) -> usize {
        self.shells.len()
    }

    pub fn is_empty(&self) -> bool {
        self.shells.is_empty()
    }

    pub fn prune(&mut self) {
        let now = Instant::now();
        self.shells.retain(|_, s| s.live(now));
    }

    /// When the unlocked shell `pid` locks again by itself, if it does.
    pub fn expires(&self, pid: u32) -> Option<Instant> {
        self.shells.get(&pid)?.expires
    }

    /// The nearest live unlocked shell that `pid` is, or descends from. An exited or
    /// expired shell grants nothing, even before it is pruned.
    pub fn unlocked_ancestor(
        &self,
        pid: u32,
        parent_of: impl Fn(u32) -> Option<u32>,
    ) -> Option<u32> {
        let now = Instant::now();
        let mut current = pid;
        for _ in 0..MAX_DEPTH {
            if self.shells.get(&current).is_some_and(|s| s.live(now)) {
                return Some(current);
            }
            match parent_of(current) {
                Some(parent) if parent > 1 && parent != current => current = parent,
                _ => return None,
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::time::Duration;

    struct Fake(Cell<bool>);

    impl Liveness for Fake {
        fn has_exited(&self) -> bool {
            self.0.get()
        }
    }

    fn alive() -> Fake {
        Fake(Cell::new(false))
    }

    // 1 <- 100 (shell) <- 200 <- 300 ; 1 <- 500 (outsider)
    fn tree(pid: u32) -> Option<u32> {
        match pid {
            100 | 500 => Some(1),
            200 => Some(100),
            300 => Some(200),
            _ => None,
        }
    }

    #[test]
    fn descendants_inherit_and_outsiders_do_not() {
        let mut s = Sessions::new();
        s.register(100, alive(), None);
        assert_eq!(s.unlocked_ancestor(100, tree), Some(100));
        assert_eq!(s.unlocked_ancestor(300, tree), Some(100));
        assert_eq!(s.unlocked_ancestor(500, tree), None);
    }

    #[test]
    fn exited_shell_grants_nothing_even_before_pruning() {
        let mut s = Sessions::new();
        s.register(100, alive(), None);
        s.shells[&100].handle.0.set(true);
        assert_eq!(s.unlocked_ancestor(300, tree), None);
        s.prune();
        assert!(s.is_empty());
    }

    #[test]
    fn expired_shell_grants_nothing_even_before_pruning() {
        let mut s = Sessions::new();
        s.register(
            100,
            alive(),
            Some(Instant::now() - Duration::from_millis(1)),
        );
        s.register(200, alive(), Some(Instant::now() + Duration::from_secs(60)));
        assert_eq!(s.unlocked_ancestor(100, tree), None);
        assert_eq!(s.unlocked_ancestor(300, tree), Some(200));
        s.prune();
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn registering_again_replaces_the_expiry() {
        let mut s = Sessions::new();
        s.register(100, alive(), Some(Instant::now() + Duration::from_secs(60)));
        assert!(s.expires(100).is_some());
        s.register(100, alive(), None);
        assert!(s.expires(100).is_none());
    }

    #[test]
    fn nearest_shell_wins() {
        let mut s = Sessions::new();
        s.register(100, alive(), None);
        s.register(200, alive(), None);
        assert_eq!(s.unlocked_ancestor(300, tree), Some(200));
    }

    #[test]
    fn walk_terminates_on_cycle() {
        let mut s: Sessions<Fake> = Sessions::new();
        s.register(9, alive(), None);
        let cycle = |pid| Some(if pid == 2 { 3 } else { 2 });
        assert_eq!(s.unlocked_ancestor(2, cycle), None);
    }
}
