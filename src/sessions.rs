use std::collections::HashMap;

use crate::procs::Liveness;

const MAX_DEPTH: usize = 4096;

/// Unlocked shells, keyed by pid, each with a handle that detects pid reuse.
pub struct Sessions<H> {
    shells: HashMap<u32, H>,
}

impl<H: Liveness> Sessions<H> {
    pub fn new() -> Self {
        Sessions {
            shells: HashMap::new(),
        }
    }

    pub fn register(&mut self, pid: u32, handle: H) {
        self.shells.insert(pid, handle);
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
        self.shells.retain(|_, h| !h.has_exited());
    }

    /// The nearest live unlocked shell that `pid` is, or descends from.
    pub fn unlocked_ancestor(
        &self,
        pid: u32,
        parent_of: impl Fn(u32) -> Option<u32>,
    ) -> Option<u32> {
        let mut current = pid;
        for _ in 0..MAX_DEPTH {
            if let Some(handle) = self.shells.get(&current)
                && !handle.has_exited()
            {
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
        s.register(100, alive());
        assert_eq!(s.unlocked_ancestor(100, tree), Some(100));
        assert_eq!(s.unlocked_ancestor(300, tree), Some(100));
        assert_eq!(s.unlocked_ancestor(500, tree), None);
    }

    #[test]
    fn exited_shell_grants_nothing_even_before_pruning() {
        let mut s = Sessions::new();
        s.register(100, alive());
        s.shells[&100].0.set(true);
        assert_eq!(s.unlocked_ancestor(300, tree), None);
        s.prune();
        assert!(s.is_empty());
    }

    #[test]
    fn nearest_shell_wins() {
        let mut s = Sessions::new();
        s.register(100, alive());
        s.register(200, alive());
        assert_eq!(s.unlocked_ancestor(300, tree), Some(200));
    }

    #[test]
    fn walk_terminates_on_cycle() {
        let mut s: Sessions<Fake> = Sessions::new();
        s.register(9, alive());
        let cycle = |pid| Some(if pid == 2 { 3 } else { 2 });
        assert_eq!(s.unlocked_ancestor(2, cycle), None);
    }
}
