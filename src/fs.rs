use std::collections::HashMap;
use std::ffi::OsStr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime};

use fuser::{
    AccessFlags, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation,
    INodeNo, LockOwner, OpenAccMode, OpenFlags, ReplyAttr, ReplyData, ReplyDirectory, ReplyEmpty,
    ReplyEntry, ReplyOpen, Request,
};

use crate::procs::{self, Pidfd};
use crate::sessions::Sessions;
use crate::users::{self, Account};
use crate::vault::{self, Kind, Tree};

/// Every answer depends on who asks, so nothing may be cached by the kernel.
const NO_CACHE: Duration = Duration::ZERO;

const ROOT: u64 = 1;

/// The caller's own directory: the same name for everyone, a different inode per user.
pub const SELF: &str = "self";

/// Each user's tree lives in its own inode range: the high half is the user's
/// slot, the low half the inode within the tree (whose root is `vault::ROOT`).
fn global_ino(slot: u32, local: u64) -> u64 {
    (u64::from(slot) << 32) | local
}

fn split_ino(ino: u64) -> (u32, u64) {
    ((ino >> 32) as u32, ino & 0xffff_ffff)
}

pub struct UserState {
    pub account: Account,
    slot: u32,
    pub tree: Option<Tree>,
    pub sessions: Sessions<Pidfd>,
}

impl UserState {
    pub fn unlocked_ancestor(&self, pid: u32) -> Option<u32> {
        self.sessions.unlocked_ancestor(pid, procs::parent_of)
    }

    fn visible_tree(&self, pid: u32) -> Option<&Tree> {
        let tree = self.tree.as_ref()?;
        self.unlocked_ancestor(pid)?;
        Some(tree)
    }
}

#[derive(Default)]
pub struct State {
    users: HashMap<u32, UserState>,
    slots: Vec<u32>,
}

impl State {
    pub fn user(&self, uid: u32) -> Option<&UserState> {
        self.users.get(&uid)
    }

    pub fn user_mut(&mut self, uid: u32) -> Option<&mut UserState> {
        if !self.users.contains_key(&uid) {
            let account = users::by_uid(uid)?;
            self.slots.push(uid);
            let slot = self.slots.len() as u32;
            self.users.insert(
                uid,
                UserState {
                    account,
                    slot,
                    tree: None,
                    sessions: Sessions::new(),
                },
            );
        }
        self.users.get_mut(&uid)
    }

    fn by_slot(&self, slot: u32) -> Option<&UserState> {
        let uid = *self
            .slots
            .get(usize::try_from(slot).ok()?.checked_sub(1)?)?;
        self.users.get(&uid)
    }

    /// Drops decrypted trees once no shell of that user is left to use them.
    pub fn prune(&mut self) {
        for user in self.users.values_mut() {
            user.sessions.prune();
            if user.sessions.is_empty() {
                user.tree = None;
            }
        }
    }

    pub fn lock_everything(&mut self) {
        for user in self.users.values_mut() {
            user.sessions.clear();
            user.tree = None;
        }
    }
}

pub type Shared = Arc<Mutex<State>>;

pub fn lock(state: &Shared) -> MutexGuard<'_, State> {
    state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// What an inode resolves to for the process asking about it.
enum Target<'a> {
    Root,
    UserDir(&'a UserState),
    Node(&'a UserState, u64, &'a vault::Node),
}

pub struct VaultFs {
    state: Shared,
    owner_uid: u32,
    owner_gid: u32,
    started: SystemTime,
}

impl VaultFs {
    pub fn new(state: Shared, owner_uid: u32, owner_gid: u32) -> VaultFs {
        VaultFs {
            state,
            owner_uid,
            owner_gid,
            started: SystemTime::now(),
        }
    }

    /// Resolves `ino` only within the caller's own slot; other users' inodes do not exist.
    fn target<'a>(&self, state: &'a State, req: &Request, ino: u64) -> Option<Target<'a>> {
        if ino == ROOT {
            return Some(Target::Root);
        }
        let (slot, local) = split_ino(ino);
        let user = state.by_slot(slot)?;
        if user.account.uid != req.uid() {
            return None;
        }
        if local == vault::ROOT {
            return Some(Target::UserDir(user));
        }
        let node = user.visible_tree(req.pid())?.node(local)?;
        Some(Target::Node(user, local, node))
    }

    fn attr(&self, ino: u64, target: &Target) -> FileAttr {
        let (kind, perm, size, nlink, uid, gid) = match target {
            Target::Root => (
                FileType::Directory,
                0o755,
                0,
                2,
                self.owner_uid,
                self.owner_gid,
            ),
            Target::UserDir(user) => (
                FileType::Directory,
                0o700,
                0,
                2,
                user.account.uid,
                user.account.gid,
            ),
            Target::Node(user, _, node) => match &node.kind {
                Kind::File { mode, data } => (
                    FileType::RegularFile,
                    *mode as u16,
                    data.len() as u64,
                    1,
                    user.account.uid,
                    user.account.gid,
                ),
                Kind::Dir { .. } => (
                    FileType::Directory,
                    0o700,
                    0,
                    2,
                    user.account.uid,
                    user.account.gid,
                ),
            },
        };
        FileAttr {
            ino: INodeNo(ino),
            size,
            blocks: size.div_ceil(512),
            atime: self.started,
            mtime: self.started,
            ctime: self.started,
            crtime: self.started,
            kind,
            perm,
            nlink,
            uid,
            gid,
            rdev: 0,
            flags: 0,
            blksize: 4096,
        }
    }

    fn user_dir_ino(user: &UserState) -> u64 {
        global_ino(user.slot, vault::ROOT)
    }
}

impl Filesystem for VaultFs {
    fn lookup(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let mut state = lock(&self.state);
        if parent.0 == ROOT {
            let Some(user) = state.user_mut(req.uid()) else {
                return reply.error(Errno::ENOENT);
            };
            if name != OsStr::new(SELF) {
                return reply.error(Errno::ENOENT);
            }
            let ino = Self::user_dir_ino(user);
            let user = state.user(req.uid()).expect("just inserted");
            return reply.entry(
                &NO_CACHE,
                &self.attr(ino, &Target::UserDir(user)),
                Generation(0),
            );
        }
        let found = match self.target(&state, req, parent.0) {
            Some(Target::UserDir(user)) => Some((user, vault::ROOT)),
            Some(Target::Node(user, local, _)) => Some((user, local)),
            _ => None,
        }
        .and_then(|(user, local)| {
            let tree = user.visible_tree(req.pid())?;
            let child = tree.child(local, name)?;
            let ino = global_ino(user.slot, child);
            Some(self.attr(ino, &Target::Node(user, child, tree.node(child)?)))
        });
        match found {
            Some(attr) => reply.entry(&NO_CACHE, &attr, Generation(0)),
            None => reply.error(Errno::ENOENT),
        }
    }

    fn getattr(&self, req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        let state = lock(&self.state);
        match self.target(&state, req, ino.0) {
            Some(target) => reply.attr(&NO_CACHE, &self.attr(ino.0, &target)),
            None => reply.error(Errno::ENOENT),
        }
    }

    fn access(&self, req: &Request, ino: INodeNo, _mask: AccessFlags, reply: ReplyEmpty) {
        let state = lock(&self.state);
        match self.target(&state, req, ino.0) {
            Some(_) => reply.ok(),
            None => reply.error(Errno::ENOENT),
        }
    }

    fn open(&self, req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        if flags.acc_mode() != OpenAccMode::O_RDONLY {
            return reply.error(Errno::EROFS);
        }
        let state = lock(&self.state);
        match self.target(&state, req, ino.0) {
            // direct I/O keeps file contents out of the shared page cache
            Some(Target::Node(_, _, node)) if matches!(node.kind, Kind::File { .. }) => {
                reply.opened(FileHandle(0), FopenFlags::FOPEN_DIRECT_IO)
            }
            Some(_) => reply.error(Errno::EISDIR),
            None => reply.error(Errno::ENOENT),
        }
    }

    fn read(
        &self,
        req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        let state = lock(&self.state);
        let Some(Target::Node(_, _, node)) = self.target(&state, req, ino.0) else {
            return reply.error(Errno::ENOENT);
        };
        let Kind::File { data, .. } = &node.kind else {
            return reply.error(Errno::EISDIR);
        };
        let start = (offset as usize).min(data.len());
        let end = start.saturating_add(size as usize).min(data.len());
        reply.data(&data[start..end]);
    }

    fn opendir(&self, req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        let state = lock(&self.state);
        match self.target(&state, req, ino.0) {
            Some(Target::Node(_, _, node)) if matches!(node.kind, Kind::File { .. }) => {
                reply.error(Errno::ENOTDIR)
            }
            Some(_) => reply.opened(FileHandle(0), FopenFlags::empty()),
            None => reply.error(Errno::ENOENT),
        }
    }

    fn readdir(
        &self,
        req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let mut state = lock(&self.state);
        if ino.0 == ROOT {
            state.user_mut(req.uid());
        }
        let mut listing: Vec<(u64, FileType, std::ffi::OsString)> = Vec::new();
        match self.target(&state, req, ino.0) {
            Some(Target::Root) => {
                listing.push((ROOT, FileType::Directory, ".".into()));
                listing.push((ROOT, FileType::Directory, "..".into()));
                if let Some(user) = state.user(req.uid()) {
                    listing.push((Self::user_dir_ino(user), FileType::Directory, SELF.into()));
                }
            }
            Some(Target::UserDir(user)) => {
                listing.push((ino.0, FileType::Directory, ".".into()));
                listing.push((ROOT, FileType::Directory, "..".into()));
                if let Some(tree) = user.visible_tree(req.pid()) {
                    push_children(&mut listing, user, tree, vault::ROOT);
                }
            }
            Some(Target::Node(user, local, node)) => {
                if !matches!(node.kind, Kind::Dir { .. }) {
                    return reply.error(Errno::ENOTDIR);
                }
                listing.push((ino.0, FileType::Directory, ".".into()));
                listing.push((
                    global_ino(user.slot, node.parent),
                    FileType::Directory,
                    "..".into(),
                ));
                if let Some(tree) = user.visible_tree(req.pid()) {
                    push_children(&mut listing, user, tree, local);
                }
            }
            None => return reply.error(Errno::ENOENT),
        }
        for (i, (child, kind, name)) in listing.into_iter().enumerate().skip(offset as usize) {
            if reply.add(INodeNo(child), (i + 1) as u64, kind, name) {
                break;
            }
        }
        reply.ok();
    }
}

fn push_children(
    listing: &mut Vec<(u64, FileType, std::ffi::OsString)>,
    user: &UserState,
    tree: &Tree,
    dir: u64,
) {
    let Some(Kind::Dir { entries }) = tree.node(dir).map(|n| &n.kind) else {
        return;
    };
    for (name, &child) in entries {
        let kind = match tree.node(child).map(|n| &n.kind) {
            Some(Kind::File { .. }) => FileType::RegularFile,
            _ => FileType::Directory,
        };
        listing.push((global_ino(user.slot, child), kind, name.clone()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inode_ranges_do_not_overlap() {
        assert_eq!(split_ino(global_ino(3, 7)), (3, 7));
        assert_ne!(global_ino(1, vault::ROOT), ROOT);
        assert_eq!(split_ino(ROOT), (0, ROOT));
    }
}
