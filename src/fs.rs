use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime};

use anyhow::Result;
use fuser::{
    AccessFlags, BsdFileFlags, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags,
    Generation, INodeNo, LockOwner, OpenFlags, RenameFlags, ReplyAttr, ReplyCreate, ReplyData,
    ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, Request, TimeOrNow, WriteFlags,
};

use crate::procs::{self, Pidfd};
use crate::sessions::Sessions;
use crate::tree::{self, Kind, Node, Tree, TreeError};
use crate::users::{self, Account};
use crate::vault::{Key, Stored};

/// Every answer depends on who asks, so nothing may be cached by the kernel.
const NO_CACHE: Duration = Duration::ZERO;

/// How long a vault may stay changed but unsaved when nothing forces a save.
const SAVE_DELAY: Duration = Duration::from_secs(1);

const ROOT: u64 = 1;

/// The caller's own directory: the same name for everyone, a different inode per user.
pub const SELF: &str = "self";

/// Inodes are the user's slot (16 bits), the generation of their tree (16 bits) and the
/// inode within the tree (32 bits). A new generation, after an import, makes inodes from
/// the old tree resolve to nothing instead of to some other file. The user's directory
/// itself uses generation 0, so it stays the same across unlocks and imports.
fn global_ino(slot: u16, generation: u16, local: u64) -> u64 {
    (u64::from(slot) << 48) | (u64::from(generation) << 32) | local
}

fn split_ino(ino: u64) -> (u16, u16, u64) {
    ((ino >> 48) as u16, (ino >> 32) as u16, ino & 0xffff_ffff)
}

pub struct Unlocked {
    pub tree: Tree,
    pub key: Key,
    pub wrapped_key: Vec<u8>,
    changed: Option<Instant>,
}

impl Unlocked {
    pub fn new(tree: Tree, key: Key, wrapped_key: Vec<u8>) -> Unlocked {
        Unlocked {
            tree,
            key,
            wrapped_key,
            changed: None,
        }
    }
}

pub struct UserState {
    pub account: Account,
    slot: u16,
    generation: u16,
    pub vault_path: PathBuf,
    pub open: Option<Unlocked>,
    pub sessions: Sessions<Pidfd>,
}

impl UserState {
    pub fn unlocked_ancestor(&self, pid: u32) -> Option<u32> {
        self.sessions.unlocked_ancestor(pid, procs::parent_of)
    }

    fn visible(&self, pid: u32) -> Option<&Unlocked> {
        let open = self.open.as_ref()?;
        self.unlocked_ancestor(pid)?;
        Some(open)
    }

    pub fn has_vault(&self) -> bool {
        self.vault_path.exists()
    }

    /// Replaces what is held in memory; inodes of the previous tree stop resolving.
    pub fn hold(&mut self, unlocked: Unlocked) {
        self.open = Some(unlocked);
        self.generation = self.generation.wrapping_add(1).max(1);
    }

    fn mark_changed(&mut self) {
        if let Some(open) = &mut self.open {
            open.changed = Some(Instant::now());
        }
    }

    pub fn save(&mut self) -> Result<()> {
        let Some(open) = &mut self.open else {
            return Ok(());
        };
        if open.changed.is_none() {
            return Ok(());
        }
        let stored = Stored {
            wrapped_key: open.wrapped_key.clone(),
            contents: open.key.seal_tree(&open.tree)?,
        };
        stored.write(&self.vault_path, false)?;
        open.changed = None;
        Ok(())
    }

    /// Stores K under a new passphrase, together with the current contents.
    pub fn rewrap(&mut self, wrapped_key: Vec<u8>) -> Result<()> {
        if let Some(open) = &mut self.open {
            open.wrapped_key = wrapped_key;
            open.changed = Some(Instant::now());
        }
        self.save()
    }

    fn save_logged(&mut self) -> bool {
        match self.save() {
            Ok(()) => true,
            Err(e) => {
                eprintln!("sshvault: saving the vault of {}: {e:#}", self.account.name);
                false
            }
        }
    }
}

pub struct State {
    users: HashMap<u32, UserState>,
    slots: Vec<u32>,
    state_dir: PathBuf,
}

impl State {
    pub fn new(state_dir: PathBuf) -> State {
        State {
            users: HashMap::new(),
            slots: Vec::new(),
            state_dir,
        }
    }

    pub fn user(&self, uid: u32) -> Option<&UserState> {
        self.users.get(&uid)
    }

    pub fn user_mut(&mut self, uid: u32) -> Option<&mut UserState> {
        if !self.users.contains_key(&uid) {
            let account = users::by_uid(uid)?;
            let slot = u16::try_from(self.slots.len() + 1).ok()?;
            self.slots.push(uid);
            let vault_path = self.state_dir.join(uid.to_string()).join("vault.sshvault");
            self.users.insert(
                uid,
                UserState {
                    account,
                    slot,
                    generation: 1,
                    vault_path,
                    open: None,
                    sessions: Sessions::new(),
                },
            );
        }
        self.users.get_mut(&uid)
    }

    fn uid_of_slot(&self, slot: u16) -> Option<u32> {
        self.slots.get(usize::from(slot).checked_sub(1)?).copied()
    }

    /// Saves vaults that have been left alone for a moment, and drops decrypted trees
    /// once no shell of that user is left to use them. A tree that cannot be saved is
    /// kept rather than lost; the next round tries again.
    pub fn prune(&mut self) {
        for user in self.users.values_mut() {
            user.sessions.prune();
            let idle = user
                .open
                .as_ref()
                .and_then(|o| o.changed)
                .is_some_and(|t| t.elapsed() >= SAVE_DELAY);
            if (idle || user.sessions.is_empty()) && user.save_logged() && user.sessions.is_empty()
            {
                user.open = None;
            }
        }
    }

    pub fn save_and_lock_everything(&mut self) {
        for user in self.users.values_mut() {
            user.save_logged();
            user.sessions.clear();
            user.open = None;
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
    Node(&'a UserState, u64, &'a Node),
}

fn errno(e: TreeError) -> Errno {
    match e {
        TreeError::NotFound => Errno::ENOENT,
        TreeError::Exists => Errno::EEXIST,
        TreeError::NotDir => Errno::ENOTDIR,
        TreeError::IsDir => Errno::EISDIR,
        TreeError::NotEmpty => Errno::ENOTEMPTY,
        TreeError::Invalid => Errno::EINVAL,
        TreeError::NoSpace => Errno::ENOSPC,
    }
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
        let (slot, generation, local) = split_ino(ino);
        let user = state.user(state.uid_of_slot(slot)?)?;
        if user.account.uid != req.uid() {
            return None;
        }
        if generation == 0 && local == tree::ROOT {
            return Some(Target::UserDir(user));
        }
        if generation != user.generation {
            return None;
        }
        let node = user.visible(req.pid())?.tree.node(local)?;
        Some(Target::Node(user, local, node))
    }

    /// The caller's tree and the tree inode `ino` names, for a change. Only an
    /// unlocked shell of the owner, or its descendants, may change anything.
    fn writable<'a>(
        &self,
        state: &'a mut State,
        req: &Request,
        ino: u64,
    ) -> Result<(&'a mut UserState, u64), Errno> {
        if ino == ROOT {
            return Err(Errno::EACCES);
        }
        let (slot, generation, local) = split_ino(ino);
        let uid = state.uid_of_slot(slot).ok_or(Errno::ENOENT)?;
        if uid != req.uid() {
            return Err(Errno::ENOENT);
        }
        let user = state.users.get_mut(&uid).ok_or(Errno::ENOENT)?;
        let user_dir = generation == 0 && local == tree::ROOT;
        if !user_dir && generation != user.generation {
            return Err(Errno::ENOENT);
        }
        if user.visible(req.pid()).is_none() {
            return Err(if user_dir {
                Errno::EACCES
            } else {
                Errno::ENOENT
            });
        }
        Ok((user, local))
    }

    fn change<T>(
        &self,
        req: &Request,
        ino: u64,
        save_now: bool,
        f: impl FnOnce(&mut Tree, u64) -> Result<T, TreeError>,
    ) -> Result<(T, u16, u16), Errno> {
        let mut state = lock(&self.state);
        let (user, local) = self.writable(&mut state, req, ino)?;
        let tree = &mut user.open.as_mut().ok_or(Errno::ENOENT)?.tree;
        let out = f(tree, local).map_err(errno)?;
        user.mark_changed();
        if save_now && !user.save_logged() {
            return Err(Errno::EIO);
        }
        Ok((out, user.slot, user.generation))
    }

    /// An entry reply for `local`, looked up again after the change that created it.
    fn entry_for(&self, req: &Request, slot: u16, generation: u16, local: u64) -> Option<FileAttr> {
        let ino = global_ino(slot, generation, local);
        let state = lock(&self.state);
        let target = self.target(&state, req, ino)?;
        Some(self.attr(ino, &target))
    }

    fn attr(&self, ino: u64, target: &Target) -> FileAttr {
        let (kind, perm, size, nlink, uid, gid, mtime) = match target {
            Target::Root => (
                FileType::Directory,
                0o755,
                0,
                2,
                self.owner_uid,
                self.owner_gid,
                self.started,
            ),
            Target::UserDir(user) => (
                FileType::Directory,
                0o700,
                0,
                2,
                user.account.uid,
                user.account.gid,
                self.started,
            ),
            Target::Node(user, _, node) => match &node.kind {
                Kind::File { mode, data } => (
                    FileType::RegularFile,
                    *mode as u16,
                    data.len() as u64,
                    1,
                    user.account.uid,
                    user.account.gid,
                    node.mtime,
                ),
                Kind::Dir { .. } => (
                    FileType::Directory,
                    0o700,
                    0,
                    2,
                    user.account.uid,
                    user.account.gid,
                    node.mtime,
                ),
            },
        };
        FileAttr {
            ino: INodeNo(ino),
            size,
            blocks: size.div_ceil(512),
            atime: mtime,
            mtime,
            ctime: mtime,
            crtime: mtime,
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
        global_ino(user.slot, 0, tree::ROOT)
    }

    fn node_ino(user: &UserState, local: u64) -> u64 {
        if local == tree::ROOT {
            Self::user_dir_ino(user)
        } else {
            global_ino(user.slot, user.generation, local)
        }
    }

    fn reply_entry(
        &self,
        req: &Request,
        result: Result<(u64, u16, u16), Errno>,
        reply: ReplyEntry,
    ) {
        match result {
            Ok((local, slot, generation)) => match self.entry_for(req, slot, generation, local) {
                Some(attr) => reply.entry(&NO_CACHE, &attr, Generation(0)),
                None => reply.error(Errno::ENOENT),
            },
            Err(e) => reply.error(e),
        }
    }

    fn reply_done<T>(result: Result<T, Errno>, reply: ReplyEmpty) {
        match result {
            Ok(_) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    /// The tree inode of `other`, which must be writable and in the same tree as `ino`.
    fn same_tree(&self, req: &Request, ino: u64, other: u64) -> Result<u64, Errno> {
        if other == ROOT || split_ino(other).0 != split_ino(ino).0 {
            return Err(Errno::EXDEV);
        }
        let mut state = lock(&self.state);
        let (_, local) = self.writable(&mut state, req, other)?;
        Ok(local)
    }

    fn save_now(&self, req: &Request, ino: u64) -> Result<(), Errno> {
        let mut state = lock(&self.state);
        let (user, _) = self.writable(&mut state, req, ino)?;
        if user.save_logged() {
            Ok(())
        } else {
            Err(Errno::EIO)
        }
    }
}

impl Filesystem for VaultFs {
    fn lookup(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let mut state = lock(&self.state);
        if parent.0 == ROOT {
            if name != OsStr::new(SELF) || state.user_mut(req.uid()).is_none() {
                return reply.error(Errno::ENOENT);
            }
            let user = state.user(req.uid()).expect("just inserted");
            let ino = Self::user_dir_ino(user);
            return reply.entry(
                &NO_CACHE,
                &self.attr(ino, &Target::UserDir(user)),
                Generation(0),
            );
        }
        let found = match self.target(&state, req, parent.0) {
            Some(Target::UserDir(user)) => Some((user, tree::ROOT)),
            Some(Target::Node(user, local, _)) => Some((user, local)),
            _ => None,
        }
        .and_then(|(user, local)| {
            let tree = &user.visible(req.pid())?.tree;
            let child = tree.child(local, name)?;
            let ino = Self::node_ino(user, child);
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

    fn setattr(
        &self,
        req: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        if uid.is_some_and(|u| u != req.uid()) || gid.is_some() {
            return reply.error(Errno::EPERM);
        }
        let result = self.change(req, ino.0, false, |tree, local| {
            if local == tree::ROOT {
                return Ok(());
            }
            if let Some(mode) = mode {
                tree.set_mode(local, mode)?;
            }
            if let Some(size) = size {
                tree.truncate(local, size)?;
            }
            if let Some(time) = mtime {
                let time = match time {
                    TimeOrNow::SpecificTime(t) => t,
                    TimeOrNow::Now => SystemTime::now(),
                };
                tree.set_mtime(local, time)?;
            }
            Ok(())
        });
        if let Err(e) = result {
            return reply.error(e);
        }
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

    fn mknod(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        _rdev: u32,
        reply: ReplyEntry,
    ) {
        if mode & libc::S_IFMT != libc::S_IFREG {
            return reply.error(Errno::EPERM);
        }
        let result = self.change(req, parent.0, false, |tree, local| {
            tree.create_file(local, name, mode & !umask)
        });
        self.reply_entry(req, result, reply);
    }

    fn mkdir(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let result = self.change(req, parent.0, false, |tree, local| tree.mkdir(local, name));
        self.reply_entry(req, result, reply);
    }

    fn unlink(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        Self::reply_done(
            self.change(req, parent.0, false, |tree, local| tree.unlink(local, name)),
            reply,
        );
    }

    fn rmdir(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        Self::reply_done(
            self.change(req, parent.0, false, |tree, local| tree.rmdir(local, name)),
            reply,
        );
    }

    fn rename(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: RenameFlags,
        reply: ReplyEmpty,
    ) {
        if flags.intersects(RenameFlags::RENAME_EXCHANGE | RenameFlags::RENAME_WHITEOUT) {
            return reply.error(Errno::EINVAL);
        }
        let no_replace = flags.contains(RenameFlags::RENAME_NOREPLACE);
        let new_local = match self.same_tree(req, parent.0, newparent.0) {
            Ok(local) => local,
            Err(e) => return reply.error(e),
        };
        // renaming over a file is how editors save; persist it before reporting success
        let result = self.change(req, parent.0, true, |tree, local| {
            tree.rename(local, name, new_local, newname, no_replace)
        });
        Self::reply_done(result, reply);
    }

    fn link(
        &self,
        req: &Request,
        ino: INodeNo,
        newparent: INodeNo,
        newname: &OsStr,
        reply: ReplyEntry,
    ) {
        let source = match self.same_tree(req, newparent.0, ino.0) {
            Ok(local) => local,
            Err(e) => return reply.error(e),
        };
        let result = self.change(req, newparent.0, false, |tree, local| {
            tree.copy_file(source, local, newname)
        });
        self.reply_entry(req, result, reply);
    }

    fn create(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        let result = self.change(req, parent.0, false, |tree, local| {
            tree.create_file(local, name, mode & !umask)
        });
        match result {
            Ok((local, slot, generation)) => match self.entry_for(req, slot, generation, local) {
                // direct I/O keeps file contents out of the shared page cache
                Some(attr) => reply.created(
                    &NO_CACHE,
                    &attr,
                    Generation(0),
                    FileHandle(0),
                    FopenFlags::FOPEN_DIRECT_IO,
                ),
                None => reply.error(Errno::ENOENT),
            },
            Err(e) => reply.error(e),
        }
    }

    fn open(&self, req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
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

    fn write(
        &self,
        req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        match self.change(req, ino.0, false, |tree, local| {
            tree.write(local, offset, data)
        }) {
            Ok(_) => reply.written(data.len() as u32),
            Err(e) => reply.error(e),
        }
    }

    fn release(
        &self,
        req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        // closing a written file (ssh adding to known_hosts) saves it; a release from a
        // process that is no longer unlocked has nothing it may save
        let _ = self.save_now(req, ino.0);
        reply.ok();
    }

    fn fsync(
        &self,
        req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        Self::reply_done(self.save_now(req, ino.0), reply);
    }

    fn fsyncdir(
        &self,
        req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        Self::reply_done(self.save_now(req, ino.0), reply);
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
        let mut listing: Vec<(u64, FileType, OsString)> = Vec::new();
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
                if let Some(open) = user.visible(req.pid()) {
                    push_children(&mut listing, user, &open.tree, tree::ROOT);
                }
            }
            Some(Target::Node(user, local, node)) => {
                if !matches!(node.kind, Kind::Dir { .. }) {
                    return reply.error(Errno::ENOTDIR);
                }
                listing.push((ino.0, FileType::Directory, ".".into()));
                listing.push((
                    Self::node_ino(user, node.parent),
                    FileType::Directory,
                    "..".into(),
                ));
                if let Some(open) = user.visible(req.pid()) {
                    push_children(&mut listing, user, &open.tree, local);
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
    listing: &mut Vec<(u64, FileType, OsString)>,
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
        listing.push((VaultFs::node_ino(user, child), kind, name.clone()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inode_ranges_do_not_overlap() {
        assert_eq!(split_ino(global_ino(3, 9, 7)), (3, 9, 7));
        assert_ne!(global_ino(1, 0, tree::ROOT), ROOT);
        assert_eq!(split_ino(ROOT), (0, 0, ROOT));
        assert_ne!(global_ino(1, 1, 5), global_ino(1, 2, 5));
    }
}
