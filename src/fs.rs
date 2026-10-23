use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Result, bail};
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

pub const DEFAULT_VAULT: &str = "default";

const VAULT_SUFFIX: &str = ".sshvault";

/// Inodes are the user's slot (12 bits), the vault's index (8 bits), the generation of
/// that vault's tree (12 bits) and the inode within the tree (32 bits). A vault's name
/// is the same path for every user, each getting their own inode there. A new
/// generation, after an import or a fresh unlock, makes inodes from the old tree
/// resolve to nothing instead of to some other file; a vault's own directory outlives
/// its trees and uses generation 0.
fn global_ino(slot: u16, vault: u8, generation: u16, local: u64) -> u64 {
    (u64::from(slot) << 52) | (u64::from(vault) << 44) | (u64::from(generation) << 32) | local
}

fn split_ino(ino: u64) -> (u16, u8, u16, u64) {
    (
        (ino >> 52) as u16,
        (ino >> 44) as u8,
        ((ino >> 32) & 0xfff) as u16,
        ino & 0xffff_ffff,
    )
}

const MAX_SLOT: usize = 0xfff;
const MAX_GENERATION: u16 = 0xfff;

pub fn check_vault_name(name: &str) -> Result<()> {
    let valid = !name.is_empty()
        && name.len() <= 64
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
    if !valid {
        bail!("vault names are up to 64 letters, digits, '.', '_' or '-', not starting with '.'");
    }
    Ok(())
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

pub struct VaultState {
    pub name: String,
    index: u8,
    generation: u16,
    pub path: PathBuf,
    pub open: Option<Unlocked>,
    pub sessions: Sessions<Pidfd>,
}

impl VaultState {
    pub fn unlocked_ancestor(&self, pid: u32) -> Option<u32> {
        self.sessions.unlocked_ancestor(pid, procs::parent_of)
    }

    fn visible(&self, pid: u32) -> Option<&Unlocked> {
        let open = self.open.as_ref()?;
        self.unlocked_ancestor(pid)?;
        Some(open)
    }

    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Replaces what is held in memory; inodes of the previous tree stop resolving.
    pub fn hold(&mut self, unlocked: Unlocked) {
        self.open = Some(unlocked);
        self.generation = if self.generation >= MAX_GENERATION {
            1
        } else {
            self.generation + 1
        };
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
        stored.write(&self.path, false)?;
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
                eprintln!("sshvault: saving {}: {e:#}", self.path.display());
                false
            }
        }
    }

    /// Saves after a moment's quiet, and drops the decrypted tree once no shell is left
    /// to use it. A tree that cannot be saved is kept rather than lost.
    fn prune(&mut self) {
        self.sessions.prune();
        let idle = self
            .open
            .as_ref()
            .and_then(|o| o.changed)
            .is_some_and(|t| t.elapsed() >= SAVE_DELAY);
        if (idle || self.sessions.is_empty()) && self.save_logged() && self.sessions.is_empty() {
            self.open = None;
        }
    }
}

pub struct UserState {
    pub account: Account,
    slot: u16,
    dir: PathBuf,
    vaults: Vec<VaultState>,
}

impl UserState {
    fn new(account: Account, slot: u16, dir: PathBuf) -> UserState {
        // a vault stored before vaults had names becomes the default one
        let unnamed = dir.join("vault.sshvault");
        let default = dir.join(format!("{DEFAULT_VAULT}{VAULT_SUFFIX}"));
        if unnamed.exists() && !default.exists() {
            let _ = std::fs::rename(&unnamed, &default);
        }
        let mut user = UserState {
            account,
            slot,
            dir,
            vaults: Vec::new(),
        };
        user.discover();
        user
    }

    /// Registers vaults present on disk, so that the mount lists them.
    fn discover(&mut self) {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return;
        };
        let mut names: Vec<String> = entries
            .flatten()
            .filter_map(|e| {
                e.file_name()
                    .to_str()?
                    .strip_suffix(VAULT_SUFFIX)
                    .map(str::to_owned)
            })
            .filter(|name| check_vault_name(name).is_ok())
            .collect();
        names.sort();
        for name in names {
            let _ = self.vault_mut(&name);
        }
    }

    pub fn vault(&self, name: &str) -> Option<&VaultState> {
        self.vaults.iter().find(|v| v.name == name)
    }

    /// The vault called `name`, known from now on whether or not it exists yet.
    pub fn vault_mut(&mut self, name: &str) -> Result<&mut VaultState> {
        check_vault_name(name)?;
        if let Some(i) = self.vaults.iter().position(|v| v.name == name) {
            return Ok(&mut self.vaults[i]);
        }
        let Ok(index) = u8::try_from(self.vaults.len() + 1) else {
            bail!("too many vaults");
        };
        self.vaults.push(VaultState {
            name: name.to_owned(),
            index,
            generation: 1,
            path: self.dir.join(format!("{name}{VAULT_SUFFIX}")),
            open: None,
            sessions: Sessions::new(),
        });
        Ok(self.vaults.last_mut().expect("just pushed"))
    }

    fn by_index(&self, index: u8) -> Option<&VaultState> {
        self.vaults.get(usize::from(index).checked_sub(1)?)
    }

    fn by_index_mut(&mut self, index: u8) -> Option<&mut VaultState> {
        self.vaults.get_mut(usize::from(index).checked_sub(1)?)
    }

    pub fn vaults(&self) -> impl Iterator<Item = &VaultState> {
        self.vaults.iter()
    }

    pub fn vaults_mut(&mut self) -> impl Iterator<Item = &mut VaultState> {
        self.vaults.iter_mut()
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
            if self.slots.len() >= MAX_SLOT {
                return None;
            }
            let account = users::by_uid(uid)?;
            self.slots.push(uid);
            let slot = self.slots.len() as u16;
            let dir = self.state_dir.join(uid.to_string());
            self.users.insert(uid, UserState::new(account, slot, dir));
        }
        self.users.get_mut(&uid)
    }

    fn uid_of_slot(&self, slot: u16) -> Option<u32> {
        self.slots.get(usize::from(slot).checked_sub(1)?).copied()
    }

    pub fn prune(&mut self) {
        for user in self.users.values_mut() {
            for vault in &mut user.vaults {
                vault.prune();
            }
        }
    }

    pub fn save_and_lock_everything(&mut self) {
        for vault in self.users.values_mut().flat_map(|u| u.vaults.iter_mut()) {
            vault.save_logged();
            vault.sessions.clear();
            vault.open = None;
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
    VaultDir(&'a UserState, &'a VaultState),
    Node(&'a UserState, &'a VaultState, u64, &'a Node),
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
        let (slot, index, generation, local) = split_ino(ino);
        let user = state.user(state.uid_of_slot(slot)?)?;
        if user.account.uid != req.uid() {
            return None;
        }
        let vault = user.by_index(index)?;
        if generation == 0 && local == tree::ROOT {
            return vault.exists().then_some(Target::VaultDir(user, vault));
        }
        if generation != vault.generation {
            return None;
        }
        let node = vault.visible(req.pid())?.tree.node(local)?;
        Some(Target::Node(user, vault, local, node))
    }

    /// The vault and tree inode `ino` names, for a change. Only an unlocked shell of the
    /// owner, or its descendants, may change anything in that vault.
    fn writable<'a>(
        &self,
        state: &'a mut State,
        req: &Request,
        ino: u64,
    ) -> Result<(&'a mut VaultState, u64), Errno> {
        if ino == ROOT {
            return Err(Errno::EACCES);
        }
        let (slot, index, generation, local) = split_ino(ino);
        let uid = state.uid_of_slot(slot).ok_or(Errno::ENOENT)?;
        if uid != req.uid() {
            return Err(Errno::ENOENT);
        }
        if index == 0 {
            return Err(Errno::EACCES);
        }
        let user = state.users.get_mut(&uid).ok_or(Errno::ENOENT)?;
        let vault = user.by_index_mut(index).ok_or(Errno::ENOENT)?;
        let vault_dir = generation == 0 && local == tree::ROOT;
        if !vault_dir && generation != vault.generation {
            return Err(Errno::ENOENT);
        }
        if vault.visible(req.pid()).is_none() {
            return Err(if vault_dir {
                Errno::EACCES
            } else {
                Errno::ENOENT
            });
        }
        Ok((vault, local))
    }

    fn change<T>(
        &self,
        req: &Request,
        ino: u64,
        save_now: bool,
        f: impl FnOnce(&mut Tree, u64) -> Result<T, TreeError>,
    ) -> Result<(T, u64), Errno> {
        let mut state = lock(&self.state);
        let slot = split_ino(ino).0;
        let (vault, local) = self.writable(&mut state, req, ino)?;
        let tree = &mut vault.open.as_mut().ok_or(Errno::ENOENT)?.tree;
        let out = f(tree, local).map_err(errno)?;
        vault.mark_changed();
        if save_now && !vault.save_logged() {
            return Err(Errno::EIO);
        }
        let base = global_ino(slot, vault.index, vault.generation, 0);
        Ok((out, base))
    }

    /// The tree inode of `other`, which must be writable and in the same vault as `ino`.
    fn same_vault(&self, req: &Request, ino: u64, other: u64) -> Result<u64, Errno> {
        let (slot, index, ..) = split_ino(ino);
        let (other_slot, other_index, ..) = split_ino(other);
        if other == ROOT || other_slot != slot || other_index != index || index == 0 {
            return Err(Errno::EXDEV);
        }
        let mut state = lock(&self.state);
        let (_, local) = self.writable(&mut state, req, other)?;
        Ok(local)
    }

    fn save_now(&self, req: &Request, ino: u64) -> Result<(), Errno> {
        let mut state = lock(&self.state);
        let (vault, _) = self.writable(&mut state, req, ino)?;
        if vault.save_logged() {
            Ok(())
        } else {
            Err(Errno::EIO)
        }
    }

    fn attr(&self, ino: u64, target: &Target) -> FileAttr {
        let dir = |uid, gid, perm, mtime| (FileType::Directory, perm, 0, 2, uid, gid, mtime);
        let (kind, perm, size, nlink, uid, gid, mtime) = match target {
            Target::Root => dir(self.owner_uid, self.owner_gid, 0o755, self.started),
            Target::VaultDir(user, _) => {
                dir(user.account.uid, user.account.gid, 0o700, self.started)
            }
            Target::Node(user, _, _, node) => match &node.kind {
                Kind::File { mode, data } => (
                    FileType::RegularFile,
                    *mode as u16,
                    data.len() as u64,
                    1,
                    user.account.uid,
                    user.account.gid,
                    node.mtime,
                ),
                Kind::Dir { .. } => dir(user.account.uid, user.account.gid, 0o700, node.mtime),
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

    fn node_ino(user: &UserState, vault: &VaultState, local: u64) -> u64 {
        if local == tree::ROOT {
            global_ino(user.slot, vault.index, 0, tree::ROOT)
        } else {
            global_ino(user.slot, vault.index, vault.generation, local)
        }
    }

    /// An entry reply for the tree inode `local` of the vault `base` belongs to.
    fn reply_entry(&self, req: &Request, result: Result<(u64, u64), Errno>, reply: ReplyEntry) {
        match result.and_then(|(local, base)| self.entry_attr(req, base | local)) {
            Ok(attr) => reply.entry(&NO_CACHE, &attr, Generation(0)),
            Err(e) => reply.error(e),
        }
    }

    fn entry_attr(&self, req: &Request, ino: u64) -> Result<FileAttr, Errno> {
        let state = lock(&self.state);
        let target = self.target(&state, req, ino).ok_or(Errno::ENOENT)?;
        Ok(self.attr(ino, &target))
    }

    fn reply_done<T>(result: Result<T, Errno>, reply: ReplyEmpty) {
        match result {
            Ok(_) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }
}

impl Filesystem for VaultFs {
    fn lookup(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let mut state = lock(&self.state);
        if parent.0 == ROOT {
            state.user_mut(req.uid());
        }
        let found = match self.target(&state, req, parent.0) {
            Some(Target::Root) => state
                .user(req.uid())
                .and_then(|user| Some((user, user.vault(name.to_str()?)?)))
                .filter(|(_, vault)| vault.exists())
                .map(|(user, vault)| {
                    let ino = Self::node_ino(user, vault, tree::ROOT);
                    self.attr(ino, &Target::VaultDir(user, vault))
                }),
            Some(Target::VaultDir(user, vault)) => {
                self.child_attr(req, user, vault, tree::ROOT, name)
            }
            Some(Target::Node(user, vault, local, _)) => {
                self.child_attr(req, user, vault, local, name)
            }
            _ => None,
        };
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
        match result.and_then(|_| self.entry_attr(req, ino.0)) {
            Ok(attr) => reply.attr(&NO_CACHE, &attr),
            Err(e) => reply.error(e),
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
        let new_local = match self.same_vault(req, parent.0, newparent.0) {
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
        let source = match self.same_vault(req, newparent.0, ino.0) {
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
        match result.and_then(|(local, base)| self.entry_attr(req, base | local)) {
            // direct I/O keeps file contents out of the shared page cache
            Ok(attr) => reply.created(
                &NO_CACHE,
                &attr,
                Generation(0),
                FileHandle(0),
                FopenFlags::FOPEN_DIRECT_IO,
            ),
            Err(e) => reply.error(e),
        }
    }

    fn open(&self, req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        let state = lock(&self.state);
        match self.target(&state, req, ino.0) {
            // direct I/O keeps file contents out of the shared page cache
            Some(Target::Node(.., node)) if matches!(node.kind, Kind::File { .. }) => {
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
        let Some(Target::Node(.., node)) = self.target(&state, req, ino.0) else {
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
            Some(Target::Node(.., node)) if matches!(node.kind, Kind::File { .. }) => {
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
        if ino.0 == ROOT
            && let Some(user) = state.user_mut(req.uid())
        {
            user.discover();
        }
        let dots = |this: u64, parent: u64| -> Vec<(u64, FileType, OsString)> {
            vec![
                (this, FileType::Directory, ".".into()),
                (parent, FileType::Directory, "..".into()),
            ]
        };
        let mut listing;
        match self.target(&state, req, ino.0) {
            Some(Target::Root) => {
                listing = dots(ROOT, ROOT);
                if let Some(user) = state.user(req.uid()) {
                    for vault in user.vaults().filter(|v| v.exists()) {
                        let ino = Self::node_ino(user, vault, tree::ROOT);
                        listing.push((ino, FileType::Directory, vault.name.clone().into()));
                    }
                }
            }
            Some(Target::VaultDir(user, vault)) => {
                listing = dots(ino.0, ROOT);
                if let Some(open) = vault.visible(req.pid()) {
                    push_children(&mut listing, user, vault, &open.tree, tree::ROOT);
                }
            }
            Some(Target::Node(user, vault, local, node)) => {
                if !matches!(node.kind, Kind::Dir { .. }) {
                    return reply.error(Errno::ENOTDIR);
                }
                listing = dots(ino.0, Self::node_ino(user, vault, node.parent));
                if let Some(open) = vault.visible(req.pid()) {
                    push_children(&mut listing, user, vault, &open.tree, local);
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

impl VaultFs {
    fn child_attr(
        &self,
        req: &Request,
        user: &UserState,
        vault: &VaultState,
        dir: u64,
        name: &OsStr,
    ) -> Option<FileAttr> {
        let tree = &vault.visible(req.pid())?.tree;
        let child = tree.child(dir, name)?;
        let ino = Self::node_ino(user, vault, child);
        Some(self.attr(ino, &Target::Node(user, vault, child, tree.node(child)?)))
    }
}

fn push_children(
    listing: &mut Vec<(u64, FileType, OsString)>,
    user: &UserState,
    vault: &VaultState,
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
        listing.push((VaultFs::node_ino(user, vault, child), kind, name.clone()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inode_ranges_do_not_overlap() {
        assert_eq!(split_ino(global_ino(3, 2, 9, 7)), (3, 2, 9, 7));
        assert_eq!(
            split_ino(global_ino(0xfff, 0xff, 0xfff, 0xffff_ffff)),
            (0xfff, 0xff, 0xfff, 0xffff_ffff)
        );
        assert_ne!(global_ino(1, 1, 0, tree::ROOT), ROOT);
        assert_eq!(split_ino(ROOT), (0, 0, 0, ROOT));
        assert_ne!(global_ino(1, 1, 1, 5), global_ino(1, 2, 1, 5));
        assert_ne!(global_ino(1, 1, 1, 5), global_ino(1, 1, 2, 5));
    }

    #[test]
    fn vault_names_are_plain() {
        for good in ["default", "work", "prod-eu.1", "a_b"] {
            assert!(check_vault_name(good).is_ok(), "{good}");
        }
        for bad in ["", ".hidden", "a/b", "..", "with space", &"x".repeat(65)] {
            assert!(check_vault_name(bad).is_err(), "{bad}");
        }
    }
}
