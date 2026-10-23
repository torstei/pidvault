use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Result, bail};

use crate::secret::{MAX_SECRET, SecretBuf};

pub const ROOT: u64 = 1;

/// The decrypted vault, held only in memory. Inode numbers are index + 1; removed
/// entries leave a hole so an inode is never reused for a different file.
pub struct Tree {
    nodes: Vec<Option<Node>>,
}

pub struct Node {
    pub parent: u64,
    pub mtime: SystemTime,
    pub kind: Kind,
}

pub enum Kind {
    Dir { entries: BTreeMap<OsString, u64> },
    File { mode: u32, data: SecretBuf },
}

#[derive(Debug)]
pub enum TreeError {
    NotFound,
    Exists,
    NotDir,
    IsDir,
    NotEmpty,
    Invalid,
    NoSpace,
}

type TreeResult<T> = std::result::Result<T, TreeError>;

/// tar spends a 512-byte header per entry and pads data to 512 bytes.
const TAR_BLOCK: usize = 512;

impl Tree {
    pub fn empty() -> Tree {
        Tree {
            nodes: vec![Some(Node {
                parent: ROOT,
                mtime: SystemTime::now(),
                kind: Kind::Dir {
                    entries: BTreeMap::new(),
                },
            })],
        }
    }

    pub fn node(&self, ino: u64) -> Option<&Node> {
        let index = usize::try_from(ino.checked_sub(1)?).ok()?;
        self.nodes.get(index)?.as_ref()
    }

    fn node_mut(&mut self, ino: u64) -> TreeResult<&mut Node> {
        let index = usize::try_from(ino.checked_sub(1).ok_or(TreeError::NotFound)?)
            .map_err(|_| TreeError::NotFound)?;
        self.nodes
            .get_mut(index)
            .and_then(Option::as_mut)
            .ok_or(TreeError::NotFound)
    }

    pub fn child(&self, parent: u64, name: &OsStr) -> Option<u64> {
        match &self.node(parent)?.kind {
            Kind::Dir { entries } => entries.get(name).copied(),
            Kind::File { .. } => None,
        }
    }

    pub fn file_count(&self) -> usize {
        self.live()
            .filter(|(_, n)| matches!(n.kind, Kind::File { .. }))
            .count()
    }

    fn live(&self) -> impl Iterator<Item = (u64, &Node)> {
        self.nodes
            .iter()
            .enumerate()
            .filter_map(|(i, n)| Some((i as u64 + 1, n.as_ref()?)))
    }

    /// What `to_tar` would produce, so the vault never outgrows what can be saved.
    fn archive_size(&self) -> usize {
        self.live()
            .map(|(_, n)| match &n.kind {
                Kind::File { data, .. } => TAR_BLOCK + data.len().div_ceil(TAR_BLOCK) * TAR_BLOCK,
                Kind::Dir { .. } => TAR_BLOCK,
            })
            .sum::<usize>()
            + 2 * TAR_BLOCK
    }

    fn check_space(&self, extra: usize) -> TreeResult<()> {
        if self.archive_size() + extra > MAX_SECRET {
            return Err(TreeError::NoSpace);
        }
        Ok(())
    }

    fn entries_mut(&mut self, dir: u64) -> TreeResult<&mut BTreeMap<OsString, u64>> {
        match &mut self.node_mut(dir)?.kind {
            Kind::Dir { entries } => Ok(entries),
            Kind::File { .. } => Err(TreeError::NotDir),
        }
    }

    fn touch_dir(&mut self, dir: u64) {
        if let Ok(node) = self.node_mut(dir) {
            node.mtime = SystemTime::now();
        }
    }

    fn insert(&mut self, parent: u64, name: &OsStr, kind: Kind) -> TreeResult<u64> {
        if name.is_empty() || name == "." || name == ".." || name.as_encoded_bytes().contains(&b'/')
        {
            return Err(TreeError::Invalid);
        }
        self.check_space(TAR_BLOCK)?;
        let ino = self.nodes.len() as u64 + 1;
        let entries = self.entries_mut(parent)?;
        if entries.contains_key(name) {
            return Err(TreeError::Exists);
        }
        entries.insert(name.to_os_string(), ino);
        self.nodes.push(Some(Node {
            parent,
            mtime: SystemTime::now(),
            kind,
        }));
        self.touch_dir(parent);
        Ok(ino)
    }

    pub fn create_file(&mut self, parent: u64, name: &OsStr, mode: u32) -> TreeResult<u64> {
        let data = SecretBuf::with_capacity(0).map_err(|_| TreeError::NoSpace)?;
        self.insert(parent, name, file(mode, data))
    }

    pub fn mkdir(&mut self, parent: u64, name: &OsStr) -> TreeResult<u64> {
        self.insert(
            parent,
            name,
            Kind::Dir {
                entries: BTreeMap::new(),
            },
        )
    }

    /// A copy, not a second name for the same inode: the tree has no link counts.
    pub fn copy_file(&mut self, ino: u64, parent: u64, name: &OsStr) -> TreeResult<u64> {
        let (mode, data) = match &self.node(ino).ok_or(TreeError::NotFound)?.kind {
            Kind::File { mode, data } => (*mode, data),
            Kind::Dir { .. } => return Err(TreeError::IsDir),
        };
        self.check_space(TAR_BLOCK + data.len())?;
        let data = data.try_clone().map_err(|_| TreeError::NoSpace)?;
        self.insert(parent, name, file(mode, data))
    }

    pub fn unlink(&mut self, parent: u64, name: &OsStr) -> TreeResult<()> {
        let ino = self.child(parent, name).ok_or(TreeError::NotFound)?;
        if matches!(self.node(ino).map(|n| &n.kind), Some(Kind::Dir { .. })) {
            return Err(TreeError::IsDir);
        }
        self.detach(parent, name, ino)
    }

    pub fn rmdir(&mut self, parent: u64, name: &OsStr) -> TreeResult<()> {
        let ino = self.child(parent, name).ok_or(TreeError::NotFound)?;
        match &self.node(ino).ok_or(TreeError::NotFound)?.kind {
            Kind::Dir { entries } if entries.is_empty() => self.detach(parent, name, ino),
            Kind::Dir { .. } => Err(TreeError::NotEmpty),
            Kind::File { .. } => Err(TreeError::NotDir),
        }
    }

    fn detach(&mut self, parent: u64, name: &OsStr, ino: u64) -> TreeResult<()> {
        self.entries_mut(parent)?.remove(name);
        self.touch_dir(parent);
        self.nodes[(ino - 1) as usize] = None;
        Ok(())
    }

    fn is_within(&self, mut ino: u64, ancestor: u64) -> bool {
        loop {
            if ino == ancestor {
                return true;
            }
            match self.node(ino) {
                Some(node) if ino != ROOT => ino = node.parent,
                _ => return false,
            }
        }
    }

    pub fn rename(
        &mut self,
        parent: u64,
        name: &OsStr,
        new_parent: u64,
        new_name: &OsStr,
        no_replace: bool,
    ) -> TreeResult<()> {
        let ino = self.child(parent, name).ok_or(TreeError::NotFound)?;
        if !matches!(
            self.node(new_parent).map(|n| &n.kind),
            Some(Kind::Dir { .. })
        ) {
            return Err(TreeError::NotDir);
        }
        let moving_dir = matches!(self.node(ino).map(|n| &n.kind), Some(Kind::Dir { .. }));
        if moving_dir && self.is_within(new_parent, ino) {
            return Err(TreeError::Invalid);
        }
        if new_name.is_empty() || new_name == "." || new_name == ".." {
            return Err(TreeError::Invalid);
        }
        if let Some(target) = self.child(new_parent, new_name) {
            if target == ino {
                return Ok(());
            }
            if no_replace {
                return Err(TreeError::Exists);
            }
            match (
                &self.node(target).ok_or(TreeError::NotFound)?.kind,
                moving_dir,
            ) {
                (Kind::Dir { entries }, true) if entries.is_empty() => {}
                (Kind::Dir { .. }, true) => return Err(TreeError::NotEmpty),
                (Kind::Dir { .. }, false) => return Err(TreeError::IsDir),
                (Kind::File { .. }, true) => return Err(TreeError::NotDir),
                (Kind::File { .. }, false) => {}
            }
            self.nodes[(target - 1) as usize] = None;
        }
        self.entries_mut(parent)?.remove(name);
        self.entries_mut(new_parent)?
            .insert(new_name.to_os_string(), ino);
        self.node_mut(ino)?.parent = new_parent;
        self.touch_dir(parent);
        self.touch_dir(new_parent);
        Ok(())
    }

    fn file_mut(&mut self, ino: u64) -> TreeResult<(&mut SecretBuf, &mut SystemTime)> {
        let node = self.node_mut(ino)?;
        match &mut node.kind {
            Kind::File { data, .. } => Ok((data, &mut node.mtime)),
            Kind::Dir { .. } => Err(TreeError::IsDir),
        }
    }

    pub fn write(&mut self, ino: u64, offset: u64, bytes: &[u8]) -> TreeResult<()> {
        let offset = usize::try_from(offset).map_err(|_| TreeError::NoSpace)?;
        let current = match &self.node(ino).ok_or(TreeError::NotFound)?.kind {
            Kind::File { data, .. } => data.len(),
            Kind::Dir { .. } => return Err(TreeError::IsDir),
        };
        let end = offset.checked_add(bytes.len()).ok_or(TreeError::NoSpace)?;
        self.check_space(end.saturating_sub(current))?;
        let (data, mtime) = self.file_mut(ino)?;
        data.write_at(offset, bytes)
            .map_err(|_| TreeError::NoSpace)?;
        *mtime = SystemTime::now();
        Ok(())
    }

    pub fn truncate(&mut self, ino: u64, len: u64) -> TreeResult<()> {
        let len = usize::try_from(len).map_err(|_| TreeError::NoSpace)?;
        let current = match &self.node(ino).ok_or(TreeError::NotFound)?.kind {
            Kind::File { data, .. } => data.len(),
            Kind::Dir { .. } => return Err(TreeError::IsDir),
        };
        self.check_space(len.saturating_sub(current))?;
        let (data, mtime) = self.file_mut(ino)?;
        data.truncate(len).map_err(|_| TreeError::NoSpace)?;
        *mtime = SystemTime::now();
        Ok(())
    }

    pub fn set_mode(&mut self, ino: u64, new_mode: u32) -> TreeResult<()> {
        if let Kind::File { mode, .. } = &mut self.node_mut(ino)?.kind {
            *mode = new_mode & 0o700;
        }
        Ok(())
    }

    pub fn set_mtime(&mut self, ino: u64, time: SystemTime) -> TreeResult<()> {
        self.node_mut(ino)?.mtime = time;
        Ok(())
    }

    fn dir_for(&mut self, path: &Path) -> Result<u64> {
        let mut ino = ROOT;
        for name in normal_components(path)? {
            ino = match self.child(ino, &name) {
                Some(existing)
                    if matches!(self.node(existing).map(|n| &n.kind), Some(Kind::Dir { .. })) =>
                {
                    existing
                }
                Some(_) => bail!("{} is both a file and a directory", path.display()),
                None => self
                    .mkdir(ino, &name)
                    .map_err(|e| anyhow::anyhow!("{}: {e:?}", path.display()))?,
            };
        }
        Ok(ino)
    }

    pub fn from_tar(bytes: &[u8]) -> Result<Tree> {
        let mut tree = Tree::empty();
        let mut archive = tar::Archive::new(bytes);
        for entry in archive.entries()? {
            let mut entry = entry?;
            let path = entry.path()?.into_owned();
            let mtime =
                UNIX_EPOCH + std::time::Duration::from_secs(entry.header().mtime().unwrap_or(0));
            match entry.header().entry_type() {
                tar::EntryType::Directory => {
                    let ino = tree.dir_for(&path)?;
                    let _ = tree.set_mtime(ino, mtime);
                }
                tar::EntryType::Regular => {
                    let Some(name) = path.file_name().map(OsStr::to_os_string) else {
                        bail!("file entry without a name: {}", path.display());
                    };
                    let parent = tree.dir_for(path.parent().unwrap_or(Path::new("")))?;
                    let mode = entry.header().mode()?;
                    let size = usize::try_from(entry.size())?;
                    let data = SecretBuf::from_reader(&mut entry, size)?;
                    tree.check_space(TAR_BLOCK + data.len())
                        .map_err(|_| anyhow::anyhow!("vault larger than {MAX_SECRET} bytes"))?;
                    let ino = tree
                        .insert(parent, &name, file(mode, data))
                        .map_err(|e| anyhow::anyhow!("{}: {e:?}", path.display()))?;
                    let _ = tree.set_mtime(ino, mtime);
                }
                other => bail!("unsupported entry type {other:?} for {}", path.display()),
            }
        }
        Ok(tree)
    }

    /// The tree as a tar archive, built in locked memory.
    pub fn to_tar(&self) -> Result<SecretBuf> {
        let mut builder = tar::Builder::new(SecretBuf::with_capacity(self.archive_size())?);
        let mut pending = vec![(ROOT, PathBuf::new())];
        while let Some((dir, path)) = pending.pop() {
            let Some(Node {
                kind: Kind::Dir { entries },
                ..
            }) = self.node(dir)
            else {
                continue;
            };
            for (name, &child) in entries {
                let Some(node) = self.node(child) else {
                    continue;
                };
                let child_path = path.join(name);
                let mut header = tar::Header::new_gnu();
                header.set_mtime(
                    node.mtime
                        .duration_since(UNIX_EPOCH)
                        .map_or(0, |d| d.as_secs()),
                );
                match &node.kind {
                    Kind::Dir { .. } => {
                        header.set_entry_type(tar::EntryType::Directory);
                        header.set_mode(0o700);
                        header.set_size(0);
                        builder.append_data(&mut header, &child_path, std::io::empty())?;
                        pending.push((child, child_path));
                    }
                    Kind::File { mode, data } => {
                        header.set_entry_type(tar::EntryType::Regular);
                        header.set_mode(*mode);
                        header.set_size(data.len() as u64);
                        builder.append_data(&mut header, &child_path, &data[..])?;
                    }
                }
            }
        }
        Ok(builder.into_inner()?)
    }
}

fn file(mode: u32, data: SecretBuf) -> Kind {
    // group/other bits would make ssh refuse private keys
    Kind::File {
        mode: mode & 0o700,
        data,
    }
}

fn normal_components(path: &Path) -> Result<Vec<OsString>> {
    let mut names = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(name) => names.push(name.to_os_string()),
            Component::CurDir => {}
            _ => bail!("refusing path {} in vault", path.display()),
        }
    }
    Ok(names)
}

#[cfg(test)]
pub fn read_file(tree: &Tree, path: &[&str]) -> Option<(u32, Vec<u8>)> {
    let mut ino = ROOT;
    for name in path {
        ino = tree.child(ino, OsStr::new(name))?;
    }
    match &tree.node(ino)?.kind {
        Kind::File { mode, data } => Some((*mode, data.to_vec())),
        Kind::Dir { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(s: &str) -> &OsStr {
        OsStr::new(s)
    }

    fn with_config() -> (Tree, u64) {
        let mut tree = Tree::empty();
        let ino = tree.create_file(ROOT, name("config"), 0o644).unwrap();
        tree.write(ino, 0, b"Host x\n").unwrap();
        (tree, ino)
    }

    #[test]
    fn files_are_created_with_owner_bits_only() {
        let (tree, _) = with_config();
        assert_eq!(
            read_file(&tree, &["config"]).unwrap(),
            (0o600, b"Host x\n".to_vec())
        );
    }

    #[test]
    fn editor_style_save_replaces_the_file() {
        let (mut tree, _) = with_config();
        let tmp = tree.create_file(ROOT, name(".config.tmp"), 0o600).unwrap();
        tree.write(tmp, 0, b"Host y\n").unwrap();
        tree.rename(ROOT, name(".config.tmp"), ROOT, name("config"), false)
            .unwrap();
        assert_eq!(read_file(&tree, &["config"]).unwrap().1, b"Host y\n");
        assert!(tree.child(ROOT, name(".config.tmp")).is_none());
        assert_eq!(tree.file_count(), 1);
    }

    #[test]
    fn append_and_truncate() {
        let (mut tree, ino) = with_config();
        tree.write(ino, 7, b"  User u\n").unwrap();
        assert_eq!(
            read_file(&tree, &["config"]).unwrap().1,
            b"Host x\n  User u\n"
        );
        tree.truncate(ino, 4).unwrap();
        assert_eq!(read_file(&tree, &["config"]).unwrap().1, b"Host");
    }

    #[test]
    fn directories_must_be_empty_to_remove() {
        let mut tree = Tree::empty();
        let dir = tree.mkdir(ROOT, name("keys")).unwrap();
        tree.create_file(dir, name("id"), 0o600).unwrap();
        assert!(matches!(
            tree.rmdir(ROOT, name("keys")),
            Err(TreeError::NotEmpty)
        ));
        tree.unlink(dir, name("id")).unwrap();
        tree.rmdir(ROOT, name("keys")).unwrap();
        assert!(tree.child(ROOT, name("keys")).is_none());
    }

    #[test]
    fn a_directory_cannot_move_into_itself() {
        let mut tree = Tree::empty();
        let a = tree.mkdir(ROOT, name("a")).unwrap();
        let b = tree.mkdir(a, name("b")).unwrap();
        assert!(matches!(
            tree.rename(ROOT, name("a"), b, name("a"), false),
            Err(TreeError::Invalid)
        ));
    }

    #[test]
    fn no_replace_rename_refuses_an_existing_target() {
        let (mut tree, _) = with_config();
        tree.create_file(ROOT, name("other"), 0o600).unwrap();
        assert!(matches!(
            tree.rename(ROOT, name("other"), ROOT, name("config"), true),
            Err(TreeError::Exists)
        ));
    }

    #[test]
    fn removed_inodes_are_never_reused() {
        let (mut tree, ino) = with_config();
        tree.unlink(ROOT, name("config")).unwrap();
        assert!(tree.node(ino).is_none());
        let again = tree.create_file(ROOT, name("config"), 0o600).unwrap();
        assert_ne!(again, ino);
    }

    #[test]
    fn copies_are_independent() {
        let (mut tree, ino) = with_config();
        let copy = tree.copy_file(ino, ROOT, name("config.old")).unwrap();
        tree.truncate(ino, 0).unwrap();
        assert_eq!(read_file(&tree, &["config.old"]).unwrap().1, b"Host x\n");
        assert_ne!(copy, ino);
    }

    #[test]
    fn the_vault_cannot_outgrow_what_can_be_saved() {
        let (mut tree, ino) = with_config();
        assert!(matches!(
            tree.write(ino, MAX_SECRET as u64, b"x"),
            Err(TreeError::NoSpace)
        ));
        assert!(matches!(
            tree.truncate(ino, MAX_SECRET as u64),
            Err(TreeError::NoSpace)
        ));
    }

    #[test]
    fn tar_round_trip_keeps_files_dirs_and_modes() {
        let (mut tree, _) = with_config();
        let keys = tree.mkdir(ROOT, name("keys")).unwrap();
        let key = tree.create_file(keys, name("id"), 0o400).unwrap();
        tree.write(key, 0, b"PRIVATE").unwrap();
        tree.mkdir(ROOT, name("empty")).unwrap();

        let back = Tree::from_tar(&tree.to_tar().unwrap()).unwrap();
        assert_eq!(read_file(&back, &["config"]).unwrap().1, b"Host x\n");
        assert_eq!(
            read_file(&back, &["keys", "id"]).unwrap(),
            (0o400, b"PRIVATE".to_vec())
        );
        assert!(back.child(ROOT, name("empty")).is_some());
    }

    #[test]
    fn rejects_parent_traversal() {
        let mut header = tar::Header::new_gnu();
        header.set_size(1);
        header.set_mode(0o600);
        header.set_entry_type(tar::EntryType::Regular);
        let path = b"../escape";
        header.as_old_mut().name[..path.len()].copy_from_slice(path);
        header.set_cksum();
        let mut builder = tar::Builder::new(Vec::new());
        builder.append(&header, &b"x"[..]).unwrap();
        assert!(Tree::from_tar(&builder.into_inner().unwrap()).is_err());
    }
}
