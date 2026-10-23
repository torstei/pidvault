use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

use age::secrecy::SecretString;
use anyhow::{Context, Result, bail};
use zeroize::Zeroizing;

use crate::secret::SecretBuf;

pub const ROOT: u64 = 1;

/// The decrypted vault, held only in memory. Inode numbers are index + 1.
pub struct Tree {
    nodes: Vec<Node>,
}

pub struct Node {
    pub parent: u64,
    pub kind: Kind,
}

pub enum Kind {
    Dir { entries: BTreeMap<OsString, u64> },
    File { mode: u32, data: SecretBuf },
}

impl Tree {
    pub fn empty() -> Tree {
        Tree {
            nodes: vec![Node {
                parent: ROOT,
                kind: Kind::Dir {
                    entries: BTreeMap::new(),
                },
            }],
        }
    }

    pub fn node(&self, ino: u64) -> Option<&Node> {
        let index = usize::try_from(ino.checked_sub(1)?).ok()?;
        self.nodes.get(index)
    }

    pub fn child(&self, parent: u64, name: &OsStr) -> Option<u64> {
        match &self.node(parent)?.kind {
            Kind::Dir { entries } => entries.get(name).copied(),
            Kind::File { .. } => None,
        }
    }

    pub fn file_count(&self) -> usize {
        self.nodes
            .iter()
            .filter(|n| matches!(n.kind, Kind::File { .. }))
            .count()
    }

    fn insert(&mut self, parent: u64, name: OsString, kind: Kind) -> Result<u64> {
        let ino = self.nodes.len() as u64 + 1;
        let Kind::Dir { entries } = &mut self.nodes[(parent - 1) as usize].kind else {
            bail!("{} is inside a file", name.to_string_lossy());
        };
        if entries.contains_key(&name) {
            bail!("duplicate entry {}", name.to_string_lossy());
        }
        entries.insert(name, ino);
        self.nodes.push(Node { parent, kind });
        Ok(ino)
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
                None => self.insert(
                    ino,
                    name,
                    Kind::Dir {
                        entries: BTreeMap::new(),
                    },
                )?,
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
            match entry.header().entry_type() {
                tar::EntryType::Directory => {
                    tree.dir_for(&path)?;
                }
                tar::EntryType::Regular => {
                    let Some(name) = path.file_name().map(OsStr::to_os_string) else {
                        bail!("file entry without a name: {}", path.display());
                    };
                    let parent = tree.dir_for(path.parent().unwrap_or(Path::new("")))?;
                    // group/other bits would make ssh refuse private keys
                    let mode = entry.header().mode()? & 0o700;
                    let size = usize::try_from(entry.size())?;
                    let data = SecretBuf::from_reader(&mut entry, size)?;
                    tree.insert(parent, name, Kind::File { mode, data })?;
                }
                other => bail!("unsupported entry type {other:?} for {}", path.display()),
            }
        }
        Ok(tree)
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

/// Archives the regular files and directories below `dir`, following symlinks.
/// Anything else (sockets, fifos, devices) is left out and returned.
pub fn pack_dir(dir: &Path) -> Result<(Zeroizing<Vec<u8>>, Vec<PathBuf>)> {
    let mut builder = tar::Builder::new(Vec::new());
    let mut skipped = Vec::new();
    let mut pending = vec![PathBuf::new()];
    while let Some(rel) = pending.pop() {
        let full = dir.join(&rel);
        let mut children: Vec<_> = std::fs::read_dir(&full)
            .with_context(|| format!("reading {}", full.display()))?
            .collect::<std::io::Result<_>>()?;
        children.sort_by_key(|e| e.file_name());
        for child in children {
            let rel_child = rel.join(child.file_name());
            let meta = std::fs::metadata(child.path())?;
            if meta.is_dir() {
                builder.append_dir(&rel_child, child.path())?;
                pending.push(rel_child);
            } else if meta.is_file() {
                builder.append_path_with_name(child.path(), &rel_child)?;
            } else {
                skipped.push(rel_child);
            }
        }
    }
    Ok((Zeroizing::new(builder.into_inner()?), skipped))
}

/// Encrypts `dir` into a vault, returning it with the paths that were left out.
pub fn seal(
    dir: &Path,
    passphrase: SecretString,
    work_factor: Option<u8>,
) -> Result<(Vec<u8>, Vec<PathBuf>)> {
    let (plain, skipped) = pack_dir(dir)?;
    Tree::from_tar(&plain).context("directory cannot be represented in a vault")?;
    Ok((encrypt(&plain, passphrase, work_factor)?, skipped))
}

pub fn encrypt(
    plaintext: &[u8],
    passphrase: SecretString,
    work_factor: Option<u8>,
) -> Result<Vec<u8>> {
    let mut recipient = age::scrypt::Recipient::new(passphrase);
    if let Some(log_n) = work_factor {
        recipient.set_work_factor(log_n);
    }
    let encryptor = age::Encryptor::with_recipients(std::iter::once(&recipient as _))?;
    let mut out = Vec::new();
    let mut writer = encryptor.wrap_output(&mut out)?;
    writer.write_all(plaintext)?;
    writer.finish()?;
    Ok(out)
}

pub fn decrypt(ciphertext: &[u8], passphrase: SecretString) -> Result<SecretBuf> {
    let identity = age::scrypt::Identity::new(passphrase);
    let decryptor = age::Decryptor::new(ciphertext)?;
    let reader = decryptor
        .decrypt(std::iter::once(&identity as _))
        .map_err(|e| anyhow::anyhow!("cannot open vault: {e}"))?;
    Ok(SecretBuf::from_reader(reader, ciphertext.len())?)
}

pub fn open(vault: &Path, passphrase: SecretString) -> Result<Tree> {
    let ciphertext =
        std::fs::read(vault).with_context(|| format!("reading {}", vault.display()))?;
    Tree::from_tar(&decrypt(&ciphertext, passphrase)?)
}

/// Accepts only passphrase-encrypted age files, without being able to decrypt them.
pub fn check_sealed(ciphertext: &[u8]) -> Result<()> {
    let decryptor = age::Decryptor::new(ciphertext).context("not an age file")?;
    if !decryptor.is_scrypt() {
        bail!("vault must be encrypted with a passphrase");
    }
    Ok(())
}

pub fn store(vault: &Path, ciphertext: &[u8]) -> Result<()> {
    if let Some(parent) = vault.parent() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(vault)
        .with_context(|| format!("creating {}", vault.display()))?;
    file.write_all(ciphertext)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn secret(s: &str) -> SecretString {
        SecretString::from(s.to_owned())
    }

    fn sample_dir() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("config"), "Host x\n").unwrap();
        std::fs::create_dir(tmp.path().join("keys")).unwrap();
        let key = tmp.path().join("keys/id_test");
        std::fs::write(&key, "PRIVATE").unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        tmp
    }

    fn read(tree: &Tree, path: &[&str]) -> Option<(u32, Vec<u8>)> {
        let mut ino = ROOT;
        for name in path {
            ino = tree.child(ino, OsStr::new(name))?;
        }
        match &tree.node(ino)?.kind {
            Kind::File { mode, data } => Some((*mode, data.to_vec())),
            Kind::Dir { .. } => None,
        }
    }

    #[test]
    fn round_trip_keeps_tree_and_strips_group_other_bits() {
        let src = sample_dir();
        let out = tempfile::tempdir().unwrap();
        let vault = out.path().join("v/vault.age");
        let (sealed, skipped) = seal(src.path(), secret("pw"), Some(4)).unwrap();
        assert!(skipped.is_empty());
        check_sealed(&sealed).unwrap();
        store(&vault, &sealed).unwrap();

        let tree = open(&vault, secret("pw")).unwrap();
        assert_eq!(tree.file_count(), 2);
        assert_eq!(read(&tree, &["config"]).unwrap().1, b"Host x\n");
        assert_eq!(
            read(&tree, &["keys", "id_test"]).unwrap(),
            (0o600, b"PRIVATE".to_vec())
        );
        assert_eq!(
            std::fs::metadata(&vault).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn wrong_passphrase_fails() {
        let src = sample_dir();
        let out = tempfile::tempdir().unwrap();
        let vault = out.path().join("vault.age");
        store(&vault, &seal(src.path(), secret("pw"), Some(4)).unwrap().0).unwrap();
        assert!(open(&vault, secret("other")).is_err());
    }

    #[test]
    fn store_never_overwrites() {
        let src = sample_dir();
        let out = tempfile::tempdir().unwrap();
        let vault = out.path().join("vault.age");
        let sealed = seal(src.path(), secret("pw"), Some(4)).unwrap().0;
        store(&vault, &sealed).unwrap();
        assert!(store(&vault, &sealed).is_err());
    }

    #[test]
    fn sockets_are_skipped() {
        let src = sample_dir();
        let _listener =
            std::os::unix::net::UnixListener::bind(src.path().join("control.sock")).unwrap();
        let (sealed, skipped) = seal(src.path(), secret("pw"), Some(4)).unwrap();
        assert_eq!(skipped, vec![PathBuf::from("control.sock")]);
        assert_eq!(
            Tree::from_tar(&decrypt(&sealed, secret("pw")).unwrap())
                .unwrap()
                .file_count(),
            2
        );
    }

    #[test]
    fn plain_and_key_encrypted_files_are_refused() {
        assert!(check_sealed(b"not age at all").is_err());
        let key = age::x25519::Identity::generate();
        let recipient = key.to_public();
        let encryptor = age::Encryptor::with_recipients(std::iter::once(&recipient as _)).unwrap();
        let mut out = Vec::new();
        let mut w = encryptor.wrap_output(&mut out).unwrap();
        w.write_all(b"x").unwrap();
        w.finish().unwrap();
        assert!(check_sealed(&out).is_err());
    }

    #[test]
    fn rejects_parent_traversal() {
        let mut header = tar::Header::new_gnu();
        header.set_size(1);
        header.set_mode(0o600);
        header.set_entry_type(tar::EntryType::Regular);
        let name = b"../escape";
        header.as_old_mut().name[..name.len()].copy_from_slice(name);
        header.set_cksum();
        let mut builder = tar::Builder::new(Vec::new());
        builder.append(&header, &b"x"[..]).unwrap();
        assert!(Tree::from_tar(&builder.into_inner().unwrap()).is_err());
    }
}
