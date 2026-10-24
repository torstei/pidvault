use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use age::secrecy::SecretString;
use anyhow::{Context, Result, bail};
use zeroize::Zeroize;

use crate::secret::SecretBuf;
use crate::tree::Tree;

/// Archives the regular files and directories below `dir`, following symlinks.
/// Anything else (sockets, fifos, devices) is left out and returned.
fn pack_dir(dir: &Path) -> Result<(SecretBuf, Vec<PathBuf>)> {
    let mut builder = tar::Builder::new(SecretBuf::with_capacity(0)?);
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
    Ok((builder.into_inner()?, skipped))
}

/// Encrypts `dir` with a passphrase, as an export would be, returning it with the
/// paths that were left out.
pub fn seal(
    dir: &Path,
    passphrase: SecretString,
    work_factor: Option<u8>,
) -> Result<(Vec<u8>, Vec<PathBuf>)> {
    let (plain, skipped) = pack_dir(dir)?;
    Tree::from_tar(&plain).context("directory cannot be represented in a vault")?;
    Ok((encrypt(&plain, passphrase, work_factor)?, skipped))
}

/// scrypt cost (log2) for what sshvault itself encrypts with a passphrase: 256 MiB and
/// around a second, fixed so that the daemon's limit below leaves room.
pub const PASSPHRASE_WORK_FACTOR: u8 = 18;

/// The highest scrypt cost spent on decrypting a file: anyone may hand the daemon one, and
/// each step up doubles the memory (2^20 takes 1 GiB).
pub const MAX_WORK_FACTOR: u8 = 20;

/// Shortest new passphrase accepted: NIST SP 800-63B-4's minimum for a password that is
/// the only factor, which it is for anyone holding a copy of the vault file.
pub const MIN_PASSPHRASE_CHARS: usize = 15;

pub fn check_new_passphrase(passphrase: &str) -> Result<()> {
    if passphrase.chars().count() < MIN_PASSPHRASE_CHARS {
        bail!("a passphrase needs at least {MIN_PASSPHRASE_CHARS} characters");
    }
    Ok(())
}

#[derive(Debug)]
pub struct WrongPassphrase;

impl std::fmt::Display for WrongPassphrase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("wrong passphrase")
    }
}

impl std::error::Error for WrongPassphrase {}

pub fn encrypt(
    plaintext: &[u8],
    passphrase: SecretString,
    work_factor: Option<u8>,
) -> Result<Vec<u8>> {
    let mut recipient = age::scrypt::Recipient::new(passphrase);
    recipient.set_work_factor(work_factor.unwrap_or(PASSPHRASE_WORK_FACTOR));
    let encryptor = age::Encryptor::with_recipients(std::iter::once(&recipient as _))?;
    let mut out = Vec::new();
    let mut writer = encryptor.wrap_output(&mut out)?;
    writer.write_all(plaintext)?;
    writer.finish()?;
    Ok(out)
}

pub fn decrypt(ciphertext: &[u8], passphrase: SecretString) -> Result<SecretBuf> {
    let mut identity = age::scrypt::Identity::new(passphrase);
    identity.set_max_work_factor(MAX_WORK_FACTOR);
    let decryptor = age::Decryptor::new(ciphertext)?;
    let reader = decryptor
        .decrypt(std::iter::once(&identity as _))
        .map_err(|e| match e {
            age::DecryptError::DecryptionFailed
            | age::DecryptError::KeyDecryptionFailed
            | age::DecryptError::NoMatchingKeys => anyhow::Error::new(WrongPassphrase),
            age::DecryptError::ExcessiveWork { required, .. } => anyhow::anyhow!(
                "this file needs scrypt cost 2^{required}, more than the 2^{MAX_WORK_FACTOR} sshvault spends"
            ),
            other => anyhow::anyhow!("cannot open vault: {other}"),
        })?;
    Ok(SecretBuf::from_reader(reader, ciphertext.len())?)
}

/// Accepts only passphrase-encrypted age files, without being able to decrypt them.
pub fn check_sealed(ciphertext: &[u8]) -> Result<()> {
    let decryptor = age::Decryptor::new(ciphertext).context("not an age file")?;
    if !decryptor.is_scrypt() {
        bail!("vault must be encrypted with a passphrase");
    }
    Ok(())
}

const KEY_BYTES: usize = 32;

/// scrypt cost for data encrypted with K. K is 256 random bits, so the cost protects
/// nothing, and saving must stay cheap.
const KEY_WORK_FACTOR: u8 = 10;

/// K, the random key the vault contents are encrypted with, held as the 64 hex digits
/// that serve as its age passphrase (so `age -d` can use it as well).
pub struct Key(SecretBuf);

impl Key {
    pub fn generate() -> Result<Key> {
        let mut raw = [0u8; KEY_BYTES];
        getrandom::fill(&mut raw).map_err(|e| anyhow::anyhow!("no randomness: {e}"))?;
        let mut hex = SecretBuf::with_capacity(2 * KEY_BYTES)?;
        for byte in raw {
            hex.extend_from_slice(&[HEX[(byte >> 4) as usize], HEX[(byte & 0xf) as usize]])?;
        }
        raw.zeroize();
        Ok(Key(hex))
    }

    fn passphrase(&self) -> SecretString {
        // the bytes are ASCII hex digits, checked in `unwrap`
        SecretString::from(String::from_utf8_lossy(&self.0).into_owned())
    }

    /// K encrypted with the user's passphrase.
    pub fn wrap(&self, passphrase: SecretString, work_factor: Option<u8>) -> Result<Vec<u8>> {
        encrypt(&self.0, passphrase, work_factor)
    }

    pub fn unwrap(wrapped: &[u8], passphrase: SecretString) -> Result<Key> {
        let hex = decrypt(wrapped, passphrase)?;
        if hex.len() != 2 * KEY_BYTES || !hex.iter().all(|b| HEX.contains(b)) {
            bail!("vault key is malformed");
        }
        Ok(Key(hex))
    }

    pub fn seal_tree(&self, tree: &Tree) -> Result<Vec<u8>> {
        encrypt(&tree.to_tar()?, self.passphrase(), Some(KEY_WORK_FACTOR))
    }

    pub fn open_tree(&self, contents: &[u8]) -> Result<Tree> {
        Tree::from_tar(&decrypt(contents, self.passphrase())?)
    }

    pub fn same_as(&self, other: &Key) -> bool {
        self.0.len() == other.0.len()
            && self
                .0
                .iter()
                .zip(other.0.iter())
                .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                == 0
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

const MAGIC: &[u8] = b"sshvault-v1\n";

/// What is stored for each user: K wrapped with the passphrase, and the contents
/// encrypted with K. One file, so a save replaces both in a single rename.
pub struct Stored {
    pub wrapped_key: Vec<u8>,
    pub contents: Vec<u8>,
}

impl Stored {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(MAGIC.len() + 4 + self.wrapped_key.len() + self.contents.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&(self.wrapped_key.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.wrapped_key);
        out.extend_from_slice(&self.contents);
        out
    }

    pub fn parse(bytes: &[u8]) -> Result<Stored> {
        let rest = bytes.strip_prefix(MAGIC).context("not an sshvault vault")?;
        let (len, rest) = rest.split_first_chunk::<4>().context("truncated vault")?;
        let len = u32::from_be_bytes(*len) as usize;
        if rest.len() < len {
            bail!("truncated vault");
        }
        let (wrapped_key, contents) = rest.split_at(len);
        Ok(Stored {
            wrapped_key: wrapped_key.to_vec(),
            contents: contents.to_vec(),
        })
    }

    pub fn read(path: &Path) -> Result<Stored> {
        Stored::parse(&std::fs::read(path).with_context(|| format!("reading {}", path.display()))?)
    }

    /// Writes in one atomic step. With `keep_previous`, the file being replaced stays
    /// as `<path>.previous`, replacing any older one.
    pub fn write(&self, path: &Path, keep_previous: bool) -> Result<()> {
        let dir = path
            .parent()
            .context("vault path has no parent directory")?;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        let staged = sibling(path, ".new");
        let _ = std::fs::remove_file(&staged);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&staged)
            .with_context(|| format!("creating {}", staged.display()))?;
        file.write_all(&self.to_bytes())?;
        file.sync_all()?;
        if keep_previous && path.exists() {
            let previous = sibling(path, ".previous");
            let _ = std::fs::remove_file(&previous);
            std::fs::hard_link(path, &previous)
                .with_context(|| format!("keeping {}", previous.display()))?;
        }
        std::fs::rename(&staged, path).with_context(|| format!("replacing {}", path.display()))?;
        std::fs::File::open(dir)?.sync_all()?;
        Ok(())
    }
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::{ROOT, read_file};
    use std::ffi::OsStr;
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

    fn stored(passphrase: &str) -> (Key, Stored) {
        let key = Key::generate().unwrap();
        let mut tree = Tree::empty();
        let ino = tree.create_file(ROOT, OsStr::new("config"), 0o600).unwrap();
        tree.write(ino, 0, b"Host x\n").unwrap();
        let stored = Stored {
            wrapped_key: key.wrap(secret(passphrase), Some(4)).unwrap(),
            contents: key.seal_tree(&tree).unwrap(),
        };
        (key, stored)
    }

    #[test]
    fn sealed_directory_strips_group_other_bits() {
        let src = sample_dir();
        let (sealed, skipped) = seal(src.path(), secret("pw"), Some(4)).unwrap();
        assert!(skipped.is_empty());
        check_sealed(&sealed).unwrap();
        let tree = Tree::from_tar(&decrypt(&sealed, secret("pw")).unwrap()).unwrap();
        assert_eq!(tree.file_count(), 2);
        assert_eq!(
            read_file(&tree, &["keys", "id_test"]).unwrap(),
            (0o600, b"PRIVATE".to_vec())
        );
    }

    #[test]
    fn the_passphrase_opens_the_key_and_the_key_opens_the_contents() {
        let (key, stored) = stored("pw");
        let back = Stored::parse(&stored.to_bytes()).unwrap();
        let unwrapped = Key::unwrap(&back.wrapped_key, secret("pw")).unwrap();
        assert!(unwrapped.same_as(&key));
        let tree = unwrapped.open_tree(&back.contents).unwrap();
        assert_eq!(read_file(&tree, &["config"]).unwrap().1, b"Host x\n");
        assert!(Key::unwrap(&back.wrapped_key, secret("other")).is_err());
    }

    #[test]
    fn contents_cannot_be_opened_with_the_passphrase_itself() {
        let (_, stored) = stored("pw");
        assert!(decrypt(&stored.contents, secret("pw")).is_err());
    }

    #[test]
    fn a_wrong_passphrase_is_recognisable() {
        let sealed = encrypt(b"x", secret("right"), Some(4)).unwrap();
        let err = decrypt(&sealed, secret("wrong")).err().unwrap();
        assert!(err.downcast_ref::<WrongPassphrase>().is_some(), "{err:#}");
    }

    #[test]
    fn files_demanding_too_much_work_are_refused_without_doing_it() {
        // a cheap file whose header claims a higher cost: age refuses on that field alone
        let cheap = encrypt(b"x", secret("pw"), Some(4)).unwrap();
        let text = String::from_utf8_lossy(&cheap).into_owned();
        let claimed = format!(" {}\n", MAX_WORK_FACTOR + 1);
        let sealed: Vec<u8> = text
            .lines()
            .map(|line| match line.strip_prefix("-> scrypt ") {
                Some(rest) => format!("-> scrypt {}{claimed}", rest.rsplit_once(' ').unwrap().0),
                None => format!("{line}\n"),
            })
            .collect::<String>()
            .into_bytes();
        // the passphrase is right: without the limit this would succeed after the work
        let err = decrypt(&sealed, secret("pw")).err().unwrap();
        assert!(
            format!("{err}").contains(&format!("scrypt cost 2^{}", MAX_WORK_FACTOR + 1)),
            "{err:#}"
        );
    }

    #[test]
    fn keys_are_random() {
        assert!(!Key::generate().unwrap().same_as(&Key::generate().unwrap()));
    }

    #[test]
    fn write_replaces_atomically_and_keeps_the_previous_when_asked() {
        let out = tempfile::tempdir().unwrap();
        let path = out.path().join("v/vault.sshvault");
        let (_, first) = stored("one");
        let (_, second) = stored("two");
        first.write(&path, true).unwrap();
        second.write(&path, true).unwrap();
        let current = Stored::read(&path).unwrap();
        assert!(Key::unwrap(&current.wrapped_key, secret("two")).is_ok());
        let previous = Stored::read(&out.path().join("v/vault.sshvault.previous")).unwrap();
        assert!(Key::unwrap(&previous.wrapped_key, secret("one")).is_ok());
        assert!(!out.path().join("v/vault.sshvault.new").exists());
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        first.write(&path, false).unwrap();
        let previous = Stored::read(&out.path().join("v/vault.sshvault.previous")).unwrap();
        assert!(
            Key::unwrap(&previous.wrapped_key, secret("one")).is_ok(),
            "previous unchanged"
        );
    }

    #[test]
    fn truncated_or_foreign_files_are_refused() {
        let (_, stored) = stored("pw");
        let bytes = stored.to_bytes();
        assert!(Stored::parse(&bytes[..MAGIC.len() + 2]).is_err());
        assert!(Stored::parse(b"age-encryption.org/v1\n").is_err());
    }

    #[test]
    fn sockets_are_skipped() {
        let src = sample_dir();
        let _listener =
            std::os::unix::net::UnixListener::bind(src.path().join("control.sock")).unwrap();
        let (_, skipped) = seal(src.path(), secret("pw"), Some(4)).unwrap();
        assert_eq!(skipped, vec![PathBuf::from("control.sock")]);
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
}
