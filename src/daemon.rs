use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use age::secrecy::SecretString;
use anyhow::{Context, Result, bail};
use base64::Engine;
use fuser::{Config, MountOption, Session, SessionACL};
use zeroize::Zeroizing;

use crate::agent;
use crate::fs::{self, Shared, State, Unlocked, VaultFs, VaultState};
use crate::procs::{self, Pidfd};
use crate::protocol::{self, Request, Response, VaultStatus};
use crate::tree::Tree;
use crate::users::{self, Account};
use crate::vault::{self, Key, Stored};

const PRUNE_INTERVAL: Duration = Duration::from_millis(250);

pub struct Options {
    pub socket: PathBuf,
    pub agent_socket: PathBuf,
    pub mount: PathBuf,
    pub state_dir: PathBuf,
    /// `None` runs as the invoking user, without separation from that user's processes.
    pub run_as: Option<String>,
    pub wrap_work_factor: Option<u8>,
}

pub fn run(options: &Options) -> Result<()> {
    // blocked before any thread exists so that only sigtimedwait below receives them
    let signals = block_termination_signals()?;

    let privileged = match &options.run_as {
        Some(name) => {
            if !users::is_root() {
                bail!(
                    "the daemon must start as root to mount for all users, then drops to {name}; \
                     use the systemd unit, or --unprivileged for testing"
                );
            }
            Some(users::by_name(name).with_context(|| format!("no such user {name}"))?)
        }
        None => None,
    };
    let (owner_uid, owner_gid) = match &privileged {
        Some(account) => (account.uid, account.gid),
        None => unsafe { (libc::getuid(), libc::getgid()) },
    };

    prepare_dirs(options, privileged.as_ref())?;
    let listener = bind_socket(&options.socket, privileged.is_some())?;
    let agent_listener = bind_socket(&options.agent_socket, privileged.is_some())?;

    let state: Shared = Arc::new(Mutex::new(State::new(options.state_dir.clone())));
    let mut config = Config::default();
    config.mount_options = vec![
        MountOption::NoSuid,
        MountOption::NoDev,
        MountOption::NoExec,
        MountOption::DefaultPermissions,
        MountOption::FSName("sshvault".into()),
        MountOption::Subtype("sshvault".into()),
    ];
    // a root mount serves every user; VaultFs itself confines each to their own tree
    config.acl = if privileged.is_some() {
        SessionACL::All
    } else {
        SessionACL::Owner
    };
    let session = Session::new(
        VaultFs::new(state.clone(), owner_uid, owner_gid),
        &options.mount,
        &config,
    )
    .with_context(|| format!("mounting {}", options.mount.display()))?;

    if let Some(account) = &privileged {
        users::drop_privileges(account)?;
    }
    // as the owner: root keeps no CAP_FOWNER to change modes on what it handed over
    std::fs::set_permissions(&options.state_dir, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("restricting {}", options.state_dir.display()))?;
    for warning in procs::harden()? {
        eprintln!("sshvault: warning: {warning}");
    }

    let session = session.spawn()?;
    {
        let state = state.clone();
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(PRUNE_INTERVAL);
                fs::lock(&state).prune();
            }
        });
    }
    {
        let ctx = Arc::new(Daemon {
            state: state.clone(),
            wrap_work_factor: options.wrap_work_factor,
        });
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let ctx = ctx.clone();
                std::thread::spawn(move || serve(&stream, &ctx));
            }
        });
    }
    {
        let state = state.clone();
        std::thread::spawn(move || {
            for stream in agent_listener.incoming().flatten() {
                let state = state.clone();
                std::thread::spawn(move || agent::serve(stream, &state));
            }
        });
    }

    eprintln!(
        "sshvault: serving {} on {}{}",
        options.mount.display(),
        options.socket.display(),
        if privileged.is_some() {
            ""
        } else {
            " (unprivileged: no protection from your own processes)"
        }
    );
    while !session.guard.is_finished() && !wait_for_signal(&signals, PRUNE_INTERVAL) {}

    fs::lock(&state).save_and_lock_everything();
    if session.guard.is_finished() {
        bail!("filesystem was unmounted from outside; exiting");
    }
    if privileged.is_some() {
        // only root may unmount now; the service manager does that after exit
        return Ok(());
    }
    let _ = std::fs::remove_file(&options.socket);
    let _ = std::fs::remove_file(&options.agent_socket);
    session.umount_and_join().context("unmounting")?;
    Ok(())
}

fn prepare_dirs(options: &Options, privileged: Option<&Account>) -> Result<()> {
    let public = if privileged.is_some() { 0o755 } else { 0o700 };
    let socket_dir = options
        .socket
        .parent()
        .context("socket path has no parent directory")?;
    let agent_dir = options
        .agent_socket
        .parent()
        .context("agent socket path has no parent directory")?;
    for (dir, mode) in [
        (socket_dir, public),
        (agent_dir, public),
        (options.mount.as_path(), public),
        (options.state_dir.as_path(), 0o700),
    ] {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(mode)
            .create(dir)
            .with_context(|| format!("creating {}", dir.display()))?;
    }
    if let Some(account) = privileged {
        for dir in [socket_dir, agent_dir] {
            let meta = std::fs::metadata(dir)?;
            if meta.uid() != 0 || meta.mode() & 0o022 != 0 {
                bail!(
                    "{} must be owned by root and writable only by root",
                    dir.display()
                );
            }
        }
        std::os::unix::fs::chown(&options.state_dir, Some(account.uid), Some(account.gid))
            .with_context(|| {
                format!(
                    "handing {} to {}",
                    options.state_dir.display(),
                    account.name
                )
            })?;
    }
    Ok(())
}

fn serve(stream: &UnixStream, ctx: &Daemon) {
    let response = handle(stream, ctx).unwrap_or_else(|e| Response {
        ok: false,
        message: format!("{e:#}"),
        vaults: Vec::new(),
        data: None,
    });
    let _ = protocol::write_response(stream, &response);
}

pub struct Daemon {
    pub state: Shared,
    /// scrypt cost for wrapping K with a passphrase; only lowered for tests
    pub wrap_work_factor: Option<u8>,
}

fn secret(passphrase: &Zeroizing<String>) -> SecretString {
    SecretString::from(passphrase.to_string())
}

/// Runs `f` on the caller's vault called `name`, under the state lock.
fn with_vault<T>(
    ctx: &Daemon,
    peer: &procs::PeerCred,
    name: &str,
    f: impl FnOnce(&mut VaultState) -> Result<T>,
) -> Result<T> {
    let mut state = fs::lock(&ctx.state);
    let user = state
        .user_mut(peer.uid)
        .context("caller has no passwd entry")?;
    f(user.vault_mut(name)?)
}

fn needs_unlock(name: &str) -> String {
    format!("needs `{name}` unlocked in this shell; run `sshvault unlock {name}` first")
}

// The scrypt steps take about a second, so they run outside the state lock; every
// write of a vault file happens under it, which keeps saves from interleaving.
fn handle(stream: &UnixStream, ctx: &Daemon) -> Result<Response> {
    let peer = procs::peer_cred(stream)?;
    let request = protocol::read_request(stream)?;
    // also finds the vaults on disk of a user this daemon has not seen yet
    fs::lock(&ctx.state)
        .user_mut(peer.uid)
        .context("caller has no passwd entry")?;

    let mut exported = None;
    let message = match request {
        Request::Import {
            vault: name,
            data,
            passphrase,
            unlock,
        } => {
            fs::check_vault_name(&name)?;
            let shell = if unlock {
                Some(calling_shell(&peer)?)
            } else {
                None
            };
            let ciphertext = base64::engine::general_purpose::STANDARD
                .decode(data)
                .context("vault is not valid base64")?;
            vault::check_sealed(&ciphertext)?;
            let tree = Tree::from_tar(&vault::decrypt(&ciphertext, secret(&passphrase))?)?;
            let key = Key::generate()?;
            let stored = Stored {
                wrapped_key: key.wrap(secret(&passphrase), ctx.wrap_work_factor)?,
                contents: key.seal_tree(&tree)?,
            };
            with_vault(ctx, &peer, &name, |vault| {
                let replacing = vault.exists();
                if replacing && vault.unlocked_ancestor(peer.pid).is_none() {
                    bail!("replacing `{name}` {}", needs_unlock(&name));
                }
                stored.write(&vault.path, true)?;
                if vault.open.is_some() || shell.is_some() {
                    vault.hold(Unlocked::new(tree, key, stored.wrapped_key));
                }
                let mut message = if replacing {
                    format!("vault `{name}` replaced; the previous one is kept as a backup")
                } else {
                    format!("vault `{name}` stored")
                };
                if let Some((shell, handle)) = shell {
                    vault.sessions.register(shell, handle);
                    message.push_str(&format!(" and unlocked for shell {shell}"));
                }
                Ok(message)
            })?
        }
        Request::Export {
            vault: name,
            passphrase,
        } => {
            let wrapped_key = with_vault(ctx, &peer, &name, |vault| {
                match (&vault.open, vault.unlocked_ancestor(peer.pid)) {
                    (Some(open), Some(_)) => Ok(open.wrapped_key.clone()),
                    _ => bail!("export {}", needs_unlock(&name)),
                }
            })?;
            let key = Key::unwrap(&wrapped_key, secret(&passphrase))?;
            let archive = with_vault(ctx, &peer, &name, |vault| match &vault.open {
                Some(open) if open.key.same_as(&key) => open.tree.to_tar(),
                _ => bail!("`{name}` changed during export; try again"),
            })?;
            let sealed = vault::encrypt(&archive, secret(&passphrase), ctx.wrap_work_factor)?;
            exported = Some(base64::engine::general_purpose::STANDARD.encode(sealed));
            String::new()
        }
        Request::Passwd {
            vault: name,
            old,
            new,
        } => {
            let wrapped_key = with_vault(ctx, &peer, &name, |vault| match &vault.open {
                Some(open) => Ok(open.wrapped_key.clone()),
                None => Ok(Stored::read(&vault.path)
                    .with_context(|| format!("you have no vault `{name}`"))?
                    .wrapped_key),
            })?;
            let key = Key::unwrap(&wrapped_key, secret(&old))?;
            let rewrapped = key.wrap(secret(&new), ctx.wrap_work_factor)?;
            with_vault(ctx, &peer, &name, |vault| {
                match &vault.open {
                    Some(open) if open.key.same_as(&key) => vault.rewrap(rewrapped)?,
                    Some(_) => bail!("`{name}` changed meanwhile; try again"),
                    None => {
                        let stored = Stored::read(&vault.path)?;
                        if stored.wrapped_key != wrapped_key {
                            bail!("`{name}` changed meanwhile; try again");
                        }
                        Stored {
                            wrapped_key: rewrapped,
                            contents: stored.contents,
                        }
                        .write(&vault.path, false)?;
                    }
                }
                Ok(format!("passphrase of `{name}` changed"))
            })?
        }
        Request::Unlock {
            vault: name,
            passphrase,
        } => {
            fs::check_vault_name(&name)?;
            let (shell, handle) = calling_shell(&peer)?;
            let path = with_vault(ctx, &peer, &name, |vault| Ok(vault.path.clone()))?;
            if !path.exists() {
                bail!("you have no vault `{name}`; create one with `sshvault create {name}`");
            }
            let stored = Stored::read(&path)?;
            let key = Key::unwrap(&stored.wrapped_key, secret(&passphrase))?;
            with_vault(ctx, &peer, &name, |vault| {
                // a vault already held keeps its unsaved changes; this unlock only proves the passphrase
                match &vault.open {
                    Some(open) if open.key.same_as(&key) => {}
                    Some(_) => bail!("`{name}` changed while unlocking; try again"),
                    None => {
                        // read again: a save may have landed while the passphrase was checked
                        let current = Stored::read(&vault.path)?;
                        if current.wrapped_key != stored.wrapped_key {
                            bail!("`{name}` changed while unlocking; try again");
                        }
                        let tree = key.open_tree(&current.contents)?;
                        vault.hold(Unlocked::new(tree, key, current.wrapped_key));
                    }
                }
                vault.sessions.register(shell, handle);
                let files = vault.open.as_ref().map_or(0, |o| o.tree.file_count());
                Ok(format!(
                    "`{name}` unlocked for shell {shell} ({files} files)"
                ))
            })?
        }
        Request::Lock { vault: name, all } => {
            let mut state = fs::lock(&ctx.state);
            let user = state
                .user_mut(peer.uid)
                .context("caller has no passwd entry")?;
            let mut locked = Vec::new();
            for vault in user.vaults_mut() {
                if name.as_ref().is_some_and(|n| *n != vault.name) {
                    continue;
                }
                if all {
                    if !vault.sessions.is_empty() {
                        locked.push(vault.name.clone());
                    }
                    vault.sessions.clear();
                } else if let Some(shell) = vault.unlocked_ancestor(peer.pid) {
                    vault.sessions.remove(shell);
                    locked.push(vault.name.clone());
                }
            }
            state.prune();
            if locked.is_empty() {
                "nothing was unlocked".to_string()
            } else {
                format!("locked {}", locked.join(", "))
            }
        }
        Request::Status => String::new(),
    };

    let mut state = fs::lock(&ctx.state);
    state.prune();
    let vaults = state
        .user(peer.uid)
        .map(|user| {
            user.vaults()
                .filter(|v| v.exists())
                .map(|v| VaultStatus {
                    name: v.name.clone(),
                    unlocked_by: v.unlocked_ancestor(peer.pid),
                    sessions: v.sessions.len(),
                    notes: v
                        .open
                        .as_ref()
                        .and_then(|open| agent::policy_of(&open.tree).err())
                        .map(|e| vec![format!("{e:#}; no key may be forwarded")])
                        .unwrap_or_default(),
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(Response {
        ok: true,
        message,
        vaults,
        data: exported,
    })
}

/// The shell that ran the client, which an unlock is for.
fn calling_shell(peer: &procs::PeerCred) -> Result<(u32, Pidfd)> {
    let shell = procs::parent_of(peer.pid).context("cannot determine calling shell")?;
    let handle = Pidfd::open(shell).context("cannot track calling shell")?;
    // a pid read before the pidfd was opened might already belong to someone else
    if procs::parent_of(peer.pid) != Some(shell) || procs::real_uid_of(shell) != Some(peer.uid) {
        bail!("calling shell changed or belongs to another user");
    }
    // an orphaned client is adopted by a subreaper such as `systemd --user`,
    // whose descendants are the whole login; it leads a session of its own
    if shell <= 1 || procs::session_of(shell) != procs::session_of(peer.pid) {
        bail!("run sshvault directly from the shell it is meant to unlock");
    }
    Ok((shell, handle))
}

fn bind_socket(path: &Path, public: bool) -> Result<UnixListener> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => {
            if UnixStream::connect(path).is_ok() {
                bail!("another daemon is already listening on {}", path.display());
            }
            std::fs::remove_file(path)?;
        }
        Ok(_) => bail!("{} exists and is not a socket", path.display()),
        Err(_) => {}
    }
    let listener =
        UnixListener::bind(path).with_context(|| format!("binding {}", path.display()))?;
    // connecting needs write permission; callers are told apart by their credentials
    let mode = if public { 0o666 } else { 0o600 };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(listener)
}

fn block_termination_signals() -> Result<libc::sigset_t> {
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            libc::sigaddset(&mut set, sig);
        }
        let rc = libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
        if rc != 0 {
            bail!(
                "pthread_sigmask failed: {}",
                std::io::Error::from_raw_os_error(rc)
            );
        }
        Ok(set)
    }
}

fn wait_for_signal(set: &libc::sigset_t, timeout: Duration) -> bool {
    let ts = libc::timespec {
        tv_sec: timeout.as_secs() as libc::time_t,
        tv_nsec: timeout.subsec_nanos() as libc::c_long,
    };
    unsafe { libc::sigtimedwait(set, std::ptr::null_mut(), &ts) > 0 }
}
