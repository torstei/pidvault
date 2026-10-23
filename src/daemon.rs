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

use crate::fs::{self, Shared, State, Unlocked, VaultFs};
use crate::procs::{self, Pidfd};
use crate::protocol::{self, Request, Response};
use crate::tree::Tree;
use crate::users::{self, Account};
use crate::vault::{self, Key, Stored};

const PRUNE_INTERVAL: Duration = Duration::from_millis(250);

pub struct Options {
    pub socket: PathBuf,
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
    session.umount_and_join().context("unmounting")?;
    Ok(())
}

fn prepare_dirs(options: &Options, privileged: Option<&Account>) -> Result<()> {
    let public = if privileged.is_some() { 0o755 } else { 0o700 };
    let socket_dir = options
        .socket
        .parent()
        .context("socket path has no parent directory")?;
    for (dir, mode) in [
        (socket_dir, public),
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
        let meta = std::fs::metadata(socket_dir)?;
        if meta.uid() != 0 || meta.mode() & 0o022 != 0 {
            bail!(
                "{} must be owned by root and writable only by root",
                socket_dir.display()
            );
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
        unlocked_by: None,
        sessions: 0,
        has_vault: false,
        vault: None,
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

const NEEDS_UNLOCK: &str = "needs an unlocked shell; run `sshvault unlock` first";

// The scrypt steps take about a second, so they run outside the state lock; every
// write of a vault file happens under it, which keeps saves from interleaving.
fn handle(stream: &UnixStream, ctx: &Daemon) -> Result<Response> {
    let peer = procs::peer_cred(stream)?;
    let request = protocol::read_request(stream)?;
    let vault_path = fs::lock(&ctx.state)
        .user_mut(peer.uid)
        .context("caller has no passwd entry")?
        .vault_path
        .clone();

    let mut exported = None;
    let message = match request {
        Request::Import {
            vault,
            passphrase,
            unlock,
        } => {
            let shell = if unlock {
                Some(calling_shell(&peer)?)
            } else {
                None
            };
            let ciphertext = base64::engine::general_purpose::STANDARD
                .decode(vault)
                .context("vault is not valid base64")?;
            vault::check_sealed(&ciphertext)?;
            let tree = Tree::from_tar(&vault::decrypt(&ciphertext, secret(&passphrase))?)?;
            let key = Key::generate()?;
            let stored = Stored {
                wrapped_key: key.wrap(secret(&passphrase), ctx.wrap_work_factor)?,
                contents: key.seal_tree(&tree)?,
            };
            let mut state = fs::lock(&ctx.state);
            let user = state
                .user_mut(peer.uid)
                .context("caller has no passwd entry")?;
            let replacing = user.has_vault();
            if replacing && user.unlocked_ancestor(peer.pid).is_none() {
                bail!("replacing your vault {NEEDS_UNLOCK}");
            }
            stored.write(&user.vault_path, true)?;
            if user.open.is_some() || shell.is_some() {
                user.hold(Unlocked::new(tree, key, stored.wrapped_key));
            }
            let mut message = if replacing {
                "vault replaced; the previous one is kept as a backup".to_string()
            } else {
                "vault stored".to_string()
            };
            if let Some((shell, handle)) = shell {
                user.sessions.register(shell, handle);
                message.push_str(&format!("; shell {shell} unlocked"));
            }
            message
        }
        Request::Export { passphrase } => {
            let wrapped_key = {
                let state = fs::lock(&ctx.state);
                let user = state.user(peer.uid).context("caller has no passwd entry")?;
                match (&user.open, user.unlocked_ancestor(peer.pid)) {
                    (Some(open), Some(_)) => open.wrapped_key.clone(),
                    _ => bail!("export {NEEDS_UNLOCK}"),
                }
            };
            let key = Key::unwrap(&wrapped_key, secret(&passphrase))?;
            let archive = {
                let state = fs::lock(&ctx.state);
                let open = state.user(peer.uid).and_then(|u| u.open.as_ref());
                match open {
                    Some(open) if open.key.same_as(&key) => open.tree.to_tar()?,
                    _ => bail!("your vault changed during export; try again"),
                }
            };
            let sealed = vault::encrypt(&archive, secret(&passphrase), ctx.wrap_work_factor)?;
            exported = Some(base64::engine::general_purpose::STANDARD.encode(sealed));
            String::new()
        }
        Request::Passwd { old, new } => {
            let wrapped_key = {
                let state = fs::lock(&ctx.state);
                match state.user(peer.uid).and_then(|u| u.open.as_ref()) {
                    Some(open) => open.wrapped_key.clone(),
                    None => {
                        Stored::read(&vault_path)
                            .context("you have no vault")?
                            .wrapped_key
                    }
                }
            };
            let key = Key::unwrap(&wrapped_key, secret(&old))?;
            let rewrapped = key.wrap(secret(&new), ctx.wrap_work_factor)?;
            let mut state = fs::lock(&ctx.state);
            let user = state
                .user_mut(peer.uid)
                .context("caller has no passwd entry")?;
            match &user.open {
                Some(open) if open.key.same_as(&key) => user.rewrap(rewrapped)?,
                Some(_) => bail!("your vault changed meanwhile; try again"),
                None => {
                    let stored = Stored::read(&vault_path)?;
                    if stored.wrapped_key != wrapped_key {
                        bail!("your vault changed meanwhile; try again");
                    }
                    Stored {
                        wrapped_key: rewrapped,
                        contents: stored.contents,
                    }
                    .write(&vault_path, false)?;
                }
            }
            "passphrase changed".to_string()
        }
        Request::Unlock { passphrase } => {
            let (shell, handle) = calling_shell(&peer)?;
            if !vault_path.exists() {
                bail!("you have no vault yet; create one with `sshvault create`");
            }
            let stored = Stored::read(&vault_path)?;
            let key = Key::unwrap(&stored.wrapped_key, secret(&passphrase))?;
            let mut state = fs::lock(&ctx.state);
            let user = state
                .user_mut(peer.uid)
                .context("caller has no passwd entry")?;
            // a vault already held keeps its unsaved changes; this unlock only proves the passphrase
            match &user.open {
                Some(open) if open.key.same_as(&key) => {}
                Some(_) => bail!("your vault changed while unlocking; try again"),
                None => {
                    let tree = key.open_tree(&stored.contents)?;
                    user.hold(Unlocked::new(tree, key, stored.wrapped_key));
                }
            }
            user.sessions.register(shell, handle);
            let files = user.open.as_ref().map_or(0, |o| o.tree.file_count());
            format!("shell {shell} unlocked ({files} files)")
        }
        Request::Lock { all } => {
            let mut state = fs::lock(&ctx.state);
            let message = match state.user_mut(peer.uid) {
                Some(user) if all => {
                    user.sessions.clear();
                    "all your shells locked".to_string()
                }
                Some(user) => match user.unlocked_ancestor(peer.pid) {
                    Some(shell) => {
                        user.sessions.remove(shell);
                        format!("shell {shell} locked")
                    }
                    None => "this shell was not unlocked".to_string(),
                },
                None => "this shell was not unlocked".to_string(),
            };
            state.prune();
            message
        }
        Request::Status => String::new(),
    };

    let mut state = fs::lock(&ctx.state);
    state.prune();
    let user = state.user(peer.uid);
    Ok(Response {
        ok: true,
        message,
        unlocked_by: user.and_then(|u| u.unlocked_ancestor(peer.pid)),
        sessions: user.map_or(0, |u| u.sessions.len()),
        has_vault: vault_path.exists(),
        vault: exported,
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
