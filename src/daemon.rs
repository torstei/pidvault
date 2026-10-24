use std::os::unix::fs::{DirBuilderExt, FileTypeExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use age::secrecy::SecretString;
use anyhow::{Context, Result, bail};
use base64::Engine;
use fuser::{Config, MountOption, Session, SessionACL};
use zeroize::Zeroizing;

use crate::agent;
use crate::fs::{self, Shared, State, Unlocked, VaultFs, VaultState};
use crate::limits::{self, Connections, Guesses};
use crate::procs::{self, Pidfd};
use crate::protocol::{self, Request, Response, VaultStatus};
use crate::systemd;
use crate::tree::Tree;
use crate::vault::{self, Key, Stored};

const PRUNE_INTERVAL: Duration = Duration::from_millis(250);

pub struct Options {
    pub socket: PathBuf,
    pub agent_socket: PathBuf,
    pub mount: PathBuf,
    /// Where the mount helper hands over the FUSE connection, when run by systemd.
    pub mount_socket: PathBuf,
    pub state_dir: PathBuf,
    /// Mount and bind as the invoking user, for tests. Otherwise systemd hands over the
    /// mount and the sockets, and the daemon never holds any privilege.
    pub unprivileged: bool,
    pub wrap_work_factor: Option<u8>,
}

/// The one step that needs root, in a unit of its own: a sandboxed unit's mounts stay in
/// its private namespace, invisible to users. For each daemon that connects (the socket is
/// reachable only by the daemon's group) it mounts the view and passes back the FUSE
/// connection, then unmounts once that daemon is gone, for whatever reason: a mount left
/// without its daemon makes the ssh_config Include fail for every host.
pub fn mount_helper(mount: &Path) -> Result<()> {
    let (_, socket) = systemd::listen_fds()?
        .into_iter()
        .next()
        .context("systemd passed no socket")?;
    for stream in UnixListener::from(socket).incoming() {
        let stream = stream?;
        match mount_fuse(mount) {
            Ok(fuse) => systemd::send_fd(&stream, &fuse)?,
            Err(e) => {
                eprintln!("sshvault: {e:#}");
                continue;
            }
        }
        let mut byte = [0u8; 1];
        let _ = std::io::Read::read(&mut &stream, &mut byte);
        unmount(mount);
    }
    Ok(())
}

fn unmount(mount: &Path) {
    if let Ok(path) = std::ffi::CString::new(mount.as_os_str().as_encoded_bytes()) {
        // SAFETY: path is a NUL-terminated string that outlives the call
        unsafe { libc::umount2(path.as_ptr(), libc::MNT_DETACH) };
    }
}

fn mount_fuse(mount: &Path) -> Result<std::os::fd::OwnedFd> {
    unmount(mount);
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o755)
        .create(mount)
        .with_context(|| format!("creating {}", mount.display()))?;
    let fuse = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/fuse")
        .context("opening /dev/fuse")?;
    let fuse = std::os::fd::OwnedFd::from(fuse);
    let path = std::ffi::CString::new(mount.as_os_str().as_encoded_bytes())?;
    let data = std::ffi::CString::new(format!(
        "fd={},rootmode=40755,user_id=0,group_id=0,allow_other,default_permissions",
        std::os::fd::AsRawFd::as_raw_fd(&fuse)
    ))?;
    // SAFETY: every pointer is to a NUL-terminated string that outlives the call
    let rc = unsafe {
        libc::mount(
            c"sshvault".as_ptr(),
            path.as_ptr(),
            c"fuse.sshvault".as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            data.as_ptr().cast(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("mounting {}", mount.display()));
    }
    Ok(fuse)
}

pub fn run(options: &Options) -> Result<()> {
    // blocked before any thread exists so that only sigtimedwait below receives them
    let signals = block_termination_signals()?;
    // SAFETY: getuid and getgid have no preconditions
    let (owner_uid, owner_gid) = unsafe { (libc::getuid(), libc::getgid()) };
    let state: Shared = Arc::new(Mutex::new(State::new(options.state_dir.clone())));
    let fs = VaultFs::new(state.clone(), owner_uid, owner_gid);

    let mut mount_connection = None;
    let (session, listener, agent_listener) = if options.unprivileged {
        for dir in [&options.socket, &options.agent_socket]
            .iter()
            .filter_map(|p| p.parent())
            .chain([options.mount.as_path(), options.state_dir.as_path()])
        {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)
                .with_context(|| format!("creating {}", dir.display()))?;
        }
        let listener = bind_socket(&options.socket)?;
        let agent_listener = bind_socket(&options.agent_socket)?;
        let mut config = Config::default();
        config.mount_options = vec![
            MountOption::NoSuid,
            MountOption::NoDev,
            MountOption::NoExec,
            MountOption::DefaultPermissions,
            MountOption::FSName("sshvault".into()),
            MountOption::Subtype("sshvault".into()),
        ];
        let session = Session::new(fs, &options.mount, &config)
            .with_context(|| format!("mounting {}", options.mount.display()))?;
        (session, listener, agent_listener)
    } else {
        let (listener, agent_listener) = sockets_from_systemd(options)?;
        let helper = UnixStream::connect(&options.mount_socket).with_context(|| {
            format!(
                "reaching the mount helper at {}",
                options.mount_socket.display()
            )
        })?;
        let fuse = systemd::recv_fd(&helper).context("receiving the FUSE connection")?;
        // held open while serving: the helper unmounts once it closes
        mount_connection = Some(helper);
        // a mount made for every user; VaultFs itself confines each to their own vaults
        let session = Session::from_fd(fs, fuse, SessionACL::All, Config::default())
            .context("taking over the FUSE connection")?;
        (session, listener, agent_listener)
    };
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&options.state_dir)
        .with_context(|| format!("creating {}", options.state_dir.display()))?;
    procs::harden()?;

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
            guesses: Guesses::default(),
            wrap_work_factor: options.wrap_work_factor,
        });
        let connections = Connections::new(MAX_CONNECTIONS, MAX_CONNECTIONS_PER_USER);
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let Some(admitted) = admit(&connections, &stream) else {
                    continue;
                };
                let ctx = ctx.clone();
                std::thread::spawn(move || {
                    serve(&stream, &ctx);
                    drop(admitted);
                });
            }
        });
    }
    {
        let state = state.clone();
        let connections = Connections::new(MAX_CONNECTIONS, MAX_CONNECTIONS_PER_USER);
        std::thread::spawn(move || {
            for stream in agent_listener.incoming().flatten() {
                let Some(admitted) = admit(&connections, &stream) else {
                    continue;
                };
                let state = state.clone();
                std::thread::spawn(move || {
                    agent::serve(stream, &state);
                    drop(admitted);
                });
            }
        });
    }

    eprintln!(
        "sshvault: serving {} on {}{}",
        options.mount.display(),
        options.socket.display(),
        if options.unprivileged {
            " (unprivileged: no protection from your own processes)"
        } else {
            ""
        }
    );
    while !session.guard.is_finished() && !wait_for_signal(&signals, PRUNE_INTERVAL) {}

    fs::lock(&state).save_and_lock_everything();
    if session.guard.is_finished() {
        bail!("filesystem was unmounted from outside; exiting");
    }
    if !options.unprivileged {
        // the helper unmounts when this connection closes; systemd removes the sockets
        drop(mount_connection);
        return Ok(());
    }
    let _ = std::fs::remove_file(&options.socket);
    let _ = std::fs::remove_file(&options.agent_socket);
    session.umount_and_join().context("unmounting")?;
    Ok(())
}

/// The control socket and the agent socket systemd passed in, told apart by path.
fn sockets_from_systemd(options: &Options) -> Result<(UnixListener, UnixListener)> {
    let mut listener = None;
    let mut agent_listener = None;
    for (_, fd) in systemd::listen_fds()? {
        let socket = UnixListener::from(fd);
        let bound = socket.local_addr()?.as_pathname().map(Path::to_path_buf);
        if bound.as_deref() == Some(&options.socket) {
            listener = Some(socket);
        } else if bound.as_deref() == Some(&options.agent_socket) {
            agent_listener = Some(socket);
        }
    }
    Ok((
        listener.with_context(|| {
            format!("systemd passed no socket for {}", options.socket.display())
        })?,
        agent_listener.with_context(|| {
            format!(
                "systemd passed no socket for {}",
                options.agent_socket.display()
            )
        })?,
    ))
}

const MAX_CONNECTIONS: usize = 1024;
const MAX_CONNECTIONS_PER_USER: usize = 64;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

fn admit(connections: &Arc<Connections>, stream: &UnixStream) -> Option<limits::Admitted> {
    let peer = procs::peer_cred(stream).ok()?;
    connections.admit(peer.uid)
}

fn serve(stream: &UnixStream, ctx: &Daemon) {
    let _ = stream.set_read_timeout(Some(REQUEST_TIMEOUT));
    let _ = stream.set_write_timeout(Some(REQUEST_TIMEOUT));
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
    pub guesses: Guesses,
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
    f: impl FnOnce(&mut VaultState, usize) -> Result<T>,
) -> Result<T> {
    let mut state = fs::lock(&ctx.state);
    let user = state
        .user_mut(peer.uid)
        .context("caller has no passwd entry")?;
    let room = user.room_for(name);
    f(user.existing_vault_mut(name)?, room)
}

/// As `with_vault`, but also for a vault that is about to be created.
fn with_new_vault<T>(
    ctx: &Daemon,
    peer: &procs::PeerCred,
    name: &str,
    f: impl FnOnce(&mut VaultState, usize) -> Result<T>,
) -> Result<T> {
    let mut state = fs::lock(&ctx.state);
    let user = state
        .user_mut(peer.uid)
        .context("caller has no passwd entry")?;
    let room = user.room_for(name);
    f(user.vault_or_new(name)?, room)
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
            let tree = Tree::from_tar(&limits::expensive(|| {
                vault::decrypt(&ciphertext, secret(&passphrase))
            })?)?;
            let key = Key::generate()?;
            let stored = Stored {
                wrapped_key: limits::expensive(|| {
                    key.wrap(secret(&passphrase), ctx.wrap_work_factor)
                })?,
                contents: key.seal_tree(&tree)?,
            };
            with_new_vault(ctx, &peer, &name, |vault, room| {
                let replacing = vault.exists();
                if replacing && vault.unlocked_ancestor(peer.pid).is_none() {
                    bail!("replacing `{name}` {}", needs_unlock(&name));
                }
                let held = vault.open.is_some() || shell.is_some();
                if held {
                    fs::check_room(&name, &tree, room)?;
                }
                stored.write(&vault.path, true)?;
                if held {
                    vault.hold(Unlocked::new(tree, key, stored.wrapped_key), room)?;
                }
                let mut message = if replacing {
                    format!("vault `{name}` replaced; the previous one is kept as a backup")
                } else {
                    format!("vault `{name}` stored")
                };
                if let Some((shell, handle)) = shell {
                    vault.sessions.register(shell, handle, None);
                    message.push_str(&format!(" and unlocked for shell {shell}"));
                }
                Ok(message)
            })?
        }
        Request::Export {
            vault: name,
            passphrase,
        } => {
            let wrapped_key = with_vault(ctx, &peer, &name, |vault, _| {
                match (&vault.open, vault.unlocked_ancestor(peer.pid)) {
                    (Some(open), Some(_)) => Ok(open.wrapped_key.clone()),
                    _ => bail!("export {}", needs_unlock(&name)),
                }
            })?;
            let key = ctx.guesses.check(peer.uid, || {
                limits::expensive(|| Key::unwrap(&wrapped_key, secret(&passphrase)))
            })?;
            let archive = with_vault(ctx, &peer, &name, |vault, _| match &vault.open {
                Some(open) if open.key.same_as(&key) => open.tree.to_tar(),
                _ => bail!("`{name}` changed during export; try again"),
            })?;
            let sealed = limits::expensive(|| {
                vault::encrypt(&archive, secret(&passphrase), ctx.wrap_work_factor)
            })?;
            exported = Some(base64::engine::general_purpose::STANDARD.encode(sealed));
            String::new()
        }
        Request::Passwd {
            vault: name,
            old,
            new,
        } => {
            vault::check_new_passphrase(&new)?;
            let wrapped_key = with_vault(ctx, &peer, &name, |vault, _| match &vault.open {
                Some(open) => Ok(open.wrapped_key.clone()),
                None => Ok(Stored::read(&vault.path)
                    .with_context(|| format!("you have no vault `{name}`"))?
                    .wrapped_key),
            })?;
            let key = ctx.guesses.check(peer.uid, || {
                limits::expensive(|| Key::unwrap(&wrapped_key, secret(&old)))
            })?;
            let rewrapped = limits::expensive(|| key.wrap(secret(&new), ctx.wrap_work_factor))?;
            with_vault(ctx, &peer, &name, |vault, _| {
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
            for_secs,
        } => {
            let expires = for_secs.map(|secs| Instant::now() + Duration::from_secs(secs));
            fs::check_vault_name(&name)?;
            let (shell, handle) = calling_shell(&peer)?;
            let path = with_vault(ctx, &peer, &name, |vault, _| Ok(vault.path.clone()))?;
            if !path.exists() {
                bail!("you have no vault `{name}`; create one with `sshvault create {name}`");
            }
            let stored = Stored::read(&path)?;
            let key = ctx.guesses.check(peer.uid, || {
                limits::expensive(|| Key::unwrap(&stored.wrapped_key, secret(&passphrase)))
            })?;
            with_vault(ctx, &peer, &name, |vault, room| {
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
                        vault.hold(Unlocked::new(tree, key, current.wrapped_key), room)?;
                    }
                }
                vault.sessions.register(shell, handle, expires);
                let files = vault.open.as_ref().map_or(0, |o| o.tree.file_count());
                let until = match for_secs {
                    Some(secs) => format!(" for {}", format_duration(secs)),
                    None => String::new(),
                };
                Ok(format!(
                    "`{name}` unlocked for shell {shell}{until} ({files} files)"
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
                    expires_in: v
                        .unlocked_ancestor(peer.pid)
                        .and_then(|shell| v.sessions.expires(shell))
                        .map(|at| at.saturating_duration_since(Instant::now()).as_secs()),
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

pub fn format_duration(secs: u64) -> String {
    match (secs / 3600, secs / 60 % 60, secs % 60) {
        (0, 0, s) => format!("{s}s"),
        (0, m, 0) => format!("{m}m"),
        (0, m, s) => format!("{m}m {s}s"),
        (h, 0, _) => format!("{h}h"),
        (h, m, _) => format!("{h}h {m}m"),
    }
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

fn bind_socket(path: &Path) -> Result<UnixListener> {
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
    UnixListener::bind(path).with_context(|| format!("binding {}", path.display()))
}

fn block_termination_signals() -> Result<libc::sigset_t> {
    // SAFETY: set is initialised by sigemptyset before any other use and outlives each call
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
    // SAFETY: set and ts outlive the call; a null siginfo pointer is allowed
    unsafe { libc::sigtimedwait(set, std::ptr::null_mut(), &ts) > 0 }
}
