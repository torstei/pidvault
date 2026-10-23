use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use age::secrecy::SecretString;
use anyhow::{Context, Result, bail};
use base64::Engine;
use fuser::{Config, MountOption, Session, SessionACL};

use crate::fs::{self, Shared, State, VaultFs};
use crate::procs::{self, Pidfd};
use crate::protocol::{self, Request, Response};
use crate::users::{self, Account};
use crate::vault;

const PRUNE_INTERVAL: Duration = Duration::from_millis(250);

pub struct Options {
    pub socket: PathBuf,
    pub mount: PathBuf,
    pub state_dir: PathBuf,
    /// `None` runs as the invoking user, without separation from that user's processes.
    pub run_as: Option<String>,
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

    let state: Shared = Arc::new(Mutex::new(State::default()));
    let mut config = Config::default();
    config.mount_options = vec![
        MountOption::RO,
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
        let state = state.clone();
        let state_dir = options.state_dir.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let state = state.clone();
                let state_dir = state_dir.clone();
                std::thread::spawn(move || serve(&stream, &state, &state_dir));
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

    fs::lock(&state).lock_everything();
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

fn serve(stream: &UnixStream, state: &Shared, state_dir: &Path) {
    let response = handle(stream, state, state_dir).unwrap_or_else(|e| Response {
        ok: false,
        message: format!("{e:#}"),
        unlocked_by: None,
        sessions: 0,
        has_vault: false,
    });
    let _ = protocol::write_response(stream, &response);
}

fn handle(stream: &UnixStream, state: &Shared, state_dir: &Path) -> Result<Response> {
    let peer = procs::peer_cred(stream)?;
    let vault_path = state_dir.join(peer.uid.to_string()).join("vault.age");
    let request = protocol::read_request(stream)?;

    let message = match request {
        Request::Create { vault } => {
            let ciphertext = base64::engine::general_purpose::STANDARD
                .decode(vault)
                .context("vault is not valid base64")?;
            vault::check_sealed(&ciphertext)?;
            if vault_path.exists() {
                bail!("you already have a vault");
            }
            vault::store(&vault_path, &ciphertext)?;
            "vault stored".to_string()
        }
        Request::Unlock { passphrase } => {
            let shell = procs::parent_of(peer.pid).context("cannot determine calling shell")?;
            let handle = Pidfd::open(shell).context("cannot track calling shell")?;
            // a pid read before the pidfd was opened might already belong to someone else
            if procs::parent_of(peer.pid) != Some(shell)
                || procs::real_uid_of(shell) != Some(peer.uid)
            {
                bail!("calling shell changed or belongs to another user");
            }
            // an orphaned client is adopted by a subreaper such as `systemd --user`,
            // whose descendants are the whole login; it leads a session of its own
            if shell <= 1 || procs::session_of(shell) != procs::session_of(peer.pid) {
                bail!("unlock must be run directly from the shell it is meant for");
            }
            if !vault_path.exists() {
                bail!("you have no vault yet; create one with `sshvault create --from DIR`");
            }
            let tree = vault::open(&vault_path, SecretString::from(passphrase.to_string()))?;
            let files = tree.file_count();
            let mut state = fs::lock(state);
            let user = state
                .user_mut(peer.uid)
                .context("caller has no passwd entry")?;
            user.tree = Some(tree);
            user.sessions.register(shell, handle);
            format!("shell {shell} unlocked ({files} files)")
        }
        Request::Lock { all } => {
            let mut state = fs::lock(state);
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

    let mut state = fs::lock(state);
    state.prune();
    let user = state.user(peer.uid);
    Ok(Response {
        ok: true,
        message,
        unlocked_by: user.and_then(|u| u.unlocked_ancestor(peer.pid)),
        sessions: user.map_or(0, |u| u.sessions.len()),
        has_vault: vault_path.exists(),
    })
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
