use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{procs, users};

/// Lets the client talk to a daemon running as the client's own user. Such a daemon
/// cannot be told apart from an impostor, so this exists for tests only.
pub const ALLOW_SAME_UID_ENV: &str = "PIDVAULT_INSECURE_ALLOW_SAME_UID_DAEMON";

const MAX_REQUEST: u64 = 8 * 1024 * 1024;

/// Every request names the vault it is about; `vault` defaults to the default vault.
#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Stores `data`, a base64 age file, as `vault` after checking that `passphrase`
    /// opens it, and with `unlock` unlocks it for the calling shell. Replacing an
    /// existing vault needs a caller that has it unlocked.
    Import {
        vault: String,
        data: String,
        passphrase: Zeroizing<String>,
        #[serde(default)]
        unlock: bool,
    },
    /// Returns the vault encrypted with `passphrase`, which must be the vault's, to a
    /// caller that has it unlocked.
    Export {
        vault: String,
        passphrase: Zeroizing<String>,
    },
    /// Re-encrypts the vault key under a new passphrase.
    Passwd {
        vault: String,
        old: Zeroizing<String>,
        new: Zeroizing<String>,
    },
    /// With `for_secs`, the unlock ends by itself after that many seconds.
    Unlock {
        vault: String,
        passphrase: Zeroizing<String>,
        #[serde(default)]
        for_secs: Option<u64>,
    },
    /// Locks `vault`, or every vault, for the caller's shell; with `all`, for every
    /// shell of the caller's user.
    Lock {
        vault: Option<String>,
        all: bool,
    },
    Status,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultStatus {
    pub name: String,
    /// The unlocked shell the caller descends from, if any.
    pub unlocked_by: Option<u32>,
    /// Seconds until the caller's unlock of this vault ends by itself, if it does.
    #[serde(default)]
    pub expires_in: Option<u64>,
    /// Shells of the caller's user that have this vault unlocked.
    pub sessions: usize,
    /// Problems worth telling the user about, such as an unreadable agent policy.
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    pub message: String,
    /// The caller's vaults.
    #[serde(default)]
    pub vaults: Vec<VaultStatus>,
    /// The base64 age file, in reply to `Export`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
}

impl Response {
    pub fn vault(&self, name: &str) -> Option<&VaultStatus> {
        self.vaults.iter().find(|v| v.name == name)
    }

    pub fn any_unlocked(&self) -> bool {
        self.vaults.iter().any(|v| v.unlocked_by.is_some())
    }
}

pub fn call(socket: &Path, request: &Request) -> Result<Response> {
    let mut stream = UnixStream::connect(socket)
        .with_context(|| format!("connecting to the pidvault daemon at {}", socket.display()))?;
    if std::env::var_os(ALLOW_SAME_UID_ENV).is_none() {
        authenticate_daemon(socket, &stream)?;
    }
    let mut line = Zeroizing::new(serde_json::to_vec(request)?);
    line.push(b'\n');
    stream.write_all(&line)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut reply = String::new();
    BufReader::new(stream).read_line(&mut reply)?;
    serde_json::from_str(&reply).context("malformed reply from daemon")
}

/// Refuses anything another process of this user could have put in the daemon's place.
fn authenticate_daemon(socket: &Path, stream: &UnixStream) -> Result<()> {
    let server = procs::peer_cred(stream)?;
    if server.uid == users::current_uid() {
        bail!(
            "the daemon at {} runs as your own user, so it could be any of your processes; refusing to talk to it",
            socket.display()
        );
    }
    let dir = socket
        .parent()
        .context("socket path has no parent directory")?;
    let meta = std::fs::metadata(dir).with_context(|| format!("inspecting {}", dir.display()))?;
    if meta.uid() != 0 || meta.mode() & 0o022 != 0 {
        bail!(
            "{} must be owned by root and writable only by root, so nobody else can place a socket there",
            dir.display()
        );
    }
    Ok(())
}

pub fn read_request(stream: &UnixStream) -> Result<Request> {
    let mut line = Zeroizing::new(String::new());
    BufReader::new(std::io::Read::take(stream, MAX_REQUEST)).read_line(&mut line)?;
    Ok(serde_json::from_str(&line)?)
}

pub fn write_response(mut stream: &UnixStream, response: &Response) -> Result<()> {
    let mut line = serde_json::to_vec(response)?;
    line.push(b'\n');
    stream.write_all(&line)?;
    Ok(())
}
