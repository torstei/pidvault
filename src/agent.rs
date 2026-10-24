use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::fs::{self, Shared};
use crate::keys::AgentKey;
use crate::procs::{self, Liveness, PeerCred, Pidfd};
use crate::secret::SecretBuf;

/// The file in a vault that says which of its keys may be used where.
pub const POLICY_FILE: &str = "agent.toml";

const FAILURE: u8 = 5;
const SUCCESS: u8 = 6;
const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;
const EXTENSION: u8 = 27;

const SESSION_BIND: &[u8] = b"session-bind@openssh.com";
const MAX_MESSAGE: usize = 256 * 1024;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default)]
    keys: BTreeMap<String, KeyPolicy>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyPolicy {
    /// May sign on connections ssh forwarded to another host.
    #[serde(default)]
    forward: bool,
}

impl Policy {
    pub fn parse(text: &[u8]) -> Result<Policy> {
        let text = std::str::from_utf8(text).context("not UTF-8")?;
        Ok(toml::from_str(text)?)
    }

    fn may_forward(&self, key: &Path) -> bool {
        key.to_str()
            .and_then(|k| self.keys.get(k))
            .is_some_and(|p| p.forward)
    }
}

/// A vault's policy; a policy that cannot be read lets nothing be forwarded.
pub fn policy_of(tree: &crate::tree::Tree) -> Result<Policy> {
    match tree.file_at(Path::new(POLICY_FILE)) {
        Some(text) => Policy::parse(text).with_context(|| format!("{POLICY_FILE} is not valid")),
        None => Ok(Policy::default()),
    }
}

struct Connection {
    peer: PeerCred,
    /// The process that connected: once it is gone, whoever holds the connection now is
    /// not the one whose shell was checked.
    process: Pidfd,
    /// ssh marks a connection it opened on behalf of a remote host; it stays marked.
    forwarded: bool,
}

pub fn serve(mut stream: UnixStream, state: &Shared) {
    let Ok(peer) = procs::peer_cred(&stream) else {
        return;
    };
    let Ok(process) = procs::peer_pidfd(&stream, peer.pid) else {
        return;
    };
    let mut connection = Connection {
        peer,
        process,
        forwarded: false,
    };
    while let Ok(Some(request)) = read_message(&mut stream) {
        let reply = connection
            .answer(&request, state)
            .unwrap_or_else(|_| vec![FAILURE]);
        if write_message(&mut stream, &reply).is_err() {
            return;
        }
    }
}

/// A request the agent answers; anything else gets a failure.
#[derive(Debug, PartialEq)]
pub enum AgentRequest<'a> {
    Identities,
    Sign {
        blob: &'a [u8],
        data: &'a [u8],
        flags: u32,
    },
    /// ssh's session-bind extension; `forwarded` marks a connection made for a remote host.
    SessionBind {
        forwarded: bool,
    },
}

pub fn parse_request(request: &[u8]) -> Result<AgentRequest<'_>> {
    let (&kind, mut body) = request.split_first().context("empty message")?;
    match kind {
        REQUEST_IDENTITIES => Ok(AgentRequest::Identities),
        SIGN_REQUEST => Ok(AgentRequest::Sign {
            blob: take_string(&mut body)?,
            data: take_string(&mut body)?,
            flags: take_u32(&mut body)?,
        }),
        EXTENSION => {
            let name = take_string(&mut body)?;
            if name != SESSION_BIND {
                bail!("unsupported extension");
            }
            let _host_key = take_string(&mut body)?;
            let _session_id = take_string(&mut body)?;
            let _signature = take_string(&mut body)?;
            let forwarding = *body.first().context("truncated session-bind")?;
            Ok(AgentRequest::SessionBind {
                forwarded: forwarding != 0,
            })
        }
        // adding, removing and locking keys: keys get in by being written to a vault
        _ => bail!("unsupported request"),
    }
}

impl Connection {
    fn answer(&mut self, request: &[u8], state: &Shared) -> Result<Vec<u8>> {
        if self.process.has_exited() {
            bail!("the process that connected is gone");
        }
        match parse_request(request)? {
            AgentRequest::Identities => {
                let keys = self.usable_keys(state);
                let mut reply = vec![IDENTITIES_ANSWER];
                reply.extend_from_slice(&(keys.len() as u32).to_be_bytes());
                for key in &keys {
                    put_string(&mut reply, &key.public_blob);
                    put_string(&mut reply, key.comment.as_bytes());
                }
                Ok(reply)
            }
            AgentRequest::Sign { blob, data, flags } => {
                let key = self
                    .usable_keys(state)
                    .into_iter()
                    .find(|k| k.public_blob == blob)
                    .context("no such key here")?;
                let mut reply = vec![SIGN_RESPONSE];
                put_string(&mut reply, &key.sign(data, flags)?);
                Ok(reply)
            }
            AgentRequest::SessionBind { forwarded } => {
                self.forwarded |= forwarded;
                Ok(vec![SUCCESS])
            }
        }
    }

    /// The keys of every vault the caller's shell has unlocked, checked anew on each
    /// request so that locking a vault takes effect at once.
    fn usable_keys(&self, state: &Shared) -> Vec<AgentKey> {
        let mut copies: Vec<(String, SecretBuf)> = Vec::new();
        {
            let state = fs::lock(state);
            let Some(user) = state.user(self.peer.uid) else {
                return Vec::new();
            };
            for vault in user.vaults() {
                let (Some(open), Some(_)) = (&vault.open, vault.unlocked_ancestor(self.peer.pid))
                else {
                    continue;
                };
                let policy = if self.forwarded {
                    match policy_of(&open.tree) {
                        Ok(policy) => Some(policy),
                        Err(_) => continue,
                    }
                } else {
                    None
                };
                for (path, data) in open.tree.keys() {
                    if policy.as_ref().is_some_and(|p| !p.may_forward(&path)) {
                        continue;
                    }
                    if let Ok(copy) = data.try_clone() {
                        copies.push((format!("{}/{}", vault.name, path.display()), copy));
                    }
                }
            }
        }
        // parsed and used outside the lock, which file operations must not wait for
        copies
            .iter()
            .filter_map(|(name, data)| AgentKey::parse(data, name).ok())
            .collect()
    }
}

/// The next length-prefixed message; `None` at the end, or for a length out of bounds.
pub fn read_message(stream: &mut impl Read) -> std::io::Result<Option<Vec<u8>>> {
    let mut length = [0u8; 4];
    match stream.read_exact(&mut length) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_MESSAGE {
        return Ok(None);
    }
    let mut message = vec![0u8; length];
    stream.read_exact(&mut message)?;
    Ok(Some(message))
}

fn write_message(stream: &mut UnixStream, message: &[u8]) -> std::io::Result<()> {
    stream.write_all(&(message.len() as u32).to_be_bytes())?;
    stream.write_all(message)
}

fn put_string(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
}

fn take_u32(input: &mut &[u8]) -> Result<u32> {
    let (value, rest) = input
        .split_first_chunk::<4>()
        .context("truncated message")?;
    *input = rest;
    Ok(u32::from_be_bytes(*value))
}

fn take_string<'a>(input: &mut &'a [u8]) -> Result<&'a [u8]> {
    let length = take_u32(input)? as usize;
    if input.len() < length {
        bail!("truncated message");
    }
    let (value, rest) = input.split_at(length);
    *input = rest;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn policy_lists_forwardable_keys_and_defaults_to_none() {
        let policy =
            Policy::parse(b"[keys.\"id_jump\"]\nforward = true\n\n[keys.\"keys/other\"]\n")
                .unwrap();
        assert!(policy.may_forward(Path::new("id_jump")));
        assert!(!policy.may_forward(Path::new("keys/other")));
        assert!(!policy.may_forward(Path::new("unlisted")));
        assert!(!Policy::default().may_forward(Path::new("id_jump")));
    }

    #[test]
    fn unknown_policy_settings_are_errors() {
        assert!(Policy::parse(b"[keys.\"id\"]\nforwrd = true\n").is_err());
        assert!(Policy::parse(b"not toml [").is_err());
    }

    fn connection(process: Pidfd) -> (Connection, Shared, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let state: Shared = std::sync::Arc::new(std::sync::Mutex::new(fs::State::new(
            dir.path().to_path_buf(),
        )));
        let peer = PeerCred {
            pid: std::process::id(),
            uid: crate::users::current_uid(),
        };
        (
            Connection {
                peer,
                process,
                forwarded: false,
            },
            state,
            dir,
        )
    }

    fn me() -> Pidfd {
        Pidfd::open(std::process::id()).unwrap()
    }

    /// A small deterministic generator, so a failure can be reproduced.
    fn noise(seed: &mut u64) -> u64 {
        *seed ^= *seed << 13;
        *seed ^= *seed >> 7;
        *seed ^= *seed << 17;
        *seed
    }

    #[test]
    fn random_and_truncated_messages_never_panic_and_get_well_formed_replies() {
        let (mut connection, state, _dir) = connection(me());
        let mut seed = 0x5eed_u64;
        let kinds = [
            0,
            FAILURE,
            SUCCESS,
            REQUEST_IDENTITIES,
            SIGN_REQUEST,
            17,
            18,
            19,
            22,
            25,
            EXTENSION,
            255,
        ];
        for _ in 0..5000 {
            let kind = kinds[(noise(&mut seed) % kinds.len() as u64) as usize];
            let len = (noise(&mut seed) % 96) as usize;
            let mut message = vec![kind];
            for _ in 0..len {
                // mostly small numbers, so lengths inside the message often look plausible
                message.push(if noise(&mut seed).is_multiple_of(3) {
                    (noise(&mut seed) % 8) as u8
                } else {
                    noise(&mut seed) as u8
                });
            }
            if let Ok(reply) = connection.answer(&message, &state) {
                assert!(
                    [SUCCESS, IDENTITIES_ANSWER, SIGN_RESPONSE].contains(&reply[0]),
                    "{message:?} -> {reply:?}"
                );
            }
        }
        let mut bind = vec![EXTENSION];
        put_string(&mut bind, SESSION_BIND);
        for cut in 0..bind.len() + 20 {
            let mut truncated = bind.clone();
            truncated.resize(cut.min(bind.len()), 0);
            let _ = connection.answer(&truncated, &state);
        }
    }

    #[test]
    fn an_oversized_message_closes_the_connection() {
        let (mut ours, theirs) = UnixStream::pair().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let state: Shared = std::sync::Arc::new(std::sync::Mutex::new(fs::State::new(
            dir.path().to_path_buf(),
        )));
        let server = std::thread::spawn(move || serve(theirs, &state));
        ours.write_all(&((MAX_MESSAGE as u32) + 1).to_be_bytes())
            .unwrap();
        server.join().unwrap();
        let mut rest = Vec::new();
        assert_eq!(
            ours.read_to_end(&mut rest).unwrap(),
            0,
            "closed without a reply"
        );
    }

    #[test]
    fn a_connection_whose_process_is_gone_gets_nothing() {
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let gone = Pidfd::open(child.id()).unwrap();
        child.wait().unwrap();
        let (mut orphaned, state, _dir) = connection(gone);
        assert!(orphaned.answer(&[REQUEST_IDENTITIES], &state).is_err());
        let (mut alive, state, _dir) = connection(me());
        assert_eq!(
            alive.answer(&[REQUEST_IDENTITIES], &state).unwrap(),
            [IDENTITIES_ANSWER, 0, 0, 0, 0]
        );
    }

    #[test]
    fn strings_round_trip_and_truncation_is_caught() {
        let mut buf = Vec::new();
        put_string(&mut buf, b"abc");
        buf.extend_from_slice(&7u32.to_be_bytes());
        let mut input = &buf[..];
        assert_eq!(take_string(&mut input).unwrap(), b"abc");
        assert_eq!(take_u32(&mut input).unwrap(), 7);
        let mut short = &buf[..5];
        assert!(take_string(&mut short).is_err());
    }
}
