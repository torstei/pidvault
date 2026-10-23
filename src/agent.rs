use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::fs::{self, Shared};
use crate::keys::AgentKey;
use crate::procs::{self, PeerCred};
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
    /// ssh marks a connection it opened on behalf of a remote host; it stays marked.
    forwarded: bool,
}

pub fn serve(mut stream: UnixStream, state: &Shared) {
    let Ok(peer) = procs::peer_cred(&stream) else {
        return;
    };
    let mut connection = Connection {
        peer,
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

impl Connection {
    fn answer(&mut self, request: &[u8], state: &Shared) -> Result<Vec<u8>> {
        let (&kind, mut body) = request.split_first().context("empty message")?;
        match kind {
            REQUEST_IDENTITIES => {
                let keys = self.usable_keys(state);
                let mut reply = vec![IDENTITIES_ANSWER];
                reply.extend_from_slice(&(keys.len() as u32).to_be_bytes());
                for key in &keys {
                    put_string(&mut reply, &key.public_blob);
                    put_string(&mut reply, key.comment.as_bytes());
                }
                Ok(reply)
            }
            SIGN_REQUEST => {
                let blob = take_string(&mut body)?;
                let data = take_string(&mut body)?;
                let flags = take_u32(&mut body)?;
                let key = self
                    .usable_keys(state)
                    .into_iter()
                    .find(|k| k.public_blob == blob)
                    .context("no such key here")?;
                let mut reply = vec![SIGN_RESPONSE];
                put_string(&mut reply, &key.sign(data, flags)?);
                Ok(reply)
            }
            EXTENSION => {
                let name = take_string(&mut body)?;
                if name != SESSION_BIND {
                    bail!("unsupported extension");
                }
                let _host_key = take_string(&mut body)?;
                let _session_id = take_string(&mut body)?;
                let _signature = take_string(&mut body)?;
                let forwarding = *body.first().context("truncated session-bind")?;
                self.forwarded |= forwarding != 0;
                Ok(vec![SUCCESS])
            }
            // adding, removing and locking keys: keys get in by being written to a vault
            _ => bail!("unsupported request"),
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

fn read_message(stream: &mut UnixStream) -> std::io::Result<Option<Vec<u8>>> {
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
