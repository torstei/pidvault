use anyhow::{Context, Result, bail};
use signature::Signer;
use ssh_encoding::Encode;
use ssh_key::private::KeypairData;
use ssh_key::{Algorithm, HashAlg, PrivateKey, Signature};

/// The opening of every unencrypted OpenSSH private key: the armour line, then the start
/// of the encoded header naming cipher and KDF "none". It holds nothing secret, so a file
/// is recognised as a key before any secret part of it has been written.
const PLAIN_OPENSSH_KEY: &[u8] =
    b"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ";

/// A key is never readable through the mount, only usable through the agent.
pub fn is_private_key(data: &[u8]) -> bool {
    data.starts_with(PLAIN_OPENSSH_KEY)
}

/// A key ready to be written to a vault: unprotected, since the vault protects it.
pub struct Importable {
    pub private: zeroize::Zeroizing<String>,
    pub public: String,
    pub fingerprint: String,
}

/// Prepares the key file `data` for a vault, asking `passphrase` only if it is protected.
pub fn importable(
    data: &[u8],
    passphrase: impl FnOnce() -> Result<zeroize::Zeroizing<String>>,
) -> Result<Importable> {
    let key = PrivateKey::from_openssh(data).map_err(|_| {
        anyhow::anyhow!(
            "not a private key in OpenSSH format; an older PEM key can be copied into the vault \
             and converted there with `ssh-keygen -p -N '' -f COPY`"
        )
    })?;
    let key = if key.is_encrypted() {
        key.decrypt(passphrase()?.as_bytes())
            .map_err(|_| anyhow::anyhow!("wrong passphrase"))?
    } else {
        key
    };
    Ok(Importable {
        private: key.to_openssh(ssh_key::LineEnding::LF)?,
        public: key.public_key().to_openssh()?,
        fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
    })
}

const SSH_AGENT_RSA_SHA2_256: u32 = 2;
const SSH_AGENT_RSA_SHA2_512: u32 = 4;

pub struct AgentKey {
    pub public_blob: Vec<u8>,
    pub comment: String,
    private: PrivateKey,
}

impl AgentKey {
    /// `fallback` names the key when it carries no comment of its own.
    pub fn parse(data: &[u8], fallback: &str) -> Result<AgentKey> {
        let private = PrivateKey::from_openssh(data).context("not a usable OpenSSH private key")?;
        if private.is_encrypted() {
            bail!("key is encrypted");
        }
        let public_blob = private.public_key().key_data().encode_vec()?;
        let comment = match private.comment() {
            "" => fallback.to_owned(),
            own => own.to_owned(),
        };
        Ok(AgentKey {
            public_blob,
            comment,
            private,
        })
    }

    /// The signature in agent wire format, honouring the RSA hash ssh asked for.
    pub fn sign(&self, data: &[u8], flags: u32) -> Result<Vec<u8>> {
        let signature = match self.private.key_data() {
            KeypairData::Rsa(rsa) if flags & SSH_AGENT_RSA_SHA2_512 != 0 => {
                rsa_sign::<sha2::Sha512>(rsa, data, HashAlg::Sha512)?
            }
            KeypairData::Rsa(rsa) if flags & SSH_AGENT_RSA_SHA2_256 != 0 => {
                rsa_sign::<sha2::Sha256>(rsa, data, HashAlg::Sha256)?
            }
            KeypairData::Rsa(_) => bail!("refusing SHA-1 RSA signatures"),
            _ => self.private.try_sign(data)?,
        };
        Ok(signature.encode_vec()?)
    }
}

fn rsa_sign<D>(
    keypair: &ssh_key::private::RsaKeypair,
    data: &[u8],
    hash: HashAlg,
) -> Result<Signature>
where
    D: sha2::Digest + rsa::pkcs8::AssociatedOid,
{
    // not RsaPrivateKey::try_from(keypair): ssh-key 0.6.7 builds that from p twice
    // instead of p and q, so every signature made with it fails
    let uint =
        |m: &ssh_key::Mpint| rsa::BigUint::from_bytes_be(m.as_positive_bytes().unwrap_or_default());
    let key = rsa::RsaPrivateKey::from_components(
        uint(&keypair.public.n),
        uint(&keypair.public.e),
        uint(&keypair.private.d),
        vec![uint(&keypair.private.p), uint(&keypair.private.q)],
    )?;
    let raw: rsa::pkcs1v15::Signature = rsa::pkcs1v15::SigningKey::<D>::new(key).try_sign(data)?;
    Ok(Signature::new(
        Algorithm::Rsa { hash: Some(hash) },
        Box::<[u8]>::from(raw).into_vec(),
    )?)
}

trait EncodeVec {
    fn encode_vec(&self) -> ssh_encoding::Result<Vec<u8>>;
}

impl<T: Encode> EncodeVec for T {
    fn encode_vec(&self) -> ssh_encoding::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len()?);
        self.encode(&mut out)?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use signature::Verifier;
    use std::process::Command;

    fn keygen(kind: &str, passphrase: &str) -> Vec<u8> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        let status = Command::new("ssh-keygen")
            .args(["-q", "-t", kind, "-N", passphrase, "-C", "test", "-f"])
            .arg(&path)
            .status()
            .unwrap();
        assert!(status.success());
        std::fs::read(path).unwrap()
    }

    #[test]
    fn real_unencrypted_keys_are_recognised_and_encrypted_ones_are_not() {
        for kind in ["ed25519", "rsa", "ecdsa"] {
            assert!(is_private_key(&keygen(kind, "")), "{kind}");
            assert!(
                !is_private_key(&keygen(kind, "secret")),
                "{kind} with passphrase"
            );
        }
        assert!(!is_private_key(b"Host x\n"));
        assert!(!is_private_key(&PLAIN_OPENSSH_KEY[..20]));
    }

    #[test]
    fn signatures_verify_for_every_supported_kind() {
        for (kind, flags) in [
            ("ed25519", 0),
            ("ecdsa", 0),
            ("rsa", SSH_AGENT_RSA_SHA2_512),
            ("rsa", SSH_AGENT_RSA_SHA2_256),
        ] {
            let data = keygen(kind, "");
            let key = AgentKey::parse(&data, "fallback").unwrap();
            assert_eq!(key.comment, "test");
            let wire = key
                .sign(b"challenge", flags)
                .unwrap_or_else(|e| panic!("{kind} {flags}: {e:#}"));
            let signature = Signature::try_from(&wire[..]).unwrap();
            let public = PrivateKey::from_openssh(&data)
                .unwrap()
                .public_key()
                .clone();
            public
                .key_data()
                .verify(b"challenge", &signature)
                .unwrap_or_else(|e| panic!("{kind}: {e}"));
        }
    }

    #[test]
    fn protected_keys_become_unprotected_on_the_way_in() {
        for kind in ["ed25519", "rsa", "ecdsa"] {
            let protected = keygen(kind, "secret");
            let ready = importable(&protected, || {
                Ok(zeroize::Zeroizing::new("secret".to_owned()))
            })
            .unwrap();
            assert!(is_private_key(ready.private.as_bytes()), "{kind}");
            assert!(ready.public.ends_with(" test"), "{kind}: {}", ready.public);
            assert!(
                importable(&protected, || Ok(zeroize::Zeroizing::new(
                    "wrong".to_owned()
                )))
                .is_err()
            );
        }
    }

    #[test]
    fn unprotected_keys_need_no_passphrase() {
        let plain = keygen("ed25519", "");
        let ready = importable(&plain, || panic!("asked for a passphrase")).unwrap();
        assert!(is_private_key(ready.private.as_bytes()));
    }

    #[test]
    fn pem_keys_are_refused_with_a_way_out() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        assert!(
            Command::new("ssh-keygen")
                .args(["-q", "-m", "PEM", "-t", "rsa", "-b", "2048", "-N", "", "-f"])
                .arg(&path)
                .status()
                .unwrap()
                .success()
        );
        let err = importable(&std::fs::read(path).unwrap(), || panic!("asked"))
            .err()
            .unwrap();
        assert!(format!("{err}").contains("ssh-keygen -p"), "{err}");
    }

    #[test]
    fn sha1_rsa_signatures_are_refused() {
        let key = AgentKey::parse(&keygen("rsa", ""), "fallback").unwrap();
        assert!(key.sign(b"challenge", 0).is_err());
    }
}
