# Changelog

## Unreleased

- The daemon no longer starts as root. It runs as `sshvault` from the start, with no
  capabilities and systemd's sandbox (read-only system, no `/home`, devices or network,
  a system-call allow-list); `systemd-analyze security` rates it 0.5 instead of 6.4.
  systemd creates its sockets, and a separate, minimal root unit, `sshvault-mount`, makes
  the mount, hands it over and unmounts when the daemon goes away.
- Limits on what any process can make the daemon do: passphrase guesses are throttled per
  user (one at a time, doubling waits after each wrong one), scrypt runs one at a time and
  never beyond cost 2^20, and connections are capped per user and in total.
- RSA signatures are blinded; the README recommends ed25519.
- The agent refuses a connection once the process that opened it has exited.
- Requests about a vault that does not exist no longer register its name, so no process
  can use up a user's 255 vault places with made-up names.
- ECDSA (P-256 and P-384) signatures in the agent are made with constant-time arithmetic.
  The libraries used before could leak timing (RUSTSEC-2026-0387), which a process in an
  unlocked shell, timing many signatures, might have used to recover the key.
- The package ships a man page and a Debian changelog, and passes lintian.
- Releases are built reproducibly, the binary carries its dependency list for auditing
  (`cargo auditable`), and each release has a CycloneDX SBOM with a signed attestation.
- A security policy (`SECURITY.md`) for reporting vulnerabilities privately.

## 0.2.0 - 2026-10-23

The first published release.

- Vaults, each with its own passphrase and its own directory under `/run/sshvault/<name>`,
  visible and writable only in shells that unlocked them.
- An ssh-agent on `/run/sshvault-agent.sock` that signs with vault keys for those shells.
  Private keys in a vault can be used but never read, and are offered on forwarded
  connections only where a vault's `agent.toml` says `forward = true`.
- `sshvault unlock --for 10m` for unlocks that end by themselves.
- `sshvault add-key` to bring in an existing key, removing its passphrase on the way.
- `export` and `import` for backups and moving to another machine, as standard `age` files.
- A starter `config` in new vaults, usable with `ssh -F` or through the block that
  `sshvault stub` prints for `~/.ssh/config`.
- A daemon that mounts as root and serves as the `sshvault` account, packaged with a
  systemd unit, for Ubuntu 24.04 or later on amd64.
