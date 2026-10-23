# Changelog

## Unreleased

- The daemon no longer starts as root. It runs as `sshvault` from the start, with no
  capabilities and systemd's sandbox (read-only system, no `/home`, devices or network,
  a system-call allow-list); `systemd-analyze security` rates it 0.5 instead of 6.4.
  systemd creates its sockets, and a separate, minimal root unit, `sshvault-mount`, makes
  the mount, hands it over and unmounts when the daemon goes away.

## 0.2.0

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
