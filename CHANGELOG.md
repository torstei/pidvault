# Changelog

## Unreleased

- `status` and the prompt marker name stored vaults as `stored/NAME`, as they appear
  under the mount, beside `ephemeral/NAME`.

## 0.5.0 - 2026-10-30

- Stored vaults moved from `/run/pidvault/NAME` to `/run/pidvault/stored/NAME`, beside
  `/run/pidvault/ephemeral`. "Upgrading from 0.4" in the README has the two steps for your
  own files: `pidvault stub` again, and one `sed` over your vaults' configs.
- Ephemeral vaults: `pidvault create --ephemeral NAME [--for 8h]` makes a vault that is
  held in memory only, without a passphrase, for the calling shell and what it starts.
  It lives under `/run/pidvault/ephemeral`, apart from stored vaults, and its name is the
  shell's own: other shells can each have a vault of that name, and see none but their
  own. `status` shows it as `ephemeral/NAME`; `lock --ephemeral NAME` ends it. It is
  gone when the shell exits or locks it, when `--for` runs out, or when the daemon stops;
  nothing of it is written to disk. For tokens you can get again by logging in, such as
  bao's with `BAO_TOKEN_PATH`, and short-lived SSH certificates.

## 0.4.0 - 2026-10-30

- sshvault is now pidvault: the package, the command, the service account, `/run/pidvault`,
  `/var/lib/pidvault`, the `PIDVAULT_*` variables and the apt repository, now at
  https://torstei.github.io/pidvault. Installing pidvault replaces sshvault and takes over
  its vaults; "Moving from sshvault" in the README has the steps left to you.
- `eval "$(pidvault shell-init)"` in `~/.bashrc` marks shells that have a vault
  unlocked: a red marker before the prompt and the vault names in the terminal title,
  with the time left after `unlock --for`. `pidvault status --prompt` prints just that.
- The security design lists a new known limitation: any of your processes can read your
  pipes and terminals through `/proc`, so a piped or typed passphrase, or a secret a
  program passes on through a pipe, can be taken. Vault files cannot be reopened that way.
- crypto-bigint, under the ECDSA signatures, is updated to 0.7.10, with fixes for edge
  cases in modular inversion and multiplication.

## 0.3.1 - 2026-10-24

- The first release of the 0.3 changes in the apt repository: publishing 0.3.0 stopped
  after the GitHub release. Release packages are built on Ubuntu 24.04, the oldest
  Ubuntu they support.

## 0.3.0 - 2026-10-24

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
- New passphrases (`create`, `passwd`) need at least 15 characters. Existing vaults and
  imported files keep the passphrase they have.
- None of the daemon's memory is swapped out any more, not only the buffers holding
  decrypted vaults. `create --from` and `add-key` wipe what they read once they are done
  with it.
- One user could stop all others from unlocking by holding vaults full of empty files:
  each file took a page of locked memory, which all users share. Vault contents are now
  held in ordinary memory, which the whole daemon keeps out of swap, and a user's
  unlocked vaults may hold 16 MiB together.
- Fuzz targets for everything other processes can hand the daemon, run in CI.
- `unlock`, and `create` and `import` when they unlock, refuse where
  `kernel.yama.ptrace_scope` is 0 or Yama is missing: any process could then trace an
  unlocked shell and act as it.
- A security design document (`docs/security-design.md`) with the threat model, the
  claims sshvault makes and the tests behind them, and its known limitations.
- Every `unsafe` block states why it is sound, checked by clippy. The daemon checks the
  file descriptors it is handed by systemd and the mount helper instead of trusting them.

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
