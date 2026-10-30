# sshvault security design

This is the assurance case for sshvault: what it protects, from whom, where the trust
boundaries are, which claims it makes and why they hold, and what it leaves open. The
README describes the same mechanisms for users; this document is for reviewers, and
names the code and tests behind each claim. It describes the version on `main`.

## Assets

1. **Private keys in a vault.** The most valuable asset: signing with one logs in, and
   pushes, wherever its owner can.
2. **The rest of a vault's contents.** `config` reveals hosts, users and jump paths;
   `known_hosts` reveals where its owner connects.
3. **The integrity of a vault.** A `ProxyCommand` or `Match exec` planted in a vault's
   `config` runs as its owner the next time they connect.
4. **The passphrase and the vault key K.** Either one opens the vault.
5. **Availability.** One user must not be able to stop another from using their vaults.

## Adversaries

| | Adversary | Can |
|---|---|---|
| A1 | A process of the vault's owner outside an unlocked shell: an AI agent, a browser, a `curl \| sh` script, a build script | Everything the owner's uid can: read and write the home directory, connect to any socket the owner can, read `/proc` of the owner's processes, signal them, and trace its own descendants (with Yama's default `ptrace_scope` of 1) |
| A2 | Another local user | Connect to sshvault's sockets and use the mount, as themselves |
| A3 | A remote host the owner forwards their agent to, including its root | Send agent requests through the forwarded connection |
| A4 | Someone with a copy of a stored vault or an export: a backup, a stolen disk | Guess passphrases offline |
| A5 | The supply chain: a dependency, the build, the apt repository | Change what runs |

A1 is the reason sshvault exists. The others are the boundaries any multi-user service
on the machine must hold anyway.

### Out of scope

- **Root and the kernel.** Anything that is, or can become, root can read the daemon's
  memory.
- **What runs inside an unlocked shell.** It can sign with the vault's keys, read and
  change everything else in the vault, and plant something that is still there in the
  next shell unlocked. It cannot read the keys themselves.
- **Code the owner's shell trusts.** A1 can write `~/.bashrc`, `~/.local/bin` and
  `~/.ssh/config`, so what it plants there runs in the next shell the owner unlocks.
- **Anyone who learns the passphrase.** They can run `sshvault unlock` themselves. See
  [Known limitations](#known-limitations) for the ways a passphrase can be observed.
- **Physical access to a running machine,** and hibernation, which writes memory to disk.

## Components and trust boundaries

```
 owner's processes             other users                    remote host (agent forwarding)
   │        │        │              │                                   │
   │ FUSE   │ agent  │ control      │ (same three interfaces)           │ via ssh in an unlocked shell
   ▼        ▼        ▼              ▼                                   ▼
 /run/sshvault  /run/sshvault-agent.sock  /run/sshvault.sock
 (kernel: uid    (SO_PEERCRED, pidfd)      (SO_PEERCRED)
  and pid of
  each request)
   └──────────────── daemon, uid sshvault, sandboxed ─────────────────┘
                     │                               ▲
                     ▼                               │ /dev/fuse fd, once
           /var/lib/sshvault/<uid>/<name>.sshvault   sshvault-mount (root, CAP_SYS_ADMIN only)
           (0700/0600, sshvault)
```

- **The kernel tells the daemon who is asking.** FUSE requests carry the caller's uid and
  pid; the sockets give the peer's credentials (`SO_PEERCRED`) and a pidfd
  (`SO_PEERPIDFD`). Nothing a client sends about itself is trusted.
- **The daemon** runs as the `sshvault` account with no capabilities, a read-only system,
  no `/home`, devices or network, and a system-call allow-list
  (`packaging/sshvault.service`). It owns the vault files.
- **The mount helper** is the only root code: it mounts `/run/sshvault`, passes the FUSE
  connection to the daemon, and unmounts when the daemon's connection closes
  (`daemon::mount_helper`). It reads nothing from the daemon but the connection itself.
- **The client** (`sshvault` run by a user) trusts the daemon only if it runs as another
  uid and its socket directory is root's (`protocol::authenticate_daemon`), so A1 cannot
  stand in for the daemon to collect a passphrase.

## Claims

Each claim gives the argument for it and the evidence. "e2e" names a test in
`tests/end_to_end.rs`; "VM" a check in `tests/vm/guest-tests.sh`; "fuzz" a target in
`fuzz/`.

### C1. Outside an unlocked shell, the owner's processes see nothing in a vault

- `unlock` registers the client's parent, the shell, by pidfd, after checking it belongs
  to the caller and is in the client's session (`daemon::calling_shell`). A client
  orphaned to a subreaper such as `systemd --user` is refused, since that would unlock
  the whole login.
- Every FUSE request is checked anew: the caller's uid must own the vault, and its pid
  must be, or descend from, a registered shell that is still alive (`fs::VaultFs::target`,
  `sessions`). A file descriptor passed out of an unlocked shell is useless, since reads
  through it are checked against the reader, and so is reopening one through
  `/proc/<pid>/fd`, which is a new open by the caller.
- Kernel caching is off (zero TTLs, direct I/O), so nothing is served from cache.
- Evidence: e2e `outsider_sees_an_empty_directory`,
  `outsider_is_refused_while_a_shell_is_unlocked`, `access_ends_when_the_shell_exits`,
  `lock_revokes_access_for_the_shell`, `an_orphaned_unlock_does_not_unlock_its_adopter`,
  `only_unlocked_shells_can_write`;
  VM "another process of alice sees nothing", "alice's user services see nothing".

### C2. Nobody can read a private key, not even an unlocked shell

- A file whose first bytes are those of an unencrypted OpenSSH private key is a key from
  the moment it is written (`keys::is_private_key`). Those bytes hold nothing secret.
- Reading a key is refused (`EACCES`), and it shows as mode `200`. Its bytes can be
  appended to or emptied, never changed, so it cannot be turned back into a readable file
  (`tree::Tree::write`, `truncate`). A copy is a key too.
- The only way out is `export`, which needs an unlocked shell and the passphrase.
- Evidence: e2e `keys_can_be_written_into_a_vault_but_never_read_back`; unit
  `a_key_can_be_appended_to_and_emptied_but_never_changed`; fuzz `tree_ops`, which checks
  after every operation in an arbitrary sequence that no key became readable or changed
  (removing the check in `Tree::write` makes it fail within seconds).

### C3. The agent signs only for the shells that unlocked the key's vault

- The agent takes the peer's uid and a pidfd when a connection opens, refuses it once
  that process has exited (so a connection handed to another process is useless), and on
  every request offers only keys of vaults that the peer's shell has unlocked
  (`agent::Connection`).
- Connections ssh marks as forwarded (`session-bind@openssh.com`) get only keys the
  vault's `agent.toml` allows; a policy that cannot be read allows nothing.
- It refuses SHA-1 RSA signatures and every request that adds, removes or locks keys.
- Evidence: e2e `the_agent_offers_vault_keys_only_to_unlocked_shells`,
  `forwarded_connections_get_only_keys_the_policy_allows`,
  `real_ssh_login_uses_the_vault_key_only_from_the_unlocked_shell`; VM "the vault agent
  offers alice's other processes nothing"; fuzz `agent_message`.

### C4. Other users learn nothing about a user's vaults

- A user's directory under `/run/sshvault` is their own inode, mode 0700 and listed only
  to them; another user asking for a vault by name gets `ENOENT`, whether or not it
  exists. Vault names are checked (`fs::check_vault_name`), and tar paths reduced to
  normal components, so nothing escapes `/var/lib/sshvault/<uid>`.
- Evidence: unit `hostile_vault_names_are_refused`,
  `every_accepted_name_stays_in_the_users_directory`; e2e
  `the_mount_lists_only_the_callers_vaults_which_belong_to_the_caller`; VM "a vault name
  only alice has does not exist for bob", "bob cannot unlock alice's vault by its name".

### C5. A copy of a vault file reveals nothing without the passphrase

- A vault file holds a random 256-bit key K encrypted with the passphrase, and the
  contents encrypted with K. Exports are encrypted with the passphrase directly. Both use
  [age](https://age-encryption.org)'s passphrase format: authenticated encryption, so
  nobody without K can produce contents that decrypt with it.
- The passphrase is stretched with scrypt; see [Cryptography](#cryptography) for the
  parameters. New passphrases need at least 15 characters (NIST SP 800-63B-4's minimum
  for a password that is the only factor).
- The daemon stores vaults where only it can read them, and exports only to an unlocked
  shell, so A1 cannot even get a copy to guess against offline. Online guessing through
  the daemon is throttled per user: one check at a time, each wrong passphrase doubling
  the wait, up to 30 seconds (`limits::Guesses`).
- Evidence: e2e `wrong_passphrase_is_rejected`, `a_wrong_passphrase_makes_the_next_try_wait`,
  `export_needs_an_unlocked_shell`, `short_new_passphrases_are_refused`; VM "alice cannot
  read her stored vault".

### C6. Decrypted data does not leave the daemon's memory

- The daemon is a separate uid, not dumpable (`PR_SET_DUMPABLE`, which also keeps the
  owner's processes from tracing it), refuses to start under a tracer, and has
  `LimitCORE=0` and `MemorySwapMax=0`.
- Decrypted contents and K live in buffers that are wiped when dropped and before they
  grow (`secret::SecretBuf`); passphrases and protocol lines in self-wiping strings.
  Everything is dropped when a vault's last unlocked shell exits.
- Evidence: VM "the daemon's memory is never swapped out", "the daemon holds no
  capabilities".

### C7. No user can deny service to the others

- Connections are capped at 64 per user and 1024 in total, with a 30-second request
  timeout; scrypt runs one at a time across the daemon, at a cost of at most 2^20 whatever
  a supplied file asks for.
- A vault holds at most 4 MiB, counted as it would be saved, and one user's unlocked
  vaults at most 16 MiB together. Requests about vaults that do not exist register
  nothing, so they cannot use up a user's 255 places.
- Evidence: e2e `the_vault_cannot_grow_past_its_limit`,
  `requests_for_made_up_vaults_cannot_use_up_a_users_places`; unit
  `a_users_unlocked_vaults_share_one_limit`; VM "four full vaults fit in what one user may
  hold", "bob still unlocks while carol holds them".

### C8. A compromised daemon is contained

- The daemon has no capabilities and no network, cannot see `/home`, and can write only
  its state directory; `systemd-analyze security` rates it 0.5. It holds every user's
  unlocked vaults, so a compromise would expose those, but not other files, keys outside
  vaults, or root.
- Evidence: VM "the daemon holds no capabilities", "the daemon has no network of its
  own", "the daemon cannot see /home", "systemd rates the service's exposure below 2".

## Design principles

- **Least privilege.** The only root code mounts and unmounts; the daemon has no
  capabilities. Keys are usable, never readable.
- **Complete mediation.** Every FUSE request and every agent request is checked against
  the current state; locking takes effect at the next request.
- **Fail-safe defaults.** A new process sees nothing; an unreadable `agent.toml` forwards
  nothing; a client that cannot tell which shell called it unlocks nothing.
- **Economy of mechanism.** One file format (age), one archive format (tar), and the
  kernel's own credentials instead of tokens or a protocol of its own for identity.
- **Separation of privilege.** Mounting (root) and holding secrets (`sshvault`) are
  separate services.
- **Least common mechanism.** One daemon serves every user, which is what makes the
  per-user limits of C7 necessary.
- **Psychological acceptability.** One unlock per shell, then plain `ssh`; nothing else
  changes.

## Common weaknesses

| Weakness | How it is countered |
|---|---|
| Memory safety (CWE-119 and family) | Rust. Every `unsafe` block states why it is sound, enforced by clippy's `undocumented_unsafe_blocks` |
| Path traversal (CWE-22) | Vault names are restricted; tar paths must be normal components |
| PID reuse, TOCTOU (CWE-367) | Shells and agent peers are held by pidfd; the calling shell is re-checked after its pidfd is opened |
| Uncontrolled resource use (CWE-400) | The limits of C7 |
| Timing side channels (CWE-208) | ECDSA with constant-time arithmetic; RSA signing blinded; K compared in constant time |
| Weak crypto (CWE-327) | No own cryptography; no SHA-1 signatures; see below |
| Spoofed server (CWE-290) | The client checks the daemon's uid and socket directory |
| Malformed input (CWE-20) | Size limits on every message and file; parsers fuzzed in CI |
| Copies of secrets (CWE-226) | Wiped buffers, no swap, no core dumps |

## Cryptography

sshvault implements no cryptography of its own.

| Use | Algorithm | Library |
|---|---|---|
| Vault and export encryption | age v1: scrypt (r=8, p=1, 16-byte salt) wrapping a file key; ChaCha20-Poly1305 in STREAM | `age` |
| Passphrase cost | scrypt N = 2^18 (256 MiB, about a second); OWASP's minimum is N = 2^17 with r=8 | |
| Cost for data encrypted with K | scrypt N = 2^10: K is 256 random bits, so stretching protects nothing | |
| Highest cost the daemon spends on a supplied file | N = 2^20 (1 GiB) | |
| K | 256 bits from the kernel's random source | `getrandom` |
| Agent signatures | Ed25519; ECDSA P-256 and P-384 (constant-time); RSA PKCS#1 v1.5 with SHA-256 or SHA-512, blinded | `ssh-key`, `p256`, `p384`, `rsa` |

Accepted advisories are listed, with reasons, in `deny.toml` and `osv-scanner.toml`.

## Supply chain

- Dependencies come only from crates.io and are checked by `cargo deny` (advisories,
  licenses, sources) and OSV-Scanner; Dependabot proposes updates after a week's
  cooldown.
- Workflows pin actions by commit and are checked by zizmor. CodeQL and the fuzz
  targets run on every change, OpenSSF Scorecard on every change to `main`.
- Releases are built reproducibly (the release workflow builds twice and compares), carry
  their dependency list (`cargo auditable`), a CycloneDX SBOM, and signed build
  provenance. The apt repository is signed with a key that exists only as a repository
  secret, and publishing needs the maintainer's approval.

## Known limitations

- **Tracing an unlocked shell.** A process that can trace an unlocked shell can act as
  it: sign, read the config and change the vault. With Yama's `ptrace_scope` at 0, or
  without Yama, any of the owner's processes could, so `unlock`, `create` and `import`
  refuse to unlock there (`procs::check_tracing_restricted`; VM "unlocking is refused
  where any process could trace the shell"). The check is the client's, made for the
  owner's sake when they unlock; the setting is root's, and changing it later is root's
  doing, which is out of scope. At 1, the shell's ancestors, such as the terminal
  emulator or a tmux server, can still trace it.
- **Seeing the passphrase typed.** On X11 any client of the owner's display can read
  keystrokes, so A1 can capture the passphrase and unlock by itself. Wayland does not
  allow this. A process that can write to the terminal of an unlocked shell can inject
  commands where the kernel still permits `TIOCSTI`.
- **Pipes and terminals.** Any of the owner's processes can open another's pipes and
  terminal through `/proc/<pid>/fd` (Yama restricts attaching, not this) and read what
  passes through them. A passphrase piped to `--passphrase-stdin` or typed at the prompt
  can be taken on its way, and so can a secret that a program in an unlocked shell passes
  on through a pipe, a helper or its environment. A program that reads the secret from
  the vault itself, as ssh does its config, is not exposed: the file cannot be reopened
  (C1).
- **RSA timing.** The `rsa` crate's arithmetic is not constant-time (RUSTSEC-2023-0071).
  Signatures are blinded, but a process in an unlocked shell can time many of them;
  Ed25519 is recommended.
- **Copies inside libraries.** Parsers for keys and tar archives, and age's stream
  buffers, may keep short-lived copies that are not wiped. They are in the daemon's
  memory, which is never swapped or dumped.
- **No common-password check.** NIST also recommends refusing passphrases found in
  breach corpora; sshvault checks only the length.
- **Hibernation** writes all memory, the daemon's included, to disk.
- **P-521 keys** are not supported by the agent.
