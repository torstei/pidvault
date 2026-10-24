# sshvault

Per-shell access to an encrypted SSH configuration directory.

## The problem

You did the right thing: your SSH key has a good passphrase. Then you added it to
`ssh-agent` (or your desktop did it for you) so you would not have to type it forty times
a day — and from that moment the unlocked key is available to **every process running as
your user**, for as long as you are logged in:

- the AI coding agent you let loose in a repository,
- your web browser, and that strange extension you decided you needed,
- the install script you downloaded with `curl` and piped to `/bin/sh`,
- every `npm install` postinstall hook, editor plugin and build script you run.

None of them have to ask. `$SSH_AUTH_SOCK` points at the agent, and a process that was not
given the variable finds it in `/proc/<pid>/environ` of any of your shells. They cannot
copy the key, but they do not need to: they can sign with it, which means logging in
wherever you can and pushing wherever you can. The rest of `~/.ssh` is no better guarded —
a key without a passphrase is just a file to read, one `ProxyCommand` added to
`~/.ssh/config` runs code the next time *you* connect, and an open `ControlMaster`
connection lets anyone run commands on that host without any key at all.

None of this is a bug. On Unix, the boundary is the user id, and everything you run is you.

## What sshvault does instead

Access is granted per shell, not per login. A shell that has run `sshvault unlock`, and
every process it starts, sees your decrypted `config` under `/run/sshvault/default/` and
can sign with the keys stored there — through sshvault's own agent, which answers only
processes of unlocked shells. The keys themselves cannot be read, not even from an
unlocked shell, so nothing running there can take them along. Every other process running
as you sees an empty directory and an agent with no keys. With several vaults, each shell
sees only the ones it unlocked: one shell can have your GitHub key and another your
production keys.

## What it does not do

sshvault is not the perfect solution. It is an attempt to make this noticeably better
without making SSH painful to work with: you unlock once per shell, and everything else
behaves as before. It draws the line at the shell you unlocked, and a lot is still yours
to get right:

- **What you do in an unlocked shell.** Anything started there can sign with your keys
  while the shell is unlocked, including the AI agent or the `curl | sh` you run in it.
  It cannot copy them, but it can change the vault, and whatever it plants there is still
  there in the next shell you unlock. Keep a shell for SSH and do the risky things
  elsewhere.
- **A replaced `ssh`, or strange things in `$PATH`.** Your own processes can write to
  `~/.local/bin`, `~/.bashrc` and the other files your shell trusts. An alias, a function
  or a binary planted there runs inside the next shell you unlock, and sshvault cannot
  tell it from the real thing.
- **The sshvault block in `~/.ssh/config`.** It is editable the same way, and an entry
  placed above it wins. `sudo chattr +i ~/.ssh ~/.ssh/config` stops that; `authorized_keys`
  and `known_hosts` stay editable in place.
- **Root.** Anything that is, or can become, root is out of scope.

## Installing

For Ubuntu 24.04 or later, on amd64, from the project's signed apt repository:

```sh
sudo curl -fsSLo /etc/apt/keyrings/sshvault.asc https://torstei.github.io/sshvault/sshvault.asc
echo "deb [signed-by=/etc/apt/keyrings/sshvault.asc] https://torstei.github.io/sshvault stable main" \
  | sudo tee /etc/apt/sources.list.d/sshvault.list
sudo apt update && sudo apt install sshvault
```

The repository is signed with the key with fingerprint
`D1434A919B60EEC6384F3CB716EFFB5096BD7539`; check it with
`gpg --show-keys /etc/apt/keyrings/sshvault.asc` before trusting it. The same key is in
this repository as `packaging/sshvault-apt.asc`. Each `.deb` on the
[releases page](https://github.com/torstei/sshvault/releases) also carries a build
attestation: `gh attestation verify sshvault_*.deb --repo torstei/sshvault` shows that it
was built by this repository's release workflow, and from which commit.

Installing starts the service. Upgrading restarts it, which locks every shell.

## How it is meant to be used

```sh
sudo apt install sshvault                   # once per machine; see Installing
sshvault create                             # once: asks for a passphrase, unlocks this shell
$EDITOR /run/sshvault/default/config        # starts as a commented example
sshvault stub                               # once: put its output at the top of ~/.ssh/config
sshvault unlock                             # in each further shell that should have access
```

`create` and `import` unlock the shell they ran in; `--no-unlock` leaves it locked.
`sshvault create --from DIR` starts from the files in a directory instead of an empty
vault. Keys you copy in from `~/.ssh` have been readable by every process you ran so far:
the clean move is to generate new ones straight into the vault, e.g.
`ssh-keygen -t ed25519 -N '' -f /run/sshvault/default/id_ed25519`, and retire the old ones.

`sshvault stub` prints a block that must sit at the top of `~/.ssh/config`:

```
Match exec "/usr/bin/sshvault status --quiet"
    IdentityAgent /run/sshvault-agent.sock
    AddKeysToAgent no
    Include /run/sshvault/*/config
```

In a shell with a vault unlocked, the vaults' entries take precedence and ssh signs
through the vault agent, never handing a key to any other agent whatever a later
`AddKeysToAgent yes` says. Everywhere else the block does nothing and your existing
config applies as before, so you can migrate one host at a time. `~/.ssh` itself,
`authorized_keys` and inbound SSH are untouched. Shells with a vault unlocked do not use
your desktop agent, so a key you still keep there works only in other shells until you
move it into a vault.

If that block is more magic than you want in `~/.ssh/config`, leave it out and name the
vault's config yourself: `ssh -F /run/sshvault/default/config HOST`. A new vault's
starter `config` already points ssh at the vault agent, so nothing else is needed. `-F`
replaces `~/.ssh/config` and `/etc/ssh/ssh_config` rather than adding to them; jump hosts
work with `ProxyJump`, which passes `-F` on, but not with a `ProxyCommand` running
`ssh`, which does not; and other tools need telling too (`scp -F`,
`rsync -e "ssh -F …"`, git's `core.sshCommand`).

An unlocked shell, and everything it starts, can change the vault like any directory:
editors, `sed -i`, `ssh-keygen` and `ssh` itself all work. Changes are saved on `fsync`,
when a written file is closed, on a rename, and otherwise within a second.

Inside the vault, refer to files through the mount, e.g.
`IdentityFile /run/sshvault/default/id_ed25519` (with its `.pub` beside it) and
`UserKnownHostsFile /run/sshvault/default/known_hosts`. Keep `ControlPath` elsewhere
(`$XDG_RUNTIME_DIR`): unix sockets cannot live on the mount. A vault holds up to 4 MiB.

`sshvault unlock --for 30m` makes any unlock end by itself; `status` shows how long is
left. Once no shell has a vault unlocked, its decrypted contents and key leave memory.

Other commands: `sshvault status`, `sshvault lock` (this shell) and `sshvault lock --all`
(every shell), and `sshvault passwd` to change a passphrase.

### Keys and the agent

A file in a vault is a key when it is an unencrypted private key in OpenSSH format, as
`ssh-keygen -N ''` writes them. sshvault tells by its first bytes, which hold nothing
secret, so a key is protected from the moment it is written:

- It shows as mode `200` and cannot be opened for reading by anyone. Its bytes cannot be
  changed either, only appended to, emptied, renamed or deleted, so nothing can turn it
  back into a readable file; a copy is a key too. `export` (which asks for the
  passphrase) is the only way to get it out again.
- The vault agent signs with it, for processes of shells that unlocked that vault, and
  checks that on every request: lock the vault and its keys stop working at once.
  Asking the agent to add or remove keys (`ssh-add`) is refused; keys get in by being
  written to a vault.
- Prefer ed25519 keys. The agent signs with RSA through the `rsa` crate, whose arithmetic
  is not constant-time ([RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071),
  unfixed); every RSA signature is blinded against timing, but a process in an unlocked
  shell may time as many as it likes, and ed25519 does not have the problem.
- Everything else stays an ordinary file: `config`, `known_hosts`, `.pub` files, and keys
  with a passphrase (which the agent cannot use; `ssh-keygen -p -N '' -f KEY` removes
  the passphrase, after which the key is protected). Keys in the old PEM format stay
  ordinary too; `ssh-keygen -p -f KEY` rewrites them in OpenSSH format.

To bring in a key you already have, `sshvault add-key ~/.ssh/id_github` (with `--vault`
and `--name` if you like) asks once for its passphrase, if it has one, and writes the key
without it, and its `.pub`, into the vault. The original is left alone: it has been
readable by every process you ran, so retire it once the copy works.

A key that deserves more protection than the rest belongs in a vault of its own: its own
passphrase, unlocked only in the shell that needs it, and with its own `agent.toml`.
Unlock it for just as long as you need it, and it locks again by itself even if you
forget:

```sh
sshvault unlock signing --for 10m           # also 90s, 1h30m; unlocking again sets a new limit
```

ssh tells the agent which connections it opens on behalf of a host you forward your
agent to. On those, the vault agent offers no key unless the vault's `agent.toml` allows
it, so remote root cannot sign with your keys even where `ForwardAgent yes` is set:

```toml
# /run/sshvault/default/agent.toml
[keys."id_jump"]          # the key's path in the vault
forward = true            # may sign through hosts this agent is forwarded to
```

A policy that cannot be read lets nothing be forwarded, and `sshvault status` says why.
Older ssh versions do not mark forwarded connections; with those, everything looks local.

### More than one vault

```sh
sshvault create prod                        # its own key, and its own passphrase if you like
sshvault unlock prod                        # in the shell that should have it
$EDITOR /run/sshvault/prod/config
sshvault lock prod                          # lock just that one
```

Every command takes a vault name and defaults to `default`; `export` and `import` take
`--vault NAME`. Vaults are included in alphabetical order and ssh uses the first value it
finds for each setting, so a `Host *` block in one vault applies to every host in shells
that have it unlocked. Paths inside a vault contain its name: renaming one is not
supported.

### Backups and moving to another machine

```sh
sshvault export ~/sshvault-backup.age       # from an unlocked shell; asks for the passphrase
sshvault import ~/sshvault-backup.age       # on the new machine; asks for its passphrase
```

An export is a standard [age](https://age-encryption.org) file encrypted with your
passphrase, holding a tar archive of the vault (`age -d backup.age | tar -t` lists it).
Only an unlocked shell may export, so your other processes cannot even get a copy to try
passphrases against. `import` checks the passphrase before storing anything. Replacing an
existing vault also needs an unlocked shell. The old one is kept as
`<name>.sshvault.previous`, where an administrator can restore it, and shells that are
already unlocked see the new contents at once.

## How it works

- One daemon per machine, running as the `sshvault` account and never as root: no
  capabilities, a read-only system, no `/home`, no devices, no network and a system-call
  allow-list (`systemd-analyze security` rates it 0.5, "safe"). systemd creates its sockets
  in root's `/run`, and a separate, minimal root service does the one thing that needs
  root: it mounts the FUSE filesystem at `/run/sshvault`, hands the connection to the
  daemon, and unmounts as soon as the daemon is gone. Your processes cannot signal the
  daemon, trace it, read its memory, unmount the view or place a socket or file where it
  lives.
- The client refuses a daemon that runs as your own uid or whose socket directory is not
  root's: such a daemon could be any of your processes, waiting for your passphrase.
- Each vault is one file, `/var/lib/sshvault/<uid>/<name>.sshvault`, readable only by the
  daemon. Vaults belong to the uid, as a home directory does: renaming an account keeps
  them, and when an account is deleted its `/var/lib/sshvault/<uid>` should go with its
  home directory, or a later account given the same uid will find them listed (though it
  cannot open them). It holds a random 256-bit key K encrypted with your passphrase, and the contents
  encrypted with K, both in `age` passphrase format; one file, so a save replaces both in
  a single rename. Unlocking costs one scrypt run on your passphrase; saving costs almost
  nothing, since K needs no slow key derivation. Because only someone holding K can
  produce contents that decrypt with it, nobody without K can plant a vault.
- Every FUSE request carries the caller's pid and uid. Like `/proc/self`, a vault's path is
  the same for everyone: each user gets their own directory there (a separate inode, owned
  by that user, mode 0700), listed only to them, and its contents only in a process that
  is, or descends from, a shell of that user that unlocked that vault. Vault paths
  therefore contain no username, so a vault works unchanged on machines where your account
  is named differently. Shells are held by pidfd, so a reused pid inherits nothing.
- Kernel caching is off (zero TTLs, direct I/O), so nothing seen by one process is
  served to another from cache.
- Decrypted data and K exist only in the daemon's memory, in buffers locked against swap
  and excluded from core dumps (an unlock fails rather than hold them otherwise), and are
  wiped when that user's last unlocked shell exits — after any unsaved change is saved.
  Unlocking another shell while one is open only checks the passphrase and keeps what is
  in memory.
- The daemon is reachable by everyone, so it limits what anyone can make it do: passphrase
  checks run one at a time per user, and after each wrong passphrase the next waits twice
  as long, up to half a minute, so a process cannot guess at the daemon's expense;
  scrypt runs one at a time across the daemon, at most at cost 2^20, whatever a supplied
  file asks for; and connections are capped per user and in total.
- `unlock` registers the shell that ran it, and only if that shell is in the same session:
  a client orphaned with `(sshvault unlock &)` is adopted by `systemd --user`, which must
  not end up unlocking the whole login.

## Development

```sh
cargo test          # unit and end-to-end tests, no root needed
tests/vm/run.sh     # the .deb, systemd and root paths, in a throwaway VM; no sudo
cargo deb           # target/debian/sshvault_<version>_amd64.deb
```

The end-to-end tests need `/dev/fuse` and `fusermount3`. They run the daemon with
`--unprivileged` and set `SSHVAULT_INSECURE_ALLOW_SAME_UID_DAEMON`, which is exactly the
setup the client otherwise refuses. One test logs in to a throwaway `sshd` on a random
local port with a key that exists only in the vault.

`tests/vm/run.sh` needs access to `/dev/kvm`, `qemu-system-x86_64`, `genisoimage`, `gpgv`
and `cargo-deb`. It downloads the Ubuntu cloud image once into `~/.cache/sshvault-vm`,
checked against Ubuntu's signed `SHA256SUMS`, and boots two VMs in parallel, each from a
fresh overlay. In one, `tests/vm/guest-tests.sh` installs the package and tests it as root,
with two users whose processes run under real `systemd --user` managers, then reinstalls,
removes and purges it. In the other, `tests/vm/guest-upgrade.sh` installs the latest release
from the published apt repository, puts a vault to use, upgrades to the package under test
and checks that the vault, its keys and the agent still work. It skips the upgrade when
nothing older than the package under test is published. Results come back as TAP on each
VM's second serial port.

`packaging/` has the systemd units — the daemon and its sockets, and the mount helper and
its socket — and the `sysusers.d` entry for the `sshvault` account.

`cargo deny check` (configured in `deny.toml`, whose accepted advisories
`osv-scanner.toml` repeats for Scorecard) checks dependencies against the RustSec
advisories, the allowed licenses and crates.io as the only source; CI runs it, and lintian on
the package. `packaging/sshvault.1` and `packaging/changelog.Debian` are generated: tests
fail when they are stale and say how to regenerate them.

To release, bump the version in `Cargo.toml`, turn `## Unreleased` in `CHANGELOG.md` into
`## X.Y.Z - YYYY-MM-DD`, regenerate the man page and Debian changelog, merge, and push a tag
`vX.Y.Z` on `main`. The release workflow runs the full test suite and builds the package
twice, in different directories, refusing to go on unless both are identical. The binary
carries its dependency list (`cargo auditable`), and the package gets a build provenance
and a CycloneDX SBOM attestation. The workflow then waits for approval in the `release`
environment before it creates the GitHub release, signs the apt repository (built by
`scripts/build-apt-repo.sh` from every released package) and publishes it on GitHub Pages.
Only that approved job can reach the signing key.

Anyone can check a downloaded package with `gh attestation verify sshvault_X.Y.Z-1_amd64.deb
--repo torstei/sshvault`, adding `--bundle` with the release's `.sigstore.json` to check it
without asking GitHub, or rebuild it from the tag and compare: with the Rust version
named in the release notes, `SOURCE_DATE_EPOCH` set to the tagged commit's time
(`git log -1 --format=%ct`), `cargo auditable build --release --locked` and
`cargo deb --no-build`.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed
as above, without any additional terms or conditions.
