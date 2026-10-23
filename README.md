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
every process it starts, sees your decrypted `config` and keys under `/run/sshvault/self/`.
Every other process running as you sees an empty directory. There is no agent socket to
find, nothing to borrow, and neither keys nor config sit in your home directory for other
processes to read or rewrite.

## What it does not do

sshvault is not the perfect solution. It is an attempt to make this noticeably better
without making SSH painful to work with: you unlock once per shell, and everything else
behaves as before. It draws the line at the shell you unlocked, and a lot is still yours
to get right:

- **What you do in an unlocked shell.** Anything started there has access, including the
  AI agent or the `curl | sh` you run in it. Keep a shell for SSH and do the risky things
  elsewhere.
- **A replaced `ssh`, or strange things in `$PATH`.** Your own processes can write to
  `~/.local/bin`, `~/.bashrc` and the other files your shell trusts. An alias, a function
  or a binary planted there runs inside the next shell you unlock, and sshvault cannot
  tell it from the real thing.
- **The `Include` line in `~/.ssh/config`.** It is editable the same way, and an entry
  placed above it wins. `sudo chattr +i ~/.ssh ~/.ssh/config` stops that; `authorized_keys`
  and `known_hosts` stay editable in place.
- **Root.** Anything that is, or can become, root is out of scope.

## How it is meant to be used

```sh
sudo systemctl enable --now sshvault        # once per machine
sshvault create --from ~/ssh-to-migrate     # once: prompts for a passphrase
sshvault stub                               # once: put its output at the top of ~/.ssh/config
sshvault unlock                             # in each shell that should have access
```

`sshvault stub` prints an `Include` line that must sit at the top of `~/.ssh/config`. In an
unlocked shell the vault's entries take precedence; everywhere else the include resolves
to nothing and your existing config applies as before. Migrate one host at a time.
`~/.ssh` itself, `authorized_keys` and inbound SSH are untouched.

Inside the vault, refer to files through the mount, e.g.
`IdentityFile /run/sshvault/self/id_ed25519`. Keep `ControlPath` elsewhere
(`$XDG_RUNTIME_DIR`): unix sockets cannot live on the mount. `known_hosts` stays in `~/.ssh`
for now, since the vault is read-only.

Other commands: `sshvault status`, `sshvault lock`, `sshvault lock --all`.

### Backups and moving to another machine

```sh
sshvault export ~/sshvault-backup.age       # from an unlocked shell
sshvault import ~/sshvault-backup.age       # on the new machine; prompts for its passphrase
```

An export is your vault exactly as stored: a standard, passphrase-encrypted
[age](https://age-encryption.org) file. Only an unlocked shell may export, so your other
processes cannot even get a copy to try passphrases against. `import` checks the
passphrase before storing anything. Replacing an existing vault also needs an unlocked
shell. The old one is kept as `vault.age.previous`, where an administrator can restore
it, and shells that are already unlocked see the new contents at once.

## How it works

- One daemon per machine. systemd starts it as root; it mounts a single FUSE filesystem at
  `/run/sshvault`, then irrevocably drops to the `sshvault` account before serving
  anything. Your processes cannot signal it, trace it, read its memory, unmount the view or
  place a socket or file where it lives (its socket is `/run/sshvault.sock`).
- The client refuses a daemon that runs as your own uid or whose socket directory is not
  root's: such a daemon could be any of your processes, waiting for your passphrase.
- Vaults are passphrase-encrypted `age` archives in `/var/lib/sshvault/<uid>/`, readable
  only by the daemon. The client encrypts; the daemon checks that the passphrase opens
  what it is given before storing it, and replaces an existing vault only for an unlocked
  shell.
- Every FUSE request carries the caller's pid and uid. Like `/proc/self`, `self` is the
  same path for everyone: each user gets their own directory there (a separate inode, owned
  by that user, mode 0700), and its contents only in a process that is, or descends from,
  an unlocked shell of that user. Vault paths therefore contain no username, so a vault
  works unchanged on machines where your account is named differently. Shells are held
  by pidfd, so a reused pid inherits nothing.
- Kernel caching is off (zero TTLs, direct I/O), so nothing seen by one process is
  served to another from cache.
- Decrypted data exists only in the daemon's memory, in buffers locked against swap and
  excluded from core dumps (an unlock fails rather than hold it otherwise), and is wiped
  when that user's last unlocked shell exits.
- `unlock` registers the shell that ran it, and only if that shell is in the same session:
  a client orphaned with `(sshvault unlock &)` is adopted by `systemd --user`, which must
  not end up unlocking the whole login.

## Not there yet

- The vault is read-only: `known_hosts` cannot be updated in it, and there is no way yet
  to change its contents or passphrase in place. Making the view writable for unlocked
  shells is next.

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
checked against Ubuntu's signed `SHA256SUMS`, and boots each run from a fresh overlay.
Inside, `tests/vm/guest-tests.sh` installs the package and tests it as root, with two users
whose processes run under real `systemd --user` managers, then upgrades, removes and purges
it. Results come back as TAP on the VM's second serial port.

`packaging/` has the systemd unit and the `sysusers.d` entry for the `sshvault` account.
Installing or upgrading the package restarts the service, which locks every shell.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed
as above, without any additional terms or conditions.
