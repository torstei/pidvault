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
every process it starts, sees your decrypted `config` and keys under
`/run/sshvault/default/`. Every other process running as you sees an empty directory. With
several vaults, each shell sees only the ones it unlocked: one shell can have your GitHub
key and another your production keys. There is no agent socket to
find, nothing to borrow, and neither keys nor config sit in your home directory for other
processes to read or rewrite.

## What it does not do

sshvault is not the perfect solution. It is an attempt to make this noticeably better
without making SSH painful to work with: you unlock once per shell, and everything else
behaves as before. It draws the line at the shell you unlocked, and a lot is still yours
to get right:

- **What you do in an unlocked shell.** Anything started there has access, including the
  AI agent or the `curl | sh` you run in it — and access includes changing the vault, so
  whatever it plants there is still there in the next shell you unlock. Keep a shell for
  SSH and do the risky things elsewhere.
- **A replaced `ssh`, or strange things in `$PATH`.** Your own processes can write to
  `~/.local/bin`, `~/.bashrc` and the other files your shell trusts. An alias, a function
  or a binary planted there runs inside the next shell you unlock, and sshvault cannot
  tell it from the real thing.
- **The sshvault block in `~/.ssh/config`.** It is editable the same way, and an entry
  placed above it wins. `sudo chattr +i ~/.ssh ~/.ssh/config` stops that; `authorized_keys`
  and `known_hosts` stay editable in place.
- **Root.** Anything that is, or can become, root is out of scope.

## How it is meant to be used

```sh
sudo apt install ./sshvault_*.deb           # once per machine; starts the service
sshvault create                             # once: asks for a passphrase, unlocks this shell
$EDITOR /run/sshvault/default/config        # fill the vault from this shell
sshvault stub                               # once: put its output at the top of ~/.ssh/config
sshvault unlock                             # in each further shell that should have access
```

`create` and `import` unlock the shell they ran in; `--no-unlock` leaves it locked.
`sshvault create --from DIR` starts from the files in a directory instead of an empty
vault. Keys you copy in from `~/.ssh` have been readable by every process you ran so far:
the clean move is to generate new ones straight into the vault, e.g.
`ssh-keygen -t ed25519 -f /run/sshvault/default/id_ed25519`, and retire the old ones.

`sshvault stub` prints a block that must sit at the top of `~/.ssh/config`:

```
Match exec "/usr/bin/sshvault status --quiet"
    AddKeysToAgent no
    Include /run/sshvault/*/config
```

In a shell with a vault unlocked, the vaults' entries take precedence, and no key is
handed to an agent, whatever a later `AddKeysToAgent yes` says: an agent would make the
keys available to every process again. Everywhere else the block does nothing and your
existing config applies as before, so you can migrate one host at a time. `~/.ssh`
itself, `authorized_keys` and inbound SSH are untouched. `ssh-add` on a vault key would
still hand it over; don't.

An unlocked shell, and everything it starts, can change the vault like any directory:
editors, `sed -i`, `ssh-keygen` and `ssh` itself all work. Changes are saved on `fsync`,
when a written file is closed, on a rename, and otherwise within a second.

Inside the vault, refer to files through the mount, e.g.
`IdentityFile /run/sshvault/default/id_ed25519` and
`UserKnownHostsFile /run/sshvault/default/known_hosts`. Keep `ControlPath` elsewhere
(`$XDG_RUNTIME_DIR`): unix sockets cannot live on the mount. A vault holds up to 4 MiB.

Other commands: `sshvault status`, `sshvault lock` (this shell) and `sshvault lock --all`
(every shell), and `sshvault passwd` to change a passphrase.

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

- One daemon per machine. systemd starts it as root; it mounts a single FUSE filesystem at
  `/run/sshvault`, then irrevocably drops to the `sshvault` account before serving
  anything. Your processes cannot signal it, trace it, read its memory, unmount the view or
  place a socket or file where it lives (its socket is `/run/sshvault.sock`).
- The client refuses a daemon that runs as your own uid or whose socket directory is not
  root's: such a daemon could be any of your processes, waiting for your passphrase.
- Each vault is one file, `/var/lib/sshvault/<uid>/<name>.sshvault`, readable only by the
  daemon. It holds a random 256-bit key K encrypted with your passphrase, and the contents
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
