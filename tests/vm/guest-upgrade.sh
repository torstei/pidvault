#!/bin/bash
# Runs as root inside a throwaway VM started by run.sh and prints TAP: installs sshvault
# 0.3.1, the last release before the rename, puts vaults to use, then moves to DEB the way
# the README says.
set -uo pipefail

DEB=$1
SEED=$(dirname "$DEB")
. "$SEED/lib.sh"

installed() { [[ $(dpkg-query -W -f '${db:Status-Status}' "$1" 2>/dev/null) == installed ]]; }

old_unlocked() {
    local user=$1
    shift
    as "$user" sh -c "echo $user$PASS_SUFFIX | sshvault unlock --passphrase-stdin >/dev/null && $*"
}

# --- sshvault, in use --------------------------------------------------------

check "sshvault installs" apt-get install -y -q "$SEED/previous.deb"
check "its service is active" systemctl is-active --quiet sshvault

useradd --create-home --shell /bin/bash alice
usermod --password '*' alice
as alice sh -c '
    set -e
    mkdir -p ~/src ~/.ssh && chmod 700 ~/.ssh
    ssh-keygen -q -t ed25519 -N "" -f ~/src/id_vm
    cat ~/src/id_vm.pub >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys
    printf "Host vm\n  HostName 127.0.0.1\n  User alice\n  IdentityFile /run/sshvault/default/id_vm\n  IdentitiesOnly yes\n  BatchMode yes\n  StrictHostKeyChecking no\n  UserKnownHostsFile /dev/null\n  LogLevel ERROR\n" > ~/src/config
    sshvault stub > ~/.ssh/config
'
check "alice creates a vault" as alice sh -c \
    'echo alice-secret-phrase | sshvault create --passphrase-stdin --work-factor 12 --from ~/src >/dev/null && rm ~/src/id_vm'
check "alice logs in with the vault key" equals "$(old_unlocked alice 'ssh vm echo logged-in')" logged-in
check "alice edits her config" old_unlocked alice "sed -i 's/LogLevel ERROR/LogLevel QUIET/' /run/sshvault/default/config"
as alice ssh-keygen -q -t ed25519 -N 'key secret' -C old-github -f /tmp/alice-old-key
check "alice adds a protected key" old_unlocked alice \
    "echo 'key secret' | sshvault add-key --passphrase-stdin --name id_github /tmp/alice-old-key >/dev/null"
as alice sh -c 'echo work-secret-phrase | sshvault create work --no-unlock --passphrase-stdin --work-factor 12 >/dev/null'

# --- upgrade ----------------------------------------------------------------

check "pidvault installs in its place" apt-get install -y -q "$DEB"
check "sshvault is removed" refused installed sshvault
check "its store is gone" refused test -e /var/lib/sshvault
check "service is active" systemctl is-active --quiet pidvault
check "the mount helper is active" systemctl is-active --quiet pidvault-mount
check "daemon runs as the pidvault account" equals "$(ps -o user= -p "$(daemon_pid)")" pidvault
check "the daemon holds no capabilities" live_daemon caps_dropped
check "view is mounted" equals "$(findmnt -n -o SOURCE,FSTYPE /run/pidvault)" "pidvault fuse.pidvault"
check "socket is connectable by all, in root's /run" equals "$(stat -c '%A %U' /run/pidvault.sock)" "srw-rw-rw- root"
check "agent socket is connectable by all, in root's /run" equals "$(stat -c '%A %U' /run/pidvault-agent.sock)" "srw-rw-rw- root"
check "vault store belongs to the daemon" equals "$(stat -c '%U %a' /var/lib/pidvault)" "pidvault 700"
check "alice's vaults belong to the daemon" equals \
    "$(stat -c '%U %a' /var/lib/pidvault/"$(id -u alice)"/{default,work}.pidvault | sort -u)" "pidvault 600"

# --- the vault after the upgrade ---------------------------------------------

check "alice lists both her vaults" equals "$(as alice ls /run/pidvault | tr '\n' ' ')" "default work "
check "alice points her stub and config at the new paths" unlocked alice \
    "pidvault stub > ~/.ssh/config && sed -i 's|/run/sshvault|/run/pidvault|g' /run/pidvault/*/config"
check "the vault opens with its passphrase and keeps the edit" unlocked alice \
    'grep -q "LogLevel QUIET" /run/pidvault/default/config'
check "the second vault opens too" as alice sh -c \
    'echo work-secret-phrase | pidvault unlock work --passphrase-stdin >/dev/null && test -d /run/pidvault/work'
check "the agent signs with the vault key" equals "$(unlocked alice 'ssh vm echo logged-in')" logged-in
check "the added key is still offered, and still unreadable" unlocked alice \
    'SSH_AUTH_SOCK=/run/pidvault-agent.sock ssh-add -l | grep -q old-github && ! cat /run/pidvault/default/id_github 2>/dev/null'
check "another process of alice sees nothing" refused as alice cat /run/pidvault/default/config
check "alice writes to the vault after the upgrade" unlocked alice 'echo "# after" >> /run/pidvault/default/config'
systemctl restart pidvault
check "the write survives a restart" unlocked alice 'grep -q "^# after" /run/pidvault/default/config'
check "daemon logged no warnings" refused sh -c 'journalctl -b -u pidvault | grep -qi warning'

finish
