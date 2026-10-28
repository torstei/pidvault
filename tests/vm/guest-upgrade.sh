#!/bin/bash
# Runs as root inside a throwaway VM started by run.sh and prints TAP: installs the latest
# published release the way users do, puts a vault to use, then upgrades to DEB.
set -uo pipefail

DEB=$1
SEED=$(dirname "$DEB")
. "$SEED/lib.sh"

skip_all() {
    echo "# skipping the upgrade: $1"
    finish
    exit 0
}

install -m 644 "$SEED/published.asc" /etc/apt/keyrings/sshvault.asc
echo "deb [signed-by=/etc/apt/keyrings/sshvault.asc] https://torstei.github.io/sshvault stable main" \
    > /etc/apt/sources.list.d/sshvault.list
only_sshvault=(-o Dir::Etc::sourcelist=/etc/apt/sources.list.d/sshvault.list -o Dir::Etc::sourceparts=-)
if out=$(apt-get update -q "${only_sshvault[@]}" 2>&1); then
    ok "the published repository can be reached"
else
    not_ok "the published repository can be reached" "$out"
    finish
    exit 1
fi

previous=$(apt-cache policy sshvault | awk '/Candidate:/ { print $2 }')
building=$(dpkg-deb --field "$DEB" Version)
[[ -n "$previous" && "$previous" != "(none)" ]] || skip_all "no release published yet"
dpkg --compare-versions "$building" gt "$previous" || skip_all "$building is not newer than $previous"
echo "# upgrading from $previous to $building"

# --- the previous release, in use --------------------------------------------

check "the previous release installs from the published repository" \
    apt-get install -y -q "${only_sshvault[@]}" sshvault
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
check "alice logs in with the vault key" equals "$(unlocked alice 'ssh vm echo logged-in')" logged-in
check "alice edits her config" unlocked alice "sed -i 's/LogLevel ERROR/LogLevel QUIET/' /run/sshvault/default/config"
as alice ssh-keygen -q -t ed25519 -N 'key secret' -C old-github -f /tmp/alice-old-key
check "alice adds a protected key" unlocked alice \
    "echo 'key secret' | sshvault add-key --passphrase-stdin --name id_github /tmp/alice-old-key >/dev/null"
as alice sh -c 'echo work-secret-phrase | sshvault create work --no-unlock --passphrase-stdin --work-factor 12 >/dev/null'

# --- upgrade ----------------------------------------------------------------

check "the package under test upgrades it" apt-get install -y -q "$DEB"
check "the package under test is installed" equals "$(dpkg-query -W -f '${Version}' sshvault)" "$building"
check "service is active" systemctl is-active --quiet sshvault
check "the mount helper is active" systemctl is-active --quiet sshvault-mount
check "daemon runs as the sshvault account" equals "$(ps -o user= -p "$(daemon_pid)")" sshvault
check "the daemon holds no capabilities" live_daemon caps_dropped
check "view is mounted" equals "$(findmnt -n -o SOURCE,FSTYPE /run/sshvault)" "sshvault fuse.sshvault"
check "socket is connectable by all, in root's /run" equals "$(stat -c '%A %U' /run/sshvault.sock)" "srw-rw-rw- root"
check "agent socket is connectable by all, in root's /run" equals "$(stat -c '%A %U' /run/sshvault-agent.sock)" "srw-rw-rw- root"
check "vault store belongs to the daemon" equals "$(stat -c '%U %a' /var/lib/sshvault)" "sshvault 700"
check "alice's vaults belong to the daemon" equals \
    "$(stat -c '%U %a' /var/lib/sshvault/"$(id -u alice)"/{default,work}.sshvault | sort -u)" "sshvault 600"

# --- the vault after the upgrade ---------------------------------------------

check "alice lists both her vaults" equals "$(as alice ls /run/sshvault | tr '\n' ' ')" "default work "
check "the vault opens with its passphrase and keeps the edit" unlocked alice \
    'grep -q "LogLevel QUIET" /run/sshvault/default/config'
check "the second vault opens too" as alice sh -c \
    'echo work-secret-phrase | sshvault unlock work --passphrase-stdin >/dev/null && test -d /run/sshvault/work'
check "the agent signs with the vault key" equals "$(unlocked alice 'ssh vm echo logged-in')" logged-in
check "the added key is still offered, and still unreadable" unlocked alice \
    'SSH_AUTH_SOCK=/run/sshvault-agent.sock ssh-add -l | grep -q old-github && ! cat /run/sshvault/default/id_github 2>/dev/null'
check "another process of alice sees nothing" refused as alice cat /run/sshvault/default/config
check "alice writes to the vault after the upgrade" unlocked alice 'echo "# after" >> /run/sshvault/default/config'
systemctl restart sshvault
check "the write survives a restart" unlocked alice 'grep -q "^# after" /run/sshvault/default/config'
check "daemon logged no warnings" refused sh -c 'journalctl -b -u sshvault | grep -qi warning'

finish
