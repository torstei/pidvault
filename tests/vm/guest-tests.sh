#!/bin/bash
# Runs as root inside the throwaway VM started by run.sh and prints TAP.
set -uo pipefail

DEB=$1
. "$(dirname "$0")/lib.sh"

# --- installation -----------------------------------------------------------

REPO=$(dirname "$DEB")/repo
only_pidvault=(-o Dir::Etc::sourcelist=/etc/apt/sources.list.d/pidvault.list -o Dir::Etc::sourceparts=-)
use_repo_signed_by() {
    echo "deb [signed-by=$1] file:$REPO stable main" > /etc/apt/sources.list.d/pidvault.list
}
use_repo_signed_by "$(dirname "$DEB")/other.asc"
check "apt refuses the repository under another signing key" refused apt-get update -q "${only_pidvault[@]}"
install -m 644 "$REPO/pidvault.asc" /etc/apt/keyrings/pidvault.asc
use_repo_signed_by /etc/apt/keyrings/pidvault.asc
check "apt accepts the signed repository" apt-get update -q "${only_pidvault[@]}"
check "package installs from the repository" apt-get install -y -q pidvault
check "service is active" systemctl is-active --quiet pidvault
check "daemon runs as the pidvault account" equals "$(ps -o user= -p "$(daemon_pid)")" pidvault
check "the daemon holds no capabilities" live_daemon caps_dropped
check "the daemon has no network of its own" live_daemon own_network
check "the daemon cannot see /home" live_daemon no_home
check "the daemon's memory is never swapped out" equals \
    "$(cat "/sys/fs/cgroup$(systemctl show -P ControlGroup pidvault)/memory.swap.max")" 0
check "the mount helper may hold no capability but CAP_SYS_ADMIN" sh -c \
    'pid=$(systemctl show --property MainPID --value pidvault-mount); [ "$pid" -gt 0 ] && grep -q "^CapBnd:[[:space:]]*0000000000200000$" /proc/$pid/status'
check "systemd rates the service's exposure below 2" \
    sh -c 'systemd-analyze security pidvault.service --no-pager | awk "/Overall exposure level/ { exit !(\$(NF-2) < 2) }"'
check "pidvault is a system account without a shell" \
    sh -c 'getent passwd pidvault | awk -F: "\$3 < 1000 && \$7 ~ /nologin\$/" | grep -q .'
check "view is mounted" equals "$(findmnt -n -o SOURCE,FSTYPE /run/pidvault)" "pidvault fuse.pidvault"
check "mount root belongs to the daemon" equals "$(stat -c '%U %a' /run/pidvault)" "pidvault 755"
check "socket is connectable by all, in root's /run" equals "$(stat -c '%A %U' /run/pidvault.sock)" "srw-rw-rw- root"
check "agent socket is connectable by all, in root's /run" equals "$(stat -c '%A %U' /run/pidvault-agent.sock)" "srw-rw-rw- root"
check "vault store belongs to the daemon" equals "$(stat -c '%U %a' /var/lib/pidvault)" "pidvault 700"

# --- users with real user managers -------------------------------------------

for user in alice bob; do
    useradd --create-home --shell /bin/bash "$user"
    usermod --password '*' "$user"
    loginctl enable-linger "$user"
done
for user in alice bob; do
    for _ in $(seq 100); do
        systemctl is-active --quiet "user@$(id -u "$user").service" && break
        sleep 0.1
    done
done
check "alice and bob have running user managers" \
    systemctl is-active --quiet "user@$(id -u alice).service" "user@$(id -u bob).service"

as alice sh -c '
    set -e
    mkdir -p ~/src ~/.ssh && chmod 700 ~/.ssh
    ssh-keygen -q -t ed25519 -N "" -f ~/src/id_vm
    cat ~/src/id_vm.pub >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys
    printf "Host vm\n  HostName 127.0.0.1\n  User alice\n  IdentityFile /run/pidvault/stored/default/id_vm\n  IdentitiesOnly yes\n  BatchMode yes\n  StrictHostKeyChecking no\n  UserKnownHostsFile /dev/null\n  LogLevel ERROR\n" > ~/src/config
    pidvault stub > ~/.ssh/config
'
check "alice creates a vault" as alice sh -c \
    'echo alice-secret-phrase | pidvault create --passphrase-stdin --work-factor 12 --from ~/src && rm ~/src/id_vm'
ALICE_VAULT="/var/lib/pidvault/$(id -u alice)/default.pidvault"
check "alice's vault is stored by the daemon" equals "$(stat -c '%U %a' "$ALICE_VAULT")" "pidvault 600"
check "alice cannot read her stored vault" refused as alice cat "$ALICE_VAULT"

as bob sh -c 'mkdir -p ~/src && printf "Host vm\n  User bob-from-vault\n" > ~/src/config'
check "bob creates a vault" as bob sh -c \
    'echo bob-secret-phrase | pidvault create --passphrase-stdin --work-factor 12 --from ~/src'

# --- access -----------------------------------------------------------------

unlocked alice "touch /tmp/alice-unlocked; exec sleep 600" &
for _ in $(seq 100); do [[ -e /tmp/alice-unlocked ]] && break; sleep 0.1; done
check "an unlocked alice shell stays up for the next checks" test -e /tmp/alice-unlocked

check "unlocked shell reads alice's config" unlocked alice 'grep -q id_vm /run/pidvault/stored/default/config'
check "alice's vault directory belongs to her" equals "$(as alice stat -c '%U %a' /run/pidvault/stored/default)" "alice 700"
check "another process of alice sees nothing" refused as alice cat /run/pidvault/stored/default/config
check "alice's user services see nothing" refused in_manager alice --wait --pipe cat /run/pidvault/stored/default/config
check "bob's unlocked shell sees only his own vault" unlocked bob 'grep -q bob-from-vault /run/pidvault/stored/default/config'
check "root sees nothing" refused cat /run/pidvault/stored/default/config
as alice sh -c 'echo work-secret-phrase | pidvault create work --no-unlock --passphrase-stdin --work-factor 12 >/dev/null'
check "a shell unlocked for one vault sees only that one" as alice sh -c \
    'echo work-secret-phrase | pidvault unlock work --passphrase-stdin >/dev/null && test -d /run/pidvault/stored/work && ! cat /run/pidvault/stored/default/config 2>/dev/null'
check "alice lists only her own vaults" equals "$(as alice ls /run/pidvault/stored | tr '\n' ' ')" "default work "
check "bob lists only his" equals "$(as bob ls /run/pidvault/stored | tr '\n' ' ')" "default "
check "a vault name only alice has does not exist for bob" refused as bob stat /run/pidvault/stored/work
check "bob cannot unlock alice's vault by its name" sh -c \
    'runuser -u bob -- sh -c "echo work-secret-phrase | pidvault unlock work --passphrase-stdin" 2>&1 | grep -q "you have no vault"'

check "ssh login with the vault key from an unlocked shell" equals "$(unlocked alice 'ssh vm echo logged-in')" logged-in
check "the login signed through the vault agent: the key itself cannot be read" refused unlocked alice \
    'cat /run/pidvault/stored/default/id_vm >/dev/null'
check "the vault agent offers alice's other processes nothing" equals \
    "$(as alice env SSH_AUTH_SOCK=/run/pidvault-agent.sock ssh-add -l 2>&1)" "The agent has no identities."
check "the vault agent offers bob none of alice's keys" equals \
    "$(unlocked bob 'SSH_AUTH_SOCK=/run/pidvault-agent.sock ssh-add -l 2>&1')" "The agent has no identities."
check "a host alice forwards her agent to gets no vault keys" equals \
    "$(unlocked alice 'ssh -o ForwardAgent=yes vm ssh-add -l 2>&1')" "The agent has no identities."
check "the same ssh from another process of alice fails" refused as alice ssh vm true
check "naming the key explicitly does not help" refused as alice ssh -F /dev/null -o BatchMode=yes \
    -o IdentityAgent=none -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -i /run/pidvault/stored/default/id_vm alice@127.0.0.1 true

check "alice edits her config from an unlocked shell" unlocked alice \
    "sed -i 's/LogLevel ERROR/LogLevel QUIET/' /run/pidvault/stored/default/config"
check "another process of alice cannot write" refused as alice sh -c 'echo planted >> /run/pidvault/stored/default/config'
check "ssh records a new host key in the vault" unlocked alice \
    'ssh -o UserKnownHostsFile=/run/pidvault/stored/default/known_hosts -o StrictHostKeyChecking=accept-new vm true && test -s /run/pidvault/stored/default/known_hosts'
as alice ssh-keygen -q -t ed25519 -N 'key secret' -C old-github -f /tmp/alice-old-key
check "add-key brings a protected key in, protected and offered by the agent" unlocked alice \
    "echo 'key secret' | pidvault add-key --passphrase-stdin --name id_github /tmp/alice-old-key >/dev/null && ! cat /run/pidvault/stored/default/id_github 2>/dev/null && SSH_AUTH_SOCK=/run/pidvault-agent.sock ssh-add -l | grep -q old-github"
check "export needs an unlocked shell" refused as alice sh -c \
    'echo alice-secret-phrase | pidvault export --passphrase-stdin /tmp/alice-denied.age'
check "alice exports her vault from an unlocked shell" unlocked alice \
    'echo alice-secret-phrase | pidvault export --passphrase-stdin /tmp/alice-export.age'
useradd --create-home --shell /bin/bash carol
install -o carol -m 600 /tmp/alice-export.age /tmp/carol-import.age
check "carol imports alice's export" as carol sh -c \
    'echo alice-secret-phrase | pidvault import --passphrase-stdin /tmp/carol-import.age'
check "the imported vault works for a user with another name" as carol sh -c \
    'echo alice-secret-phrase | pidvault unlock --passphrase-stdin >/dev/null && grep -q id_vm /run/pidvault/stored/default/config'

# an orphaned client is adopted by alice's systemd --user, the subreaper of her whole login
as alice mkfifo /tmp/orphan-fifo
in_manager alice --property=ExitType=cgroup --unit=orphan-test \
    sh -c '( pidvault unlock --passphrase-stdin < /tmp/orphan-fifo > /tmp/orphan.out 2>&1 & )'
manager=$(systemctl show --property MainPID --value "user@$(id -u alice).service")
orphan=
for _ in $(seq 50); do
    orphan=$(pgrep -u alice -P "$manager" -x sh | head -1)
    [[ -n "$orphan" ]] && break
    sleep 0.1
done
check "the orphaned client was adopted by alice's systemd --user" test -n "$orphan"
as alice sh -c 'echo alice-secret-phrase > /tmp/orphan-fifo'
for _ in $(seq 50); do [[ -s /tmp/orphan.out ]] && break; sleep 0.1; done
check "an orphaned unlock is refused" grep -q "directly from the shell" /tmp/orphan.out
check "alice's user services still see nothing" refused in_manager alice --wait --pipe cat /run/pidvault/stored/default/config

# however small one user's vaults are when stored, holding them must not use up what the
# daemon can hold for everyone else
as carol sh -c '
    for v in flood1 flood2 flood3 flood4 flood5; do
        echo carol-secret-phrase | pidvault create "$v" --passphrase-stdin --work-factor 10 >/dev/null &&
            (cd "/run/pidvault/stored/$v" && seq 8000 | xargs touch 2>/dev/null)
        ls "/run/pidvault/stored/$v" | wc -l > "/tmp/carol-$v"
    done
    touch /tmp/carol-flooded; exec sleep 600' &
for _ in $(seq 1200); do [[ -e /tmp/carol-flooded ]] && break; sleep 0.1; done
check "carol holds vaults full of empty files" test -e /tmp/carol-flooded
check "four full vaults fit in what one user may hold" equals "$(cat /tmp/carol-flood4)" 8001
check "a fifth is cut short" test "$(cat /tmp/carol-flood5)" -lt 8001
check "bob still unlocks while carol holds them" unlocked bob 'test -d /run/pidvault/stored/default'

sysctl -q -w kernel.yama.ptrace_scope=0
check "unlocking is refused where any process could trace the shell" sh -c \
    'runuser -u bob -- sh -c "echo bob-secret-phrase | pidvault unlock --passphrase-stdin" 2>&1 | grep -q ptrace_scope'
sysctl -q -w kernel.yama.ptrace_scope=1

check "daemon logged no warnings" refused sh -c 'journalctl -b -u pidvault | grep -qi warning'

# --- lifecycle --------------------------------------------------------------

systemctl restart pidvault
check "service comes back after a restart" systemctl is-active --quiet pidvault
check "a restart drops existing unlocks" sh -c \
    'out=$(runuser -u alice -- pidvault status || true); if printf "%s\n" "$out" | grep -qv "locked here (0 "; then echo "$out"; false; fi'
check "vaults and edits survive a restart" unlocked alice \
    'grep -q "LogLevel QUIET" /run/pidvault/stored/default/config && test -s /run/pidvault/stored/default/known_hosts'

as alice sh -c 'printf "Host plain\n  HostName 192.0.2.1\n" >> ~/.ssh/config'
check "ssh config parses while the daemon runs" sh -c 'runuser -u alice -- ssh -G plain | grep -q "^hostname 192.0.2.1"'
systemctl kill --signal=KILL pidvault
for _ in $(seq 50); do
    [[ "$(systemctl show --property ActiveState --value pidvault)" != active ]] && break
    sleep 0.05
done
check "ssh config still parses right after the daemon is killed" \
    sh -c 'runuser -u alice -- ssh -G plain | grep -q "^hostname 192.0.2.1"'
for _ in $(seq 100); do systemctl is-active --quiet pidvault && break; sleep 0.1; done
check "service restarts after being killed" systemctl is-active --quiet pidvault
check "vault works after the restart" unlocked alice 'grep -q id_vm /run/pidvault/stored/default/config'

check "reinstalling over an installed package works" apt-get install -y -q --reinstall "$DEB"
check "service is active after reinstalling" systemctl is-active --quiet pidvault
check "vaults survive reinstalling" unlocked bob 'grep -q bob-from-vault /run/pidvault/stored/default/config'

check "package removes" apt-get remove -y -q pidvault
check "service is stopped after removal" refused systemctl is-active --quiet pidvault
check "view is unmounted after removal" refused findmnt /run/pidvault
check "sockets are gone after removal" refused \
    test -e /run/pidvault.sock -o -e /run/pidvault-agent.sock -o -e /run/pidvault-mount.sock
check "vaults are kept on removal" test -s "$ALICE_VAULT"
check "package purges" apt-get purge -y -q pidvault
check "vaults are kept on purge" test -s "$ALICE_VAULT"

finish
