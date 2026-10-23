#!/bin/bash
# Runs as root inside the throwaway VM started by run.sh and prints TAP.
set -uo pipefail

DEB=$1
n=0

ok() { n=$((n + 1)); echo "ok $n - $1"; }
not_ok() {
    n=$((n + 1))
    echo "not ok $n - $1"
    [[ -n "${2:-}" ]] && sed 's/^/#   /' <<<"$2"
}
check() {
    local name=$1 out
    shift
    if out=$("$@" 2>&1); then ok "$name"; else not_ok "$name" "$out"; fi
}
refused() { ! "$@"; }
equals() { [[ "$1" == "$2" ]] || { echo "expected '$2', got '$1'"; return 1; }; }

as() {
    local user=$1
    shift
    runuser -u "$user" -- "$@"
}
# runs inside the user's own systemd --user manager, like a desktop session's processes
in_manager() {
    local user=$1 uid
    shift
    uid=$(id -u "$user")
    runuser -u "$user" -- env XDG_RUNTIME_DIR="/run/user/$uid" \
        DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus" systemd-run --user --quiet "$@"
}
unlocked() {
    local user=$1
    shift
    as "$user" sh -c "echo $user-pass | sshvault unlock --passphrase-stdin >/dev/null && $*"
}
daemon_pid() { systemctl show --property MainPID --value sshvault; }

# --- installation -----------------------------------------------------------

REPO=$(dirname "$DEB")/repo
only_sshvault=(-o Dir::Etc::sourcelist=/etc/apt/sources.list.d/sshvault.list -o Dir::Etc::sourceparts=-)
use_repo_signed_by() {
    echo "deb [signed-by=$1] file:$REPO stable main" > /etc/apt/sources.list.d/sshvault.list
}
use_repo_signed_by "$(dirname "$DEB")/other.asc"
check "apt refuses the repository under another signing key" refused apt-get update -q "${only_sshvault[@]}"
install -m 644 "$REPO/sshvault.asc" /etc/apt/keyrings/sshvault.asc
use_repo_signed_by /etc/apt/keyrings/sshvault.asc
check "apt accepts the signed repository" apt-get update -q "${only_sshvault[@]}"
check "package installs from the repository" apt-get install -y -q sshvault
check "service is active" systemctl is-active --quiet sshvault
check "daemon runs as the sshvault account" equals "$(ps -o user= -p "$(daemon_pid)")" sshvault
check "sshvault is a system account without a shell" \
    sh -c 'getent passwd sshvault | awk -F: "\$3 < 1000 && \$7 ~ /nologin\$/" | grep -q .'
check "view is mounted" equals "$(findmnt -n -o SOURCE,FSTYPE /run/sshvault)" "sshvault fuse"
check "mount root belongs to the daemon" equals "$(stat -c '%U %a' /run/sshvault)" "sshvault 755"
check "socket is connectable by all, in root's /run" equals "$(stat -c '%A %U' /run/sshvault.sock)" "srw-rw-rw- root"
check "agent socket is connectable by all, in root's /run" equals "$(stat -c '%A %U' /run/sshvault-agent.sock)" "srw-rw-rw- root"
check "vault store belongs to the daemon" equals "$(stat -c '%U %a' /var/lib/sshvault)" "sshvault 700"

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
    printf "Host vm\n  HostName 127.0.0.1\n  User alice\n  IdentityFile /run/sshvault/default/id_vm\n  IdentitiesOnly yes\n  BatchMode yes\n  StrictHostKeyChecking no\n  UserKnownHostsFile /dev/null\n  LogLevel ERROR\n" > ~/src/config
    sshvault stub > ~/.ssh/config
'
check "alice creates a vault" as alice sh -c \
    'echo alice-pass | sshvault create --passphrase-stdin --work-factor 12 --from ~/src && rm ~/src/id_vm'
ALICE_VAULT="/var/lib/sshvault/$(id -u alice)/default.sshvault"
check "alice's vault is stored by the daemon" equals "$(stat -c '%U %a' "$ALICE_VAULT")" "sshvault 600"
check "alice cannot read her stored vault" refused as alice cat "$ALICE_VAULT"

as bob sh -c 'mkdir -p ~/src && printf "Host vm\n  User bob-from-vault\n" > ~/src/config'
check "bob creates a vault" as bob sh -c \
    'echo bob-pass | sshvault create --passphrase-stdin --work-factor 12 --from ~/src'

# --- access -----------------------------------------------------------------

unlocked alice "touch /tmp/alice-unlocked; exec sleep 600" &
for _ in $(seq 100); do [[ -e /tmp/alice-unlocked ]] && break; sleep 0.1; done
check "an unlocked alice shell stays up for the next checks" test -e /tmp/alice-unlocked

check "unlocked shell reads alice's config" unlocked alice 'grep -q id_vm /run/sshvault/default/config'
check "alice's vault directory belongs to her" equals "$(as alice stat -c '%U %a' /run/sshvault/default)" "alice 700"
check "another process of alice sees nothing" refused as alice cat /run/sshvault/default/config
check "alice's user services see nothing" refused in_manager alice --wait --pipe cat /run/sshvault/default/config
check "bob's unlocked shell sees only his own vault" unlocked bob 'grep -q bob-from-vault /run/sshvault/default/config'
check "root sees nothing" refused cat /run/sshvault/default/config
as alice sh -c 'echo work-pass | sshvault create work --no-unlock --passphrase-stdin --work-factor 12 >/dev/null'
check "a shell unlocked for one vault sees only that one" as alice sh -c \
    'echo work-pass | sshvault unlock work --passphrase-stdin >/dev/null && test -d /run/sshvault/work && ! cat /run/sshvault/default/config 2>/dev/null'
check "alice lists only her own vaults" equals "$(as alice ls /run/sshvault | tr '\n' ' ')" "default work "
check "bob lists only his" equals "$(as bob ls /run/sshvault | tr '\n' ' ')" "default "
check "decrypted vault is held in locked memory" \
    awk '/^VmLck:/ { exit !($2 > 0) }' "/proc/$(daemon_pid)/status"

check "ssh login with the vault key from an unlocked shell" equals "$(unlocked alice 'ssh vm echo logged-in')" logged-in
check "the login signed through the vault agent: the key itself cannot be read" refused unlocked alice \
    'cat /run/sshvault/default/id_vm >/dev/null'
check "the vault agent offers alice's other processes nothing" equals \
    "$(as alice env SSH_AUTH_SOCK=/run/sshvault-agent.sock ssh-add -l 2>&1)" "The agent has no identities."
check "the vault agent offers bob none of alice's keys" equals \
    "$(unlocked bob 'SSH_AUTH_SOCK=/run/sshvault-agent.sock ssh-add -l 2>&1')" "The agent has no identities."
check "a host alice forwards her agent to gets no vault keys" equals \
    "$(unlocked alice 'ssh -o ForwardAgent=yes vm ssh-add -l 2>&1')" "The agent has no identities."
check "the same ssh from another process of alice fails" refused as alice ssh vm true
check "naming the key explicitly does not help" refused as alice ssh -F /dev/null -o BatchMode=yes \
    -o IdentityAgent=none -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -i /run/sshvault/default/id_vm alice@127.0.0.1 true

check "alice edits her config from an unlocked shell" unlocked alice \
    "sed -i 's/LogLevel ERROR/LogLevel QUIET/' /run/sshvault/default/config"
check "another process of alice cannot write" refused as alice sh -c 'echo planted >> /run/sshvault/default/config'
check "ssh records a new host key in the vault" unlocked alice \
    'ssh -o UserKnownHostsFile=/run/sshvault/default/known_hosts -o StrictHostKeyChecking=accept-new vm true && test -s /run/sshvault/default/known_hosts'
as alice ssh-keygen -q -t ed25519 -N 'key secret' -C old-github -f /tmp/alice-old-key
check "add-key brings a protected key in, protected and offered by the agent" unlocked alice \
    "echo 'key secret' | sshvault add-key --passphrase-stdin --name id_github /tmp/alice-old-key >/dev/null && ! cat /run/sshvault/default/id_github 2>/dev/null && SSH_AUTH_SOCK=/run/sshvault-agent.sock ssh-add -l | grep -q old-github"
check "export needs an unlocked shell" refused as alice sh -c \
    'echo alice-pass | sshvault export --passphrase-stdin /tmp/alice-denied.age'
check "alice exports her vault from an unlocked shell" unlocked alice \
    'echo alice-pass | sshvault export --passphrase-stdin /tmp/alice-export.age'
useradd --create-home --shell /bin/bash carol
install -o carol -m 600 /tmp/alice-export.age /tmp/carol-import.age
check "carol imports alice's export" as carol sh -c \
    'echo alice-pass | sshvault import --passphrase-stdin /tmp/carol-import.age'
check "the imported vault works for a user with another name" as carol sh -c \
    'echo alice-pass | sshvault unlock --passphrase-stdin >/dev/null && grep -q id_vm /run/sshvault/default/config'

# an orphaned client is adopted by alice's systemd --user, the subreaper of her whole login
as alice mkfifo /tmp/orphan-fifo
in_manager alice --property=ExitType=cgroup --unit=orphan-test \
    sh -c '( sshvault unlock --passphrase-stdin < /tmp/orphan-fifo > /tmp/orphan.out 2>&1 & )'
manager=$(systemctl show --property MainPID --value "user@$(id -u alice).service")
orphan=
for _ in $(seq 50); do
    orphan=$(pgrep -u alice -P "$manager" -x sh | head -1)
    [[ -n "$orphan" ]] && break
    sleep 0.1
done
check "the orphaned client was adopted by alice's systemd --user" test -n "$orphan"
as alice sh -c 'echo alice-pass > /tmp/orphan-fifo'
for _ in $(seq 50); do [[ -s /tmp/orphan.out ]] && break; sleep 0.1; done
check "an orphaned unlock is refused" grep -q "directly from the shell" /tmp/orphan.out
check "alice's user services still see nothing" refused in_manager alice --wait --pipe cat /run/sshvault/default/config

check "daemon logged no warnings" refused sh -c 'journalctl -b -u sshvault | grep -qi warning'

# --- lifecycle --------------------------------------------------------------

systemctl restart sshvault
check "service comes back after a restart" systemctl is-active --quiet sshvault
check "a restart drops existing unlocks" sh -c \
    'out=$(runuser -u alice -- sshvault status || true); if printf "%s\n" "$out" | grep -qv "locked here (0 "; then echo "$out"; false; fi'
check "vaults and edits survive a restart" unlocked alice \
    'grep -q "LogLevel QUIET" /run/sshvault/default/config && test -s /run/sshvault/default/known_hosts'

as alice sh -c 'printf "Host plain\n  HostName 192.0.2.1\n" >> ~/.ssh/config'
check "ssh config parses while the daemon runs" sh -c 'runuser -u alice -- ssh -G plain | grep -q "^hostname 192.0.2.1"'
systemctl kill --signal=KILL sshvault
for _ in $(seq 50); do
    [[ "$(systemctl show --property ActiveState --value sshvault)" != active ]] && break
    sleep 0.05
done
check "ssh config still parses right after the daemon is killed" \
    sh -c 'runuser -u alice -- ssh -G plain | grep -q "^hostname 192.0.2.1"'
for _ in $(seq 100); do systemctl is-active --quiet sshvault && break; sleep 0.1; done
check "service restarts after being killed" systemctl is-active --quiet sshvault
check "vault works after the restart" unlocked alice 'grep -q id_vm /run/sshvault/default/config'

check "reinstalling over an installed package works" apt-get install -y -q --reinstall "$DEB"
check "service is active after reinstalling" systemctl is-active --quiet sshvault
check "vaults survive reinstalling" unlocked bob 'grep -q bob-from-vault /run/sshvault/default/config'

check "package removes" apt-get remove -y -q sshvault
check "service is stopped after removal" refused systemctl is-active --quiet sshvault
check "view is unmounted after removal" refused findmnt /run/sshvault
check "sockets are gone after removal" refused test -e /run/sshvault.sock -o -e /run/sshvault-agent.sock
check "vaults are kept on removal" test -s "$ALICE_VAULT"
check "package purges" apt-get purge -y -q sshvault
check "vaults are kept on purge" test -s "$ALICE_VAULT"

echo "1..$n"
{
    echo "--- journalctl -u sshvault"
    journalctl -b -u sshvault --no-pager -o short-monotonic | tail -n 60
    echo "--- mounts"
    findmnt -n /run/sshvault
} | sed 's/^/# /'
echo "# done"
