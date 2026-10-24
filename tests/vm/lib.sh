# Helpers shared by the guest scripts; sourced, prints TAP.

n=0
# what `unlocked` appends to the user name to get the vault passphrase
PASS_SUFFIX=${PASS_SUFFIX:--secret-phrase}

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
    as "$user" sh -c "echo $user$PASS_SUFFIX | sshvault unlock --passphrase-stdin >/dev/null && $*"
}
daemon_pid() { systemctl show --property MainPID --value sshvault; }
# a check about the daemon process must fail, not pass, when there is none
live_daemon() {
    local pid
    pid=$(daemon_pid)
    [[ "$pid" -gt 0 ]] || { echo "no daemon running"; return 1; }
    "$@" "$pid"
}
caps_dropped() { awk '/^Cap(Eff|Prm|Bnd):/ && $2 != "0000000000000000" { bad = 1 } END { exit bad }' "/proc/$1/status"; }
own_network() { test "$(readlink "/proc/$1/ns/net")" != "$(readlink /proc/1/ns/net)"; }
no_home() { ! nsenter --target "$1" --mount ls /home/ubuntu >/dev/null 2>&1; }

finish() {
    echo "1..$n"
    {
        echo "--- journalctl -u sshvault"
        journalctl -b -u sshvault --no-pager -o short-monotonic | tail -n 60
        echo "--- mounts"
        findmnt -n /run/sshvault
    } | sed 's/^/# /'
    echo "# done"
}
