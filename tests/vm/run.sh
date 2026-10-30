#!/bin/bash
# Builds the .deb and runs each guest script as root in a throwaway Ubuntu VM of its own, in
# parallel: guest-tests.sh installs the package fresh, guest-upgrade.sh moves to it from the
# last release of sshvault, its name before.
# Needs read/write access to /dev/kvm, qemu-system-x86_64, qemu-img, genisoimage, gpg, gpgv,
# apt-ftparchive, curl and cargo-deb. No sudo. The verified cloud image is cached; every run
# boots fresh overlays.
#
#   PIDVAULT_VM_KEEP=1     keep the work directory (console logs, results, disks) afterwards
#   PIDVAULT_VM_REFRESH=1  download and verify the cloud image again
#   PIDVAULT_VM_TIMEOUT=N  seconds before the VMs are killed (default 600)
set -euo pipefail

cd "$(dirname "$0")/../.."
RELEASE=26.04
BASE_URL="https://cloud-images.ubuntu.com/releases/$RELEASE/release"
IMAGE="ubuntu-$RELEASE-server-cloudimg-amd64.img"
KEYRING=/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg
CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/pidvault-vm"
TIMEOUT="${PIDVAULT_VM_TIMEOUT:-600}"
VMS=(guest-tests guest-upgrade)
PREVIOUS_URL=https://github.com/torstei/sshvault/releases/download/v0.3.1/sshvault_0.3.1-1_amd64.deb
PREVIOUS_SHA256=49b5226a6db9ab39d14ec4eee18a62b7010529afb3589b548ec387022cdf99b0

fetch_image() {
    mkdir -p "$CACHE"
    if [[ -f "$CACHE/$IMAGE.verified" && -z "${PIDVAULT_VM_REFRESH:-}" ]]; then
        return
    fi
    rm -f "$CACHE/$IMAGE.verified"
    echo "fetching $IMAGE" >&2
    curl -fsSL -o "$CACHE/SHA256SUMS" "$BASE_URL/SHA256SUMS"
    curl -fsSL -o "$CACHE/SHA256SUMS.gpg" "$BASE_URL/SHA256SUMS.gpg"
    gpgv --keyring "$KEYRING" "$CACHE/SHA256SUMS.gpg" "$CACHE/SHA256SUMS" 2>/dev/null \
        || { echo "SHA256SUMS signature does not verify" >&2; exit 1; }
    curl -fL --progress-bar -o "$CACHE/$IMAGE.part" "$BASE_URL/$IMAGE"
    local expected
    expected=$(awk -v f="*$IMAGE" '$2 == f { print $1 }' "$CACHE/SHA256SUMS")
    [[ -n "$expected" ]] || { echo "$IMAGE not listed in SHA256SUMS" >&2; exit 1; }
    echo "$expected  $CACHE/$IMAGE.part" | sha256sum --check --quiet
    mv "$CACHE/$IMAGE.part" "$CACHE/$IMAGE"
    touch "$CACHE/$IMAGE.verified"
}

fetch_previous() {
    local deb="$CACHE/$PREVIOUS_SHA256.deb"
    if [[ ! -f "$deb" ]]; then
        curl -fsSL -o "$deb.part" "$PREVIOUS_URL"
        echo "$PREVIOUS_SHA256  $deb.part" | sha256sum --check --quiet
        mv "$deb.part" "$deb"
    fi
    cp "$deb" "$WORK/seed/previous.deb"
}

fetch_image
DEB=$(cargo deb --quiet 2>/dev/null | tail -1)
[[ -f "$DEB" ]] || { echo "cargo deb did not produce a package" >&2; exit 1; }

WORK=$(mktemp -d "${TMPDIR:-/tmp}/pidvault-vm.XXXXXX")
declare -A QEMU=()
cleanup() {
    local pid
    for pid in "${QEMU[@]}"; do kill "$pid" 2>/dev/null; done
    if [[ -n "${PIDVAULT_VM_KEEP:-}" ]]; then echo "kept $WORK" >&2; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

mkdir "$WORK/seed"
cp "$DEB" "$WORK/seed/pidvault.deb"

# a repository signed with a throwaway key, installed from as users would, and a second
# key it must not be accepted under
export GNUPGHOME="$WORK/gnupg"
mkdir -m 700 "$GNUPGHOME"
for name in "pidvault test" "someone else"; do
    gpg --batch --quiet --pinentry-mode loopback --passphrase '' \
        --quick-gen-key "$name <test@invalid>" ed25519 sign never
done
mkdir "$WORK/debs" && cp "$DEB" "$WORK/debs/"
scripts/build-apt-repo.sh "$WORK/debs" "$WORK/seed/repo" "pidvault test" >/dev/null
gpg --armor --export "someone else" > "$WORK/seed/other.asc"
fetch_previous
cp tests/vm/lib.sh "$WORK/seed/"
printf 'instance-id: pidvault-test\nlocal-hostname: pidvault-test\n' > "$WORK/seed/meta-data"

boot() {
    local vm=$1 dir="$WORK/$1"
    mkdir "$dir"
    cp -r "$WORK/seed" "$dir/seed"
    cp "tests/vm/$vm.sh" "$dir/seed/"
    cat > "$dir/seed/user-data" <<EOF
#cloud-config
runcmd:
  - [sh, -c, 'mkdir -p /mnt/seed && mount -o ro /dev/disk/by-label/cidata /mnt/seed && bash /mnt/seed/$vm.sh /mnt/seed/pidvault.deb > /dev/ttyS1 2>&1; sync; systemctl poweroff']
EOF
    genisoimage -quiet -output "$dir/seed.iso" -volid cidata -joliet -rock "$dir/seed"
    qemu-img create -q -f qcow2 -b "$CACHE/$IMAGE" -F qcow2 "$dir/disk.qcow2" 10G

    # ttyS0 carries the boot console, ttyS1 the TAP results
    qemu-system-x86_64 \
        -machine q35,accel=kvm -cpu host -smp 2 -m 2048 \
        -display none -monitor none -no-reboot \
        -drive file="$dir/disk.qcow2",if=virtio \
        -drive file="$dir/seed.iso",media=cdrom,readonly=on \
        -nic user,model=virtio-net-pci \
        -serial file:"$dir/console.log" \
        -serial file:"$dir/results.tap" &
    QEMU[$vm]=$!
}
for vm in "${VMS[@]}"; do boot "$vm"; done

deadline=$((SECONDS + TIMEOUT))
for vm in "${VMS[@]}"; do
    while kill -0 "${QEMU[$vm]}" 2>/dev/null; do
        if (( SECONDS > deadline )); then
            echo "$vm: VM did not finish within ${TIMEOUT}s; last console lines:" >&2
            tail -n 30 "$WORK/$vm/console.log" >&2
            exit 1
        fi
        sleep 1
    done
    unset "QEMU[$vm]"
done

failed=
for vm in "${VMS[@]}"; do
    echo "# --- $vm"
    tr -d '\r' < "$WORK/$vm/results.tap" | tee "$WORK/$vm/results.clean.tap"
    if ! grep -q '^# done' "$WORK/$vm/results.clean.tap"; then
        echo "$vm: guest tests did not run to completion; last console lines:" >&2
        tail -n 30 "$WORK/$vm/console.log" >&2
        failed=1
    fi
    if grep -q '^not ok' "$WORK/$vm/results.clean.tap"; then
        failed=1
    fi
done
[[ -z "$failed" ]]
