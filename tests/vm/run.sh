#!/bin/bash
# Builds the .deb, installs it in a throwaway Ubuntu VM and runs guest-tests.sh there as root.
# Needs read/write access to /dev/kvm, qemu-system-x86_64, qemu-img, genisoimage, gpgv, curl
# and cargo-deb. No sudo. The verified cloud image is cached; every run boots a fresh overlay.
#
#   SSHVAULT_VM_KEEP=1     keep the work directory (console log, results, disk) afterwards
#   SSHVAULT_VM_REFRESH=1  download and verify the cloud image again
#   SSHVAULT_VM_TIMEOUT=N  seconds before the VM is killed (default 600)
set -euo pipefail

cd "$(dirname "$0")/../.."
RELEASE=26.04
BASE_URL="https://cloud-images.ubuntu.com/releases/$RELEASE/release"
IMAGE="ubuntu-$RELEASE-server-cloudimg-amd64.img"
KEYRING=/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg
CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/sshvault-vm"
TIMEOUT="${SSHVAULT_VM_TIMEOUT:-600}"

fetch_image() {
    mkdir -p "$CACHE"
    if [[ -f "$CACHE/$IMAGE.verified" && -z "${SSHVAULT_VM_REFRESH:-}" ]]; then
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

fetch_image
DEB=$(cargo deb --quiet 2>/dev/null | tail -1)
[[ -f "$DEB" ]] || { echo "cargo deb did not produce a package" >&2; exit 1; }

WORK=$(mktemp -d "${TMPDIR:-/tmp}/sshvault-vm.XXXXXX")
QEMU=
cleanup() {
    [[ -n "$QEMU" ]] && kill "$QEMU" 2>/dev/null
    if [[ -n "${SSHVAULT_VM_KEEP:-}" ]]; then echo "kept $WORK" >&2; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

mkdir "$WORK/seed"
cp "$DEB" "$WORK/seed/sshvault.deb"
cp tests/vm/guest-tests.sh "$WORK/seed/"
printf 'instance-id: sshvault-test\nlocal-hostname: sshvault-test\n' > "$WORK/seed/meta-data"
cat > "$WORK/seed/user-data" <<'EOF'
#cloud-config
runcmd:
  - [sh, -c, 'mkdir -p /mnt/seed && mount -o ro /dev/disk/by-label/cidata /mnt/seed && bash /mnt/seed/guest-tests.sh /mnt/seed/sshvault.deb > /dev/ttyS1 2>&1; sync; systemctl poweroff']
EOF
genisoimage -quiet -output "$WORK/seed.iso" -volid cidata -joliet -rock "$WORK/seed"
qemu-img create -q -f qcow2 -b "$CACHE/$IMAGE" -F qcow2 "$WORK/disk.qcow2" 10G

# ttyS0 carries the boot console, ttyS1 the TAP results
qemu-system-x86_64 \
    -machine q35,accel=kvm -cpu host -smp 2 -m 2048 \
    -display none -monitor none -no-reboot \
    -drive file="$WORK/disk.qcow2",if=virtio \
    -drive file="$WORK/seed.iso",media=cdrom,readonly=on \
    -nic user,model=virtio-net-pci \
    -serial file:"$WORK/console.log" \
    -serial file:"$WORK/results.tap" &
QEMU=$!

deadline=$((SECONDS + TIMEOUT))
while kill -0 "$QEMU" 2>/dev/null; do
    if (( SECONDS > deadline )); then
        echo "VM did not finish within ${TIMEOUT}s; last console lines:" >&2
        tail -n 30 "$WORK/console.log" >&2
        exit 1
    fi
    sleep 1
done
QEMU=

tr -d '\r' < "$WORK/results.tap" | tee "$WORK/results.clean.tap"
if ! grep -q '^# done' "$WORK/results.clean.tap"; then
    echo "guest tests did not run to completion; last console lines:" >&2
    tail -n 30 "$WORK/console.log" >&2
    exit 1
fi
! grep -q '^not ok' "$WORK/results.clean.tap"
