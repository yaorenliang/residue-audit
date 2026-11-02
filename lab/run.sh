#!/bin/sh
# One-command lab: boot a throwaway guest with no egress, plant the synthetic
# artifact set, and audit a real ext4 root instead of a macOS temp directory.
#
# Nothing is written back to the host tree: the repository is mounted read-only
# and the guest prints its verdict to the serial console, which the host greps.
#
# Usage:
#   sh lab/run.sh              first run downloads a cloud image (~600 MB)
#   RESIDUE_IMAGE=/path.img    reuse an image you already have
#   sh lab/run.sh --keep       keep out/lab-console.log for inspection

set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(dirname "$here")
out="$repo/out"
seed_dir="$out/seed"
cache="$repo/lab/.cache"
console="$out/lab-console.log"
timeout_s=${RESIDUE_LAB_TIMEOUT:-900}

keep=0
[ "${1:-}" = "--keep" ] && keep=1

mkdir -p "$out" "$seed_dir" "$cache"

# Which guest architecture to boot. The kernel has to match the image, not the
# host: an amd64 cloud image will not boot on qemu-system-aarch64 no matter how
# long you wait, so when a pre-existing image is supplied we trust its name over
# the host arch (and allow RESIDUE_ARCH to override both).
host_arch=$(uname -m)
if [ -n "${RESIDUE_ARCH:-}" ]; then
    want=$RESIDUE_ARCH
elif [ -n "${RESIDUE_IMAGE:-}" ]; then
    case "$(basename "$RESIDUE_IMAGE")" in
        *arm64*|*aarch64*) want=arm64 ;;
        *) want=x86_64 ;;
    esac
else
    case "$host_arch" in
        arm64|aarch64) want=arm64 ;;
        *) want=x86_64 ;;
    esac
fi

case "$want" in
    arm64|aarch64)
        qemu=qemu-system-aarch64
        image=noble-server-cloudimg-arm64.img
        machine="-M virt -cpu max"
        ;;
    x86_64|amd64)
        qemu=qemu-system-x86_64
        image=noble-server-cloudimg-amd64.img
        machine="-machine q35 -cpu max"
        ;;
    *)
        echo "LAB_ERROR=unsupported-arch:$want"
        exit 2
        ;;
esac

if ! command -v "$qemu" > /dev/null 2>&1; then
    echo "LAB_ERROR=no-qemu:$qemu (install: brew install qemu)"
    exit 2
fi

if [ -n "${RESIDUE_IMAGE:-}" ]; then
    base=$RESIDUE_IMAGE
    [ -f "$base" ] || { echo "LAB_ERROR=image-missing:$base"; exit 2; }
else
    base="$cache/$image"
    if [ ! -f "$base" ]; then
        echo "LAB_FETCH=1 url=https://cloud-images.ubuntu.com/noble/current/$image"
        curl -fsSL -o "$base.part" "https://cloud-images.ubuntu.com/noble/current/$image"
        mv "$base.part" "$base"
    fi
fi

# work image: a qcow2 overlay, so the downloaded base stays pristine
work="$out/lab.qcow2"
rm -f "$work"
qemu-img create -f qcow2 -b "$base" -F qcow2 "$work" > /dev/null

cat > "$seed_dir/meta-data" <<META
instance-id: residue-lab
local-hostname: residue-lab
META
cp "$here/user-data.yaml" "$seed_dir/user-data"

seed="$out/seed.iso"
rm -f "$seed"
if command -v cloud-localds > /dev/null 2>&1; then
    cloud-localds "$seed" "$seed_dir/user-data" "$seed_dir/meta-data"
elif command -v hdiutil > /dev/null 2>&1; then
    hdiutil makehybrid -quiet -o "$seed" -iso -joliet \
        -default-volume-name cidata "$seed_dir" > /dev/null
elif command -v genisoimage > /dev/null 2>&1; then
    genisoimage -quiet -output "$seed" -volid cidata -joliet -rock "$seed_dir"
else
    echo "LAB_ERROR=no-seed-tool"
    exit 2
fi

: > "$console"

echo "LAB_BOOT=1 qemu=$qemu host=$host_arch guest=$want image=$(basename "$base") tcg=$([ "$host_arch" != "$want" ] && echo 1 || echo 0)"
"$qemu" $machine -m 2048 -smp 2 -display none -monitor none \
    -drive if=virtio,file="$work",format=qcow2 \
    -drive if=virtio,file="$seed",format=raw,readonly=on \
    -netdev user,id=n0,restrict=on -device virtio-net-pci,netdev=n0 \
    -virtfs local,path="$repo",mount_tag=repo,security_model=none,readonly=on \
    -serial "file:$console" \
    > /dev/null 2>&1 &
pid=$!

waited=0
while [ "$waited" -lt "$timeout_s" ]; do
    if grep -q 'LAB_DONE=1' "$console" 2>/dev/null; then
        break
    fi
    if ! kill -0 "$pid" 2>/dev/null; then
        break
    fi
    sleep 5
    waited=$((waited + 5))
done
kill "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true

for key in LAB_GUEST_READY LAB_MOUNT LAB_EGRESS LAB_ROOT_ARTIFACTS LAB_ROOT_OURS LAB_ROOT_FOREIGN LAB_ROOT_WEAK LAB_ALIGNED LAB_LEAKS LAB_ARTIFACTS LAB_CTIME LAB_ORDER LAB_VERDICT LAB_NEG_LEAKS LAB_NEG_VERDICT LAB_DONE; do
    value=$(grep -o "$key=[A-Za-z0-9._-]*" "$console" 2>/dev/null | tail -1 || true)
    echo "${value:-$key=missing}"
done

[ "$keep" = "1" ] || rm -f "$work"
echo "LAB_CONSOLE=$console"

# The scoped run must align all five; the stock-root run is a precision
# measurement, not an assertion; the negative control must not pass.
if grep -q 'LAB_MOUNT=1' "$console" 2>/dev/null \
    && grep -q 'LAB_ALIGNED=5' "$console" 2>/dev/null \
    && grep -q 'LAB_LEAKS=0' "$console" 2>/dev/null \
    && grep -q 'PLANT_OK=1' "$console" 2>/dev/null \
    && grep -q 'LAB_NEG_VERDICT=fail' "$console" 2>/dev/null \
    && ! grep -q 'LAB_EGRESS=0' "$console" 2>/dev/null \
    && grep -q 'LAB_DONE=1' "$console" 2>/dev/null; then
    echo "LAB_OK=1"
    exit 0
fi

echo "LAB_OK=0"
exit 1