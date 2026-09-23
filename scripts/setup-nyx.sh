#!/usr/bin/env bash
#
# Setup script for Nyx mode fuzzing with AFL++
#
# Usage: ./scripts/setup-nyx.sh <sharedir> <docker-image> <aflplusplus-path>
#
# Environment Variables:
#   NYX_MEM_MB: Sets the memory allocation for the Nyx VM in MB (default: 2048).
#
# Example:
#   NYX_MEM_MB=4096 ./scripts/setup-nyx.sh /tmp/smite-lnd-nyx smite-lnd ~/AFLplusplus
#
# Creates the necessary files in sharedir for snapshot fuzzing using
# docker-image.  Requires that docker-image is already built and that AFL++ has
# been built from source (including Nyx mode) at aflplusplus-path.

set -eu

if [ $# -ne 3 ]; then
    echo "Usage: $0 <sharedir> <docker-image> <aflplusplus-path>"
    exit 1
fi

SHAREDIR="$1"
DOCKER_IMAGE="$2"
AFLPP_PATH="$3"

# Validate AFL++ path
if [ ! -d "$AFLPP_PATH/nyx_mode/packer/packer" ]; then
    echo "Error: AFL++ not found at $AFLPP_PATH"
    echo "Make sure AFL++ is installed with Nyx mode support."
    echo "See: https://github.com/AFLplusplus/AFLplusplus/blob/stable/nyx_mode/README.md"
    exit 1
fi

# Validate Docker image exists
if ! docker image inspect "$DOCKER_IMAGE" > /dev/null 2>&1; then
    echo "Error: Docker image '$DOCKER_IMAGE' not found."
    echo "Build it first with: docker build -t $DOCKER_IMAGE -f workloads/<target>/Dockerfile ."
    exit 1
fi

PACKER_PATH="$AFLPP_PATH/nyx_mode/packer/packer"
BINARIES_PATH="$PACKER_PATH/linux_x86_64-userspace/bin64"

# Check if packer binaries exist, compile if needed
if [ ! -f "$BINARIES_PATH/hget" ]; then
    echo "Compiling packer binaries..."
    (cd "$PACKER_PATH/linux_x86_64-userspace" && bash compile_64.sh)
fi

echo "Creating sharedir at: $SHAREDIR"
rm -rf "$SHAREDIR"
mkdir -p "$SHAREDIR"

# Export Docker container filesystem
echo "Exporting Docker container to container.tar..."
CONTAINER_ID=$(docker create "$DOCKER_IMAGE")
docker export "$CONTAINER_ID" -o "$SHAREDIR/container.tar"
docker rm "$CONTAINER_ID" > /dev/null

# Copy packer binaries
echo "Copying packer binaries..."
cp "$BINARIES_PATH"/* "$SHAREDIR/"

# Generate Nyx config.
#
# Python 3.14 changed the default multiprocessing start method to 'forkserver',
# which breaks the packer's common/debug.py. We force 'fork' via a
# sitecustomize.py injected on PYTHONPATH to restore the pre-3.14 behavior.
echo "Generating Nyx config..."
FORCE_FORK_DIR="$(mktemp -d)"
trap 'rm -rf "$FORCE_FORK_DIR"' EXIT
cat > "$FORCE_FORK_DIR/sitecustomize.py" <<'EOF'
import multiprocessing
multiprocessing.set_start_method("fork", force=True)
EOF

# The memory allocated to a single QEMU VM instance. Defaults to 2048 MB.
NYX_MEM_MB="${NYX_MEM_MB:-2048}"
echo "Using VM image size: ${NYX_MEM_MB} MB"

(cd "$PACKER_PATH" && PYTHONPATH="$FORCE_FORK_DIR${PYTHONPATH:+:$PYTHONPATH}" ./nyx_config_gen.py "$SHAREDIR" Kernel -m "$NYX_MEM_MB")

# Create fuzz_no_pt.sh script
echo "Creating fuzz_no_pt.sh..."
cat > "$SHAREDIR/fuzz_no_pt.sh" << 'EOF'
chmod +x hget
cp hget /tmp
cd /tmp
# /tmp is a tmpfs holding the tarball, the tree extracted from it, and the
# target's runtime writes. Its default cap is half the VM's RAM, too low to
# unpack a 600 MB image below 3 GB. The guest has no swap, so leave 10% for
# anonymous memory.
mount -o remount,size=90% /tmp
echo 0 > /proc/sys/kernel/randomize_va_space
echo 0 > /proc/sys/kernel/printk
./hget hcat_no_pt hcat
./hget habort_no_pt habort
chmod +x ./hcat
chmod +x ./habort
./hget container.tar container.tar
export __AFL_DEFER_FORKSRV=1
ip addr add 127.0.0.1/8 dev lo
ip addr add ::1/128 dev lo
ip link set lo up
ip a | ./hcat
# Drop the tarball once unpacked; keeping it would pin a second copy of the
# image in tmpfs for the life of the VM.
mkdir rootfs/ && tar -xf container.tar -C /tmp/rootfs && rm -f container.tar
mount -t proc /proc rootfs/proc/
mount --rbind /sys rootfs/sys/
mount --rbind /dev rootfs/dev/
echo '127.0.0.1 localhost' > rootfs/etc/hosts
echo '::1 localhost' >> rootfs/etc/hosts
echo '# No nameserver configured' > rootfs/etc/resolv.conf
chroot /tmp/rootfs /init.sh
cat rootfs/init.log | ./hcat
./habort "$(tail rootfs/init.log)"
EOF
chmod +x "$SHAREDIR/fuzz_no_pt.sh"

echo ""
echo "Sharedir created successfully at: $SHAREDIR"
echo ""
echo "Contents:"
ls -lh "$SHAREDIR"
echo ""
echo "To start fuzzing, run:"
echo "  mkdir -p /tmp/smite-seeds && echo 'AAAA' > /tmp/smite-seeds/seed1"
echo "  $AFLPP_PATH/afl-fuzz -X -i /tmp/smite-seeds -o /tmp/smite-out -- $SHAREDIR"
