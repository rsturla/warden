#!/usr/bin/env bash
set -euo pipefail

# QEMU vsock integration test for Warden
#
# Requirements:
#   - qemu-system-x86_64 with KVM support
#   - vhost_vsock kernel module loaded
#   - Root or appropriate permissions for /dev/vhost-vsock
#
# Usage: ./test/vsock/run.sh
#
# This test:
#   1. Builds warden and warden-bridge statically
#   2. Starts warden on host listening on vsock (CID=any, port=8080)
#   3. Boots a minimal QEMU VM with vsock device (guest CID=3)
#   4. Inside the VM: runs warden-bridge connecting to host vsock
#   5. Inside the VM: curls through the bridge proxy
#   6. Verifies the request was proxied through warden

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
WORK_DIR="$(mktemp -d)"
VSOCK_PORT=8080
GUEST_CID=3
WARDEN_CONFIG="$WORK_DIR/config.yaml"

cleanup() {
    kill "$WARDEN_PID" 2>/dev/null || true
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

# --- Preflight checks ---

check_requirements() {
    local missing=0
    if ! command -v qemu-system-x86_64 &>/dev/null; then
        echo "SKIP: qemu-system-x86_64 not found"
        exit 0
    fi
    if [[ ! -e /dev/kvm ]]; then
        echo "SKIP: /dev/kvm not available"
        exit 0
    fi
    if [[ ! -e /dev/vhost-vsock ]]; then
        echo "SKIP: /dev/vhost-vsock not available (load vhost_vsock module)"
        exit 0
    fi
    if ! command -v curl &>/dev/null; then
        echo "SKIP: curl not found"
        exit 0
    fi
}

check_requirements

echo "=== Building static binaries ==="
cd "$ROOT_DIR"
CGO_ENABLED=0 go build -trimpath -o "$WORK_DIR/warden" ./cmd/warden
CGO_ENABLED=0 go build -trimpath -o "$WORK_DIR/warden-bridge" ./cmd/warden-bridge

echo "=== Creating test config ==="
cat > "$WARDEN_CONFIG" <<'YAML'
server:
  listen: "vsock://:8080"
  health_listen: "127.0.0.1:19090"
ca:
  auto: true
  cert_output: /tmp/warden-vsock-test-ca.crt
secrets:
  - type: env
policies:
  - name: allow-example
    host: "example.com"
    action: allow
telemetry:
  logs:
    level: info
    format: json
YAML

echo "=== Starting warden on vsock ==="
"$WORK_DIR/warden" --config "$WARDEN_CONFIG" &
WARDEN_PID=$!
sleep 1

if ! kill -0 "$WARDEN_PID" 2>/dev/null; then
    echo "FAIL: warden failed to start"
    exit 1
fi

echo "=== Building initramfs ==="
INITRD_DIR="$WORK_DIR/initrd"
mkdir -p "$INITRD_DIR"/{bin,etc,proc,sys,dev,tmp}

# Copy static binaries
cp "$WORK_DIR/warden-bridge" "$INITRD_DIR/bin/"

# Use busybox if available, otherwise download
if command -v busybox &>/dev/null; then
    cp "$(command -v busybox)" "$INITRD_DIR/bin/busybox"
else
    curl -sL "https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox" \
        -o "$INITRD_DIR/bin/busybox"
fi
chmod +x "$INITRD_DIR/bin/busybox"

# Create busybox symlinks
for cmd in sh wget cat echo sleep mount mkdir ln; do
    ln -sf busybox "$INITRD_DIR/bin/$cmd"
done

# Create init script
cat > "$INITRD_DIR/init" <<'INIT'
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs devtmpfs /dev

echo "=== Guest VM booted ==="

# Start warden-bridge: TCP 127.0.0.1:8080 -> vsock CID=2 (host) port=8080
/bin/warden-bridge --listen 127.0.0.1:8080 --vsock-cid 2 --vsock-port 8080 &
sleep 1

echo "=== Testing HTTP proxy through vsock bridge ==="
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080

# Test allowed host
RESULT=$(wget -q -O - http://example.com/ 2>&1 | head -c 100)
if echo "$RESULT" | grep -qi "example"; then
    echo "PASS: HTTP proxy through vsock works"
    echo "VSOCK_TEST_RESULT=PASS" > /dev/ttyS0
else
    echo "FAIL: unexpected response: $RESULT"
    echo "VSOCK_TEST_RESULT=FAIL" > /dev/ttyS0
fi

# Shutdown
echo "=== Guest shutting down ==="
poweroff -f
INIT
chmod +x "$INITRD_DIR/init"

# Build initramfs
(cd "$INITRD_DIR" && find . | cpio -o -H newc 2>/dev/null | gzip) > "$WORK_DIR/initrd.img"

echo "=== Booting QEMU VM with vsock (CID=$GUEST_CID) ==="
SERIAL_LOG="$WORK_DIR/serial.log"

timeout 30 qemu-system-x86_64 \
    -enable-kvm \
    -m 256 \
    -nographic \
    -no-reboot \
    -kernel /boot/vmlinuz-$(uname -r) \
    -initrd "$WORK_DIR/initrd.img" \
    -append "console=ttyS0 quiet panic=-1" \
    -device vhost-vsock-pci,guest-cid=$GUEST_CID \
    -serial file:"$SERIAL_LOG" \
    2>&1 || true

echo "=== VM output ==="
cat "$SERIAL_LOG" 2>/dev/null || echo "(no serial output)"

if grep -q "VSOCK_TEST_RESULT=PASS" "$SERIAL_LOG" 2>/dev/null; then
    echo ""
    echo "=== VSOCK TEST PASSED ==="
    exit 0
else
    echo ""
    echo "=== VSOCK TEST FAILED ==="
    exit 1
fi
