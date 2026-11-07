#!/usr/bin/env bash
# two-clients.sh — two mounts of one cluster; a write on A appears on B.
#
# Usage:  ./examples/two-clients.sh
# Env:    PORT (default 18081), SYNCMOUNT_MASTER_PASSWORD (default demo-password)
#
# The check is eventual: the script polls B for the file for up to five
# seconds. The two clients share one master password and one URL, which is what
# gives them the same derived key and the same cluster identity.
#
# Expected output (paths and log lines abridged):
#   == sequencer http://127.0.0.1:18081/sync
#   == mount A and B
#   == write on A
#   == wait for B to converge
#   == last-writer-wins on the same path
#   == status
#   ... two mount ids, state STEADY ...
#   OK: two-clients passed

set -euo pipefail

PORT=${PORT:-18081}
PASSWORD=${SYNCMOUNT_MASTER_PASSWORD:-demo-password}
URL="http://127.0.0.1:${PORT}/sync"
BIN=${SYNCMOUNT_BIN:-syncmount}

ROOT=$(mktemp -d "${TMPDIR:-/tmp}/syncmount-two.XXXXXX")
MNT_A="$ROOT/a"
MNT_B="$ROOT/b"
export SYNCMOUNT_RUN_DIR="$ROOT/run"
export XDG_STATE_HOME="$ROOT/state"
export SYNCMOUNT_MASTER_PASSWORD="$PASSWORD"

SERVER_PID=
CLIENT_A=
CLIENT_B=

cleanup() {
    for pid in "$CLIENT_A" "$CLIENT_B" "$SERVER_PID"; do
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill -TERM "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    for mnt in "$MNT_A" "$MNT_B"; do
        if mountpoint -q "$mnt" 2>/dev/null; then
            fusermount3 -uz "$mnt" 2>/dev/null || umount -l "$mnt" 2>/dev/null || true
        fi
    done
    rm -rf "$ROOT"
}
trap cleanup EXIT INT TERM

command -v "$BIN" >/dev/null || { echo "missing: $BIN" >&2; exit 2; }
command -v fusermount3 >/dev/null || { echo "missing: fusermount3" >&2; exit 2; }
[ -r /dev/fuse ] && [ -w /dev/fuse ] || {
    echo "/dev/fuse is not readable and writable by this user" >&2
    exit 2
}

mkdir -p "$MNT_A" "$MNT_B" "$SYNCMOUNT_RUN_DIR" "$XDG_STATE_HOME" "$ROOT/state-a" "$ROOT/state-b"

echo "== sequencer $URL"
"$BIN" server "$URL" --listen "127.0.0.1:${PORT}" --log-format json \
    >"$ROOT/server.log" 2>&1 &
SERVER_PID=$!

wait_for_port() {
    for _ in $(seq 1 50); do
        if (exec 3<>"/dev/tcp/127.0.0.1/${PORT}") 2>/dev/null; then
            exec 3>&- 3<&- 2>/dev/null || true
            return 0
        fi
        kill -0 "$SERVER_PID" 2>/dev/null || return 1
        sleep 0.1
    done
    return 1
}

wait_for_port || {
    echo "sequencer did not listen on 127.0.0.1:${PORT}:" >&2
    cat "$ROOT/server.log" >&2
    exit 2
}

MOUNT_PID=
mount_client() {
    local mnt=$1 log=$2 state=$3
    # A distinct XDG_STATE_HOME gives each client its own Ed25519 identity.
    # One identity mounted twice is the duplicate-client case, and the server
    # kicks the older session.
    XDG_STATE_HOME="$state" "$BIN" client "$URL" "$mnt" --log-format json >"$log" 2>&1 &
    MOUNT_PID=$!
    for _ in $(seq 1 100); do
        mountpoint -q "$mnt" && return 0
        kill -0 "$MOUNT_PID" 2>/dev/null || return 1
        sleep 0.1
    done
    return 1
}

echo "== mount A and B"
mount_client "$MNT_A" "$ROOT/a.log" "$ROOT/state-a" || { cat "$ROOT/a.log" >&2; exit 2; }
CLIENT_A=$MOUNT_PID
mount_client "$MNT_B" "$ROOT/b.log" "$ROOT/state-b" || { cat "$ROOT/b.log" >&2; exit 2; }
CLIENT_B=$MOUNT_PID

echo "== write on A"
printf 'converged\n' >"$MNT_A/shared.txt"
test "$(cat "$MNT_A/shared.txt")" = "converged"

echo "== wait for B to converge"
seen=0
for _ in $(seq 1 100); do
    if [ -f "$MNT_B/shared.txt" ] && [ "$(cat "$MNT_B/shared.txt")" = "converged" ]; then
        seen=1
        break
    fi
    sleep 0.05
done
if [ "$seen" -ne 1 ]; then
    echo "B did not converge within five seconds" >&2
    echo "--- A log" >&2; cat "$ROOT/a.log" >&2
    echo "--- B log" >&2; cat "$ROOT/b.log" >&2
    exit 2
fi

echo "== last-writer-wins on the same path"
printf 'from-b\n' >"$MNT_B/shared.txt"
for _ in $(seq 1 100); do
    [ "$(cat "$MNT_A/shared.txt")" = "from-b" ] && break
    sleep 0.05
done
test "$(cat "$MNT_A/shared.txt")" = "from-b"

echo "== status"
"$BIN" status || true
echo "OK: two-clients passed"
