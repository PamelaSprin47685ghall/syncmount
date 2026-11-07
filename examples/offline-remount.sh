#!/usr/bin/env bash
# offline-remount.sh — a lost transport unmounts the client; a remount is
# cluster-wins.
#
# Usage:  ./examples/offline-remount.sh
# Env:    PORT (default 18082), SYNCMOUNT_MASTER_PASSWORD (default demo-password)
#
# Steps:
#   1. mount and write a file;
#   2. stop the sequencer, which drops the transport;
#   3. observe the client unmount and exit with status 10;
#   4. start a fresh sequencer (new epoch, empty sequence) and remount;
#   5. observe that the local-only file is gone: the cluster is the only truth.
#
# Expected output (paths and log lines abridged):
#   == first mount
#   == stop the sequencer
#   == wait for the client to unmount
#   client exit status: 10
#   == restart the sequencer and remount
#   == cluster-wins: the local-only file is gone
#   == status
#   OK: offline-remount passed

set -euo pipefail

PORT=${PORT:-18082}
PASSWORD=${SYNCMOUNT_MASTER_PASSWORD:-demo-password}
URL="http://127.0.0.1:${PORT}/sync"
BIN=${SYNCMOUNT_BIN:-syncmount}

ROOT=$(mktemp -d "${TMPDIR:-/tmp}/syncmount-offline.XXXXXX")
MNT="$ROOT/mnt"
export SYNCMOUNT_RUN_DIR="$ROOT/run"
export XDG_STATE_HOME="$ROOT/state"
export SYNCMOUNT_MASTER_PASSWORD="$PASSWORD"

SERVER_PID=
CLIENT_PID=

cleanup() {
    for pid in "$CLIENT_PID" "$SERVER_PID"; do
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill -TERM "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    if mountpoint -q "$MNT" 2>/dev/null; then
        fusermount3 -uz "$MNT" 2>/dev/null || umount -l "$MNT" 2>/dev/null || true
    fi
    rm -rf "$ROOT"
}
trap cleanup EXIT INT TERM

command -v "$BIN" >/dev/null || { echo "missing: $BIN" >&2; exit 2; }
command -v fusermount3 >/dev/null || { echo "missing: fusermount3" >&2; exit 2; }
[ -r /dev/fuse ] && [ -w /dev/fuse ] || {
    echo "/dev/fuse is not readable and writable by this user" >&2
    exit 2
}

mkdir -p "$MNT" "$SYNCMOUNT_RUN_DIR" "$XDG_STATE_HOME"

start_server() {
    "$BIN" server "$URL" --listen "127.0.0.1:${PORT}" --log-format json \
        >>"$ROOT/server.log" 2>&1 &
    SERVER_PID=$!
    for _ in $(seq 1 50); do
        (exec 3<>"/dev/tcp/127.0.0.1/${PORT}") 2>/dev/null && {
            exec 3>&- 3<&- 2>/dev/null || true
            return 0
        }
        kill -0 "$SERVER_PID" 2>/dev/null || return 1
        sleep 0.1
    done
    return 1
}

start_client() {
    "$BIN" client "$URL" "$MNT" --log-format json >>"$ROOT/client.log" 2>&1 &
    CLIENT_PID=$!
    for _ in $(seq 1 100); do
        mountpoint -q "$MNT" && return 0
        kill -0 "$CLIENT_PID" 2>/dev/null || return 1
        sleep 0.1
    done
    return 1
}

echo "== first mount"
start_server || {
    echo "sequencer did not start:" >&2
    cat "$ROOT/server.log" >&2
    exit 2
}
start_client || { cat "$ROOT/client.log" >&2; exit 2; }
printf 'local only\n' >"$MNT/local.txt"
test -f "$MNT/local.txt"

echo "== stop the sequencer"
kill -TERM "$SERVER_PID"
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=

echo "== wait for the client to unmount"
gone=0
for _ in $(seq 1 100); do
    if ! mountpoint -q "$MNT"; then
        gone=1
        break
    fi
    sleep 0.1
done
[ "$gone" -eq 1 ] || { echo "client did not unmount" >&2; exit 2; }

code=0
wait "$CLIENT_PID" 2>/dev/null || code=$?
CLIENT_PID=
echo "client exit status: $code"
[ "$code" -eq 10 ] || {
    echo "expected exit status 10 (disconnected), got $code" >&2
    exit 2
}

echo "== restart the sequencer and remount"
start_server || {
    echo "sequencer did not restart:" >&2
    cat "$ROOT/server.log" >&2
    exit 2
}
start_client || { cat "$ROOT/client.log" >&2; exit 2; }

echo "== cluster-wins: the local-only file is gone"
for _ in $(seq 1 100); do
    [ ! -e "$MNT/local.txt" ] && break
    sleep 0.1
done
if [ -e "$MNT/local.txt" ]; then
    echo "local-only file survived the remount" >&2
    exit 2
fi

echo "== status"
"$BIN" status || true
echo "OK: offline-remount passed"
