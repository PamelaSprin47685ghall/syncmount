#!/usr/bin/env bash
# mount-demo.sh — one sequencer, one mount, one write/read round trip.
#
# Usage:  ./examples/mount-demo.sh
# Env:    PORT (default 18080), SYNCMOUNT_MASTER_PASSWORD (default demo-password)
#
# The script is self-contained: it uses a private runtime and state directory,
# mounts into a temporary directory, verifies the write through the mount, and
# removes everything on exit.
#
# Expected output (paths and log lines abridged):
#   == start sequencer on http://127.0.0.1:18080/sync
#   == mount /tmp/syncmount-demo.XXXXXX/mnt
#   == write and read through the mount
#   hello from <hostname>
#   == status
#   ... mount id, state STEADY, applied seq ...
#   == clean shutdown
#   OK: mount-demo passed

set -euo pipefail

PORT=${PORT:-18080}
PASSWORD=${SYNCMOUNT_MASTER_PASSWORD:-demo-password}
URL="http://127.0.0.1:${PORT}/sync"
BIN=${SYNCMOUNT_BIN:-syncmount}

ROOT=$(mktemp -d "${TMPDIR:-/tmp}/syncmount-demo.XXXXXX")
MNT="$ROOT/mnt"
export SYNCMOUNT_RUN_DIR="$ROOT/run"
export XDG_DATA_HOME="$ROOT/data"
export SYNCMOUNT_MASTER_PASSWORD="$PASSWORD"

SERVER_PID=
CLIENT_PID=

cleanup() {
    if [ -n "${CLIENT_PID}" ] && kill -0 "$CLIENT_PID" 2>/dev/null; then
        kill -TERM "$CLIENT_PID" 2>/dev/null || true
        wait "$CLIENT_PID" 2>/dev/null || true
    fi
    if [ -n "${SERVER_PID}" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill -TERM "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    if mountpoint -q "$MNT" 2>/dev/null; then
        fusermount3 -uz "$MNT" 2>/dev/null || umount -l "$MNT" 2>/dev/null || true
    fi
    rm -rf "$ROOT"
}
trap cleanup EXIT INT TERM

require() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "missing prerequisite: $1" >&2
        exit 2
    }
}

require "$BIN"
require fusermount3
[ -r /dev/fuse ] && [ -w /dev/fuse ] || {
    echo "/dev/fuse is not readable and writable by this user" >&2
    exit 2
}

mkdir -p "$MNT" "$SYNCMOUNT_RUN_DIR" "$XDG_DATA_HOME"

echo "== start sequencer on $URL"
"$BIN" server "$URL" --listen "127.0.0.1:${PORT}" --log-format json \
    >"$ROOT/server.log" 2>&1 &
SERVER_PID=$!

# Wait for the listener to accept a TCP connection.
ready=0
for _ in $(seq 1 50); do
    if (exec 3<>"/dev/tcp/127.0.0.1/${PORT}") 2>/dev/null; then
        exec 3>&- 3<&- 2>/dev/null || true
        ready=1
        break
    fi
    kill -0 "$SERVER_PID" 2>/dev/null || {
        echo "server exited during startup:" >&2
        cat "$ROOT/server.log" >&2
        exit 2
    }
    sleep 0.1
done
[ "$ready" -eq 1 ] || {
    echo "server did not listen on 127.0.0.1:${PORT} within five seconds:" >&2
    cat "$ROOT/server.log" >&2
    exit 2
}

echo "== mount $MNT"
"$BIN" client "$URL" "$MNT" --db "$ROOT/client.db" \
    --log-format json >"$ROOT/client.log" 2>&1 &
CLIENT_PID=$!

for _ in $(seq 1 100); do
    if mountpoint -q "$MNT"; then
        break
    fi
    kill -0 "$CLIENT_PID" 2>/dev/null || {
        echo "client exited during startup:" >&2
        cat "$ROOT/client.log" >&2
        exit 2
    }
    sleep 0.1
done
mountpoint -q "$MNT" || {
    echo "mount did not appear" >&2
    cat "$ROOT/client.log" >&2
    exit 2
}

echo "== write and read through the mount"
printf 'hello from %s\n' "$(uname -n)" >"$MNT/hello.txt"
cat "$MNT/hello.txt"
test "$(cat "$MNT/hello.txt")" = "hello from $(uname -n)"

echo "== status"
"$BIN" status || true

echo "== clean shutdown"
kill -TERM "$CLIENT_PID"
wait "$CLIENT_PID" || true
CLIENT_PID=
kill -TERM "$SERVER_PID"
wait "$SERVER_PID" || true
SERVER_PID=

mountpoint -q "$MNT" && {
    echo "mountpoint is still mounted" >&2
    exit 2
}
echo "OK: mount-demo passed"
