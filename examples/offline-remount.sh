#!/usr/bin/env bash
# offline-remount.sh — a lost transport unmounts the client; the write it had
# not delivered survives in the durable outbox and is resent on the next mount.
#
# Usage:  ./examples/offline-remount.sh
# Env:    PORT (default 18082), SYNCMOUNT_MASTER_PASSWORD (default demo-password)
#
# Steps:
#   1. mount, write one file and let its operations reach the server, so the
#      server sequence is above zero and the next join is a replay, not a seed;
#   2. freeze the sequencer (SIGSTOP) and write a second file: the write
#      returns after the local commit, while the server has not seen it;
#   3. kill the frozen sequencer (SIGKILL): the transport fails, the client
#      unmounts and exits with status 10. This is a crash, not a graceful
#      stop, so the epoch and the sequence are kept;
#   4. restart the sequencer on the same database and remount the same client
#      database: the file is still in the replica, the outbox resends the
#      operation the server never acknowledged, and applied_seq advances;
#   5. start a fresh second client: it replays the same total order from the
#      server and sees both files at the same applied_seq.
#
# The point is that the local write is not lost and not rolled back to a
# cluster snapshot: it is durable locally, then delivered in order.
#
# Expected output (paths and log lines abridged):
#   == first mount
#   == write and wait for the outbox to drain
#   == freeze the sequencer and write again
#   == kill the frozen sequencer
#   == wait for the client to unmount
#   client exit status: 10
#   == restart the sequencer and remount the same database
#   == the local write survived the disconnect
#   == wait for the outbox to drain and applied_seq to catch up
#   == a fresh client replays the same order
#   == status
#   OK: offline-remount passed

set -euo pipefail

PORT=${PORT:-18082}
PASSWORD=${SYNCMOUNT_MASTER_PASSWORD:-demo-password}
URL="http://127.0.0.1:${PORT}/sync"
BIN=${SYNCMOUNT_BIN:-syncmount}

ROOT=$(mktemp -d "${TMPDIR:-/tmp}/syncmount-offline.XXXXXX")
MNT_A="$ROOT/mnt-a"
MNT_B="$ROOT/mnt-b"
RUN_A="$ROOT/run-a"
RUN_B="$ROOT/run-b"
DB_A="$ROOT/client-a.db"
DB_B="$ROOT/client-b.db"
SERVER_DB="$ROOT/server.db"
export SYNCMOUNT_RUN_DIR="$ROOT/run"
export XDG_DATA_HOME="$ROOT/data"
export SYNCMOUNT_MASTER_PASSWORD="$PASSWORD"

SERVER_PID=
CLIENT_A=
CLIENT_B=

cleanup() {
    for pid in "$CLIENT_A" "$CLIENT_B" "$SERVER_PID"; do
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill -TERM "$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
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

mkdir -p "$MNT_A" "$MNT_B" "$RUN_A" "$RUN_B" "$XDG_DATA_HOME"

start_server() {
    "$BIN" server "$URL" --listen "127.0.0.1:${PORT}" --db "$SERVER_DB" \
        --log-format json >>"$ROOT/server.log" 2>&1 &
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
    local run=$1 db=$2 mnt=$3 log=$4
    SYNCMOUNT_RUN_DIR="$run" "$BIN" client "$URL" "$mnt" --db "$db" \
        --log-format json >"$log" 2>&1 &
    CLIENT_PID=$!
    for _ in $(seq 1 100); do
        mountpoint -q "$mnt" && return 0
        kill -0 "$CLIENT_PID" 2>/dev/null || return 1
        sleep 0.1
    done
    return 1
}

# The status document is republished every five seconds; these helpers read the
# text form of `syncmount status` for one runtime directory.
status_line() {
    SYNCMOUNT_RUN_DIR="$1" "$BIN" status 2>/dev/null || true
}

applied_seq() {
    status_line "$1" | sed -n 's/.*applied_seq=\([0-9][0-9]*\).*/\1/p'
}

outbox_ops() {
    status_line "$1" | sed -n 's/.*outbox=\([0-9][0-9]*\)ops.*/\1/p'
}

state_of() {
    status_line "$1" | sed -n 's/.*state=\([A-Z][A-Z]*\).*/\1/p'
}

echo "== first mount"
start_server || {
    echo "sequencer did not start:" >&2
    cat "$ROOT/server.log" >&2
    exit 2
}
start_client "$RUN_A" "$DB_A" "$MNT_A" "$ROOT/client-a-1.log" || {
    cat "$ROOT/client-a-1.log" >&2
    exit 2
}
CLIENT_A=$CLIENT_PID

echo "== write and wait for the outbox to drain"
printf 'warmup\n' >"$MNT_A/warmup.txt"
test "$(cat "$MNT_A/warmup.txt")" = "warmup"
warm=0
for _ in $(seq 1 150); do
    if [ "$(state_of "$RUN_A")" = "STEADY" ] &&
        [ "$(outbox_ops "$RUN_A")" = "0" ] &&
        [ -n "$(applied_seq "$RUN_A")" ] &&
        [ "$(applied_seq "$RUN_A")" -gt 0 ]; then
        warm=1
        break
    fi
    sleep 0.1
done
[ "$warm" -eq 1 ] || {
    echo "the warmup write did not reach the server" >&2
    status_line "$RUN_A" >&2
    exit 2
}
warm_seq=$(applied_seq "$RUN_A")
echo "applied_seq after the warmup write: $warm_seq"

echo "== freeze the sequencer and write again"
kill -STOP "$SERVER_PID"
printf 'local only\n' >"$MNT_A/local.txt"
# Local-first: the write returned from the replica, not from the network.
test "$(cat "$MNT_A/local.txt")" = "local only"

echo "== kill the frozen sequencer"
kill -KILL "$SERVER_PID"
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=

echo "== wait for the client to unmount"
gone=0
for _ in $(seq 1 150); do
    if ! mountpoint -q "$MNT_A"; then
        gone=1
        break
    fi
    sleep 0.1
done
[ "$gone" -eq 1 ] || { echo "client did not unmount" >&2; exit 2; }

code=0
wait "$CLIENT_A" 2>/dev/null || code=$?
CLIENT_A=
echo "client exit status: $code"
[ "$code" -eq 10 ] || {
    echo "expected exit status 10 (disconnected), got $code" >&2
    exit 2
}

echo "== restart the sequencer and remount the same database"
# A crash keeps the epoch and the sequence; only a graceful shutdown compacts.
rm -rf "$RUN_A"/*
start_server || {
    echo "sequencer did not restart:" >&2
    cat "$ROOT/server.log" >&2
    exit 2
}
start_client "$RUN_A" "$DB_A" "$MNT_A" "$ROOT/client-a-2.log" || {
    cat "$ROOT/client-a-2.log" >&2
    exit 2
}
CLIENT_A=$CLIENT_PID

echo "== the local write survived the disconnect"
kept=0
for _ in $(seq 1 50); do
    if [ -f "$MNT_A/local.txt" ] &&
        [ "$(cat "$MNT_A/local.txt" 2>/dev/null)" = "local only" ]; then
        kept=1
        break
    fi
    sleep 0.1
done
[ "$kept" -eq 1 ] || {
    echo "the local write did not survive the remount" >&2
    cat "$ROOT/client-a-2.log" >&2
    exit 2
}

echo "== wait for the outbox to drain and applied_seq to catch up"
drained=0
for _ in $(seq 1 200); do
    seq_now=$(applied_seq "$RUN_A")
    if [ "$(state_of "$RUN_A")" = "STEADY" ] &&
        [ "$(outbox_ops "$RUN_A")" = "0" ] &&
        [ -n "$seq_now" ] && [ "$seq_now" -gt "$warm_seq" ]; then
        drained=1
        break
    fi
    sleep 0.1
done
[ "$drained" -eq 1 ] || {
    echo "the outbox did not drain after the remount" >&2
    status_line "$RUN_A" >&2
    exit 2
}
seq_a=$(applied_seq "$RUN_A")
echo "applied_seq after the resend: $seq_a"

echo "== a fresh client replays the same order"
start_client "$RUN_B" "$DB_B" "$MNT_B" "$ROOT/client-b.log" || {
    cat "$ROOT/client-b.log" >&2
    exit 2
}
CLIENT_B=$CLIENT_PID
seen=0
for _ in $(seq 1 200); do
    seq_b=$(applied_seq "$RUN_B")
    if [ -f "$MNT_B/local.txt" ] &&
        [ "$(cat "$MNT_B/local.txt" 2>/dev/null)" = "local only" ] &&
        [ -n "$seq_b" ] && [ "$seq_b" = "$seq_a" ]; then
        seen=1
        break
    fi
    sleep 0.1
done
[ "$seen" -eq 1 ] || {
    echo "the second client did not converge on the same sequence" >&2
    echo "A: $(applied_seq "$RUN_A")" >&2
    echo "B: $(applied_seq "$RUN_B")" >&2
    exit 2
}

test "$(cat "$MNT_A/local.txt")" = "local only"
test "$(cat "$MNT_B/local.txt")" = "local only"
test "$(cat "$MNT_B/warmup.txt")" = "warmup"

echo "== status"
status_line "$RUN_A"
status_line "$RUN_B"
echo "OK: offline-remount passed"
