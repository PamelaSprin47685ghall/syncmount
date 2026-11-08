#!/usr/bin/env bash
# install.sh - install the syncmount 1.1 mm deployment artifacts.
#
# It creates the systemd units, the server/client state directories and the mm
# master key. It does NOT start, stop, enable or reload any service, and it
# does NOT touch Caddy or the 1.0 units/databases.
#
# Idempotent rules:
#   - an existing /etc/syncmount/mm.key is reused, never rotated;
#   - /etc/syncmount/mm-client.key must hold the same bytes, otherwise the
#     script refuses to guess which copy is current;
#   - only mm-*.service files are written under /etc/systemd/system.
#
# The key is never printed. Run as root.
set -euo pipefail
umask 077

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
SYSTEMD_DIR=/etc/systemd/system
BIN=/usr/local/bin/syncmount
CLIENT_USER=${CLIENT_USER:-syncmount}
CLIENT_GROUP=${CLIENT_GROUP:-$CLIENT_USER}
SERVER_ROOT=/var/lib/syncmount-mm
CLIENT_ROOT=/var/lib/syncmount-mm-client
KEY_DIR=/etc/syncmount
SERVER_KEY=$KEY_DIR/mm.key
CLIENT_KEY=$KEY_DIR/mm-client.key
NAMESPACES=(private-mm public-mm)

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

note() {
    printf '%s\n' "$*"
}

[ "$(id -u)" -eq 0 ] || die "run as root: sudo $0"

id -u "$CLIENT_USER" >/dev/null 2>&1 ||
    die "client user $CLIENT_USER does not exist; set CLIENT_USER to the account that owns the mounts"
CLIENT_HOME=$(getent passwd "$CLIENT_USER" | cut -d: -f6)
[ -n "$CLIENT_HOME" ] || die "cannot read the home directory of $CLIENT_USER"

if [ -x "$BIN" ]; then
    note "binary: $BIN"
else
    note "warning: $BIN is missing or not executable; install the 1.1 build before starting the units"
fi

# ---------------------------------------------------------------------------
# directories
# ---------------------------------------------------------------------------
ensure_dir() {
    local path=$1 mode=$2 owner=$3 group=$4
    if [ -L "$path" ]; then
        die "$path is a symlink; refusing"
    fi
    if [ -e "$path" ] && [ ! -d "$path" ]; then
        die "$path exists and is not a directory"
    fi
    install -d -m "$mode" -o "$owner" -g "$group" "$path"
}

ensure_dir "$SERVER_ROOT" 0700 root root
ensure_dir "$CLIENT_ROOT" 0700 "$CLIENT_USER" "$CLIENT_GROUP"

# 0755 so the client user can traverse to its 0600 key; the files stay 0600.
ensure_dir "$KEY_DIR" 0755 root root

for ns in "${NAMESPACES[@]}"; do
    ensure_dir "$SERVER_ROOT/$ns" 0700 root root
    ensure_dir "$SERVER_ROOT/$ns/spool" 0700 root root
    ensure_dir "$CLIENT_ROOT/$ns" 0700 "$CLIENT_USER" "$CLIENT_GROUP"

    mountpoint_path=/$ns
    if mountpoint -q -- "$mountpoint_path" 2>/dev/null; then
        note "note: $mountpoint_path is already a mount point; leaving owner/mode alone"
    else
        ensure_dir "$mountpoint_path" 0755 "$CLIENT_USER" "$CLIENT_GROUP"
    fi
done

# ---------------------------------------------------------------------------
# master key: 32 raw bytes, 0600
#
# The binary checks both mode (0600) and owner (owner == euid). The server runs
# as root and the client as CLIENT_USER, so one file cannot serve both. Both
# files below must contain the same bytes; they are two views of one key.
# ---------------------------------------------------------------------------
for key in "$SERVER_KEY" "$CLIENT_KEY"; do
    if [ -L "$key" ]; then
        die "$key is a symlink; refusing"
    fi
    if [ -e "$key" ] && [ ! -f "$key" ]; then
        die "$key exists and is not a regular file"
    fi
done

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

is_ascii_whitespace() {
    case $1 in
        9|10|11|12|13|32) return 0 ;;
        *) return 1 ;;
    esac
}

validate_key() {
    local file=$1 size first last
    size=$(wc -c <"$file" | tr -d ' ')
    case $size in
        32|64|65) ;;
        *) die "key file $file has $size bytes; require 32 raw bytes or 64 hex characters" ;;
    esac
    if [ "$size" -eq 32 ]; then
        first=$(od -An -tu1 -N1 "$file" | tr -d ' ')
        last=$(tail -c 1 "$file" | od -An -tu1 | tr -d ' ')
        if is_ascii_whitespace "$first" || is_ascii_whitespace "$last"; then
            die "key file $file starts or ends with ASCII whitespace; parse_mm_key would trim it below 32 bytes"
        fi
    fi
    if [ "$size" -ge 64 ]; then
        head -c 64 "$file" | LC_ALL=C grep -E '^[0-9a-fA-F]{64}$' >/dev/null ||
            die "key file $file is not 64 hex characters"
    fi
    if [ "$size" -eq 65 ]; then
        last=$(tail -c 1 "$file" | od -An -tu1 | tr -d ' ')
        if ! is_ascii_whitespace "$last"; then
            die "key file $file has 65 bytes but the last byte is not whitespace"
        fi
    fi
}

# parse_mm_key trims ASCII whitespace from both ends. A 32-byte raw key that
# starts or ends with whitespace would be shortened and rejected, so redraw
# until both edges are non-whitespace.
generate_key() {
    local first last
    while :; do
        head -c 32 /dev/urandom >"$tmp"
        first=$(od -An -tu1 -N1 "$tmp" | tr -d ' ')
        last=$(tail -c 1 "$tmp" | od -An -tu1 | tr -d ' ')
        if ! is_ascii_whitespace "$first" && ! is_ascii_whitespace "$last"; then
            return 0
        fi
    done
}

if [ -f "$SERVER_KEY" ]; then
    validate_key "$SERVER_KEY"
    key_source=$SERVER_KEY
elif [ -f "$CLIENT_KEY" ]; then
    validate_key "$CLIENT_KEY"
    key_source=$CLIENT_KEY
else
    generate_key
    key_source=$tmp
fi

if [ "$key_source" = "$SERVER_KEY" ]; then
    chown root:root "$SERVER_KEY"
    chmod 0600 "$SERVER_KEY"
else
    install -m 0600 -o root -g root "$key_source" "$SERVER_KEY"
fi

if [ -f "$CLIENT_KEY" ]; then
    validate_key "$CLIENT_KEY"
    if ! cmp -s "$SERVER_KEY" "$CLIENT_KEY"; then
        die "$CLIENT_KEY differs from $SERVER_KEY; refusing to overwrite. Keep the copy that is in use and remove the stale one by hand."
    fi
else
    install -m 0600 -o "$CLIENT_USER" -g "$CLIENT_GROUP" "$SERVER_KEY" "$CLIENT_KEY"
fi
chown "$CLIENT_USER:$CLIENT_GROUP" "$CLIENT_KEY"
chmod 0600 "$CLIENT_KEY"

# ---------------------------------------------------------------------------
# units
# ---------------------------------------------------------------------------
for unit in mm-server-private-mm.service mm-server-public-mm.service 'mm-client@.service'; do
    [ -f "$SCRIPT_DIR/$unit" ] || die "missing unit source: $SCRIPT_DIR/$unit"
    if [ "$unit" = 'mm-client@.service' ]; then
        rendered=$(mktemp)
        sed -e "s|^User=.*|User=$CLIENT_USER|" \
            -e "s|^Group=.*|Group=$CLIENT_GROUP|" \
            -e "s|^Environment=HOME=.*|Environment=HOME=$CLIENT_HOME|" \
            "$SCRIPT_DIR/$unit" >"$rendered"
        install -m 0644 -o root -g root "$rendered" "$SYSTEMD_DIR/$unit"
        rm -f "$rendered"
    else
        install -m 0644 -o root -g root "$SCRIPT_DIR/$unit" "$SYSTEMD_DIR/$unit"
    fi
done

note ""
note "installed units:"
note "  $SYSTEMD_DIR/mm-server-private-mm.service"
note "  $SYSTEMD_DIR/mm-server-public-mm.service"
note "  $SYSTEMD_DIR/mm-client@.service"
note "installed directories:"
note "  $SERVER_ROOT/{private-mm,public-mm}/{,spool}  (root, 0700)"
note "  $CLIENT_ROOT/{private-mm,public-mm}            ($CLIENT_USER, 0700)"
note "  /private-mm /public-mm                         ($CLIENT_USER, 0755)"
note "installed keys (contents never printed):"
note "  $SERVER_KEY      (root:root, 0600)"
note "  $CLIENT_KEY      ($CLIENT_USER:$CLIENT_GROUP, 0600)"
note ""
note "nothing was started, enabled or reloaded. Next steps are in README.md."
