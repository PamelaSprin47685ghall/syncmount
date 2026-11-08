#!/usr/bin/env bash
# install.sh — download, verify and install a syncmount release.
#
# Usage:
#   ./install.sh                      install the latest release to ~/.local/bin
#   ./install.sh --version 1.1.0      install a specific version
#   ./install.sh --prefix /usr/local  install under /usr/local (may need sudo)
#
# Environment:
#   SYNCMOUNT_VERSION   version without the leading "v" (default: latest)
#   SYNCMOUNT_BASE_URL  release download base (mirrors and tests)
#   PREFIX              install prefix (default: ~/.local)
#
# The script verifies the published sha256 before touching the install prefix.
# It never invokes sudo: if the prefix is not writable, it stops and tells you
# to re-run under sudo or pick a user-writable prefix.

set -euo pipefail

REPOSITORY=${SYNCMOUNT_REPOSITORY:-PamelaSprin47685ghall/syncmount}
VERSION=${SYNCMOUNT_VERSION:-}
PREFIX=${PREFIX:-$HOME/.local}
BASE_URL=${SYNCMOUNT_BASE_URL:-}

usage() {
    cat <<'USAGE'
install.sh — download, verify and install a syncmount release.

Usage:
  ./install.sh                      install the latest release to ~/.local/bin
  ./install.sh --version 1.1.0      install a specific version
  ./install.sh --prefix /usr/local  install under /usr/local (may need sudo)

Environment:
  SYNCMOUNT_VERSION   version without the leading "v" (default: latest)
  SYNCMOUNT_BASE_URL  release download base (mirrors and tests)
  PREFIX              install prefix (default: ~/.local)

The script verifies the published sha256 before touching the install prefix.
USAGE
    exit "${1:-0}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --version)
            [ $# -ge 2 ] || { echo "--version needs a value" >&2; exit 2; }
            VERSION=$2
            shift 2
            ;;
        --prefix)
            [ $# -ge 2 ] || { echo "--prefix needs a value" >&2; exit 2; }
            PREFIX=$2
            shift 2
            ;;
        -h|--help) usage 0 ;;
        *) echo "unknown argument: $1" >&2; usage 2 ;;
    esac
done

case "$(uname -s)" in
    Linux) ;;
    *) echo "syncmount supports Linux only (found $(uname -s))" >&2; exit 2 ;;
esac
case "$(uname -m)" in
    x86_64|amd64) TARGET=x86_64-unknown-linux-musl ;;
    aarch64|arm64) TARGET=aarch64-unknown-linux-musl ;;
    *) echo "no release for architecture $(uname -m); only x86_64 and aarch64 are published" >&2; exit 2 ;;
esac

for tool in curl tar sha256sum; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "missing prerequisite: $tool" >&2
        exit 2
    }
done

BIN_DIR="$PREFIX/bin"
MAN_DIR="$PREFIX/share/man/man1"

ensure_writable_dir() {
    if ! mkdir -p "$1" 2>/dev/null; then
        echo "cannot create $1" >&2
        echo "re-run with sudo, or pass --prefix \"\$HOME/.local\"" >&2
        exit 2
    fi
    if [ ! -w "$1" ]; then
        echo "$1 is not writable by $(id -un 2>/dev/null || echo this user)" >&2
        echo "re-run with sudo, or pass --prefix \"\$HOME/.local\"" >&2
        exit 2
    fi
}

ensure_writable_dir "$BIN_DIR"
ensure_writable_dir "$MAN_DIR"

if [ -z "$BASE_URL" ]; then
    BASE_URL="https://github.com/${REPOSITORY}/releases/download"
fi

if [ -z "$VERSION" ]; then
    latest=$(curl -fsSLI -o /dev/null -w '%{url_effective}' \
        "https://github.com/${REPOSITORY}/releases/latest" 2>/dev/null || true)
    VERSION=${latest##*/}
    VERSION=${VERSION#v}
    if [ -z "$VERSION" ] || [ "$VERSION" = "latest" ]; then
        echo "cannot resolve the latest release; pass --version X.Y.Z" >&2
        exit 2
    fi
fi
VERSION=${VERSION#v}

ASSET="syncmount-${VERSION}-${TARGET}.tar.gz"
URL="${BASE_URL}/v${VERSION}/${ASSET}"
TMP=$(mktemp -d "${TMPDIR:-/tmp}/syncmount-install.XXXXXX")
trap 'rm -rf "$TMP"' EXIT INT TERM

echo "== download $ASSET"
# HTTPS is mandatory for the public release host; an explicit mirror may use
# plain HTTP on a trusted network.
case "$URL" in
    https://*) PROTO=(--proto '=https' --tlsv1.2) ;;
    *) PROTO=() ;;
esac
curl -fL --retry 3 "${PROTO[@]}" -o "$TMP/$ASSET" "$URL"
curl -fL --retry 3 "${PROTO[@]}" -o "$TMP/$ASSET.sha256" "$URL.sha256"

echo "== verify sha256"
(
    cd "$TMP"
    sha256sum -c "$ASSET.sha256"
)

echo "== unpack"
tar -xzf "$TMP/$ASSET" -C "$TMP"
test -x "$TMP/syncmount" || {
    echo "the archive does not contain a syncmount binary" >&2
    exit 2
}

install -m 0755 "$TMP/syncmount" "$BIN_DIR/syncmount"
if [ -f "$TMP/syncmount.1" ]; then
    install -m 0644 "$TMP/syncmount.1" "$MAN_DIR/syncmount.1"
fi

echo "== installed $("$BIN_DIR/syncmount" --version) at $BIN_DIR/syncmount"

case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *) echo "note: add $BIN_DIR to PATH" ;;
esac

echo "== prerequisites"
status=0
if [ -e /dev/fuse ]; then
    if [ -r /dev/fuse ] && [ -w /dev/fuse ]; then
        echo "  /dev/fuse: present and accessible"
    else
        echo "  /dev/fuse: present but not readable and writable by $(id -un 2>/dev/null || echo this user)" >&2
        status=2
    fi
else
    echo "  /dev/fuse: MISSING (load the fuse kernel module: modprobe fuse)" >&2
    status=2
fi
if command -v fusermount3 >/dev/null 2>&1; then
    echo "  fusermount3: $(command -v fusermount3)"
else
    echo "  fusermount3: MISSING (install the fuse3 package)" >&2
    status=2
fi
if grep -qs '^[[:space:]]*user_allow_other' /etc/fuse.conf; then
    echo "  /etc/fuse.conf: user_allow_other present"
else
    echo "  /etc/fuse.conf: user_allow_other absent (only --allow-other needs it)"
fi

if [ "$status" -ne 0 ]; then
    echo "  the binary is installed; server mode works without FUSE, client mounts do not" >&2
fi

cat <<EOF

Next:
  export SYNCMOUNT_MASTER_PASSWORD='...'
  syncmount server http://127.0.0.1:8080/sync --listen 127.0.0.1:8080
  syncmount client http://127.0.0.1:8080/sync /mnt/share

The master password is never accepted in argv; use the environment or a
0600 file with --key-file.
EOF

exit "$status"
