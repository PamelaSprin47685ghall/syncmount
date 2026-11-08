# Building and releasing syncmount

Owner: W21 (D1). This document is the build contract for the release binary.

## Toolchain

| Item | Value |
|---|---|
| Rust | `1.85.0` (pinned by `rust-toolchain.toml`) |
| Edition | 2024 |
| Components | `rustfmt`, `clippy` |
| Targets | `x86_64-unknown-linux-gnu` (development), `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` (release) |
| Linker | host `cc`; the musl target ships its own libc/crt |
| Extra tools | `fusermount3` and `/dev/fuse` for FUSE tests only |

The dependency set is pinned in `Cargo.toml` and `Cargo.lock`; every CI and
release command uses `--locked`.

## Features

| Feature | Default | Effect |
|---|---|---|
| `reduced-round` | on | ChaCha8-Poly1305 on the wire (`alg=0`); off selects ChaCha20-Poly1305 (`alg=1`). |
| `fuse` | on | Builds the FUSE client. `--no-default-features` produces a server-only binary whose `client` command fails with an explicit message. |
| `fuse-tests` | off | FUSE integration tests; require a mounted filesystem. |
| `slow-tests` | off | Opt-in long-running tests. |
| `pure-blake3` | off | Disables blake3's C/asm build. |

Release builds use the default feature set (`reduced-round` + `fuse`).

## Local build

```bash
rustup toolchain install 1.85.0
rustup target add x86_64-unknown-linux-musl

cargo +1.85.0 build --locked --release
cargo +1.85.0 test --locked
cargo +1.85.0 clippy --locked --all-targets -- -D warnings
cargo +1.85.0 fmt --all -- --check
```

Server-only check (the `client` command must report that FUSE is not compiled
in):

```bash
cargo +1.85.0 build --locked --no-default-features
```

## Static musl release

```bash
cargo +1.85.0 build --locked --profile dist --target x86_64-unknown-linux-musl
bin=target/x86_64-unknown-linux-musl/dist/syncmount
file "$bin"
ldd "$bin" || true                 # "not a dynamic executable"
readelf -d "$bin" | grep NEEDED    # must print nothing
stat -c%s "$bin"                   # must be < 15 * 1024 * 1024
"$bin" --version
```

`profile.dist` inherits `release` and sets `lto = "fat"`,
`codegen-units = 1`, `strip = "symbols"`. `panic` stays `unwind` because the
unmount path must run after a worker panic.

### aarch64 musl cross build

The aarch64 target uses a musl cross toolchain; the host `cc` cannot link it.
One working setup (musl-cross) is:

```bash
export PATH="$HOME/.local/share/musl-cross/aarch64-linux-musl-cross/bin:$PATH"
export CC_aarch64_unknown_linux_musl=aarch64-linux-musl-gcc
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-musl-gcc
cargo +1.85.0 build --locked --profile dist --target aarch64-unknown-linux-musl
bin=target/aarch64-unknown-linux-musl/dist/syncmount
file "$bin"                        # ELF 64-bit LSB executable, ARM aarch64, statically linked
readelf -l "$bin" | grep INTERP    # must print nothing
readelf -d "$bin" | grep NEEDED    # must print nothing
```

The resulting binary is `ET_EXEC` (not static-PIE); it has no build-id, so
release records must identify it by sha256. The FUSE runtime dependency is
unchanged.

A release build does not link `libfuse`; fuser talks to `/dev/fuse` directly.
The host still needs the `fusermount3` helper at runtime.

### FUSE runtime dependency

The binary is static; FUSE is not. A client mount needs:

| Item | Why | Check |
|---|---|---|
| `/dev/fuse` | the kernel channel fuser opens | `[ -r /dev/fuse ] && [ -w /dev/fuse ]` |
| `fusermount3` | setuid mount and unmount helper from the `fuse3` package | `command -v fusermount3` |
| `/etc/fuse.conf` | only for `--allow-other`, which needs `user_allow_other` | `grep user_allow_other /etc/fuse.conf` |

The package is `fuse3` on Debian, Ubuntu, Arch and Fedora; older releases call
it `fuse`. Server mode needs none of these: it only binds a TCP port. A scratch
container for the client must bind-mount `/dev/fuse` and carry `fusermount3`
from the host or an image layer; it must also mount `/etc/resolv.conf` and
`/etc/hosts`, because musl has no NSS (see the failure table below).

The CI FUSE job installs `fuse3`, removes a shadowing
`/usr/local/bin/fusermount3`, appends `user_allow_other` to `/etc/fuse.conf`,
and skips with a printed reason when `/dev/fuse` is unusable.
`SYNCMOUNT_REQUIRE_FUSE=1` turns that skip into a failure.

## Release assets

A tag `vX.Y.Z` triggers `.github/workflows/release.yml`, which produces:

```
syncmount-X.Y.Z-x86_64-unknown-linux-musl.tar.gz
syncmount-X.Y.Z-x86_64-unknown-linux-musl.tar.gz.sha256
```

The tarball contains:

```
syncmount                     static musl binary
syncmount.1                   man page
README.md
LICENSE-MIT
LICENSE-APACHE
THIRD-PARTY-LICENSES.md
examples/mount-demo.sh
examples/two-clients.sh
examples/offline-remount.sh
```

`sha256sum` is computed inside the staging directory so the file names in the
`.sha256` match the tarball next to it. `install.sh` verifies that checksum
before installing. `THIRD-PARTY-LICENSES.md` is generated from `cargo metadata`
at release time; the crate set is the one in `Cargo.lock`.

Asset naming is frozen: `syncmount-<version>-<target>.tar.gz` with the version
without a leading `v`.

## Install

`install.sh` downloads the release tarball, verifies the published sha256, and
installs the binary and the man page:

| Invocation | Binary | Man page |
|---|---|---|
| `./install.sh` | `~/.local/bin/syncmount` | `~/.local/share/man/man1/syncmount.1` |
| `./install.sh --prefix /usr/local` | `/usr/local/bin/syncmount` | `/usr/local/share/man/man1/syncmount.1` |

`PREFIX` and `SYNCMOUNT_VERSION` are the environment forms of `--prefix` and
`--version`; `SYNCMOUNT_BASE_URL` points the script at a mirror.
The script never calls `sudo`: if the prefix is not writable it stops and asks
you to re-run under sudo or choose `~/.local`.

After installing, it reports whether `/dev/fuse` and `fusermount3` are usable.
A missing FUSE prerequisite exits 2 but leaves the binary in place, because
server mode does not need FUSE.

## CI

`.github/workflows/ci.yml` runs:

- `cargo fmt --check`, `clippy -D warnings`, `cargo test`;
- a FUSE job when `/dev/fuse` is usable, with `SYNCMOUNT_REQUIRE_FUSE=1`;
- an MSRV/musl job that builds `profile dist`, asserts static linking and the
  15 MiB ceiling, and runs `--version`.

The release workflow repeats the static assertions and refuses to publish an
asset that fails them.

## Prerequisites and failure modes

| Symptom | Cause | Fix |
|---|---|---|
| `cannot open /dev/fuse` | module not loaded or device not granted | `modprobe fuse`; check device permissions |
| ``fusermount3` was not found` | fuse3 not installed | install `fuse3` |
| `--allow-other requires user_allow_other` | `/etc/fuse.conf` lacks the line | add `user_allow_other` as root |
| `no master password source` | no env var, no `--key-file`, no terminal | set `SYNCMOUNT_MASTER_PASSWORD` or `SYNCMOUNT_MASTER_PASSWORD_FILE` |
| `master password file … has mode 0644` | credential file is readable by others | `chmod 0600` |
| DNS fails in a scratch container | musl has no NSS; `/etc/resolv.conf` and `/etc/hosts` are missing | bind-mount both files |
| `master password rejected` / exit 4 | the client and server use different passwords | use the same password for the server and every client; a changed password derives a new namespace id and needs new databases |
| `another process holds the lock` | a second client opened the same `client.db` | use a distinct `--db` or `SYNCMOUNT_STATE_DIR` for each mount |
| `database belongs to a different cluster` | the database was created under another password | re-import or recreate the database under the current password |

## Source layout

```
src/cli.rs          argv, exit codes, implicit aliases
src/bin/syncmount.rs  five lines from argv to lib::run
src/client/         FUSE-over-SQLite client, durable outbox, replay, status
src/server/         HTTP, sequencer, authoritative store, health
src/protocol/       frame, crypto, handshake, messages
src/state/          pure operation planner and conflict rules
src/store/          shared SQLite schema, backing helpers, runtime directory
src/fuse/           FUSE callbacks over the client database
man/                man page source
examples/           runnable demonstrations
install.sh          verified release installer
```
