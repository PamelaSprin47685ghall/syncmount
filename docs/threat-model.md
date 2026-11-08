# Threat model

Status: normative security boundary for syncmount v2 (protocol 3.0). This
document states what the design protects, against whom, and what it explicitly
does not protect. It describes the design, not a particular build. The
semantic limits are in [`known-limitations.md`](known-limitations.md); the
operational surface is in [`../README.md`](../README.md) and
`man/syncmount.1`.

## 1. System and trust boundaries

```
client A (PSK, client.db plaintext) ── HTTP/1.1 ──┐
                                                  ├── server (PSK, server.db plaintext)
client B (PSK, client.db plaintext) ── HTTP/1.1 ──┘
        │                                              │
        └── local SQLite replica                       └── authoritative SQLite + event log
```

- The **server** holds the master password, derives the same PSK as every
  client, decrypts every operation, applies it to the authoritative SQLite
  database, stores plaintext file data and broadcasts the ordered event. It is
  the single ordering authority. It is trusted with the confidentiality and
  integrity of the data: it can read, modify or delete everything, and clients
  cannot cryptographically distinguish a server-forged event from a legitimate
  one.
- A **client** holds the PSK and a full plaintext replica in `client.db`. It
  trusts the server's order and applies every event the server sends. A
  password holder is a full member.
- The **network** is untrusted. HTTP/1.1 is used without built-in TLS. Frame
  headers, frame sizes, timing, route prefixes and the number of connections
  are visible; paths and payloads are sealed under the PSK.
- The **local host** is trusted for the client process, the password file and
  the SQLite databases. The mount ACL (`RootAndOwner` by default, `All` with
  `--allow-other`) is a local access boundary, not a cluster permission model.
- The **password distribution channel** is out of scope. Operators must
  deliver the master password out of band. Anyone with the password is a full
  member and can open every database.

The server is **not** an untrusted sequencer in v2. It is a trusted reader and
writer that happens to sit across a network link. This is the central
difference from an end-to-end encrypted design: the PSK protects the link, not
the data from the server.

## 2. Assets

- confidentiality of file data, paths, operation arguments and metadata on the
  wire and at rest;
- integrity and authenticity of the authoritative tree and the event log;
- the total order and the clients' ability to detect their own gaps and epoch
  changes;
- availability of the mount and of the server;
- the master password, the password file and the SQLite databases;
- the namespace id and the key hierarchy.

## 3. Adversaries

| ID | Adversary | Capabilities | Goal |
|---|---|---|---|
| A1 | Network attacker | Eavesdrop, inject, modify, drop, delay, replay, open connections; no PSK | Read data, forge or alter frames, disrupt service |
| A2 | Malicious or compromised server | Holds the PSK; reads and writes `server.db`; assigns or rewrites `seq`; drops, delays, duplicates or reorders events; forges events and kicks; refuses service | Read or alter all data, split or stall clients, deny service |
| A3 | Authorized password holder | Holds the PSK; can open both databases, join as a new client, send operations, replay captured frames, flood the server | Read or alter data, deny service |
| A4 | Local unprivileged user | Can access the mount only if `--allow-other` is on; can read files only under host permissions | Read or modify the mounted tree |
| A5 | Password or backup thief | Holds the password file, a database copy or a disk image; may or may not have a live host | Read all data, join as a client, decrypt recordings |

## 4. Protections

### 4.1 Link confidentiality

- The master password is stretched with Argon2id (`m = 64 MiB`, `t = 3`,
  `p = 4`) using the fixed 16-byte PSK salt. The 32-byte master key is
  expanded with HKDF-SHA256, using the namespace id as the salt, into the
  encryption, control and handshake keys.
- The namespace id is `BLAKE3("sm/v2/namespace" || master key)[..16]`. It is
  derived from the password, not from the URL. Every client and the server
  must use the same password; a different password derives a different id and
  a different key.
- Every steady-state frame is sealed with ChaCha8-Poly1305 (default) or
  ChaCha20-Poly1305 (selectable). Each frame uses an independent nonce from
  the nonce minter. The AEAD covers the frame body and binds the header fields
  except `seq`, which the server must assign.
- Paths, file data, chunk bytes and operation arguments are inside the sealed
  body. The server can read them because it holds the PSK; a network attacker
  without the PSK cannot.

The link is not encrypted against the server, and there is no built-in TLS.
On an untrusted network, use a local TLS tunnel that accepts plain HTTP on
loopback. TLS hides frame metadata from the network; it does not change the
server's trust status.

### 4.2 Link authentication

The handshake is one round trip:

```
client  HELLO(plain body + sealed AUTH) ─────▶ server
        ◀──── WELCOME(plain body + server proof + sealed ACCEPT)
        STEADY (sealed)
```

Both sides derive the `AUTH` key from the PSK and the client nonce, and the
`WELCOME` proof and `ACCEPT` key from the PSK and both nonces. The `WELCOME`
proof covers the canonical body including the sealed `ACCEPT`; a wrong PSK and
a tampered body both fail as an authentication error. The sealed `AUTH` also
authenticates the `HELLO` control prefix (`applied_seq`, `epoch_seen`), so a
relay cannot move the replay point. The server closes a failed sealed `AUTH`
silently so that "wrong password" and "tampered transcript" are not
distinguishable oracles.

After the sealed `ACCEPT` verifies, the steady-state key is used. AEAD tags
reject modified ciphertext. A replayed client nonce is rejected by the server's
nonce window.

### 4.3 Server authority and ordering

The server assigns `seq`, appends the event and only then broadcasts. A crash
between commit and broadcast is repaired by replay; the reverse order would
let a client apply an event the server never persisted.

The server can rewrite `seq`, delay, drop, duplicate or reorder events. A
client detects its own sequence gaps and an epoch change, but it cannot prove
a cross-client reorder: the server can put B's operation before A's as long as
each client's stream stays monotonic. Preventing that requires
client-to-client consensus or a global hash chain, which v2 does not have.

The server can also forge an event because it holds the PSK. Clients have no
independent signature to check. A compromised server is therefore a full
integrity compromise, not merely an ordering fault.

### 4.4 At rest

Both `client.db` and `server.db` contain plaintext paths, file data, chunk
bytes and metadata. The client creates its database with mode 0600 in a
directory set to 0700. The server database follows the process umask; a server
unit must set `UMask=0077` (or pre-create the file 0600) and keep it in a 0700
directory. File permissions are not encryption: a local user who can read the
file, a backup, a disk image or a volume image can read everything.

Use full-disk or volume encryption when the host disk is not trusted. Protect
backups at least as strictly as the live database. The password file is
equivalent to the databases: mode 0600, owned by the effective user, regular
file, no symlink.

### 4.5 Availability

- The server has a per-session outbound budget of 32 MiB and 512 data frames.
  A sequenced frame that does not fit ends the session with `QueueOverflow`
  instead of being dropped; the client reconnects and replays.
- A watermark that regresses or exceeds `current_seq` is kicked as
  `Regression` or `Overclaim`.
- A graceful shutdown drains for at most 30 seconds, compacts the event log,
  advances the epoch and kicks every session with `EpochMismatch`.
- The server accepts unauthenticated connections; garbage is dropped at AEAD
  or at the handshake proof. Rate limiting, connection quotas and a reverse
  proxy are operational controls, not protocol guarantees.

### 4.6 Local protection

- The default mount ACL is `RootAndOwner`; `--allow-other` widens it to every
  local user and requires `user_allow_other` in `/etc/fuse.conf`.
- The master password comes from a `0600` file, an environment variable or a
  TTY prompt. A password in argv is refused because argv is visible in `ps`
  and shell history. There is no keyring or credential cache.
- The client listens on no port. The server exposes only the sync endpoint
  and `GET /__syncmount/healthz`.
- The client database is locked with an exclusive `flock`; a second process on
  the same file fails at startup.

## 5. Adversary analysis

### 5.1 A1 — network attacker

**Can:** observe frame headers, sizes, timing, connection pairs and the number
of clients; drop, delay, duplicate or reorder frames; inject garbage; open many
connections; replay captured ciphertext.

**Cannot:** decrypt paths or payloads without the PSK; produce a valid AEAD tag
without the key; complete the handshake without the password; read the master
password from the protocol.

**Detection:** AEAD failure, handshake proof failure, nonce replay rejection,
sequence gap, epoch mismatch, connection loss.

**Residual:** traffic analysis and denial of service. Without a TLS tunnel the
attacker can also observe the plaintext handshake and frame metadata. The
payload remains sealed, but the server is still able to read it.

### 5.2 A2 — malicious or compromised server

**Can:** read every path, payload and chunk; modify or delete the authoritative
tree; rewrite `seq`; drop, delay, duplicate or reorder events; forge events and
kicks; roll back to an older database; refuse service; choose which clients to
serve.

**Cannot:** be detected by a client that has no independent copy. There is no
client signature and no hash chain; the client trusts the server's order and
content. Encryption does not help because the server holds the PSK.

**Residual:** this is a full confidentiality and integrity compromise. The only
mitigations are operational: restrict access to the server host and
`server.db`, keep independent backups, and treat the server as part of the
trusted data boundary. A compromised server can also read every client
database it can reach, because the password is shared.

### 5.3 A3 — authorized password holder

**Can:** open `server.db` and any `client.db`; decrypt recorded traffic; join
as a new client; send valid operations; replay captured frames; flood the
server; withhold service.

**Cannot:** be distinguished from another member by a per-client credential:
there is no such credential. The `client_id` in a `HELLO` is a random local
label, not an identity and not a routing key.

**Residual:** every password holder is equal. There are no per-client ACLs,
roles or read restrictions. A member can always read the cluster's plaintext
and can always deny service. The password is the tenant boundary. Revocation
requires a new password, new namespace id and rebuilt or re-imported
databases; old recordings remain decryptable with the old password.

### 5.4 A4 — local unprivileged user

With the default `RootAndOwner` ACL, only the mounting user and root can access
the mount. With `--allow-other`, every local user can read and write the tree
under the daemon's credentials; uid/gid metadata is not an access-control
mechanism. A local user who can read the password file or `client.db` has the
same access as the mount owner.

### 5.5 A5 — password or backup thief

A stolen password file, database copy or disk image gives full read access to
the data and, with the password, the ability to join as a client. There is no
perfect forward secrecy: recordings made before the theft remain decryptable.
The response is to change the password, rebuild or re-import the databases and
assume the old data was exposed.

## 6. Key lifecycle

```
master password
  └─ Argon2id(fixed PSK salt, m=64 MiB, t=3, p=4) → 32-byte master key
       └─ HKDF-SHA256(salt = namespace id) → enc / ctrl / handshake keys
namespace id = BLAKE3("sm/v2/namespace" || master key)[..16]

per connection
  ├─ AUTH key = KDF(PSK, client nonce)
  └─ handshake key = KDF(PSK, client nonce, server nonce)
       ├─ WELCOME proof
       └─ sealed ACCEPT verified → steady-state session key
```

- The server and every client use the same master password. There is no
  per-client key, no client certificate and no key directory.
- The password file must be a regular file, owned by the effective user, mode
  0600 or stricter. One trailing newline is stripped; an empty file is
  refused. Violations are a startup error.
- **No rotation.** Changing the password derives a new namespace id, so
  existing databases refuse to open. The operator must rebuild the server and
  re-import or recreate every client database under the new password. This is
  a migration, not an in-band rotation.
- **No revocation.** Removing a member means changing the password and
  rebuilding. There is no revocation list and no per-client credential to
  revoke.
- **No forward secrecy.** A leaked password decrypts past and future traffic.
  ChaCha20-Poly1305 does not change that.
- **Compromise response.** A leaked password: rebuild under a new password and
  assume all old data and recordings are exposed. A stolen database: treat all
  plaintext in it as exposed. A compromised server: treat the whole tree as
  exposed and restored from a trusted backup if one exists.

## 7. Out of scope

- end-to-end encryption, a zero-knowledge server or server-side opacity;
- perfect forward secrecy, password rotation, revocation or per-client
  credentials;
- per-client ACLs, roles or read restrictions;
- Byzantine fault-tolerant total order, client-to-client consensus or
  detection of cross-client reordering by the server;
- traffic-analysis resistance (padding, cover traffic, timing obfuscation);
- built-in encryption at rest;
- public-key infrastructure, certificate chains or a CA;
- cryptographic denial-of-service protection;
- multi-tenant isolation;
- TPM, secure boot, memory encryption or side-channel hardening;
- supply-chain verification beyond pinned dependencies and licence checks;
- protection of the master password distribution channel;
- protection against a compromised client host after the password is
  unlocked.

## 8. Assurance and references

This document states design boundaries; it is not a formal security audit. The
implementation must demonstrate the claims with handshake and AEAD golden
vectors, tamper and nonce-replay tests, deterministic replay tests,
drain/compaction tests and the multi-host acceptance run. Passing tests is
engineering evidence, not a proof.

References:

- [`known-limitations.md`](known-limitations.md) — the semantic boundary;
- [`../README.md`](../README.md) — architecture, deployment and CLI;
- `man/syncmount.1` — command, environment and exit-status reference;
- `docs/contracts/ledger.toml` — frozen contract index.
