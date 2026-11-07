# Threat model

Status: normative security boundary for syncmount v1. This document states what
the design protects, against whom, and what it explicitly does not protect. It
describes the design, not a particular build. The semantic limits are in
[`known-limitations.md`](known-limitations.md); the protocol and key decisions
are in `39-s1-spec.md`, `49-arbitration-list.md`, `50-client-signing.md` and
`15/21-protocol-spec`.

## 1. System and trust boundaries

```
client A (PSK, Ed25519 sk) ── HTTP/1.1 ──┐
                                        ├── sequencer (zero keys, no durable state)
client B (PSK, Ed25519 sk) ── HTTP/1.1 ──┘
        │                                        │
        └── local backing tree                   └── broadcast ciphertext
```

- The **server** is a stateless sequencer. It reads the 21-byte frame header,
  `seq`, message type, lengths, route prefixes and plaintext control frames.
  It assigns `seq`, routes frames and keeps an online-session table. It holds
  no payload key, no control key, no join key, no signing key and no
  authentication key, it does not verify signatures, and it keeps no durable
  state. It is not trusted for confidentiality, authenticity or correct
  ordering beyond the clients' ability to detect some ordering faults.
- A **client** holds the cluster PSK (derived from the master password and the
  cluster id), its own Ed25519 private key and a full local copy of the tree.
  Clients are trusted to follow the protocol. An authorized member is still an
  adversary for other members' data and for availability.
- The **network** is untrusted. HTTP/1.1 is used without built-in TLS.
  Payloads are end-to-end encrypted; frame headers, route prefixes and control
  frames are not.
- The **local host** is trusted for the client process and its backing tree.
  The mount ACL (`RootAndOwner` by default, `All` with `--allow-other`) is a
  local access boundary, not a cluster permission model.
- The **password distribution channel** is out of scope. Operators must
  deliver the master password out of band (password manager, sealed channel,
  secret mount). Anyone with the password is a full member.

The server is **not** trusted to be honest. It is trusted only as the single
ordering point: clients accept its `seq` as the order in which they replay.
That is an architectural trade-off, not an assumption of good behaviour.

## 2. Assets

- confidentiality of file data, paths, operation arguments, manifests and
  chunk contents;
- integrity and authenticity of operations and of the resulting tree;
- member identity and attribution;
- the total order and the ability to detect gaps and rollback;
- availability of the mount and of the sequencer;
- lock state and namespace ownership;
- the client's private key and the cluster password.

## 3. Adversaries

| ID | Adversary | Capabilities | Goal |
|---|---|---|---|
| A1 | Network attacker | Eavesdrop, inject, modify, drop, delay, replay, open connections; no PSK, no private key | Read data, forge or alter operations, disrupt service |
| A2 | Malicious or compromised server | Read headers, `seq`, control frames and route prefixes; assign or rewrite `seq`; drop, delay, duplicate, reorder; inject plaintext control frames; choose join validators; refuse service; no PSK, no client private key | Read data, forge operations, split or stall clients, deny service |
| A3 | Authorized member | Holds PSK; can decrypt all traffic, join as a new client, send its own operations, replay within the dedup window, equivocate, refuse snapshot data | Read other members' data, impersonate another member, corrupt state, deny service |
| A4 | Private-key thief | Holds one client's Ed25519 private key; may or may not hold the PSK | Impersonate that `client_id`, sign operations as that member |
| A5 | Local unprivileged user | Can access the mount only if `--allow-other` is on; can read the client's files only under host permissions | Read or modify the mounted tree, steal local key material |

## 4. Protections

### 4.1 Confidentiality

- All payloads are sealed with ChaCha8-Poly1305 (default) or
  ChaCha20-Poly1305 (selectable). The AEAD covers data, paths, operation
  arguments, manifests and chunk contents. At the protocol level, the server
  sees only the frame header, routing prefix, control prefix and ciphertext
  length.
- The master password is stretched with Argon2id (`m=64 MiB`, `t=3`, `p=4`)
  using a 16-byte cluster-derived salt, then expanded with HKDF-SHA256
  (salt = cluster id) into the payload, control and join keys. The server
  never receives the password or any derived key.
- Each AEAD frame uses an independent nonce from the nonce minter. Nonce reuse
  would be catastrophic for ChaCha20-Poly1305; the nonce minter is part of the
  crypto contract and is covered by golden tests.
- Each 64 KiB content envelope uses a fresh 96-bit random nonce. Equal
  plaintext produces different ciphertext; the design does not use
  deterministic or content-derived nonces.
- Content chunks are addressed by `chunk_id = BLAKE3(256 KiB plaintext)`. The
  chunk index is a plaintext hash, so a member holding it can tell whether two
  blocks are identical. The server does not see `chunk_id`; it is inside the
  encrypted WCP payload. The leak is limited to cluster members and is stated
  in `known-limitations.md` §4.3.
- Logs and the status document never contain payloads, keys or clear paths;
  they publish at most a short BLAKE3 path-hash prefix for local diagnostics.
  No plaintext path hash is sent to the server.

### 4.2 Integrity and authenticity

**AEAD.** The AAD binds the frame header fields except `seq`, plus the
routing/control prefix. It is the `V1Minimal` profile: a domain separator,
`alg`, `kid`, the header fields, a prefix tag and the prefix bytes. `seq` is
excluded because the sender does not know it when sealing and the server must
be able to assign it. The AEAD tag rejects modified ciphertext.

**Client signatures.** Every `ORDERED` operation is signed by its author with
Ed25519. The signature input is a fixed 103-byte concatenation:

```
"sm/v1/op\0"         10 B
sig_ver u8            1 B
cluster_id [16]      16 B
client_id [16]       16 B
frame_type u8         1 B
flags u16 LE          2 B
iid u64 LE            8 B
local_seq u64 LE      8 B
op_class u8           1 B
epoch u64 LE          8 B
payload_hash [32]    32 B
```

`payload_hash = BLAKE3-256(plaintext payload after the AUTH block)`. The
signature block is inside the AEAD ciphertext, before the WCP payload, so the
server cannot see it, strip it, modify it or verify it. A receiver opens the
AEAD, parses the AUTH block, verifies the self-certifying `client_id`,
recomputes the payload hash and calls `verify_strict`. A signed frame must not
be compressed in v1.

`STREAM_DATA` fragments are not signed individually. The whole payload is
bound by the `ORDERED` signature and `payload_hash`; each fragment is protected
by its own AEAD tag. This avoids one Ed25519 operation per 64 KiB fragment.

**Self-certifying identity.** Each client generates a random Ed25519 key pair.
The key is not derived from the shared PSK. The identity is:

```
client_id = BLAKE3("sm/v1/client-id" ‖ cluster_id ‖ public_key)[..16]
skid      = BLAKE3("sm/v1/skid" ‖ public_key)[..8]
```

The private key seed is stored in a `0600` file under
`$XDG_STATE_HOME/syncmount/keys/<cluster_id>/ed25519.key` (directory `0700`).
The file is opened with `O_NOFOLLOW`, must be owned by the current user, and is
rejected if group or other permissions are present. The seed is zeroized in
memory and never appears in logs. A keyring may replace the file; the file is
the baseline. There is no `Debug` or `Clone` implementation for the seed
holder. The file is bound to one cluster and rejected for another.

**Key distribution.** `JOIN_PROOF` is sealed with a join key derived from the
master key and the two handshake nonces (`sm/v1/join`, `sm/v1/jnonce`). It
carries the joining client's `client_id`, public key, `skid` and a
`sm/v1/keyproof` self-signature over the cluster id, `client_id`, public key
and handshake nonces. A member opens it only with the same cluster key, checks
`client_id == BLAKE3(...)`, checks `skid`, and verifies the self-signature. It
answers `JOIN_ACCEPT` with the keys it knows. The server forwards these
messages and cannot read them.

Later distribution uses the snapshot `keys[]` section, inline public keys on
ordered frames (first frame and at least every 64 frames), and
`KEY_REQ`/`KEY_RESP`. A receiver that does not know a key caches a bounded
number of frames, requests the key and drops the frames if the key does not
arrive. The server's key directory, if one is deployed, is a cache and never
authoritative. Trust-on-first-use is optional and is not a trust root.

**Receive path.** The order is:

1. parse the 21-byte header and validate magic, version, type, flags and
   length;
2. AEAD open;
3. parse the AUTH block; an unknown `auth_ver` or `auth_alg` is dropped;
4. look up `skid`; use an inline public key if present and verify
   `skid == H(pk)[..8]`;
5. verify `client_id == H(cluster_id‖pk)[..16]`;
6. recompute `payload_hash` and verify the Ed25519 signature with
   `verify_strict`;
7. check `epoch`;
8. deduplicate by `op_id`;
9. buffer or reject out-of-order `local_seq`;
10. apply in `seq` order and advance `applied_seq` and the per-client
    watermark.

A header, AEAD, self-certification or signature failure drops the frame and
does not advance `applied_seq`. Repeated failures from one `client_id` mark it
locally `UNTRUSTED` and raise an alert. The client does not use a server
`KICK` as a security decision: the server is untrusted, and a forged `KICK`
can hit any client. If a client's own operation echoes back with a failed
signature, it stops writing, alerts and unmounts because its local state is
not trustworthy.

**What the signature does not cover.** The signature does not cover `seq`,
`req_id`, `len`, the nonce, the ciphertext or the tag. It proves who wrote an
operation and what it contains; it does not prove where the server placed it
in the order. Replay protection is stateful, not part of the signature.

### 4.3 Replay and ordering

- Each operation has `op_id = (client_id, iid, local_seq)`. Receivers
  deduplicate on `op_id` for 1M entries or 24 hours, whichever comes first.
  The same `op_id` under multiple `seq` values keeps the smallest `seq`.
- Each client maintains a `local_seq` window (4096 entries). A gap is buffered
  or triggers a `RELAY` request; a value below the window is treated as a
  replay and dropped.
- The server epoch is checked before apply. A server restart draws a new epoch;
  frames from another epoch are rejected and the client resynchronises.
- Snapshots carry per-client watermarks, so a new node can reject operations
  older than the snapshot it installed.
- The server keeps no replay window. A client that falls behind gets a full
  snapshot plus rsync resynchronisation, not an incremental replay.

**Residual ordering risk.** The server can reorder operations across clients.
It can put B's operation before A's as long as each client's own `local_seq` is
monotonic. No client can prove that this happened, because the server is the
ordering authority and signatures deliberately exclude `seq`. Preventing
cross-client reordering requires client-to-client consensus or a global hash
chain, which v1 does not have. This is an accepted design boundary, not a bug.

The server can also delay or drop frames. A client detects its own gaps and
heartbeat timeouts, but cannot prove that a frame was delayed rather than
never sent. The accepted recovery is a full resynchronisation.

### 4.4 Availability

- Heartbeats (`PING`/`PONG`) carry `applied_seq`. The server's watermark check
  detects stalls, rollback, out-of-range values and duplicate `client_id`
  sessions, and can kick a client.
- A kick is an availability hint. A malicious server can force an unmount by
  sending one. The client exits 10 and releases the mount; no shared state is
  changed by the kick itself.
- The server accepts unauthenticated connections. Garbage is dropped at AEAD;
  rate limits, connection quotas and a reverse proxy are the operational DoS
  controls. The protocol does not provide cryptographic DoS protection.
- A signature failure is fail-closed: the receiver drops the frame and does
  not advance `applied_seq`. An authorized member can use invalid signatures to
  stall a receiver. This is an accepted denial-of-service risk.

### 4.5 Transport

- The protocol is HTTP/1.1 with chunked request and event streams. There is no
  built-in TLS termination in v1.
- On an untrusted network, terminate TLS in a reverse proxy or tunnel in front
  of the sequencer. TLS protects frame headers, control frames and traffic
  metadata on the wire.
- TLS is the transport baseline, not a trust root. The server is still not
  trusted, and TLS does not make its control frames authoritative. The payload
  remains end-to-end encrypted even without TLS.
- A network attacker without the PSK cannot read or forge the payload, but can
  drop, delay, replay or inject garbage, and can observe traffic shape.
  Without TLS, the attacker can also tamper with plaintext control frames.

### 4.6 Local protection

- The default mount ACL is `RootAndOwner`; `--allow-other` widens it to every
  local user and requires `user_allow_other` in `/etc/fuse.conf`.
- The master password comes from an environment variable, a `0600` file or a
  TTY prompt. A password in argv is refused because argv is visible in `ps`
  and shell history. There is no keyring or credential cache.
- The client listens on no port. The server exposes only the sync endpoint and
  `GET /__syncmount/healthz`.
- The Ed25519 key file is `0600` in a `0700` directory, opened with
  `O_NOFOLLOW`, owner-checked and rejected if group or other permissions are
  present. A local user who can read it has the client's signing key.
- Device nodes and special files may be created, but their endpoints are local
  kernel objects. Access remains subject to the local mount policy; a device
  node is not a cross-host device passthrough.

## 5. Adversary analysis

### 5.1 A1 — network attacker

**Can:** observe frame sizes, timing, connection pairs, route prefixes and
plaintext control frames; drop, delay, duplicate or reorder frames; inject
garbage; open many connections; replay captured ciphertext.

**Cannot:** decrypt payloads or paths without the PSK; produce a valid AEAD tag
without the key; produce a valid Ed25519 signature without a client key; read
the master password from the protocol.

**Detection:** AEAD failure, signature failure, `op_id` dedup, `local_seq`
window, epoch mismatch, `seq` gap, heartbeat timeout.

**Residual:** traffic analysis, denial of service, and — without TLS —
tampering with plaintext control frames. TLS mitigates the last one on the
wire, but does not protect against a malicious server.

### 5.2 A2 — malicious or compromised server

**Can:** read the 21-byte header, `seq`, message type, lengths, route prefixes
and client identifiers; assign or rewrite `seq`; drop, delay, duplicate or
reorder frames; replay old ciphertext; inject `WELCOME`, `PONG`, `KICK`,
`ERROR`, `FLOW`, `SYNC_END` and `LEAVE`; choose which member validates a join;
refuse service; lie about `epoch` or `current_seq`.

**Cannot:** read payloads, paths, manifests, chunk ids, public keys or
signatures; forge or alter an `ORDERED` payload without breaking AEAD; forge a
client signature; read a client's private key or the PSK.

**Detection:** AEAD failure; signature failure; `op_id` dedup; `local_seq`
window; epoch mismatch; `seq` gap; local comparison of `client_id` with the
public key; snapshot watermarks.

**Residual:**

- **Cross-client reordering is not detectable.** The server can put B's
  operation before A's as long as each client's own `local_seq` is monotonic.
  Preventing this requires client-to-client consensus or a global hash chain,
  which v1 does not have.
- **Delay and drop are not provable.** The server can starve a client until
  the heartbeat/watermark path declares it unhealthy.
- **Control-frame forgery affects availability.** A forged `KICK` can unmount
  a client; a forged `LEAVE` cannot release locks or change state. The client
  treats these frames as hints. A signed client `LEAVE` or a lease is required
  to release locks.
- **The server's `client_id` is a claim, not a credential.** A malicious
  client can claim another `client_id` in `HELLO` and trigger the
  duplicate-session kick against the real owner. This is a denial of service,
  not impersonation of signed operations.
- **A malicious server can lie about `epoch`/`current_seq`.** The affected
  client's operations are rejected by peers or trigger a resync. This is a
  denial of service, not a confidentiality break.
- **A malicious server can choose a hostile or silent join validator.** The
  validator must still hold the PSK; it can reject or delay the join, but it
  cannot forge an acceptance or a key. This is a denial of service.
- **A malicious snapshot provider is a member.** It can withhold data or
  supply a bad baseline, causing a denial of service or a wrong starting point.
  Snapshot content is content-addressed and ordered replay still converges; a
  provider cannot forge a signed operation.

### 5.3 A3 — authorized member

**Can:** decrypt all traffic (the PSK is shared); read every path and payload;
join as a new client; send its own valid operations; replay captured
operations inside the dedup window; equivocate (two different payloads for one
`op_id`); refuse to serve snapshot data; flood the sequencer; send invalid
signatures to stall a fail-closed receiver; claim another `client_id` in
`HELLO` to trigger a duplicate-session kick.

**Cannot:** derive another member's Ed25519 private key from the PSK (the keys
are independent random keys, not HKDF outputs of the PSK); forge another
member's signature while the receiver holds that member's key; read a private
key file on another host.

**Detection:** a duplicate `op_id` with a different payload hash is
equivocation; the receiver does not apply either version, marks the sender
untrusted and may force a resync. An invalid signature is dropped
(fail-closed). A member that withholds data causes a timeout or a snapshot-
source switch.

**Residual:** every PSK holder is equal. There are no per-client ACLs, roles or
read restrictions. A member can always read the cluster's plaintext and can
always deny service. This is a single-tenant trust model: the PSK is the
tenant boundary. A member can also claim another `client_id` in `HELLO`; the
server kicks the real owner (availability, not forgery).

Key distribution is peer-mediated. A member that has not learned a peer's key
cannot verify that peer's frames; it drops them and requests the key. The
snapshot `keys[]` section, inline public keys and `KEY_REQ` are the recovery
paths. A malicious member can refuse to answer a key request, causing a
denial of service for that peer.

### 5.4 A4 — private-key thief

**Can:** sign operations as the stolen `client_id`. If the attacker also has
the PSK, it can produce valid ciphertext and fully impersonate that member
until the cluster is rebuilt. Without the PSK it cannot produce valid
ciphertext.

**Cannot:** sign as a different member (different key), read the PSK from the
key file (the file contains only the Ed25519 seed), or revoke the theft.

**Response:** v1 has no revocation list and no same-id key rotation. The only
global response is to change the master password, rebuild the cluster and
re-enrol clients with new identities. The stolen key remains able to sign
historical-looking operations, but without the new PSK those operations cannot
be encrypted validly.

### 5.5 A5 — local unprivileged user

With the default `RootAndOwner` ACL, only the mounting user and root can access
the mount. With `--allow-other`, every local user can read and write the tree
under the daemon's credentials; uid/gid metadata is not an access-control
mechanism. The key file is `0600`; a local user who can read it has the
client's signing key.

## 6. Key lifecycle

```
master password
  └─ Argon2id(cluster-derived salt) → master_key
       └─ HKDF-SHA256(salt = cluster_id) → enc_key / ctrl_key / join_key
per client
  └─ OsRng → Ed25519 seed → public key
       └─ client_id = BLAKE3("sm/v1/client-id" ‖ cluster_id ‖ pk)[..16]
```

- The cluster id is derived from the normalised URL
  (`scheme://authority/prefix`). A different URL spelling derives a different
  key and a different cluster.
- The server needs no password and holds no key of any kind. TLS termination,
  if used, is external and does not give the sequencer payload or signing keys.
- The Ed25519 key file is bound to one cluster and rejected for another. It is
  written with a temporary file, `fsync`, `rename` and a directory `fsync`;
  an existing key is not silently replaced. `--new-key` explicitly creates a
  new identity.
- Key backup is a copy of the file. Loss means a new identity (`client_id`
  changes) and a rejoin; there is no recovery service.
- **No rotation.** Changing the password derives a new cluster key; every
  client must change it. There is no in-band rotation, no key epoch rollover
  and no revocation list. Deleting a client key creates a new `client_id` and
  a new identity.
- **Compromise response.** PSK leak: rebuild the cluster with a new password;
  old traffic remains decryptable to the attacker (no forward secrecy).
  Private-key leak: rebuild the cluster and re-enrol; the old `client_id`
  cannot be revoked individually. Both leaked: full compromise; rebuild.
- **No forward secrecy.** A leaked password decrypts all recorded traffic,
  past and future. ChaCha20-Poly1305 does not change that.

## 7. Out of scope

- Byzantine fault-tolerant total order or client-to-client consensus;
- detection or prevention of cross-client reordering by the server;
- perfect forward secrecy;
- traffic-analysis resistance (padding, cover traffic, timing obfuscation);
- public-key infrastructure, certificate chains or a CA;
- per-client ACLs, roles or read restrictions;
- cryptographic denial-of-service protection;
- multi-tenant isolation;
- TPM, secure boot, memory encryption or side-channel hardening;
- supply-chain verification beyond pinned dependencies and licence checks;
- protection of the master password distribution channel;
- protection against a compromised client host after the key is unlocked.

## 8. Assurance and references

This document states design boundaries; it is not a formal security audit. The
implementation must demonstrate the claims with golden vectors for frame
layout, AEAD and signature inputs; tamper matrices; deterministic replay tests;
join and rsync tests; and chaos tests for loss, reorder, duplication and
restart. Passing tests is engineering evidence, not a proof.

References:

- `39-s1-spec.md` — S1 requirements, threat boundary and v1 scope;
- `49-arbitration-list.md` — frame widths, AAD, chunk addressing, locks, rsync
  segments and the decision that the server holds no key;
- `50-client-signing.md` — per-client Ed25519, self-certifying id, signature
  scope, key distribution and residual ordering risks;
- `36-known-limitations.md` — limitation inventory;
- `15/21-protocol-spec` — frame, AEAD and message layout;
- `28-master-password.md` and `33-join-handshake.md` — Argon2id and join proof.
