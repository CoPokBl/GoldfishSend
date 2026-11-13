# GoldfishSend: Project Plan

An end-to-end encrypted messenger for Android. It has no accounts and a server that knows as little as possible.
The server is a **blind relay**. It takes an opaque ciphertext addressed to an opaque mailbox, pushes it to
the recipient's device through UnifiedPush, and forgets it.

---

## 1. Goals and non-goals

**Goals**
- No accounts, phone numbers, emails or usernames. Contacts are added out of band (QR code or link).
- The server never sees message content, the sender's identity, or a stable recipient identity.
- The server never keeps a message after the push server accepts it. Undelivered messages are held, encrypted, until their TTL runs out.
- Strong, modern, audited cryptography: post-quantum hybrid key agreement, forward secrecy and post-compromise security.
- Abuse resistance without accounts: rate limiting, proof of work, and protection against SSRF and spam through push URLs.
- Hardened on-device storage and user security controls: auto-deleting messages, app lock and panic wipe (§10a).
- A fast native Android client (Kotlin and Jetpack Compose, with a native crypto core).

**Non-goals (v1)**
- Multi-device per user, groups, attachments, and message history sync. These are covered in phase 6.
- Contact discovery. It's deliberately impossible.

---

## 2. Architecture

```
 Sender app                     GoldfishSend server                         Push server            Recipient app
 (Kotlin)                       (ASP.NET Core, .NET 10)                     (ntfy, etc.)           (Kotlin)
    │                                                                          │                       │
    │ POST /v1/messages ─────▶ [API] ──▶ Redis stream (hot, seconds)            │                       │
    │  send_token + E2E blob       │            │                              │                       │
    │ ◀── 202 Accepted             │      [Delivery worker]                    │                       │
    │                              │        unseal endpoint, Web Push          │                       │
    │                              │        encrypt (RFC 8291), VAPID ────────▶│ ── distributor ─────▶ │
    │                              │        2xx → delete                       │                       │
    │                              │        fail → MySQL pending_messages      │                       │
    │                              │               (retry with backoff)        │                       │
    │                          MySQL: mailboxes (sealed), pending_messages     │                       │
    │                          Redis: queue, rate limits, PoW nonces, idempotency                       │
```

The encryption is layered:
1. **E2E layer** (sender to recipient): libsignal session (PQXDH and Double Ratchet). The server sees opaque padded bytes.
2. **Push layer** (server to device): RFC 8291 Web Push encryption to the device's `p256dh`/`auth` keys. The push provider (ntfy, Google via an FCM distributor, and so on) sees only Web Push ciphertext, and can't even see the E2E envelope structure.
3. **Transport**: TLS 1.3 only. The client can optionally pin the server's key, configurable per server because servers are self-hostable.

---

## 3. Core concept: sealed, per-contact mailboxes

A **mailbox** is a one-way inbox on the server that one specific contact can deliver to. The recipient creates **one mailbox per contact**.
As a result, the server can't tell that two mailboxes belong to the same person.

The client generates these per mailbox:
- `send_secret`: 32 random bytes. It's given to the contact, who uses it to send.
- `owner_secret`: 32 random bytes. It's kept by the owner and used for management (rotate endpoint, refresh, delete).

The server derives:
| Value | Derivation | Purpose |
|---|---|---|
| `mailbox_id` | `HMAC-SHA256(server_pepper, SHA256("gf/mbx-id" ‖ send_secret))` | Indexed DB key. A DB dump alone can't be matched against a leaked secret. |
| `seal_key` | `HKDF-SHA256(ikm = send_secret, salt = server_seal_salt, info = "gf/mbx-seal")` | AES-256-GCM key for the endpoint record |
| `owner_hash` | `SHA256(owner_secret)` | Authorizes management. The secret is high-entropy, so a fast hash is fine. Compare with `CryptographicOperations.FixedTimeEquals`. |

The **sealed endpoint** is `AES-256-GCM(seal_key, {endpoint_url, p256dh, auth})`, with `mailbox_id` as associated data.
**At rest, the server can't read any UnifiedPush URL, and it can't link mailboxes that share a device.** An endpoint is
unsealed only in memory at the moment a valid `send_secret` arrives with a message.

Mailboxes expire after 90 days (configurable) unless the owner refreshes them. `expires_at` is stored as a `DATE`, so it gives no fine-grained timestamp.

---

## 4. Flows

### 4.1 Contact exchange (only one side has to scan)
1. Alice creates a mailbox for "the next contact", encrypts her libsignal bundle (identity key, signed prekey, Kyber prekey) plus that
   mailbox's `send_secret` under a random key, and uploads it as a one-time invite (`POST /v1/invites`). Her QR code or link only
   carries `server_url + invite_id + key` (in the URI fragment), so it's small and easy to scan. See `docs/protocol.md`.
2. Bob scans it, fetches the invite (which deletes it from the server), builds a libsignal session from the bundle, and creates a mailbox on *his own* server for Alice.
3. Bob sends a PreKey message (a `hello` Content) to Alice's mailbox containing `{bob_server_url, bob_send_secret}`. No bundle is needed, because the PreKey message itself establishes Alice's side of the session.
4. Alice receives it and has a session plus a return mailbox. Both sides are verified, because the scan happened in person.
   Remote link sharing marks the contact "unverified" until safety numbers are compared.

> The QR code carries the server URL, so **federation comes free**: Alice and Bob can use different servers.

### 4.2 Mailbox creation (anti-abuse)
1. `POST /v1/pow/challenge` returns `{challenge, difficulty, expires}`. The challenge is stored in Redis and is single-use.
2. `POST /v1/mailboxes` with `{pow_solution, send_secret, owner_hash, endpoint, p256dh, auth}`.
3. The server validates the endpoint (§7), creates the mailbox in state `PendingVerification`, and **sends a verification push**
   with a random 128-bit code.
4. The client gets the push and sends `POST /v1/mailboxes/verify` with `{send_secret, owner_secret, code}`. The mailbox becomes `Active`.
   - This proves the registrant controls the endpoint, so **the server can't be used as a cannon against arbitrary URLs.**
   - Unverified mailboxes are purged after 10 minutes. Each mailbox gets at most 5 verify attempts.

### 4.3 Sending
1. `POST /v1/messages` with raw `application/octet-stream` body (no base64 overhead). Headers:
   `GF-Send-Token: <send_secret b64url>`, `GF-Idempotency-Key: <16 bytes>`, `GF-TTL: <seconds>`.
2. Server: rate-limit checks, then mailbox lookup, idempotency check (Redis, 24 h), then `XADD` to the Redis stream, then `202 {msg_id}`.
   Error responses: `404` unknown mailbox, `413` too large, `429` rate limited (with `Retry-After`).
3. The sender is **never authenticated**. Sealed sender is inherent, because the per-contact mailbox already tells the recipient who sent it.

### 4.4 Delivery
1. The worker reads from the stream with `XREADGROUP`. Crashed workers' entries are reclaimed by `XAUTOCLAIM`.
2. The worker unseals the endpoint, builds the push payload `{v, mailbox_tag, e2e_blob}`, encrypts it with RFC 8291 `aes128gcm`, and signs the VAPID JWT (ES256).
3. It sends `POST endpoint` with headers `TTL: <remaining msg TTL>`, `Urgency: high`, and `Authorization: vapid t=…,k=…`.
4. It handles the response:
   | Response | Action |
   |---|---|
   | `201`/`2xx` | `XACK` and `XDEL`. **The message is gone.** |
   | `404`/`410` | The endpoint is dead. Mark the mailbox `EndpointGone` and hold the message in MySQL until the owner rotates the endpoint or the TTL expires. |
   | `429`/`5xx`/timeout | Move the message to MySQL `pending_messages` with backoff, honouring `Retry-After`. |
   | `400`/`413` | Drop the message permanently and count it as a metric. |
5. Retry worker: `SELECT … FOR UPDATE SKIP LOCKED WHERE next_attempt_at <= NOW()`, using the same delivery path.
   Backoff is 10 s, 30 s, 2 m, 10 m, 30 m, 1 h, then capped at 6 h, with ±20% jitter, until `expires_at`.
6. Endpoint rotation (`PUT /v1/mailboxes/endpoint`) re-verifies, then immediately flushes that mailbox's pending messages.

### 4.5 Reliability gap and how to close it
After the push server returns `201`, the push server holds the message. If the device stays offline longer than the push server's
cache (ntfy defaults to about 12 h), the message is lost. **The client closes this gap end to end.** The recipient sends an E2E delivery
receipt, which is just another message. The sender's outbox keeps the plaintext encrypted locally and re-sends with a new ratchet step if no receipt
arrives within N hours. The server stays stateless about this.

---

## 5. Data storage

### MySQL 8 (InnoDB, `skip-log-bin` on single node, TLS, at-rest encryption on)
```sql
CREATE TABLE mailboxes (
    id               BINARY(32)     NOT NULL PRIMARY KEY,
    owner_hash       BINARY(32)     NOT NULL,
    sealed_endpoint  VARBINARY(4096) NOT NULL,
    state            TINYINT        NOT NULL,          -- 0 pending, 1 active, 2 endpoint_gone
    verify_hash      BINARY(32)     NULL,
    verify_attempts  TINYINT        NOT NULL DEFAULT 0,
    expires_at       DATE           NOT NULL,
    INDEX ix_expires (expires_at)
);

CREATE TABLE pending_messages (
    id               BINARY(16)     NOT NULL PRIMARY KEY,
    mailbox_id       BINARY(32)     NOT NULL,
    key_epoch        INT            NOT NULL,          -- which daily epoch key encrypts the row
    payload          VARBINARY(4200) NOT NULL,         -- SecretBox(epochKey, seal_key ‖ push envelope, aad = id)
    attempts         SMALLINT       NOT NULL DEFAULT 0,
    next_attempt_at  DATETIME       NOT NULL,
    expires_at       DATETIME       NOT NULL,
    INDEX ix_due (next_attempt_at),
    INDEX ix_mailbox (mailbox_id)
);
```
- **Crypto-shredding**: epoch keys rotate daily and are destroyed once `max TTL` has passed. Deleted rows left in redo logs or on disk
  become unrecoverable.
- Access is through **Dapper + MySqlConnector** (fast, explicit SQL, with no ORM lag on .NET 10). Migrations are plain versioned SQL files run by DbUp.

### Redis (or Valkey), private network only, ACL/password, `appendonly yes`, `appendfsync everysec`, `noeviction`
| Key | Use |
|---|---|
| `gf:q` (stream, group `delivery`) | Hot message queue. Entries live for seconds. |
| `gf:rl:{scope}:{key}` | GCRA rate-limit state, through an atomic Lua script |
| `gf:pow:{challenge}` | Single-use PoW challenges, TTL 5 min |
| `gf:idem:{mailbox}:{key}` | Idempotency, TTL 24 h |
| `gf:wake` (pub/sub) | Wakes workers on other nodes |

---

## 6. Cryptography

| Layer | Choice |
|---|---|
| E2E session | **libsignal** (Rust core, official Java/Android bindings): PQXDH (X25519 and ML-KEM-1024), Double Ratchet, and newer releases add the SPQR post-quantum ratchet. ⚠ AGPL-3.0, see §11. |
| E2E padding | Pad plaintext to fixed buckets (256 / 1024 / 2048 / 3072 B) before encryption to hide message length |
| Push layer | RFC 8291 Web Push (`aes128gcm`, P-256 ECDH, HKDF, AES-128-GCM) and RFC 8292 VAPID (ES256), both implemented on .NET BCL primitives (`ECDiffieHellman`, `HKDF`, `AesGcm`, `ECDsa`) |
| Server at rest | AES-256-GCM, HMAC-SHA256, HKDF-SHA256. Keys come from files mounted as secrets, never from the DB. |
| Client at rest | SQLCipher database, with the key wrapped by an Android Keystore key (StrongBox when available). `allowBackup=false`, plus data-extraction rules that exclude everything. |
| Transport | TLS 1.3 only, HSTS, optional SPKI pinning per server |
| PoW | SHA-256 hashcash with adaptive difficulty (about 1 s on a mid-range phone, rising under load) |

**Payload budget**: UnifiedPush allows 4096 bytes. RFC 8291 overhead is 103 B and the push envelope is 9 B, which leaves **about 3984 B for the
E2E blob**. A PQXDH PreKey message carries a 1568 B Kyber ciphertext, so first messages must be short. Long texts get
chunked with E2E reassembly.

**Rules**: no hand-rolled primitives or protocols on the client. All E2E crypto goes through libsignal. The server-side Web Push code
is tested against the RFC 8291 Appendix A test vector.

---

## 7. UnifiedPush endpoint protections

Endpoint URLs come from untrusted clients and are capabilities to wake a device, so they are treated as hostile input and as secrets.

**Validation at registration**
- `https` only (dev flag allows `http`). Port 443 only by default (configurable allowlist). Max length 2048.
- No userinfo, no fragment. The host must be a DNS name, not an IP literal (configurable).
- Optional mode: an **allowlist** of push hosts. The default is open mode with the filters below, because self-hosted ntfy is common.
- Block the server's own hostnames to prevent loops.
- Verification push required (§4.2).

**SSRF-safe outbound client** (`SocketsHttpHandler.ConnectCallback`)
- Resolve DNS **inside the connect callback** and validate every resolved IP *at connect time*, which defeats DNS rebinding and TOCTOU.
- Reject loopback, RFC 1918, CGNAT (100.64/10), link-local (incl. 169.254.169.254 metadata), multicast, broadcast,
  0.0.0.0/8, IPv6 ULA (fc00::/7), link-local (fe80::/10), IPv4-mapped/compatible IPv6, NAT64 (64:ff9b::/96), 6to4, Teredo, documentation ranges.
- `AllowAutoRedirect = false`, no proxy, no cookies. Connect timeout 5 s, total timeout 10 s. The response body is read up to a 4 KB cap and then discarded.
- Per-host outbound concurrency and rate caps, and a circuit breaker per push host.

**Confidentiality**
- Sealed at rest (§3). Endpoints are never returned by any API and never logged. Logs record only a host hash.
- **VAPID**: the client passes the server's VAPID public key to the distributor at registration. Distributors that enforce VAPID
  will then reject pushes to that endpoint from anyone else, so a leaked URL is useless.

---

## 8. Rate limiting and abuse (no accounts)

GCRA token buckets live in Redis through a single atomic Lua script. Every limit is configurable. Proposed defaults:

| Scope | Key | Default |
|---|---|---|
| Send, per client | IP (IPv4 /32, IPv6 /64) | 60/min, burst 20 |
| Send, per recipient mailbox | `mailbox_id` | 30/min, 1000/day (protects recipients from a hostile contact) |
| Mailbox create | IP | PoW plus 10/hour |
| Verify attempts | `mailbox_id` | 5 total |
| Owner ops | IP | 30/min |
| Outbound, per push host | host | 50/s, plus circuit breaker |
| Global | n/a | Overall accept-rate ceiling, plus PoW difficulty that rises automatically under load |

- **IP privacy**: rate-limit keys are `HMAC(daily_rotating_key, ip_prefix)` with a short TTL. Raw IPs are never stored or logged.
  `X-Forwarded-For` is trusted only from configured proxies.
- **Tor and shared-IP users**: a client that hits the IP limit can solve a PoW to get a short-lived bypass token.
- **Recipient defence**: blocking a contact means deleting their mailbox. That's instant and server-side, and the sender just gets `404`.
- **Redis down**: mailbox creation fails closed. Sends fall back to an in-process `System.Threading.RateLimiting` limiter.
- **Later option**: Privacy Pass (RFC 9576/9578) with anonymous, unlinkable rate-limit tokens issued when a mailbox is created.
- Kestrel limits: max body 4 KB on `/v1/messages` and 8 KB elsewhere. Request timeouts and header limits are tightened.

---

## 9. Server (C#, .NET 10)

**Style**: K&R braces, enforced through `.editorconfig`:
```ini
[*.cs]
csharp_new_line_before_open_brace = none
csharp_new_line_before_else = false
csharp_new_line_before_catch = false
csharp_new_line_before_finally = false
```

**Layout**
```
server/
  GoldfishSend.slnx, Directory.Build.props
  src/GoldfishSend.Core/           pure code, no I/O
    Crypto/                        WebPushCrypto (RFC 8291), VapidSigner (RFC 8292), MailboxCrypto, ProofOfWork, SecretBox
    Net/                           IpRangeFilter, EndpointValidator (SSRF rules)
    Protocol/, Options/            envelope, endpoint record, limits, config and rate policies
  src/GoldfishSend.Infrastructure/
    MySql/                         Dapper repositories, embedded SQL migrations, EpochKeyring (crypto-shredding)
    Redis/                         stream queue, GCRA limiter (Lua), PoW, idempotency and invites, wake-up signals
    Push/                          SSRF-safe PushClient (connect-time IP checks), HostGuards (pacing, circuit breaker)
    Delivery/                      DeliveryService + StreamDeliveryWorker, RetryWorker, MaintenanceWorker
    Services/                      Mailbox, Message and Invite services
  src/GoldfishSend.Api/            minimal APIs, Kestrel hardening, `keygen` command; the `Roles` config picks api and/or worker
  tests/GoldfishSend.Tests/        Core unit tests (incl. RFC 8291 vector) + Integration/ (real MySQL and Redis, fake push server)
deploy/                            compose (caddy, api, worker, mysql, redis), Caddyfile, redis.conf, my.cnf
docs/protocol.md                   wire contract shared with the Android client
android/                           Kotlin + Compose client
```

**API (v1)**
| Method | Path | Auth |
|---|---|---|
| GET | `/v1/info` (VAPID public key, limits, max payload, PoW params) | n/a |
| POST | `/v1/pow/challenge` | n/a |
| POST | `/v1/mailboxes` | PoW |
| POST | `/v1/mailboxes/verify` | `send_secret` and `owner_secret` |
| PUT | `/v1/mailboxes/endpoint` (rotate; batch of up to 100) | owner |
| POST | `/v1/mailboxes/refresh` (batch) | owner |
| DELETE | `/v1/mailboxes` | owner |
| POST | `/v1/messages` | `send_secret` (header) |
| GET | `/healthz`, `/readyz` (internal only) | n/a |

Secrets go in the request body or headers, never in the URL path, so they never land in proxy logs.

**Operational hygiene**: no IP or URL logging (Caddy access logs off, structured app logs with scrubbing). Metrics are
aggregate counters only (OpenTelemetry). Generic error bodies. AOT/trimming compatible where practical, for fast startup.

---

## 10. Android client (Kotlin)

- **Stack**: Kotlin, Jetpack Compose, Coroutines and Flow, Hilt (or manual DI to keep it lean), OkHttp, Wire (protobuf) for
  E2E message bodies, Room on SQLCipher, WorkManager for the outbox, CameraX and ML Kit-free ZXing for QR codes (works on de-Googled devices).
- **Native crypto**: `libsignal-android` (Rust through JNI). The app implements libsignal's `IdentityKeyStore`, `PreKeyStore`,
  `SignedPreKeyStore`, `KyberPreKeyStore` and `SessionStore` over the SQLCipher DB.
- **UnifiedPush**: `org.unifiedpush.android:connector` 3.x. It handles distributor selection, key generation and Web Push decryption, and
  takes the server's VAPID key at registration. When an endpoint changes, the app batch-rotates every mailbox (`PUT /v1/mailboxes/endpoint`).
- **Performance**: Baseline Profiles, R8 full mode, no reflection-heavy libraries, decryption off the main thread, and paging lists.
- **Modules**: `:app`, `:core:crypto` (libsignal stores, padding, envelope), `:core:net` (API client, PoW solver),
  `:core:db`, `:core:push`, `:feature:contacts`, `:feature:chat`.
- **Privacy features**: disappearing messages (local), screen-security flag, app lock (BiometricPrompt and Keystore),
  optional Orbot/SOCKS proxy, and no analytics or crash reporting by default.
- **Outbox**: each message carries an idempotency key. WorkManager retries with backoff, and the app re-sends if there's no E2E receipt (§4.5).
- **Push envelope inside the Web Push layer**: `{v: u8, mailbox_tag: 8 B, e2e_blob}`. The tag maps to the local contact,
  and the client verifies it against the mailboxes it owns.

---

## 10a. On-device storage security and auto-delete

The phone is where messages actually live, so it needs the strongest protection in the system.

### Key hierarchy
```
  [optional passphrase] ──Argon2id (m=64 MiB, t=3)──┐
                                                    ├─ HKDF ─▶ Master Key (MK, 256-bit, RAM only while unlocked)
  Android Keystore AES key (StrongBox if present, ──┘            │
   setUnlockedDeviceRequired, non-exportable)                     ├─▶ DB key ─▶ SQLCipher (whole-DB AES-256, HMAC per page)
                                                                  └─▶ wraps per-message keys (see crypto-shredding)
```
- If there's no passphrase, MK is unwrapped by the hardware-backed Keystore key alone. If there is one, both factors are required,
  so a seized phone with an unlocked bootloader *and* a Keystore extraction still can't open the database without the passphrase.
- Keystore keys use `setUnlockedDeviceRequired(true)`, so they're unusable while the device is locked. App lock can additionally require
  `setUserAuthenticationRequired` (BiometricPrompt or device credential).
- **Locking the app** (on timeout, screen off, or by hand) closes the DB, zeroes MK and the DB key `ByteArray`s, and clears the
  decrypted-message caches. Key material is never held in a `String`.

### Secure deletion (crypto-shredding)
Flash wear-levelling and SQLite free pages and WAL mean "delete" doesn't reliably erase data. So:
- **Every message body is encrypted with its own random key** (AES-256-GCM, with the message id as AAD), stored in a separate
  `message_keys` table. **Deleting a message deletes its key first.** Any ciphertext left behind is then unrecoverable.
- SQLCipher runs with `PRAGMA secure_delete = ON` (zeroes freed pages), `cipher_memory_security = ON`, and
  `journal_mode = WAL` with frequent `wal_checkpoint(TRUNCATE)`. An idle-time `VACUUM` runs after bulk deletes.
- libsignal already deletes used one-time prekeys and old chain keys, so forward secrecy holds on the device too.

### Auto-delete (disappearing messages)
- **Per-conversation timer** (5 min up to 4 weeks, or off). It's set by either side and synchronised as an E2E control message.
  A **global default** applies to new chats.
- **Timer start**: on read (default) or on receipt (configurable). **View-once** messages are deleted when the viewer closes.
- **Enforcement on two layers**: every query filters `expires_at <= now`, so nothing expired is ever shown even if a job is late.
  An exact `AlarmManager` alarm, with a WorkManager sweep as fallback, then performs the crypto-shred delete. The app also sweeps on every unlock and start.
- When a message is deleted, its notification, any reply draft, and its in-memory copies go too.
- **Delete for everyone** is an E2E control message. The UI must be honest that a modified client can ignore it.

### Additional security controls
- **App lock**: PIN, passphrase or biometric, with configurable auto-lock (immediately, 1 min, 5 min, and so on).
- **Wrong-PIN wipe**: optionally, N failed attempts trigger a full wipe. A **duress PIN** (a verifier that can't decrypt real data) wipes silently or opens a separate decoy profile.
- **Panic wipe**: an in-app action plus an optional quick-settings tile. It destroys the Keystore keys and MK first (instant crypto-shred) and then deletes files.
- **Notifications**: by default they say only "New message", with no name or content, and nothing on the lock screen (`VISIBILITY_SECRET`).
- **Screen**: `FLAG_SECURE` (blocks screenshots and recents thumbnails) is on by default. Android 14+ screen-capture detection can optionally notify the contact.
- **Input**: `IME_FLAG_NO_PERSONALIZED_LEARNING` on all text fields. Copied text auto-clears from the clipboard after 30 s and is marked sensitive.
- **No backups**: `allowBackup=false` and data-extraction rules exclude everything. An optional passphrase-encrypted export can come later.
- **Integrity**: the app refuses to run its DB on debuggable builds of release keys. Root and bootloader state is shown as a warning, not a blocker.

### Client DB sketch (inside SQLCipher)
```
contacts(id, display_name, identity_key, verified, disappearing_secs, mailbox_out{server,send_secret}, mailbox_in{send_secret,owner_secret})
messages(id, contact_id, direction, ciphertext, sent_at, received_at, read_at, expires_at, status)
message_keys(message_id PK, key BLOB)          -- delete this row to shred the message
outbox(message_id, attempts, next_attempt_at, idempotency_key)
signal_* (identity, prekeys, signed_prekeys, kyber_prekeys, sessions)
```

---

## 11. Decisions (settled 2026-11-13)

1. **libsignal**, which makes the project AGPL-3.0.
2. Message TTL: **72 h default, 14 day max**.
3. Push hosts: **any push server**, with the full SSRF and verification suite (§7). There's no allowlist mode.
4. Attachments are out of v1.
5. **Invites** go through a one-time encrypted blob on the server (`/v1/invites`, fetch deletes it). The QR code then only carries
   `server + inviteId + key`, which keeps it small and easy to scan. It also allows remote invite links.
6. The app is sleek and modern Material 3 with **dynamic colour** (Material You), light/dark/system and an AMOLED black option.
7. **Security tab**: on-device audit with warnings, for example an outdated security patch, an end-of-life Android version, a Google (FCM) push distributor,
   no screen lock, developer options or USB debugging on, a likely root or unlocked bootloader, accessibility services that can read the screen,
   a closed-source keyboard (e.g. Gboard; open-source ones and anything installed via F-Droid are trusted; known cloud keyboards are critical), missing StrongBox, an app lock that's off, notification previews that are on, unverified contacts, a non-TLS server, a long auto-lock delay, notification-listener apps, and Private DNS off (a note only).
   Findings with a legitimate justification can be dismissed. Those without one can't. The audit never requires extra permissions.
8. Extra controls: **wipe messages on device restart** (detected through `BOOT_COMPLETED` *and* a `Settings.Global.BOOT_COUNT` check at
   start, so it can't be missed), plus an **inactivity wipe** (a dead man's switch).

9. **Horizontally scalable**: api and worker are stateless and coordinate only through MySQL and Redis (a stream
   consumer group, `SKIP LOCKED` leases, pub/sub wake-ups, shared GCRA limits and circuit breakers, and a maintenance lease).
   Rate-limit, PoW and breaker state lives in a separate **non-persistent** Redis, so no on-disk log records client activity.

10. **Optional security features (2026-11-13).** Every one is a setting. Only those with no downside are on by default.
    | Feature | Default |
    |---|---|
    | Unlock method: none / **phone screen lock** (system prompt; the app never sees the credential) / **app PIN on GoldfishSend's own keypad** (the keyboard app never sees it) / passphrase (advanced) | none |
    | Scrambled keypad | off |
    | Mailbox rotation: a fresh inbound mailbox per contact every N days, with the old one drained after the contact switches | **every 30 days** (invisible, no downside) |
    | PanicKit responder: panic apps may lock; only the user-approved app may erase | off |
    | Safety-number changes: verified contacts are always paused for review, and unverified ones are accepted with a notice (option: pause all) | pause verified |
    | Hidden chats behind a separate PIN (real profile only, UI-level) | off |
    | Duress PIN: a verifier only (it can never decrypt real data), which either erases everything or opens a separate decoy profile (its own database, keyed by the duress PIN; real data stays encrypted, and pushes wait in the locked inbox) | off / erase |
    | Clear app memory on lock | **on** (only cost is a brief CPU spike) |
    | Trust-on-first-use server key pinning | off (servers legitimately rotate keys) |
    | Built-in Tor and `.onion` servers | off |
    The duress and hidden-chat slots always hold same-shaped data, so their presence can't be read from disk.
11. **Deferred: two-relay routing.** The sender's own server would forward to the recipient's server, so the recipient's
    server never sees the sender's IP (as in SimpleX private message routing). It fits the federated design, since the
    sender's server is already known to the client. It needs a server-to-server forwarding endpoint with its own abuse
    controls. It's not built yet.
12. **Future: memory-hard PoW or Privacy Pass tokens** for mailbox creation (SHA-256 hashcash is cheap on GPUs).

The exact wire format lives in `docs/protocol.md`.

---

## 12. Milestones

| # | Milestone | Done when |
|---|---|---|
| M0 | Repo skeleton, `.editorconfig`, CI, `docs/protocol.md` and `docs/threat-model.md` | Spec reviewed |
| M1 | Core crypto: RFC 8291 encryptor, VAPID, mailbox sealing, IP filter | Unit tests pass, including the RFC vectors |
| M2 | Mailboxes and messages API, Redis stream, delivery worker, SSRF-safe client | End-to-end push to a local ntfy |
| M3 | Reliability: MySQL retry queue, backoff, `EndpointGone` hold and flush, idempotency, sweeper, epoch-key shredding | Chaos test (kill worker and push server) loses nothing within TTL |
| M4 | Abuse: GCRA limits, PoW, verification push, per-host breakers | Load test (k6/NBomber) plus abuse test suite |
| M5 | Android: UP registration, mailbox lifecycle, QR exchange, libsignal sessions, send/receive, SQLCipher key hierarchy, per-message keys, outbox and receipts | Two phones chat through a self-hosted ntfy |
| M6 | Security controls: disappearing messages and view-once, app lock, wrong-PIN, duress and panic wipe, notification and screen hardening | Forensic test: no deleted plaintext or keys recoverable from a DB or file dump |
| M7 | Hardening: padding, chunking, pinning, Baseline Profiles, external security review | Review findings closed |
| Future | Abuse resistance: a memory-hard PoW (e.g. Equi-X/Argon2-based) or Privacy Pass (RFC 9576/9578) tokens. SHA-256 hashcash costs a GPU milliseconds but a phone tens of seconds. Changing it is a protocol change for clients. | n/a |
| M8+ | Groups (client fan-out first, MLS later), attachments, multi-device, Privacy Pass, onion service | n/a |
