# GoldfishSend Wire Protocol v1

This is the contract between the server (`server/`) and the Android client (`android/`). Change it here first.

## Conventions
- All binary values in JSON or headers use **base64url without padding** (`b64u`).
- JSON uses camelCase. Errors are JSON `{ "error": "<code>" }` with an appropriate HTTP status.
- `429 rate_limited` errors also carry `"scope"`: which limit was hit, so the client knows how to react.

  | scope | Limited subject | Client reaction |
  |---|---|---|
  | `ip` | this client's IPv4 /32 or IPv6 /64 | On `POST /v1/messages` only: solve a PoW and retry once with `GF-PoW`. Elsewhere, wait `Retry-After`. |
  | `network` | this client's IPv4 /24 or IPv6 /48 | Wait `Retry-After`. |
  | `mailbox` | the target mailbox (protects the recipient) | Wait `Retry-After`. PoW does **not** help. |
  | `global` | the whole server | Wait `Retry-After`. |
- `‖` means concatenation. String literals are UTF-8 bytes with no terminator.
- `SHA256`, `HMAC-SHA256` and `HKDF-SHA256` follow RFC 6234, RFC 2104 and RFC 5869.

## Secrets held by the client (per mailbox)
| Name | Size | Who has it |
|---|---|---|
| `sendSecret` | 32 B random | The mailbox owner and the one contact allowed to send to it |
| `ownerSecret` | 32 B random | The mailbox owner only |

## Derivations
| Value | Formula | Computed by |
|---|---|---|
| `verifyHash` (server-side) | `SHA256(code ‖ mailboxId)`, so rows of one batch don't share a value | server only |
| `ownerHash` | `SHA256(ownerSecret)` | client (sent at creation), server (on owner ops) |
| `mailboxTag` | `SHA256("gf/mbx-tag" ‖ sendSecret)[0..8]` | client and server |
| `mailboxId` | `HMAC-SHA256(key = serverPepper, SHA256("gf/mbx-id" ‖ sendSecret))` | server only |
| `sealKey` | `HKDF-SHA256(ikm = sendSecret, salt = serverSealSalt, info = "gf/mbx-seal", L = 32)` | server only |
| sealed endpoint | `nonce(12) ‖ AES-256-GCM(sealKey, nonce, plaintext = endpointRecord, aad = mailboxId)` | server only |

## Proof of work
- `POST /v1/pow/challenge` returns `{ "challenge": b64u(32 B), "difficulty": int, "expiresAt": unixSeconds }`.
- Solution: an 8-byte big-endian unsigned `nonce` such that
  `SHA256("gf/pow/v1" ‖ challenge ‖ nonce)` has at least `difficulty` leading zero **bits**.
- A challenge is single-use and expires after 5 minutes.
- Submitted as `"pow": { "challenge": b64u, "nonce": b64u(8 B) }`.

## Push payload (plaintext inside the RFC 8291 Web Push layer)
```
byte 0      version   = 0x01
byte 1      type      = 0x01 message | 0x02 verification
bytes 2..9  mailboxTag (8 B)
bytes 10..  body
```
- `type = 0x02`: body is the 16-byte verification `code`.
- `type = 0x01`: body is the sender's E2E blob, passed through unchanged.

The server encrypts this with RFC 8291 `aes128gcm` (a single record, `rs = 4096`) to the device's `p256dh`/`auth`, and signs
with VAPID (RFC 8292, ES256, `Authorization: vapid t=<jwt>, k=<b64u P-256 public key>`). The UnifiedPush Android connector 3.x
decrypts it. The client must register with the server's VAPID public key from `/v1/info`.

**Size budget**: 4096 total, minus 86 B content-coding header, 16 B tag and 1 B delimiter, which leaves **3993 B of push plaintext**.
Subtract the 10 B envelope header and the result is **`maxMessageBytes = 3983`**.

## HTTP API

### `GET /v1/info`
Response: `{ "protocol": 1, "vapidPublicKey": b64u(65 B uncompressed P-256), "maxMessageBytes": 3983, "maxInviteBytes": 4096,
"defaultTtlSeconds": 259200, "maxTtlSeconds": 1209600, "powDifficulty": int }`

### `POST /v1/pow/challenge`
No body. Response as above. Rate limited per IP.

### `POST /v1/mailboxes`: create a mailbox
```json
{ "pow": { "challenge": "...", "nonce": "..." },
  "sendSecret": "b64u 32B", "ownerHash": "b64u 32B",
  "endpoint": "https://push.example/...", "p256dh": "b64u 65B", "auth": "b64u 16B" }
```
- `202 { "status": "pending_verification" }`. The server sends a **verification push** (type 0x02) to the endpoint.
- Error codes: `400 invalid_request | invalid_endpoint`, `403 pow_invalid`, `409 mailbox_exists`, `429 rate_limited`, `502 endpoint_unreachable`.
- Unverified mailboxes are purged after 10 minutes.

### `POST /v1/mailboxes/verify`
```json
{ "items": [ { "sendSecret": "...", "ownerSecret": "..." } ], "code": "b64u 16B" }
```
- Confirms a new mailbox, or a pending endpoint rotation, for **every** item listed. Allows at most 5 attempts per mailbox.
- `200 { "expiresAt": "YYYY-MM-DD" }`. Errors: `403 verification_failed`, `404 not_found`.
- On success, any held (undelivered) messages for those mailboxes are flushed immediately.

### `PUT /v1/mailboxes/endpoint`: rotate the push endpoint (batch, up to 100 items)
```json
{ "items": [ { "sendSecret": "...", "ownerSecret": "..." } ], "endpoint": "...", "p256dh": "...", "auth": "..." }
```
- `202 { "status": "pending_verification" }`. One verification push goes to the new endpoint, tagged with the **first** item's `mailboxTag`.
  The client then calls `/v1/mailboxes/verify` with the same items.
- Only active mailboxes (or ones whose endpoint died) can rotate. A mailbox still pending creation returns `404`, so it has to be created again.
- Rotations are budgeted per mailbox (default 10 per day, burst 5): `429` when exceeded.
- Note: a batch request necessarily shows the server that its mailboxes belong together. Clients that care can split batches
  and space them out.

### `POST /v1/mailboxes/refresh` (batch, up to 100)
`{ "items": [...] }` → `200 { "expiresAt": "YYYY-MM-DD" }`. Extends expiry by the configured lifetime (default 90 days).

### `POST /v1/mailboxes/delete` (batch, up to 100)
`{ "items": [...] }` → `204`. Deletes the mailboxes and any held messages. Used for "block contact" and "delete contact".

### `POST /v1/messages`: send
- Body: raw bytes, 1 to `maxMessageBytes` (the E2E blob). **`Content-Type: application/octet-stream` is required** (`415` otherwise).
- Headers:
  - `GF-Send-Token: b64u(sendSecret)`, required.
  - `GF-Idempotency-Key: b64u(16 B)`, optional but recommended. Duplicates within 24 h return the original `202`.
  - `GF-TTL: seconds`, optional. The default is `defaultTtlSeconds`, clamped to `[60, maxTtlSeconds]`.
  - `GF-PoW: <challenge b64u>.<nonce b64u>`, optional. A solved `/v1/pow/challenge` that pays for this request after a
    `429` with `"scope": "ip"` (shared IPs, Tor). It doesn't bypass any other scope.
- Responses: `202 { "id": b64u(16 B) }`, `404 not_found` (unknown, expired or deleted mailbox), `413 too_large`,
  `415 unsupported_media_type`, `429 rate_limited` (with `Retry-After`), and `507 mailbox_full` (with `Retry-After`).
  `507` means the recipient's device has been unreachable long enough that the server holds its maximum number of undelivered
  messages for this mailbox (default 500). Keep the message in the outbox and retry later.
- A `202` means the server accepted the message durably. It holds the message until the push server accepts it, or the TTL expires.

### `POST /v1/invites`: upload a one-time invite blob
- Body: raw bytes, 1 to `maxInviteBytes`, with **`Content-Type: application/octet-stream`** (`415` otherwise). Header `GF-TTL` is
  60 to 86400 seconds (default 900).
- `201 { "id": b64u(16 B) }`. Rate limited per IP.

### `GET /v1/invites/{id}`: fetch an invite blob and delete it atomically
- `200` with raw bytes, or `404 not_found`. **Fetching deletes it**: an invite works exactly once.

## Client notes

- Verification bodies may be padded. The code is always the first 16 bytes.
- An `endpointGone: true` on refresh or verify makes the client re-register with its distributor and rotate its mailboxes, which triggers a fresh verification push. It does this at most once every 6 hours.
- On `POST /v1/messages`, a `429` with scope `ip` or `network` is retried once with `GF-PoW`. Clients refuse challenges harder than 28 bits.
- Clients read at most 64 KiB of any response body.
- A first PreKey `hello` is only accepted on the mailbox whose invite published that signed prekey.

## Client-side formats (opaque to the server)

### Invite QR code / link
`gfsend://invite#v=1&s=<percent-encoded server base URL>&i=<inviteId b64u>&k=<inviteKey b64u 32 B>`

Everything after `#` is the URI fragment, so it isn't sent anywhere if opened as a link. The invite blob is
`nonce(12) ‖ AES-256-GCM(inviteKey, nonce, plaintext = JSON InviteBundle, aad = "gf/invite/v1")`.

`InviteBundle` (JSON):
```json
{ "v": 1, "server": "https://...", "sendSecret": "b64u",
  "registrationId": 1234, "deviceId": 1,
  "identityKey": "b64u", "signedPreKeyId": 1, "signedPreKey": "b64u", "signedPreKeySig": "b64u",
  "kyberPreKeyId": 1, "kyberPreKey": "b64u", "kyberPreKeySig": "b64u",
  "name": "optional suggested display name" }
```
`sendSecret` is the inviter's freshly created mailbox for the person who scans it.

### E2E blob (body of `POST /v1/messages`)
```
byte 0      0x03 PreKeySignalMessage | 0x02 SignalMessage   (libsignal CiphertextMessage type)
bytes 1..   libsignal serialized ciphertext
```
The plaintext inside libsignal is `pad(contentJson)`. Padding uses ISO/IEC 7816-4: append `0x80`, then `0x00` bytes up to the
next multiple of 256. The maximum padded plaintext is 2048 B for PreKey messages and 3584 B for normal messages. Longer texts are chunked.

`Content` (JSON, `t` = type):
| t | Fields | Meaning |
|---|---|---|
| `hello` | `server`, `sendSecret`, `name?` | The scanner's first message. Gives the inviter a return mailbox. |
| `text` | `id`, `body`, `ts`, `exp?` (disappearing seconds), `once?` (view-once), `part?`, `parts?` | A chat message, or one chunk of one |
| `receipt` | `ids[]`, `kind` (`delivered` \| `read`) | E2E receipts |
| `timer` | `secs` | Sets the conversation's disappearing timer (0 = off) |
| `delete` | `ids[]` | Delete for everyone (best effort) |
| `mailbox` | `server`, `sendSecret` | The sender moved its inbox for this contact |
