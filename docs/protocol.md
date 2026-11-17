# GoldfishSend Wire Protocol v2

This is the contract between the server (`server/`) and the Android client (`android/`). Change it here first.

## Conventions
- All binary values in JSON or headers use **base64url without padding** (`b64u`).
- JSON uses camelCase. Errors are JSON `{ "error": "<code>" }` with an appropriate HTTP status.
- `429 rate_limited` errors also carry `"scope"`: which limit was hit, so the client knows how to react.

  | scope | Limited subject | Client reaction |
  |---|---|---|
  | `ip` | this client's IPv4 /32 or IPv6 /64 | On `POST /v1/messages` only: solve a PoW and retry once with `GF-PoW`. Elsewhere, wait `Retry-After`. |
  | `network` | this client's IPv4 /24 or IPv6 /48 | On `POST /v1/messages` only: solve a PoW and retry once with `GF-PoW` (shared networks, Tor exits, onion services). Elsewhere, wait `Retry-After`. |
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
- `POST /v1/pow/challenge` returns
  `{ "scheme": "gf/pow/v2", "challenge": b64u(32 B), "difficulty": int, "memoryKiB": int, "iterations": int, "expiresAt": unixSeconds }`.
- Solution: an 8-byte big-endian unsigned `nonce` such that
  `Argon2id(password = "gf/pow/v2" ‖ challenge ‖ nonce, salt = challenge, m = memoryKiB, t = iterations, p = 1, 32 bytes)`
  (RFC 9106, version 0x13, no secret or associated data) has at least `difficulty` leading zero **bits**. That takes
  about `2^difficulty` Argon2 calls. Verifying takes one. Vectors: `docs/test-vectors/pow-v2.json`.
- The server picks the parameters (defaults: 16 MiB, `t = 1`, 6 bits). Clients refuse a challenge with another `scheme`,
  `difficulty` over 20, `memoryKiB` outside 8–65536, `iterations` outside 1–4, or expected work
  `2^difficulty × memoryKiB × iterations` over 2^28 KiB (the default server's worst case), and give up after 180 s.
- Difficulty adapts to load. Creations from the requester's IPv4 /24 or IPv6 /48 in the last 5 minutes raise its own
  difficulty (one bit when over 5, one more per doubling, up to +6). Verified creations server-wide add up to +2 bits for
  everyone. A challenge keeps the parameters it was issued with.
- A challenge is single-use and expires after 5 minutes.
- Submitted as `"pow": { "challenge": b64u, "nonce": b64u(8 B) }`, or in `GF-PoW` on sends.
- `503 unavailable` (with `Retry-After`) on a request carrying a solution means the server's verification slots were all
  busy. The challenge was not used up: retry the same solution.

## Push payload (plaintext inside the RFC 8291 Web Push layer)
```
byte 0      version   = 0x01
byte 1      type      = 0x01 message | 0x02 verification
bytes 2..9  mailboxTag (8 B)
bytes 10..  body
```
- `type = 0x02`: the verification `code` is the **first 16 bytes** of the body. The rest is random padding (the body is
  1024 bytes today) so that verification pushes look like ordinary messages to the push service. Clients must read
  only the first 16 bytes and ignore the rest, whatever the length.
- `type = 0x01`: body is the sender's E2E blob, passed through unchanged.

The server encrypts this with RFC 8291 `aes128gcm` (a single record, `rs = 4096`) to the device's `p256dh`/`auth`, and signs
with VAPID (RFC 8292, ES256, `Authorization: vapid t=<jwt>, k=<b64u P-256 public key>`). The UnifiedPush Android connector 3.x
decrypts it. The client must register with the server's VAPID public key from `/v1/info`.

The `TTL` header sent to the push service is rounded **down** to one of 60 s, 10 min, 1 h, 6 h, 1 d, 3 d, 7 d or 14 d, so it
doesn't reveal a message's exact age or the sender's chosen lifetime. A push never outlives its message.

**Size budget**: 4096 total, minus 86 B content-coding header, 16 B tag and 1 B delimiter, which leaves **3993 B of push plaintext**.
Subtract the 10 B envelope header and the result is **`maxMessageBytes = 3983`**.

## Encrypted transport and server identity (gateway v1)

Every API call is end-to-end encrypted between the client and the GoldfishSend process, inside TLS. TLS terminators
(Traefik, a load balancer, a CDN) see only ciphertext, and the server proves its identity with a key the operator
controls, independent of the TLS certificate. Only four plaintext HTTP routes exist:

| Route | Purpose |
|---|---|
| `GET /v1/key` | The server key blob (`application/octet-stream`, 1250 B). Public. |
| `POST /v1/gw` | The encrypted gateway. Carries every endpoint listed under "HTTP API". |
| `GET /healthz`, `GET /readyz` | Health checks (not routed by the reverse proxy configs). |

Every other path returns `404`. The endpoints under "HTTP API" are only reachable as inner requests.

### Server key
- **Secret:** `Goldfish:Keys:ServerKey`, b64u of 96 B = `mlkemSeed(64) ‖ p256Scalar(32)`. `mlkemSeed` is the FIPS 203
  ML-KEM-768 seed `d ‖ z`; `p256Scalar` is a big-endian P-256 private scalar. Generated once by `keygen`. It never
  expires and is never rotated automatically.
- **Key blob** (served by `GET /v1/key`): `0x01 ‖ ekMLKEM768(1184) ‖ pkP256(65, uncompressed)` = 1250 B.
- **Fingerprint:** `fp = SHA-256("gf/server-key/v1" ‖ blob)` (32 B). This is the server's identity. In links and
  messages it is `b64u(fp)` (43 chars). For display it is `base32(fp)` (RFC 4648 alphabet, no padding, 52 chars) in
  groups of 4.
- **Key id:** `keyId = fp[0..8]`.

Clients pin `fp` per server. They fetch the blob from `GET /v1/key` and use it only if
`SHA-256("gf/server-key/v1" ‖ blob) == fp` and the blob parses (version 1, exact length, valid P-256 point). Where `fp`
comes from, strongest first: built into the app for its default server; an invite link, invite bundle, `hello` or
`mailbox` message for a contact's server; trust on first use for a server typed in by hand.

### Request encapsulation
The client, for each request:
1. `(ssM, ctM) = ML-KEM-768.Encaps(ekMLKEM768)` (`ctM` 1088 B, `ssM` 32 B).
2. A fresh P-256 key pair `e`. `ctX = e.public` (65 B uncompressed), `ssX = ECDH(e, pkP256)` x-coordinate (32 B).
3. `enc = ctM ‖ ctX` (1153 B).
4. `th = SHA-256("gf/gw/v1" ‖ fp ‖ enc)`; `prk = HKDF-Extract(salt = th, ikm = ssM ‖ ssX)` (HKDF-SHA-256).
5. `reqKey = HKDF-Expand(prk, "gf/gw/v1 req", 32)`; `respSecret = HKDF-Expand(prk, "gf/gw/v1 resp", 32)`.
6. `header = 0x01 ‖ keyId` (9 B). `ct = AES-256-GCM(reqKey, nonce = 12 zero bytes, aad = header, plaintext = innerRequest)`.
   A zero nonce is safe because `reqKey` is fresh for every request.
7. `POST /v1/gw`, `Content-Type: application/octet-stream`, body `header ‖ enc ‖ ct`.

The hybrid is secure as long as either ML-KEM-768 or P-256 holds. `th` binds the server key (through `fp`) and both
KEM ciphertexts.

### Response encapsulation
The server derives the same `respSecret`, then:
1. `respNonce` = 32 random bytes.
2. `rprk = HKDF-Extract(salt = respNonce, ikm = respSecret)`; `respKey = HKDF-Expand(rprk, "gf/gw/v1 resp key", 32)`.
3. Body `respNonce ‖ AES-256-GCM(respKey, nonce = 12 zero bytes, aad = "gf/gw/v1 resp", plaintext = innerResponse)`,
   with outer status `200` and `Content-Type: application/octet-stream`.

The random `respNonce` keeps the response key unique even if the same request is replayed. A response that decrypts
proves it came from the holder of the server key, because only it can derive `respSecret`.

### Inner request (`innerRequest`), big-endian
```
u8   method          1 GET, 2 POST, 3 PUT, 4 DELETE
u64  timestamp       client's unix seconds (corrected by any learned offset)
u16  pathLen, path   path and query, starts with "/v1/", not "/v1/gw" or "/v1/key"
u8   headerCount     then per header: u8 nameLen, name (lowercase ASCII), u16 valueLen, value (ASCII)
u32  bodyLen, body
...  zero padding
```
The path is printable ASCII (`!`..`~`) with no `#` or `\`, at most 2048 bytes. The route part (before `?`) has no
`%`, no `//` and no `.`/`..` segments. Header names are 1–64 bytes of `a-z`, `0-9` and `-`, values printable ASCII
(space allowed) up to 4096 bytes, at most 32 headers, no duplicates. The padding must be zeros and the total length
exactly the bucket the content needs: anything else is rejected, so a client padding bug can't leak sizes.

The server accepts only `content-type` and `gf-*` headers and ignores the rest. Endpoints see the inner method, path,
headers and body exactly as if they had been sent in plaintext. Rate limiting still uses the outer connection's
client IP.

### Inner response (`innerResponse`)
```
u16  status
u8   headerCount     same encoding. The server includes content-type, retry-after and gf-* only.
u32  bodyLen, body
...  zero padding
```

### Padding
Both inner messages are zero-padded to the smallest bucket that fits: 512, 1024, 2048, 4096, 8192, 17408 B. A larger
response is padded to a multiple of 4096. An inner request larger than 17408 B is rejected. Inner bodies keep the
16 KiB endpoint limit, and the outer request body limit is 20 KiB.

### Replay and clock skew
- The server rejects a timestamp more than 600 s from its clock with an **encrypted** inner `400`
  `{ "error": "clock_skew", "serverTime": unixSeconds }`. The client stores `offset = serverTime - now` and retries once.
  The response is authenticated, so a network attacker can't fake it.
- The server keeps `SHA-256(enc)[0..16]` in the ephemeral Redis for 1200 s (`SET NX`). A repeat gets the encrypted inner
  `409 { "error": "replay" }`.

### Outer errors (plaintext, unauthenticated)
| Status | Body `error` | Meaning |
|---|---|---|
| `400` | `bad_request` | Malformed or undecryptable (also a wrong `Content-Type`) |
| `413` | `too_large` | Over the size limits |
| `421` | `unknown_key` | `keyId` isn't this server's |
| `429` | `rate_limited` (`scope: ip`) | The per-node flood guard, checked before any decryption (default 50/s, burst 200 per IP). `Retry-After: 1`. |
| `405` | `method_not_allowed` | Anything but `POST` on `/v1/gw` |

Once a request decrypts, every answer is encrypted, including the gateway's own: `400 bad_request` (the inner request
doesn't parse, or its body is over 16 KiB), `400 clock_skew`, `409 replay`, `500 internal` (an endpoint failed) and
`503 unavailable` (the replay cache is unreachable). A request timeout can still surface as a plaintext `504`.

Clients treat outer errors as untrusted. On `421` the client re-fetches `GET /v1/key`. If the fingerprint no longer
matches the pin, it reports "server identity changed" and stops using that server until the user decides. It never
re-pins silently.

### Interop vectors
`docs/test-vectors/gateway-server.json` is written by the server's tests and `gateway-client.json` by the app's tests.
Both use the test key `ServerKey = bytes 0x00..0x5f`:
```json
{ "serverKey": "b64u", "blob": "hex", "fp": "b64u",
  "exchanges": [ { "innerRequest": "hex (padded)", "outerRequest": "hex", "innerResponse": "hex (padded)", "outerResponse": "hex" } ] }
```
Each side checks the other's file: the same `blob` and `fp` from `serverKey`, that `outerRequest` decrypts to
`innerRequest`, and that `outerResponse` decrypts, under the `respSecret` of that request, to `innerResponse`. The app
does this with a test-only decapsulator. The files are regenerated only when the format changes.

`docs/test-vectors/gateway-codec-fuzz.json` is written by the server's `GatewayCodecVectorTests` from a fixed seed:
generated, mostly hostile inputs with the server's verdict on each (inner requests and responses to decode, inner
requests to encode, padding sizes, key blobs with their fingerprints, sealed responses, proof-of-work solutions). Both
sides check every case, so the app's codec is exactly as strict as the server's. Byte strings are `{ "hex", "len" }`:
the hex bytes, then zeros up to `len`.

### Operator notes
- `keygen` prints `ServerKey` with the other keys, and the fingerprint on stderr. `fingerprint` prints the fingerprint
  of the configured key. The server logs it at startup.
- Losing or replacing `ServerKey` gives every client a "server identity changed" warning. Back it up with the other keys.

## HTTP API

All of these are inner requests through `POST /v1/gw` (see above). Statuses and headers described here are the inner ones.

### `GET /v1/info`
Response: `{ "protocol": 2, "vapidPublicKey": b64u(65 B uncompressed P-256), "maxMessageBytes": 3983, "maxInviteBytes": 4096,
"defaultTtlSeconds": 259200, "maxTtlSeconds": 1209600, "powDifficulty": int }`. `powDifficulty` is what a challenge
issued to this client would need right now.

### `POST /v1/pow/challenge`
No body. Response as above. Rate limited per IP and per network.

### `POST /v1/mailboxes`: create a mailbox
```json
{ "pow": { "challenge": "...", "nonce": "..." },
  "sendSecret": "b64u 32B", "ownerHash": "b64u 32B",
  "endpoint": "https://push.example/...", "p256dh": "b64u 65B", "auth": "b64u 16B" }
```
- `202 { "status": "pending_verification" }`. The server sends a **verification push** (type 0x02) to the endpoint.
- Error codes: `400 invalid_request | invalid_endpoint`, `403 pow_invalid`, `409 mailbox_exists`, `429 rate_limited`, `502 endpoint_unreachable`, `503 unavailable` (see Proof of work).
- Unverified mailboxes are purged after 10 minutes.

### `POST /v1/mailboxes/verify`
```json
{ "items": [ { "sendSecret": "...", "ownerSecret": "..." } ], "code": "b64u 16B" }
```
- Confirms a new mailbox, or a pending endpoint rotation, for **every** item listed. Allows at most 5 attempts per mailbox.
- `200 { "expiresAt": "YYYY-MM-DD", "endpointGone": false }`. Errors: `403 verification_failed`, `404 not_found`.
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
`{ "items": [...] }` → `200 { "expiresAt": "YYYY-MM-DD", "endpointGone": bool }`. Extends expiry by the configured lifetime
(default 90 days). `endpointGone: true` means the push service told the server (404/410) that the endpoint of at least
one listed mailbox no longer exists. Messages for it are being held. The client should re-register with its UnifiedPush
distributor and rotate (`PUT /v1/mailboxes/endpoint`). The server also re-probes such endpoints with backoff, and
resumes on its own if one starts accepting again. Clients that call refresh periodically get this signal for free.

### `POST /v1/mailboxes/delete` (batch, up to 100)
`{ "items": [...] }` → `204`. Deletes the mailboxes and any held messages. Used for "block contact" and "delete contact".

### `POST /v1/messages`: send
- Body: raw bytes, 1 to `maxMessageBytes` (the E2E blob). **`Content-Type: application/octet-stream` is required** (`415` otherwise).
- Headers:
  - `GF-Send-Token: b64u(sendSecret)`, required.
  - `GF-Idempotency-Key: b64u(16 B)`, optional but recommended. A duplicate within about 1 hour returns the original id with `202`, even if the mailbox has filled up or hit its rate limit since.
    Delivery is at-least-once: in rare crash windows the same message may be pushed twice, and clients must drop
    duplicates (a repeated Signal ciphertext is rejected anyway). Retry with the same key and body.
  - `GF-TTL: seconds`, optional. The default is `defaultTtlSeconds`, clamped to `[60, maxTtlSeconds]`.
  - `GF-PoW: <challenge b64u>.<nonce b64u>`, optional. A solved `/v1/pow/challenge` that pays for this request after a
    `429` with `"scope": "ip"` or `"network"` (shared IPs, Tor). It doesn't bypass `mailbox` or `global`.
- Responses: `202 { "id": b64u(16 B) }`, `404 not_found` (unknown, expired or deleted mailbox), `413 too_large`,
  `415 unsupported_media_type`, `429 rate_limited` (with `Retry-After`), and `507 mailbox_full` (with `Retry-After` and a `scope`).
  `507` with `"scope": "mailbox"` means the recipient's device has been unreachable long enough that the server holds its
  maximum number of undelivered messages for this mailbox (default 500). `"scope": "global"` means the server's overall
  held-message quota is reached and this recipient is already backlogged. Either way, keep the message in the outbox and
  retry later. Messages to a recipient whose endpoint is gone are held for at most 3 days (server default), even if a
  longer `GF-TTL` was asked for.
- A `202` means the server accepted the message durably. It holds the message until the push server accepts it, or the TTL expires.

### `POST /v1/messages/batch`: send up to 32 messages in one request
For group fan-out. Each item is a send exactly as above (its own `sendSecret`, idempotency key, TTL and blob), and the
response reports each item in order. The client (IP and network) buckets are charged `ceil(count / 8)` tokens once
for the whole batch, and `GF-PoW` pays for all of it. The binary body format, results and limits are in
[`docs/groups.md`](groups.md#server-batch-send).

### `POST /v1/invites`: upload a one-time invite blob
- Body: raw bytes, 1 to `maxInviteBytes`, with **`Content-Type: application/octet-stream`** (`415` otherwise). Header `GF-TTL` is
  60 to 86400 seconds (default 900).
- `201 { "id": b64u(16 B) }`. Rate limited per IP, per network and globally. When the server's live-invite cap is reached,
  it answers `429` with `"scope": "global"`.

### `GET /v1/invites/{id}`: fetch an invite blob and delete it atomically
- `200` with raw bytes, or `404 not_found`. **Fetching deletes it**: an invite works exactly once.

## Client notes

- Verification bodies may be padded. The code is always the first 16 bytes.
- An `endpointGone: true` on refresh or verify makes the client re-register with its distributor and rotate its mailboxes, which triggers a fresh verification push. It does this at most once every 6 hours.
- On `POST /v1/messages`, a `429` with scope `ip` or `network` is retried once with `GF-PoW`. Clients refuse unreasonable challenges (see Proof of work).
- Clients read at most 64 KiB of any response body.
- A first PreKey `hello` is only accepted on the mailbox whose invite published that signed prekey.

## Client-side formats (opaque to the server)

### Invite QR code / link
`gfsend://invite#v=2&s=<percent-encoded server base URL>&f=<server fp b64u>&i=<inviteId b64u>&k=<inviteKey b64u 32 B>`

The app rejects `v=1` links. `f` pins the inviter's server before anything is fetched from it.

Everything after `#` is the URI fragment, so it isn't sent anywhere if opened as a link. The invite blob is
`nonce(12) ‖ AES-256-GCM(inviteKey, nonce, plaintext = JSON InviteBundle, aad = "gf/invite/v1")`.

`InviteBundle` (JSON):
```json
{ "v": 2, "server": "https://...", "serverKey": "b64u fp", "sendSecret": "b64u",
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
| `hello` | `server`, `serverKey`, `sendSecret`, `name?` | The scanner's first message. Gives the inviter a return mailbox. |
| `text` | `id`, `body`, `ts`, `exp?` (disappearing seconds), `once?` (view-once), `part?`, `parts?` | A chat message, or one chunk of one |
| `receipt` | `ids[]`, `kind` (`delivered` \| `read`) | E2E receipts |
| `timer` | `secs` | Sets the conversation's disappearing timer (0 = off) |
| `delete` | `ids[]` | Delete for everyone (best effort) |
| `mailbox` | `server`, `serverKey`, `sendSecret` | The sender moved its inbox for this contact |
| `chunk` | `id`, `part`, `parts`, `data` | One part of any content too large for one message ([`docs/groups.md`](groups.md#chunking)) |
| `g*` | see [`docs/groups.md`](groups.md) | Group content: invitations, forwarded cards and rosters arrive over 1:1 too |

Group chats, their blob format (`0x12`/`0x13` plus a sender hint) and their content types are specified in
[`docs/groups.md`](groups.md).
