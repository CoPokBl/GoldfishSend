# GoldfishSend server

GoldfishSend is a blind push relay for an end-to-end encrypted messenger. A sender posts an opaque, already
end-to-end encrypted blob to a per-contact *mailbox*. The server wraps it in RFC 8291 Web Push encryption and
hands it to the recipient's UnifiedPush server (ntfy, an FCM distributor, ...). Once the push server accepts it,
the message is gone. If delivery fails, the message is held, encrypted, until it can be delivered or its TTL
runs out.

Licence: **[MIT](LICENSE)**. The Android app is AGPL-3.0-or-later, because it's built on libsignal.

It is written in ASP.NET Core (.NET 10) with MySQL 8.4 and Redis 7.4 (or Valkey). The wire protocol is in
[`docs/protocol.md`](../docs/protocol.md), and the project overview in the [top-level README](../README.md).

## Privacy model, in plain words

There are no accounts. A recipient creates **one mailbox per contact** and gives that contact a random
`sendSecret` out of band (QR code or link). Whoever holds the secret can send to that mailbox, and nobody else can.

**The server never learns:**
- **Message content.** It only ever sees end-to-end ciphertext, and the push provider sees only Web Push ciphertext.
- **Who is sending.** There's no sender identity, just a per-contact capability.
- **Who is receiving, or which mailboxes belong to the same person.** Mailbox ids are HMACs of the secret
  under a server key. Every mailbox's push endpoint is sealed with a key derived from that mailbox's own
  `sendSecret`, so two mailboxes on the same phone look unrelated at rest.
- **Push endpoint URLs at rest.** An endpoint is unsealed in memory only for the moment a valid `sendSecret`
  arrives with a message, and it is never returned by the API or logged.
- **Your contact graph.** There's no contact discovery. It is impossible by design.
- **Your API calls, even at the TLS terminator.** Every request is end-to-end encrypted to the server's own key
  (a hybrid of ML-KEM-768 and P-256, so it holds against a future quantum computer too) and sent as
  `POST /v1/gw`. Caddy, Traefik or a load balancer that terminates TLS sees only opaque bodies in a few fixed
  sizes: not which endpoint was called, nor any secret, push endpoint or invite id. Clients pin that key, so a
  forged or mis-issued TLS certificate gets an attacker nothing either. See [Server identity](#server-identity).
- **Client IP addresses beyond the request.** IPs are used in memory for rate limiting, as
  `HMAC(daily random key, IPv4 address or IPv6 /64)`, with short TTLs. Raw IPs are never stored or logged, and
  there are no access logs anywhere in the stack.

**The server does store:**
- Per mailbox: the HMAC id, the sealed endpoint, `SHA256(ownerSecret)`, a verification state and an expiry
  **date** (day granularity only).
- Per undelivered message, until delivery or TTL (at most 14 days by default): the mailbox id, the ciphertext,
  attempt counters and timestamps. The row is encrypted under a daily *epoch key*. Epoch keys are deleted once
  no message could still need them, which makes deleted rows lingering in redo logs or free disk space
  unrecoverable (crypto-shredding).
- In Redis, for seconds to hours: the delivery queue (epoch-key encrypted), rate-limit buckets, PoW challenges,
  idempotency markers and one-time invite blobs (encrypted by the client).
- In logs: an opaque fingerprint of the push *host* when a delivery fails. Never URLs, tokens or IPs.

**Limits of the model.** This protects against retrospective disclosure: a seized disk, a leaked backup or a
subpoenaed database. Someone who controls the *running* server can watch requests as they arrive (IPs,
endpoints at the moment of delivery, traffic timing), just as any relay operator could. Run it on hardware you
trust, and don't put a logging CDN or WAF in front of it. The full picture, for the server and the app, is in
[`docs/threat-model.md`](../docs/threat-model.md).

## Architecture

```
 client ──TLS 1.3──▶ caddy ──▶ api ──▶ MySQL (mailboxes, held messages, epoch keys)
   └──── gateway encryption (server key) ────┘
                                 │  └─▶ Redis (queue stream, rate limits, PoW, idempotency, invites)
                                 │                │
                                 │             worker ──Web Push + VAPID──▶ push server ──▶ device
                                 └─ verification pushes (sent synchronously on mailbox create/rotate)
```

One image, two roles, selected with `Goldfish:Roles` (`api`, `worker`, or the default `api,worker` in one process):

| Role | What runs |
|---|---|
| `api` | The encrypted gateway (`POST /v1/gw`, `GET /v1/key`) in front of the minimal-API endpoints under `/v1`, plus `/healthz` and `/readyz`. Accepts messages into the Redis stream and sends verification pushes itself. |
| `worker` | `StreamDeliveryWorker` (consumes `gf:q`, delivers, moves failures to MySQL), `RetryWorker` (retries held messages with backoff under a lease), `MaintenanceWorker` (every minute: rotate and shred epoch keys, delete expired messages, purge expired or unverified mailboxes). Serves only `/healthz`. |

Every process runs the embedded SQL migrations (serialised by a MySQL named lock) and creates today's and
tomorrow's epoch keys at startup.

Source layout:

| Path | Contents |
|---|---|
| `src/GoldfishSend.Core` | Options, protocol types, crypto (the gateway's hybrid ML-KEM-768 + P-256 encryption, RFC 8291 Web Push, VAPID, mailbox sealing, PoW, SecretBox), endpoint validation and IP range filtering. No I/O. |
| `src/GoldfishSend.Infrastructure` | MySQL (Dapper + MySqlConnector, migrations, epoch keyring), Redis (queue, GCRA limiter in Lua, PoW and ephemeral stores), SSRF-safe push client, services and background workers. |
| `src/GoldfishSend.Api` | `Program.cs` (Kestrel limits, forwarded headers, security headers, `keygen`, `fingerprint`), the gateway middleware and endpoints. |
| `tests/GoldfishSend.Tests` | Unit tests and Testcontainers-based integration tests. |
| `tools/HealthProbe` | A tiny HTTP probe used by container healthchecks (the runtime image has no shell or curl). |
| `tools/LoadTest` | A load generator that speaks the encrypted gateway and runs its own push server (see [Load testing](#load-testing)). |
| `Dockerfile` | Multi-stage build to a distroless (`noble-chiseled`) non-root runtime image. |
| `../deploy` | Compose stack: Caddy (or a Traefik overlay), api, worker, MySQL, two Redis instances, optional Tor. |

Code style: K&R braces (opening brace on the same line, also for `else`/`catch`/`finally`), file-scoped
namespaces, braces always. It is enforced through the repository's `.editorconfig`; run `dotnet format` before
committing.

## Local development

You need the .NET 10 SDK and podman or docker.

```bash
# MySQL and Redis on localhost only
podman run -d --name gf-mysql -p 127.0.0.1:3306:3306 \
  -e MYSQL_RANDOM_ROOT_PASSWORD=yes -e MYSQL_DATABASE=goldfish -e MYSQL_USER=goldfish -e MYSQL_PASSWORD=dev \
  docker.io/library/mysql:8.4 --skip-log-bin
podman run -d --name gf-redis -p 127.0.0.1:6379:6379 \
  docker.io/library/redis:7.4-alpine redis-server --appendonly yes --requirepass dev

cd server

# Generate a development key set (JSON on stdout; the VAPID public key and server key fingerprint on stderr)
dotnet run --project src/GoldfishSend.Api -- keygen > ../goldfish-dev-keys.json

# Export the keys and connection strings (bash; needs jq)
eval "$(jq -r '.Goldfish.Keys | to_entries[] | "export Goldfish__Keys__\(.key)=\(.value|@sh)"' ../goldfish-dev-keys.json)"
export ConnectionStrings__MySql='Server=127.0.0.1;Port=3306;Database=goldfish;User ID=goldfish;Password=dev'
export ConnectionStrings__Redis='127.0.0.1:6379,password=dev'

# Run (the "http" launch profile listens on http://localhost:5234 in the Development environment)
dotnet run --project src/GoldfishSend.Api

curl -s http://localhost:5234/v1/key | wc -c    # 1250: the server key blob
```

Every other API call goes through the encrypted gateway, so plain `curl` gets a 404 for `/v1/info` and friends. The
tests' `GatewayHandler` (in `tests/GoldfishSend.Tests/Integration`) is a client-side implementation to borrow when
scripting against the API.

Don't commit `goldfish-dev-keys.json`, and never reuse development keys in production.

To test against a local ntfy on `http://localhost`, set `Goldfish__Push__DangerouslyAllowInsecureLoopback=true`.
This turns off parts of the SSRF protection, and the server refuses to start with it in Production.

### Tests

`dotnet test` runs the unit tests. The integration tests (real MySQL and Redis, a fake push server) run when
`GF_TEST_MYSQL` and `GF_TEST_REDIS` point at **disposable** instances, because the fixture drops the tables and
flushes every Redis database:

```bash
podman run -d --name gf-test-mysql -p 127.0.0.1:33306:3306 -e MYSQL_ROOT_PASSWORD=test -e MYSQL_DATABASE=goldfish \
  docker.io/library/mysql:8.4 --skip-log-bin
podman run -d --name gf-test-redis -p 127.0.0.1:36379:6379 docker.io/library/redis:7.4-alpine

export GF_TEST_MYSQL="Server=127.0.0.1;Port=33306;User=root;Password=test;Database=goldfish"
export GF_TEST_REDIS="127.0.0.1:36379"
dotnet test                                   # everything, about 2.5 minutes
dotnet test --filter "Category!=Chaos"        # without the chaos tests, about 30 seconds
dotnet test --filter "Category=Chaos"         # only the chaos tests, about 2 minutes
```

The integration tests bind extra loopback addresses (127.0.0.2 to 127.0.0.8) for push servers of their own, which
Linux provides out of the box.

- **Chaos tests** (`ChaosTests`): messages keep flowing while a push server refuses connections,
  answers 5xx or times out, and while a worker node is killed with deliveries in flight and a fresh node takes over.
  Nothing accepted is lost within its TTL, nothing is delivered after it, and idempotent retries get the original id.
  The worker test waits out the real recovery timeouts (stream entries are reclaimed after a minute or more, retry
  leases after 85 s), which is why it is slow.
- **Abuse suite** (`AbuseTests`, plus parts of `EndToEndTests`, `GatewayTests`, `HardeningTests` and
  `BatchSendTests`): proof of work, adaptive difficulty, per-address, per-network, per-mailbox and global
  limits, verification pushes and the new-host budget, the per-host circuit breaker, the gateway flood guard, replay
  cache and size limits, and SSRF checks at registration and at connect time.

### Fuzzing

The tests in `tests/GoldfishSend.Tests/Fuzz` and `Integration/ApiFuzzTests.cs` are property-based fuzz tests
([CsCheck](https://github.com/AnthonyLloyd/CsCheck)). They feed generated, mostly hostile input to everything a client
can reach, and compare the answers with independent references rather than with the code under test:

| Tests | Input | Property |
|---|---|---|
| `GatewayFuzzTests` | Outer gateway requests (garbage, truncated, oversized, foreign key ids, bad P-256 points, bit flips), sealed responses, inner requests and responses, padding | Only an intact request opens, and every other one is `Malformed` or `UnknownKey` without an exception. The inner codec agrees with `SpecCodec`, a separate reading of docs/protocol.md, and whatever it accepts re-encodes to the same bytes. |
| `CodecFuzzTests` | Batch send bodies, proof-of-work solutions and parameters, Web Push `p256dh`/`auth` and encryption, endpoint records, push envelopes | Each matches a re-implementation from the spec (the batch grammar, the PoW parameter bounds and leading zero bits as a `BigInteger`, the P-256 curve equation with `BigInteger`). The Argon2 output itself is pinned by `docs/test-vectors/pow-v2.json`, which the app checks too and which matches OpenSSL's Argon2id. |
| `SsrfFuzzTests` | Push endpoint URLs (decimal, octal, hex and short IPv4, IDNA dots, fullwidth digits, IPv4-mapped, compatible, NAT64, 6to4, Teredo and ISATAP IPv6, zone ids, userinfo, backslashes, ports, special-use names), addresses, hostile DNS answers | A URL the validator accepts makes HttpClient connect only to a name that may be resolved, or to an address that `SsrfOracle` (the IANA special-purpose registries and glibc's `inet_aton`, written out separately) says is globally reachable. `IpRangeFilter` and the connect-time check allow only such addresses. |
| `ApiFuzzTests` (integration) | Outer bodies, sealed inner requests with fuzzed paths, headers and bodies, and malformed JSON for every JSON endpoint, through the real pipeline | Outer answers are only the documented `400`/`413`/`421`. Every decrypted request gets an encrypted answer that decodes, with a JSON `{"error": …}` body, and never a `500`. |
| `GatewayCodecVectorTests` | Writes `docs/test-vectors/gateway-codec-fuzz.json` | The app's `GatewayCodecFuzzVectorsTest` must reach the server's verdict on every case. |

A normal `dotnet test` replays the same seeded cases every time (a few seconds in all), so CI is deterministic. For a
longer local run, give each property a time budget. It then runs on random seeds, and CsCheck shrinks any failure to a
small input:

```bash
export GF_FUZZ_SECONDS=120 GF_FUZZ_THREADS=4 GF_FUZZ_LOG=$PWD/fuzz.log   # per property; the log counts the cases run
nice dotnet test -c Release --filter "FullyQualifiedName~Fuzz"          # ApiFuzzTests also need GF_TEST_MYSQL/REDIS
```

A failure prints its seed. `GF_FUZZ_SEED=<seed> dotnet test --filter <test name>` replays exactly that case. Add what
it found as a regression case (`InlineData` on a theory next to the property), so normal runs keep checking it. After
changing the codec generators or verdicts, regenerate the vectors with
`GF_WRITE_VECTORS=1 dotnet test --filter GatewayCodecVectorTests` and run the app's unit tests.

### Load testing

`tools/LoadTest` drives a running server the way the app does: every call goes through the encrypted gateway, and it
runs its own push server, so verification codes and messages come back to it. Each simulated client creates and
verifies mailboxes (solving the proof of work), then loops over a mix of single sends (60%), group batch sends (15%),
invite upload and fetch (10%), mailbox refreshes (10%) and `/v1/info` (5%), and deletes its mailboxes at the end. It
reports throughput, p50/p95/p99 latency per operation, error and throttling counts, and the time from send to the push
arriving, and exits non-zero when a threshold is breached (`--help` lists them).

The server under test must run in Development with `Goldfish__Push__DangerouslyAllowInsecureLoopback=true` (pushes go
to `http://127.0.0.1`), on the same machine as the tool, with the limits in
[`tools/LoadTest/server.env`](tools/LoadTest/server.env) relaxed: every simulated client shares one address and every
simulated phone one push host. That file also makes the PoW tiny (test only: 8 calls of 256 KiB) and turns off its
adaptive difficulty. **Use a separate (existing) database and
separate Redis databases**, since the run leaves queue, rate-limit and idempotency state behind.

Smoke run, as CI does it (about a minute; 8 clients, 45 s, 50 ms think time, fails on more than 1% errors, more
than 5% throttled calls, a p95 above 1 s or under 99% of messages pushed back):

```bash
cd server
dotnet build -c Release src/GoldfishSend.Api
dotnet build -c Release tools/LoadTest
api=src/GoldfishSend.Api/bin/Release/net10.0
export Goldfish__Keys__ServerKey="$(dotnet $api/GoldfishSend.Api.dll keygen 2>/dev/null | jq -r .Goldfish.Keys.ServerKey)"
export ConnectionStrings__MySql='Server=127.0.0.1;Port=3306;User=root;Password=…;Database=goldfish_load'
export ConnectionStrings__Redis='127.0.0.1:6379,defaultDatabase=2'
export ConnectionStrings__RedisEphemeral='127.0.0.1:6379,defaultDatabase=3'
env $(grep -v '^#' tools/LoadTest/server.env | xargs) \
  dotnet $api/GoldfishSend.Api.dll --contentRoot "$PWD/$api" --urls http://127.0.0.1:5299 &
server=$!
dotnet run --project tools/LoadTest -c Release --no-build -- --url http://127.0.0.1:5299 --smoke --json loadtest.json
status=$?
kill $server
exit $status
```

The other keys come from `appsettings.Development.json`. The tool waits up to a minute for the server to answer. For a
real load test, raise `--clients` and `--duration` (the defaults are 32 clients for 120 s with no think time). On a
16-core desktop, 16 clients with no think time reach about 1,500 calls/s and 2,000 pushes/s with a p95 under 50 ms,
with the server, MySQL, Redis and the tool on the same machine.

## Configuration reference

Configuration is standard ASP.NET Core: `appsettings.json`, then `appsettings.{Environment}.json`, then
environment variables, then command-line arguments. In environment variables `:` becomes `__`
(`Goldfish:Keys:Pepper` is `Goldfish__Keys__Pepper`) and array items are indexed
(`Goldfish__Push__AllowedPorts__0=443`).

### Connection strings (required)

| Key | Example | Notes |
|---|---|---|
| `ConnectionStrings:MySql` | `Server=mysql;Port=3306;Database=goldfish;User ID=goldfish;Password=…;SslMode=Required` | MySqlConnector syntax. The user needs DDL rights on the database, because migrations run at startup. |
| `ConnectionStrings:Redis` | `redis:6379,user=goldfish,password=…,abortConnect=false` | The persistent Redis (AOF): the hot queue, idempotency keys and invites. StackExchange.Redis syntax. Add `,$CONFIG=` if CONFIG is disabled on the server, as in `deploy/redis.conf`. |
| `ConnectionStrings:RedisEphemeral` | `redis-ephemeral:6379,user=goldfish,password=…` | Optional but recommended. A **non-persistent** Redis for rate-limit buckets and their daily HMAC keys, PoW challenges and push-host circuit breakers, so no on-disk log ever records client activity. If unset, the main Redis is used and a startup warning is logged. |

### `Goldfish` (root)

| Key | Default | Meaning |
|---|---|---|
| `Roles` | `api,worker` | Comma-separated roles this process runs: `api`, `worker`. |

### `Goldfish:Keys` (required, except `VapidSubject`)

All keys are base64url: 32 bytes each, except `ServerKey` (96). Generate a full set with `GoldfishSend.Api keygen`. See
[Keys and what losing them means](#keys-and-what-losing-them-means).

| Key | Default | Meaning |
|---|---|---|
| `Pepper` | (none) | HMAC key that turns a `sendSecret` into a mailbox id. |
| `SealSalt` | (none) | HKDF salt for the per-mailbox endpoint sealing keys. |
| `EpochKek` | (none) | Key-encryption key that wraps the daily epoch keys stored in MySQL. |
| `VapidPrivateKey` | (none) | P-256 private scalar used to sign VAPID (RFC 8292) JWTs. Its public key is published by `/v1/info`. |
| `ServerKey` | (none) | The server's identity and gateway key: an ML-KEM-768 seed (64 bytes) followed by a P-256 scalar (32 bytes). Its public half is served by `GET /v1/key`, and clients pin its fingerprint. It never expires and needs no renewal. Required on `api` nodes; worker-only nodes ignore it. See [Server identity](#server-identity). |
| `VapidSubject` | `mailto:admin@example.invalid` | The VAPID `sub` claim: a `mailto:` or `https:` contact for push providers. Set it to something you control. |

### `Goldfish:Messages`

| Key | Default | Meaning |
|---|---|---|
| `DefaultTtlSeconds` | `259200` (72 h) | TTL when the sender sends no `GF-TTL` header. |
| `MaxTtlSeconds` | `1209600` (14 d) | Upper clamp for `GF-TTL`. It also sets epoch key retention (`ceil(MaxTtl / 1 day) + 1` days), so it bounds how long a held message's key exists. |
| `MinTtlSeconds` | `60` | Lower clamp for `GF-TTL`. |
| `DeliveryParallelism` | `32` | Concurrent deliveries per worker process, for both the stream and retry workers. |
| `IdempotencyWindowSeconds` | `3600` (1 h, ±10% jitter) | How long a `GF-Idempotency-Key` is remembered, in the **ephemeral** Redis only, under an HMAC of mailbox id ‖ key. It's reserved as "pending", then the message is queued, then it's marked "done". A retry that finds "pending" queues again under the same id. So sends are at-least-once, never a false success: the worst case is a duplicate push of identical ciphertext, which the client's Signal session drops. |
| `MaxHeldPerMailbox` | `500` | The most undelivered messages held per mailbox. Further sends get `507 mailbox_full` with scope `mailbox`. This bounds the storage a dead endpoint or hostile contact can use. |
| `MaxHeldTotal` | `500000` | Server-wide held-message quota (rows, about 4.3 KiB each). Once reached, sends to mailboxes that are already holding messages (or whose endpoint is gone) get `507 mailbox_full` with scope `global`. Healthy mailboxes keep working, and messages that fail after acceptance are still held (a small overshoot), so nothing accepted is dropped. `0` = unlimited. |
| `GoneMaxTtlSeconds` | `259200` (3 d) | TTL ceiling for messages accepted for a mailbox whose endpoint is gone. |
| `MaxStreamLength` | `50000` | Bound on the hot Redis stream. Beyond it, or if Redis reports out-of-memory, new messages go straight to MySQL `pending_messages` (due now) and are delivered by the retry worker. A backlog or Redis memory pressure never fails sends. |

### `Goldfish:Mailboxes`

| Key | Default | Meaning |
|---|---|---|
| `LifetimeDays` | `90` | Expiry granted at creation and by each refresh. |
| `VerificationMinutes` | `10` | How long a new mailbox or endpoint rotation can wait for verification before it's purged. It's also the TTL of the verification push. |
| `MaxVerifyAttempts` | `5` | Wrong verification codes allowed per mailbox. |
| `MaxBatch` | `100` | Maximum items per owner batch request (verify, rotate, refresh, delete). |

### `Goldfish:Pow`

Argon2id proof of work (`gf/pow/v2`, see docs/protocol.md). Solving costs about `2^difficulty` Argon2 calls of
`MemoryKiB` each, and verifying costs one. It's tuned to make mass creation cost something, not to be quick: the app
keeps a pool of ready mailboxes, so people rarely wait, and when they do it shows progress and carries on in the
background.

Measured on a desktop x86 CPU (AVX2), one 16 MiB call (`t = 1`) takes:

| Implementation | One core | Notes |
|---|---|---|
| libsodium (native, AVX2) | 12 ms | What an attacker would use. Many threads at once are held back by memory bandwidth. |
| BouncyCastle .NET (this server) | 30–45 ms | Verification, including allocating the 16 MiB. |
| BouncyCastle JVM (HotSpot) | 17 ms | 5 ms per call on 4 threads. |
| BouncyCastle on Android (x86_64 emulator on the same CPU, ART, non-debuggable) | 47 ms | 18 ms per call on its 3 solver threads. |

A mid-range ARM phone should be about 2× slower per core than that emulator, so roughly 25–60 ms per call
on 4 threads. At the base difficulty (256 calls) that's a median of about 4–11 s (mean 6–15 s). This comes from CPU
benchmark ratios, not a phone, so treat it as good to about 2×.

**What it costs an attacker** (native Argon2 at 12 ms per call per core, cloud CPU at $0.01–0.04 per core-hour, a GPU at
$0.3–0.8 an hour):

| Difficulty | When | Core-seconds per mailbox | Per million mailboxes (CPU) | Per million (GPU, rough) |
|---|---|---|---|---|
| 8 | base | 3 | 850 core-hours, $9–35 | 6–14 GPU-hours, $2–11 |
| 12 | one network at the default `create-net` burst (+4) | 49 | 14 000 core-hours, $140–550 | $30–180 |
| 16 | a busy network during a global flood (+6 +2) | 790 | 220 000 core-hours, $2 200–8 700 | $500–2 900 |

The GPU column assumes the GPU is limited by memory bandwidth: each call moves about 48 MiB, so an RTX 4090 (1 TB/s)
manages at most about 20 000 calls a second, and likely 5 000–12 000. That's 60–150 CPU cores' worth, or roughly 1–20×
cheaper per call than cloud CPUs. There's no published Argon2 GPU benchmark at these parameters, so this is the least
certain number here (an order of magnitude either way). Proof of work prices out cheap mass abuse; it doesn't stop a
funded attacker. The real caps are the per-IP, per-network and per-/32 limits below, and each network an attacker uses
pays its own rising difficulty.

| Key | Default | Meaning |
|---|---|---|
| `BaseDifficulty` | `8` | Leading zero bits for mailbox creation at no load: 256 Argon2 calls. |
| `SendDifficulty` | `6` | Fixed bits for `?purpose=send` challenges, which only pay a send limit (64 calls). The app solves at most 2^11 calls of 16 MiB, for 180 s, for a server that isn't its own, so keep this well below that. |
| `MemoryKiB` | `16384` | Argon2 memory per call. The app runs up to 4 solver threads, so up to 4× this. 16 MiB is large enough that GPUs are held back by memory bandwidth, and small enough for low-memory phones. |
| `Iterations` | `1` | Argon2 passes over the memory. Raising `MemoryKiB` buys more memory-hardness for the same time. |
| `ChallengeTtlSeconds` | `300` | Lifetime of a single-use challenge. The app fetches a fresh one 30 s before expiry when its search takes longer, so this only needs to cover a send-limit solve (180 s) and the round trip. |
| `LoadWindowMinutes` | `5` | How far back creations count toward load. |
| `NetworkLoadThreshold` | `5` | Creations from one network (IPv4 /24, IPv6 /48) in the window before that network's difficulty rises: +1 bit when over it, +1 more per doubling. A household setting up a few phones stays at base. Counted for every creation that passes the rate limits, verified or not, since it only slows that network. Shared networks (CGNAT, Tor exits) get slower too, and the app copes with that. `0` disables it. |
| `AllocationLoadThreshold` | `50` | The same for a whole IPv6 /32, 10× looser, since a /32 can hold an ISP's customers. It catches one actor spread over many /48s. A network gets the larger of its own and its /32's extra bits. `0` disables it. |
| `MaxNetworkExtraDifficulty` | `6` | Bits a busy network (or /32) can gain: 64×, ten minutes or more on a phone. With the default `create-net` limit (burst 50) one network reaches about +4. |
| `GlobalLoadThresholdPerMinute` | `120` | **Verified** mailboxes per minute, server-wide, before everyone's difficulty rises. Raising it this way needs real push endpoints and a round trip per mailbox. `0` disables it. |
| `MaxGlobalExtraDifficulty` | `2` | Bits everyone can gain from server-wide load (4×). Kept small, so a flood spread over many networks can't make onboarding slow for everyone. |
| `MaxConcurrentVerifications` | `0` | Argon2 verifications at once per process (`0`: one per CPU). Each takes about 30–45 ms of a core and `MemoryKiB` of memory. One network (/24 or /48) may hold at most a quarter of them and one IPv6 /32 half (at least one each), so junk solutions from one place can't take them all. When none comes free within 250 ms, the request gets `503` with `Retry-After: 1`, and the challenge is kept for a retry. |

The load counters are per-minute counts in the ephemeral Redis that expire after `LoadWindowMinutes` + 1. The
per-network and per-/32 ones are keyed by the same daily HMAC as short-period rate-limit buckets. None refers to a
mailbox. The fair-share counts live only in process memory, while a verification runs. The startup check refuses
parameters the app would refuse: `create` difficulty over 24 at full load or expected work over 2^17 calls of 16 MiB,
`send` difficulty over 20 or work over 2^11 calls of 16 MiB, `MemoryKiB` outside 8–65536, `Iterations` outside 1–4.

### `Goldfish:Push` (outbound requests to push servers)

| Key | Default | Meaning |
|---|---|---|
| `AllowedPorts` | `[443]` | Ports allowed in endpoint URLs besides the scheme default. |
| `AllowIpLiterals` | `false` | Allow endpoints whose host is an IP address instead of a DNS name. |
| `BlockedHosts` | `[]` | Hostnames (and their subdomains) that may never be endpoints. Put this server's own names here; the compose file adds `GOLDFISH_DOMAIN`. |
| `ExtraBlockedRanges` | `[]` | Extra CIDRs to refuse at connect time, for example this server's public addresses. Private, loopback, link-local, CGNAT, multicast, ULA, NAT64, 6to4, Teredo and documentation ranges are always refused. |
| `ConnectTimeoutSeconds` | `5` | TCP + TLS connect timeout. |
| `ResponseHeadersTimeoutSeconds` | `3` | How long a push service may take to answer once connected. The push deadline is `min(RequestTimeoutSeconds, ConnectTimeoutSeconds + ResponseHeadersTimeoutSeconds)` (8 s by default). The response body is never read. A timeout puts the host's base domain in the slow lane for 10 minutes. |
| `RequestTimeoutSeconds` | `10` | Upper bound on the push deadline above. Each worker job gets the deadline plus 15 s. |
| `MaxConnectionsPerHost` | `16` | Connection pool size per push host. |
| `MaxInFlightPerHost` | `4` | Concurrent pushes to one host per process, well below `DeliveryParallelism`, so one slow host can't take every slot. Extra jobs are deferred (retried within a second, not counted as an attempt). |
| `MaxInFlightPerMailbox` | `4` | Concurrent pushes to one mailbox, cluster-wide. A burst to one contact still goes out in parallel, but one mailbox (say, one pointing at a tarpit) can't hold more slots. |
| `SlowLaneSlots` | `4` | Concurrent pushes per process to hosts whose base domain (`a1.evil.example` → `evil.example`) recently timed out. Tarpits spread across wildcard subdomains share these few slots. |
| `CircuitBreakerMinVolume` | `20` | Breaker: minimum pushes to a host within a minute before it can open. |
| `CircuitBreakerFailureRatio` | `0.5` | Breaker: share of those pushes that must be **host** failures (connection errors, timeouts, 5xx). 4xx, 429 and 401/403 refuse one subscription and never count, so one subscriber can't pause a shared push service. |
| `CircuitBreakerMinEndpoints` | `3` | Breaker: the failures must come from at least this many distinct endpoints. |
| `CircuitBreakerOpenSeconds` | `30` | How long an open circuit stays open. Every node honours it. Deferred pushes don't count as attempts. |
| `DangerouslyAllowInsecureLoopback` | `false` | Testing only: allows `http://` and loopback endpoints and relaxes the SSRF filter. Startup fails outside the Development environment. |

### `Goldfish:Invites`

| Key | Default | Meaning |
|---|---|---|
| `DefaultTtlSeconds` | `900` | Invite lifetime when no `GF-TTL` is sent. |
| `MinTtlSeconds` | `60` | Lower clamp. |
| `MaxTtlSeconds` | `86400` | Upper clamp. |
| `MaxLiveInvites` | `20000` | Invites stored at once (each at most 4 KiB, so about 80 MiB). Uploads beyond it get `429` with scope `global`. |

### `Goldfish:Network`

| Key | Default | Meaning |
|---|---|---|
| `GatewayRequestsPerSecond` | `50` | Gateway requests per second per client (IPv4 address or IPv6 /64) on each api node, checked in memory **before** any decryption. Opening a request costs about 0.3 ms of CPU, and this keeps one client from making the server do that work unboundedly. Over the limit: a plaintext `429` with `Retry-After: 1`. `0` turns it off. Onion clients all share the tor container's address, so raise it for a large onion user base. |
| `GatewayBurst` | `200` | Bucket size for `GatewayRequestsPerSecond`. |
| `GatewayMaxClients` | `100000` | Clients the flood guard tracks per api node (about 200 bytes each, so about 20 MB at most). An IPv6 allocation holds many /64s, so this stops one client growing the table by rotating addresses. Clients first seen while it's full share one overflow bucket until idle entries expire (after a minute). |
| `GatewayOverflowFactor` | `20` | The overflow bucket's rate and size, as a multiple of one client's. |
| `ForwardLimit` | `1` | How many proxy hops to unwrap from `X-Forwarded-For`. Use `2` when Traefik (or Caddy) sits behind a load balancer, and add the load balancer's addresses to `TrustedProxies`. Each hop is only believed if the hop in front of it is trusted. |
| `TrustedProxies` | `[]` | IPs or CIDRs whose `X-Forwarded-For` is trusted. Blank entries are ignored and invalid ones stop startup. Empty means XFF is ignored and the TCP peer is the client. Behind Caddy in compose, this is set to the caddy/api network's IPv4 and IPv6 subnets. If a forwarded client address ever falls *inside* these networks, the API logs a warning (at most every 10 minutes): the container runtime is collapsing clients into one address. |

### `Goldfish` (other)

| Key | Default | Meaning |
|---|---|---|
| `EpochKeyStore` | `MySql` | Where the wrapped daily epoch keys live. `MySql`: held messages survive any restart, but a deleted key row can linger in InnoDB redo, undo and free pages until overwritten (see "Data on disk"). `Ephemeral`: keys live only in the non-persistent ephemeral Redis, so shredding is real and nothing is on disk. But restarting that Redis drops every queued and held message (their keys are gone). |

### `Goldfish:RateLimits`

A dictionary of GCRA policies: `Limit` events per `PeriodSeconds`, with bursts of up to `Burst`. Subjects are
HMACed with a daily random key, which lives only in the ephemeral Redis, before they reach Redis. Every limit is shared
cluster-wide. A partial override is fine: any field you leave out (or set to `0`) keeps its default.
"IP" subjects are an IPv4 /32 or IPv6 /64. "Network" subjects are an IPv4 /24 or IPv6 /48, which stops one
allocation from multiplying its quota by rotating addresses. "-alloc" subjects are an IPv6 /32, with much looser limits:
a /48 costs little in bulk, so they stop one actor that holds thousands of them. All are keyed by HMAC like the rest, and
a `429` from them has scope `network`.

| Policy | Subject | Default (`Limit` / `PeriodSeconds`, `Burst`) | Applies to |
|---|---|---|---|
| `send-ip` | client IP (/32 or /64) | 60 / 60 s, burst 20 | `POST /v1/messages` (1 token) and `POST /v1/messages/batch` (`ceil(items / 8)` tokens per batch). A valid PoW (`GF-PoW` header) bypasses it. |
| `send-mailbox` | mailbox | 30 / 60 s, burst 30 | Every message, single or batched. Protects recipients from a hostile contact. |
| `send-mailbox-day` | mailbox | 1000 / 86400 s, burst 1000 | Every message, single or batched |
| `send-global` | whole server | 2000 / 1 s, burst 4000 | Every message, single or batched: the overall accept ceiling. Charged last, only for messages about to be accepted, so junk can't drain it. |
| `create-ip` | client IP | 30 / 3600 s, burst 20 | `POST /v1/mailboxes` (fails closed if Redis is down) |
| `create-net` | client network | 100 / 3600 s, burst 50 | `POST /v1/mailboxes` (fails closed) |
| `create-alloc` | client IPv6 /32 | 2000 / 3600 s, burst 500 | `POST /v1/mailboxes` (fails closed), checked before `create-net`. 20× one /48: a normal ISP's /32 shares it among many customers, but one actor holding thousands of /48s gets what 20 of them would. IPv4 clients skip it. |
| `pow-ip` | client IP | 30 / 60 s, burst 30 | `POST /v1/pow/challenge` |
| `pow-net` | client network | 300 / 60 s, burst 100 | `POST /v1/pow/challenge` |
| `pow-alloc` | client IPv6 /32 | 3000 / 60 s, burst 1000 | `POST /v1/pow/challenge`, checked first. 10× one /48. IPv4 clients skip it. |
| `owner-ip` | client IP | 30 / 60 s, burst 30 | Owner operations (verify, rotate, refresh, delete) |
| `rotate-mailbox` | mailbox | 10 / 86400 s, burst 5 | `PUT /v1/mailboxes/endpoint`. Each rotation pushes to a new URL, so it's budgeted per mailbox. |
| `invite-create-ip` | client IP | 20 / 3600 s, burst 10 | `POST /v1/invites` (fails closed) |
| `invite-create-net` | client network | 100 / 3600 s, burst 30 | `POST /v1/invites` (fails closed) |
| `invite-create-global` | whole server | 5 / 1 s, burst 50 | `POST /v1/invites`. Bounds the Redis memory invites can take, at most 5/s × 4 KiB × `Invites:MaxTtlSeconds`. |
| `invite-fetch-ip` | client IP | 60 / 60 s, burst 20 | `GET /v1/invites/{id}` |
| `push-host` | push-service host | 200 / 1 s, burst 200 | Outbound pushes to one push host, from all workers together |
| `push-mailbox` | mailbox | 2 / 1 s, burst 10 | Outbound pushes per mailbox, in front of `push-host`, so a few mailboxes can't take a shared push service's budget |
| `send-net` | client network | 600 / 60 s, burst 200 | Like `send-ip` (same per-batch cost), checked before it. A valid `GF-PoW` pays for either. |
| `send-lookup-global` | whole server | 3000 / 1 s, burst 6000 | Every message (single or batched item) before the mailbox lookup. It caps how many token lookups reach MySQL. |
| `create-global` | whole server | 30000 / 3600 s, burst 3000 | `POST /v1/mailboxes` (after the PoW, fails closed). A resource cap only, not the main defence: at most 30 000 rows an hour (unverified ones are purged after 10 minutes) and 8 verification pushes a second, against 2000 message pushes a second for `send-global`. It is about 6000 new users an hour with 5 mailboxes each. Filling it takes 300 networks at the `create-net` rate, each paying its own rising difficulty. |
| `newhost-global` | whole server | 120 / 3600 s, burst 30 | Verification pushes to push hosts no mailbox has used in 30 days. It stops the server being used to POST to arbitrary sites. |
| `owner-net` | client network | 300 / 60 s, burst 100 | Owner operations. Always charged. (`owner-ip` is only charged on **failed** ownership or verification, so junk from a shared address can't lock out real owners.) |
| `invite-fetch-net` | client network | 300 / 60 s, burst 100 | `GET /v1/invites/{id}`, checked before `invite-fetch-ip` |

Order: for every request, the widest scope (global, then network) is checked before the narrowest, so a request a
wide limit refuses never creates narrow buckets. For mailbox creation, the proof of work is redeemed **before** any
address budget is charged: first a GETDEL of the challenge (so only challenges issued under `pow-ip` and `pow-net` ever
cost an Argon2 call), then one Argon2 call in the `MaxConcurrentVerifications` pool. Budgets with a period of an hour
or more are keyed with a stable cluster secret (in the ephemeral Redis) instead of the daily key, so the key rotation
at UTC midnight doesn't reset them.

Example: `Goldfish__RateLimits__send-ip__Limit=120`, `…__PeriodSeconds=60`, `…__Burst=40`.

### Fixed limits (not configurable)

Kestrel caps request bodies at 20 KiB (the gateway's outer body), headers at 16 KiB / 50 headers and the request line
at 4 KiB, with a 30 s request timeout. Inside the gateway, request bodies are capped at 16 KiB and the padded inner
request at 17 KiB. Each request carries about 1.2 KB of overhead (1153 B of KEM ciphertexts, a 9 B header and a 16 B
tag) and each response 48 B, and both are padded to 512 B, 1, 2, 4, 8 or 17 KiB. Messages are capped at 3983 bytes
and invites at 4096 bytes (see the protocol's size budget).

## Deployment with Docker Compose

The stack in [`../deploy`](../deploy) runs six containers on four networks (plus `tor`, with the `onion` profile):

| Service | Networks | Notes |
|---|---|---|
| `caddy` | `public`, `onion` | The only published service (80/tcp, 443/tcp, 443/udp). Automatic Let's Encrypt, TLS 1.3, HSTS, 20 KiB body limit, no access logs. Only `/v1/gw` and `/v1/key` are proxied; `/healthz`, `/readyz` and everything else get 404. |
| `api` | `public`, `internal` | `Goldfish__Roles=api`. Trusts `X-Forwarded-For` only from the `public` subnet. Uses `public` for outbound verification pushes. |
| `worker` | `internal`, `egress` | `Goldfish__Roles=worker`. `egress` gives it outbound internet for push servers. |
| `mysql` | `internal` | MySQL 8.4, no binlog, fsync on every commit, no query logs, performance_schema off. |
| `redis` | `internal` | Redis 7.4 for the queue and invites: AOF only, `noeviction`, `default` user disabled, an ACL-restricted `goldfish` app user, dangerous commands removed. |
| `redis-ephemeral` | `internal` | Redis 7.4 for rate limits, PoW, idempotency and breakers: no persistence and no volume, `volatile-ttl`, the same ACL setup. |

`internal` is a Docker `internal: true` network with no route out. `onion` only links Caddy and the optional `tor`
container (see "Onion service"). All app containers run with a read-only
root filesystem, `no-new-privileges`, all capabilities dropped (Caddy keeps only `NET_BIND_SERVICE`), and core
dumps disabled.

### Steps

1. **DNS and firewall.** Point an A record (and an AAAA record, if IPv6 is enabled on the `public` network, which is the default) for your domain at the host. Open 80/tcp, 443/tcp and
   443/udp.
2. **Configure.**
   ```bash
   cd deploy
   cp .env.example .env               # GOLDFISH_DOMAIN and the MySQL/Redis passwords
   cp goldfish.env.example goldfish.env
   chmod 600 .env goldfish.env
   openssl rand -hex 32               # run once per password and paste into .env
   ```
   `.env` feeds compose interpolation, and each value reaches only the containers that reference it.
   `goldfish.env` is loaded into the api and worker only. Both files are gitignored.
3. **Build and generate keys.**
   ```bash
   docker compose build api
   docker run --rm localhost/goldfishsend:latest keygen
   ```
   Or skip the build: set `GOLDFISH_IMAGE=ghcr.io/<owner>/goldfishsend:latest` in `.env` (the image CI publishes from
   `main` for amd64 and arm64; see `docs/RELEASING.md`), `docker compose pull api worker`, and run `keygen` with that
   image.
   Copy the five keys into `goldfish.env` (`Goldfish__Keys__Pepper=…` and so on), set
   `Goldfish__Keys__VapidSubject`, and **back them up offline now** (see below). Note the server key fingerprint
   printed on stderr: that's your server's identity (see [Server identity](#server-identity)).
4. **Start.**
   ```bash
   docker compose up -d
   docker compose ps                  # api, worker, mysql and both redis should become "healthy"
   curl -s https://push.example.com/v1/key | wc -c    # 1250
   docker compose logs api | grep "Server key fingerprint"
   ```
5. **Point clients** at `https://<your domain>`. They pin the server key's fingerprint on first contact (or use the one
   built into the app, or the one in an invite), then fetch everything else, including the VAPID key, through the
   encrypted gateway.

Podman works too: `podman compose` (backed by docker-compose or podman-compose) and `podman build`.

**Upgrading:** `git pull && docker compose up -d --build`, or with a published image,
`docker compose pull api worker && docker compose up -d`. Migrations run automatically at startup. Pin a version tag
(`ghcr.io/<owner>/goldfishsend:0.1.123`) instead of `latest` if you'd rather upgrade on purpose. Each image has a
provenance attestation: `gh attestation verify oci://ghcr.io/<owner>/goldfishsend:latest --owner <owner>`.

### Keys as Docker secrets instead of environment variables

Environment variables are visible to anyone who can run `docker inspect`. To keep keys out of them, use a file:

1. Save the `keygen` JSON as `deploy/secrets/goldfish.json` (gitignored). Its shape is already an
   `appsettings` fragment (`{"Goldfish":{"Keys":{…}}}`).
2. Make it readable by the container's `app` user (UID 1654) and nobody else:
   `sudo chown root:1654 secrets/goldfish.json && sudo chmod 0640 secrets/goldfish.json`
   (rootless podman: `podman unshare chown 1654:1654 secrets/goldfish.json`).
3. Uncomment the two `secrets:` blocks in `docker-compose.yml`. The file is mounted as
   `/app/appsettings.Production.json`, which ASP.NET Core loads automatically.
4. Remove the `Goldfish__Keys__*` lines from `goldfish.env`, because environment variables take precedence.

### Real client IPs

Rate limiting needs the real client address at Caddy:
- **IPv6:** the compose file enables IPv6 on the `public` network (ULA subnet `GOLDFISH_PUBLIC_SUBNET6`), so IPv6
  clients reach Caddy with their real address. Without it, `docker-proxy` (or rootless port forwarding) forwards
  IPv6 clients from the bridge gateway's address, and they'd all share one rate-limit bucket (the API warns when it
  sees that). If your Docker can't do IPv6, set `GOLDFISH_ENABLE_IPV6=false` and publish only an A record.
- **Rootless Podman:** use the `pasta` network backend (the default since Podman 5), which preserves source
  addresses. `slirp4netns` with the default port handler does not.

### Running behind Traefik

If you already run Traefik (v3), use the overlay instead of the bundled Caddy:

```bash
cd deploy
# in deploy/.env:
#   GOLDFISH_TRAEFIK_NETWORK=traefik            # the external Docker network your Traefik watches
#   GOLDFISH_TRAEFIK_SUBNET=172.18.0.0/16       # that network's subnet: docker network inspect traefik
#   GOLDFISH_TRAEFIK_ENTRYPOINT=websecure        # your TLS entrypoint
#   GOLDFISH_TRAEFIK_CERTRESOLVER=letsencrypt    # your ACME resolver
docker compose -f docker-compose.yml -f docker-compose.traefik.yml up -d --build
```

The overlay leaves Caddy out, attaches the api to your Traefik network, and publishes it with labels. The labels:
- route only `Host(GOLDFISH_DOMAIN)` with the paths `/v1/gw` and `/v1/key` on the TLS entrypoint, so `/healthz`,
  `/readyz` and every other path return Traefik's 404, and plain HTTP has no API route;
- cap request bodies at 20 KiB (the `buffering` middleware);
- add HSTS (2 years, includeSubDomains, preload), `nosniff` and `no-referrer`, and strip `Server`;
- load-balance every `--scale api=N` replica, with health checks on `/healthz`.

The api trusts `X-Forwarded-For` only from `GOLDFISH_TRAEFIK_SUBNET` (plus optional `GOLDFISH_TRAEFIK_SUBNET6`).

**What your Traefik must do (static configuration):**
- **Don't trust client-supplied forwarded headers.** Leave `entryPoints.<tls>.forwardedHeaders.insecure` unset. Traefik
  then replaces any `X-Forwarded-For` sent by a client with the real peer address, so clients can't pick their own
  rate-limit bucket.
- **Behind a load balancer** (cloud LB, HAProxy, a second Traefik): set `forwardedHeaders.trustedIPs` to the load
  balancer's addresses on Traefik, and in `deploy/.env` set `GOLDFISH_FORWARD_LIMIT=2` and
  `GOLDFISH_UPSTREAM_PROXIES=<the load balancer's CIDR>`.
- **No access logs** for this router. Traefik writes none unless `accessLog` is configured. If it is, it records
  client IPs and URLs for every request, so turn it off, or set `accessLog.fields.defaultMode: drop` and
  `accessLog.fields.headers.defaultMode: drop`.
- Sensible entrypoint timeouts (`transport.respondingTimeouts`, for example `readTimeout: 30s`), so slow clients can't hold connections.
- The Docker provider with `exposedByDefault: false` is recommended, so only labelled containers are published.

**Misconfiguration is visible.** If Traefik's network isn't in `GOLDFISH_TRAEFIK_SUBNET`, the api logs
`Ignoring X-Forwarded-For from untrusted proxy <traefik's address>` (at most every 10 minutes). Until that's fixed,
every client shares one rate limit.

**Server identity doesn't depend on the certificate.** The app verifies your server by its server key (see
[Server identity](#server-identity)), never by the TLS certificate, so Traefik's ACME resolver can change the
certificate's key at every renewal without affecting anyone. Traefik also only ever sees encrypted request bodies.

**Optional TLS key pinning.** Clients who also turn on the extra "Pin server keys" layer pin your certificate's public
key. Traefik's ACME resolver has no setting to keep the key, so it may generate a new one on renewal and warn those
users every couple of months. To check, compare the TLS fingerprint (see below) before and after a renewal. If it
changes, either tell users the extra layer isn't useful on your server, or let certbot manage this one certificate with
a fixed key and have Traefik serve it from its file provider:

1. Get the certificate with certbot and `--reuse-key`. The flag is saved in the renewal config, so every
   `certbot renew` keeps the key. A DNS-01 plugin is simplest, because Traefik already owns port 80:
   ```bash
   certbot certonly --dns-cloudflare --dns-cloudflare-credentials /root/cf.ini \
     --key-type ecdsa --reuse-key -d push.example.com
   ```
2. Mount `/etc/letsencrypt` read-only into Traefik (the whole directory, because `live/` holds symlinks into
   `archive/`) and enable the file provider with `watch: true`. Add a dynamic config file:
   ```yaml
   tls:
     certificates:
       - certFile: /etc/letsencrypt/live/push.example.com/fullchain.pem
         keyFile: /etc/letsencrypt/live/push.example.com/privkey.pem
   ```
   Traefik reloads the files on renewal by itself.
3. Set `GOLDFISH_TRAEFIK_CERTRESOLVER=` (empty) in `deploy/.env`, so Traefik doesn't also request its own certificate
   for the domain, and recreate the api container.

To rotate the key on purpose later, run `certbot renew --force-renewal --new-key` once, and publish the new
fingerprint first (see "Publishing your TLS key fingerprint").

**Onion service with Traefik.** `--profile onion` still works. Tor forwards straight to the api, which gets a fixed
address on the onion network (`GOLDFISH_ONION_API_IP`), because Tor can't target a hostname. On that path only Kestrel's
own limits apply, and `/healthz` and `/readyz` are reachable from the onion (they only answer "ok"/"ready").

This setup was tested against a real Traefik 3.5:
- Each client got its own rate-limit bucket.
- A client-supplied `X-Forwarded-For` was ignored.
- The load-balancer setup (`ForwardLimit=2` plus a trusted upstream) resolved the real client, and a non-LB peer couldn't spoof it.
- A 20 KiB body got 413.
- `/healthz` and `/readyz` returned 404.
- Plain HTTP had no route.
- The untrusted-proxy warning appeared.

### Onion service (optional)

Clients can use the app's built-in Tor (or Orbot) to hide their IP address from the server. You can also give
the server a v3 onion address, so Tor users never leave the Tor network:

```bash
cd deploy
docker compose --profile onion up -d --build
docker compose --profile onion exec tor cat /var/lib/tor/goldfish/hostname   # → <56 chars>.onion
```

Users then set their server to `http://<that address>.onion` with Tor turned on. Plain `http` is correct here:
the onion address authenticates the server, and Tor encrypts the connection end to end. Invites carry the
server URL, so contacts on an onion server work too, and the app asks their contacts to turn on Tor if needed.

How it's wired:
- The `tor` container (profile `onion`, read-only, all capabilities dropped, non-root) publishes the onion and
  forwards its port 80 to Caddy's onion-only listener (`:8081`, bound to Caddy's fixed address on the dedicated
  `onion` network). The same routes, 20 KiB body limit and health-endpoint blocking apply as on the public site.
- The `onion` network is **not** a trusted proxy network. Tor never talks to the api directly, so it can't inject
  `X-Forwarded-For`.
- Tor's built-in introduction-point DoS defence and onion-service proof-of-work defence are on.
- **Back up the `tor_data` volume.** `/var/lib/tor/goldfish` holds the onion service's private key, which *is* the
  address. Lose it and the address is gone. Leak it and someone else can impersonate the server. Treat it like the
  Goldfish keys.

**Rate limiting for onion clients.** Every onion client reaches the api from the tor container's single address,
so the server sees all onion users as **one IP** (and one /24 network). That's inherent to onion services: there's
no client address to see, and Tor circuits are free to create, so per-circuit limits wouldn't stop anyone.
What this means in practice:
- The per-IP and per-network limits (`send-ip`, `create-ip`, `create-net`, `pow-ip`, `pow-net`, `owner-ip`,
  `invite-*-ip`, `invite-create-net`) are **shared by all onion users**.
- Sends hitting `send-ip` get `429` with `"scope": "ip"`, and the client automatically pays with a proof of work
  (`GF-PoW` header) and retries, so onion users can still send under load. Per-mailbox and global limits apply to
  everyone as usual.
- Mailbox creation already needs a PoW, but `create-ip`/`create-net` still cap the total. A server with many onion
  users should raise those limits, plus `pow-ip`, `pow-net`, `owner-ip` and the invite limits, for example
  `Goldfish__RateLimits__create-ip__Limit=200`. Partial overrides keep the other fields' defaults. Clear-net
  users get the same higher per-IP limits, so raise them only as far as you need.

Push delivery is unaffected: notifications still reach phones through each user's UnifiedPush distributor,
which Tor doesn't cover.

### Server identity

Every server has one **server key** (`Goldfish:Keys:ServerKey`): a hybrid ML-KEM-768 + P-256 key pair whose public half
is served by `GET /v1/key`. Its **fingerprint** (SHA-256 of that public key) is the server's identity:
- Clients encrypt every API call to it, and only the holder of the private key can read the call or produce a valid
  answer. A TLS interception proxy, a mis-issued certificate or a compromised reverse proxy learns nothing, and
  can't impersonate the server.
- It never expires, so there's nothing to renew or rotate, and no volume is needed: it lives in `goldfish.env` or
  the secrets file with the other keys.
- Clients pin the fingerprint per server: from the app build for its default server, from an invite (for a contact's
  server), or on first contact for a server typed in by hand. If it ever changes, the app shows
  "server identity changed" and stops using the server until the user decides.

**Publish the fingerprint** wherever your users can check it (your website, an announcement channel). The server
prints it at startup (`Server key fingerprint: ABCD EFGH …`), and you can print it at any time:

```bash
docker compose run --rm --no-deps api fingerprint      # b64u on stdout, the grouped form on stderr
```

**Build it into the app** for a server you ship as the default, so users don't depend on first contact:
`./gradlew assembleRelease -Pgf.defaultServer=https://push.example.com -Pgf.defaultServerKey=<b64u fingerprint>`.

**Changing it** (only if the private key leaked or was lost): run `keygen`, replace `Goldfish__Keys__ServerKey`,
restart, and announce the new fingerprint *before* users see the warning. Every user then has to accept the new
identity, so treat the key as permanent and back it up with the others.

### Publishing your TLS key fingerprint (optional extra pinning)

The app already verifies the server by its server key, whatever the TLS certificate is. On top of that, users can turn
on **Pin server keys**, an optional extra layer: the app remembers the SHA-256 of your certificate's public key (SPKI)
on first connection and refuses to connect if it changes. The Caddyfile sets `reuse_private_keys`, so renewals keep
the same key and pinned clients aren't disturbed. Publish the fingerprint somewhere users can check it (your
website, an announcement channel):

```bash
openssl s_client -connect push.example.com:443 -servername push.example.com </dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary | openssl enc -base64
```

The app shows exactly this value under Settings › Network › Connection. **To rotate the key** (suspected compromise, or
policy), remove `reuse_private_keys` for one renewal (or delete the key under `caddy_data`), restore it, and
announce the new fingerprint *before* users see the "server identity changed" warning. Pinned clients block the
server until each user accepts the new key, so do this rarely and deliberately.

## Operations

### Keys and what losing them means

Back up `Pepper`, `SealSalt`, `EpochKek`, `VapidPrivateKey` and `ServerKey` offline and encrypted (for example an
`age`-encrypted file in two places, or a password manager). They are not stored anywhere else, and a database
backup is useless without them (by design).

| Key | If it's lost or changed | If it leaks |
|---|---|---|
| `Pepper` | **Every mailbox is orphaned.** Ids no longer match, so sends return 404 and owners can't manage mailboxes. Every user has to re-pair with every contact. | Together with a DB dump, someone who also holds a `sendSecret` can find its row. On its own it reveals nothing. |
| `SealSalt` | **Every mailbox is orphaned.** Endpoints can't be unsealed, so nothing can be delivered. Every user has to re-pair. | On its own, nothing: unsealing an endpoint needs that mailbox's `sendSecret`, **or** a held-message row (which carries the mailbox's seal key) plus `EpochKek`. See "Data on disk". |
| `EpochKek` | **All queued and held messages are lost.** The stored epoch keys can't be unwrapped. The server also refuses to start when the `epoch_keys` rows don't match the KEK. To recover, run `DELETE FROM epoch_keys; DELETE FROM pending_messages;` and restart. Mailboxes are unaffected. | Together with a DB dump that still holds the epoch keys, held messages can be unwrapped to their E2E ciphertext (still end-to-end encrypted). |
| `ServerKey` | Every client shows **"server identity changed"** and stops using the server until each user accepts the new key. Contacts on other servers that deliver to yours do the same. | Someone who can also intercept TLS to your server (or controls your reverse proxy) can read API calls and impersonate the server, for as long as the leaked key is in use, since it never expires. Replace it (above) and announce the new fingerprint. |
| `VapidPrivateKey` | Distributors that pin the server's VAPID key (the client registers it with them) **reject every push** until each client re-registers its endpoint with the new key. Distributors without VAPID pinning keep working. | Anyone who also has an endpoint URL can push to it as this server. Endpoints are sealed, so this needs a second leak. |

None of these keys can be rotated in place today, so treat them as permanent.

### Backups

- **Keys:** see above. This is the one thing you must never lose.
- **MySQL:** the only table worth keeping is `mailboxes`. If you lose it, every contact has to re-pair.
  `pending_messages` and `epoch_keys` are transient, so leave them out:
  ```bash
  docker compose exec -T mysql sh -c 'MYSQL_PWD="$MYSQL_PASSWORD" exec mysqldump --single-transaction \
    --no-tablespaces --ignore-table=goldfish.pending_messages --ignore-table=goldfish.epoch_keys \
    -ugoldfish goldfish' > goldfish-$(date +%F).sql
  ```
  **Retention:** a backup that contains `epoch_keys` and `pending_messages` defeats crypto-shredding for as
  long as it exists, because it plus `EpochKek` decrypts every message held at that moment. If you back those
  tables up at all, keep the backups no longer than `MaxTtlSeconds` (14 days by default). Also keep in mind that
  restoring an old `mailboxes` backup brings back mailboxes that users have since deleted ("blocked contact").
  Short retention is better.
- **Redis:** don't back it up. It only holds seconds of queue, rate-limit state and short-lived invites.
- **Caddy (`caddy_data`):** optional. Certificates are simply re-issued if it's lost (mind Let's Encrypt rate
  limits).

### Logging

There are no request logs anywhere in the stack:
- **Caddy** writes no access log, because the Caddyfile has no `log` directive. Caddy doesn't log requests by
  default. The global logger runs at WARN and also excludes the error-path loggers (`http.log.*`,
  `http.handlers.reverse_proxy`, `http.stdlib`), which would otherwise include client IPs and URIs. Don't add a
  `log` directive.
- **The app** never logs IPs, URLs, endpoints or secrets, only an opaque push-host fingerprint on failures.
  Framework request logging (`Microsoft.AspNetCore`, `System.Net.Http`) is pinned to Warning in `appsettings.json`
  and in compose. Keep it there: at Information, ASP.NET Core's routing logs the inner route of every decrypted
  gateway request (for example `GET /v1/invites/{id}`), though never ids or bodies. The push
  client bypasses `IHttpClientFactory`, so its URL logging is never in the pipeline.
- **MySQL**: general log, slow log and binlog are off, the error log is at verbosity 2, and performance_schema
  (which keeps statement texts in memory) is off.
- **Redis**: slowlog is disabled, `MONITOR` is removed and the ACL log is small.
- **Container logs** use the json-file driver, rotated at 3 × 10 MB per container.

Outside this stack, check the host: firewall or conntrack logging, journald forwarding, and your provider's
flow logs. Don't put a CDN or WAF in front of the server. It would see every client IP and the traffic timing.

### Data on disk

- **MySQL** deletes rows on delivery and expiry, but InnoDB pages, redo and undo logs, the doublewrite buffer and
  free blocks keep old bytes until overwritten. Held messages are encrypted under daily epoch keys that are deleted
  `ceil(MaxTtl / 1 day) + 1` days later ("crypto-shredding"). **Be clear about what that buys with the default
  `EpochKeyStore=MySql`:** the epoch keys are wrapped by the static `EpochKek` and stored in the *same* InnoDB files.
  A deleted key row can survive in redo, undo or free pages on the current disk. The KEK is in `goldfish.env` and in
  the container's config on the same host. So **one image of an unencrypted disk can recover recently "shredded"
  epochs.** Each held row also contains its mailbox's seal key (that's how the worker reaches the endpoint without
  the `sendSecret`). A DB dump plus `EpochKek` therefore unseals the push endpoints of every mailbox with held
  messages, and identical endpoint URLs then link one device's mailboxes. Mitigations, strongest first:
  1. `Goldfish__EpochKeyStore=Ephemeral`: keys only in the non-persistent Redis, so shredding is real. The cost:
     restarting that Redis drops held messages.
  2. InnoDB redo and undo log encryption with the keyring on a different device (see `deploy/mysql/my.cnf`).
  3. Full-disk encryption on the host, `EpochKek` delivered as a Docker secret rather than an env file, and
     database backups kept no longer than `MaxTtl` (or without `epoch_keys` and `pending_messages`).
- **Ephemeral Redis** (rate limits, PoW, breakers) has no persistence at all, so it leaves nothing on disk.
- **Redis AOF** (main instance) is an append-only log. Deleted queue entries (opaque mailbox ids, ciphertext and
  timestamps) and invite blobs stay in the AOF until the next rewrite. Idempotency markers are **not** here (they're
  in the ephemeral Redis), so the AOF has no per-mailbox send counter. Rewrites happen automatically as the file grows, but on a quiet server that can
  take days, so compact it hourly from the host's crontab:
  ```cron
  0 * * * * cd /path/to/deploy && docker compose exec -T redis sh -c 'REDISCLI_AUTH="$REDIS_PASSWORD" redis-cli --no-auth-warning --user goldfish BGREWRITEAOF' >/dev/null
  ```
- Deleted files aren't wiped from the underlying disk. Use **full-disk encryption** (LUKS) on the host, plus
  encrypted swap or no swap, since keys live in process memory. Core dumps are disabled in the containers.

### Delivery semantics

Delivery is **at-least-once**: a crash between a push and its acknowledgement, an expired retry lease, or a
reclaimed stream entry can push the same message twice. Clients drop duplicates (a repeated Signal ciphertext is
rejected), so nothing is shown twice. Retry leases are 5× the job timeout, and stream entries are reclaimed only
after 4× the job timeout (at least a minute), so a slow-but-alive node isn't normally duplicated. Messages to a
mailbox whose endpoint returned 404/410 are parked, not retried hourly. They're woken by verification or rotation,
by a successful push of a newer message, or by a re-probe that retries the oldest held message after 1 h, 2 h, 4 h …
(capped at 24 h). `refresh` and `verify` responses carry `endpointGone`, so clients re-register.

### Scaling (distributed)

Every process is stateless and coordinates only through MySQL and the two Redis instances, so api and worker
replicas can run on any number of hosts:

```bash
docker compose up -d --scale api=3 --scale worker=4
```

- **api**: Caddy discovers replicas through DNS (`dynamic a` in the Caddyfile) and balances by least connections.
  Rate limits, PoW challenges and idempotency are in Redis, so a client can hit any replica.
- **worker**: all workers join one Redis-stream consumer group, so each queued message goes to exactly one worker.
  Entries held by a dead worker are reclaimed after 1 minute, walking the whole pending list with the XAUTOCLAIM cursor.
  Retries are claimed from MySQL with `FOR UPDATE SKIP LOCKED` under a lease. Push-host pacing and circuit
  breakers are shared through the ephemeral Redis. Workers on other hosts are woken through Redis pub/sub.
- **maintenance** (expiry sweeps, mailbox purge, removing consumers left by departed nodes) runs on one node at a time
  under a Redis lease. Migrations use a MySQL named lock, so concurrent startups are safe.
- Each worker processes `DeliveryParallelism` jobs at once as continuous consumers, so a slow push host ties up
  one slot, never a batch.
- The integration suite includes a two-node test: messages accepted by either node are delivered exactly once.
- A small server can run one container with `Goldfish__Roles=api,worker`. It then needs a network with outbound
  access, which `public` provides.
- MySQL and Redis are single instances here. Scaling them (replicas, Sentinel, managed services) is outside this
  stack. Redis **Cluster** isn't supported, because the enqueue script touches two keys. If you enable the MySQL
  binlog for replication, set `binlog_expire_logs_seconds` to at most `MaxTtl`.

### Health and monitoring

- `/healthz`: process liveness (`ok`). `/readyz`: MySQL and Redis reachable (api role only). Both are reachable
  only from inside the compose networks, because Caddy answers 404 for them. `docker compose ps` shows the
  healthcheck state.
- The app records aggregate counters on the `GoldfishSend` meter (System.Diagnostics.Metrics), with no
  per-user dimensions. No exporter is wired up yet. The image sets `DOTNET_EnableDiagnostics=0`, so
  `dotnet-counters` can't attach to it.

## API summary

Full request and response formats, derivations and error codes are in [`docs/protocol.md`](../docs/protocol.md).

Only these exist in plaintext:

| Method | Path | Purpose |
|---|---|---|
| GET | `/v1/key` | The server key blob (1250 B). Clients check it against their pinned fingerprint. |
| POST | `/v1/gw` | The encrypted gateway: one sealed inner request in, one sealed inner response out (always `200`, except `400 bad_request`, `413 too_large`, `421 unknown_key` and the flood guard's `429`). |
| GET | `/healthz`, `/readyz` | Liveness and readiness (internal only). |

Everything else is an inner request through `/v1/gw` (a direct plaintext request gets 404). Secrets are only ever
sent in inner bodies or headers, never in paths. The one exception is the one-time invite id, which is inside the
encrypted request too.

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/v1/info` | none | Protocol version, VAPID public key, size limits, TTLs, current PoW difficulty |
| POST | `/v1/pow/challenge` | none | Issue a single-use PoW challenge |
| POST | `/v1/mailboxes` | PoW | Create a mailbox. Sends a verification push to the endpoint. |
| POST | `/v1/mailboxes/verify` | `sendSecret` + `ownerSecret` | Confirm a creation or rotation with the pushed code |
| PUT | `/v1/mailboxes/endpoint` | owner | Rotate the push endpoint for a batch of mailboxes |
| POST | `/v1/mailboxes/refresh` | owner | Extend expiry for a batch |
| POST | `/v1/mailboxes/delete` | owner | Delete a batch (block or delete contact) |
| POST | `/v1/messages` | `GF-Send-Token` header | Send an E2E blob (`GF-TTL`, `GF-Idempotency-Key`, `GF-PoW` optional) |
| POST | `/v1/messages/batch` | a `sendSecret` per item | Send up to 32 blobs in one request (group fan-out); per-item results. Format in [`docs/groups.md`](../docs/groups.md#server-batch-send). |
| POST | `/v1/invites` | none | Upload a one-time invite blob |
| GET | `/v1/invites/{id}` | none | Fetch and delete an invite blob |
| GET | `/healthz`, `/readyz` | internal only | Liveness and readiness |
