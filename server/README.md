# GoldfishSend server

GoldfishSend is a blind push relay for an end-to-end encrypted messenger. A sender posts an opaque, already
end-to-end encrypted blob to a per-contact *mailbox*. The server wraps it in RFC 8291 Web Push encryption and
hands it to the recipient's UnifiedPush server (ntfy, an FCM distributor, ...). Once the push server accepts it,
the message is gone. If delivery fails, the message is held, encrypted, until it can be delivered or its TTL
runs out.

It is written in ASP.NET Core (.NET 10) with MySQL 8.4 and Redis 7.4 (or Valkey). The wire protocol is in
[`docs/protocol.md`](../docs/protocol.md) and the design rationale in [`PLAN.md`](../PLAN.md).

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
trust, and don't put a logging CDN or WAF in front of it.

## Architecture

```
 client ──TLS 1.3──▶ caddy ──▶ api ──▶ MySQL (mailboxes, held messages, epoch keys)
                                 │  └─▶ Redis (queue stream, rate limits, PoW, idempotency, invites)
                                 │                │
                                 │             worker ──Web Push + VAPID──▶ push server ──▶ device
                                 └─ verification pushes (sent synchronously on mailbox create/rotate)
```

One image, two roles, selected with `Goldfish:Roles` (`api`, `worker`, or the default `api,worker` in one process):

| Role | What runs |
|---|---|
| `api` | Minimal-API endpoints under `/v1`, plus `/healthz` and `/readyz`. Accepts messages into the Redis stream and sends verification pushes itself. |
| `worker` | `StreamDeliveryWorker` (consumes `gf:q`, delivers, moves failures to MySQL), `RetryWorker` (retries held messages with backoff under a lease), `MaintenanceWorker` (every minute: rotate and shred epoch keys, delete expired messages, purge expired or unverified mailboxes). Serves only `/healthz`. |

Every process runs the embedded SQL migrations (serialised by a MySQL named lock) and creates today's and
tomorrow's epoch keys at startup.

Source layout:

| Path | Contents |
|---|---|
| `src/GoldfishSend.Core` | Options, protocol types, crypto (RFC 8291 Web Push, VAPID, mailbox sealing, PoW, SecretBox), endpoint validation and IP range filtering. No I/O. |
| `src/GoldfishSend.Infrastructure` | MySQL (Dapper + MySqlConnector, migrations, epoch keyring), Redis (queue, GCRA limiter in Lua, PoW and ephemeral stores), SSRF-safe push client, services and background workers. |
| `src/GoldfishSend.Api` | `Program.cs` (Kestrel limits, forwarded headers, security headers, `keygen`) and endpoints. |
| `tests/GoldfishSend.Tests` | Unit tests and Testcontainers-based integration tests. |
| `tools/HealthProbe` | A tiny HTTP probe used by container healthchecks (the runtime image has no shell or curl). |
| `Dockerfile` | Multi-stage build to a distroless (`noble-chiseled`) non-root runtime image. |
| `../deploy` | Compose stack: Caddy, api, worker, MySQL, Redis. |

Code style: K&R braces (opening brace on the same line, also for `else`/`catch`/`finally`), file-scoped
namespaces, braces always. It is enforced through the repository's `.editorconfig`; run `dotnet format` before
committing.

## Local development

You need the .NET 10 SDK and podman or docker.

```bash
# MySQL and Redis on localhost only
podman run -d --name gf-mysql -p 127.0.0.1:3306:3306 \
  -e MYSQL_ROOT_PASSWORD=dev -e MYSQL_DATABASE=goldfish -e MYSQL_USER=goldfish -e MYSQL_PASSWORD=dev \
  docker.io/library/mysql:8.4 --skip-log-bin
podman run -d --name gf-redis -p 127.0.0.1:6379:6379 \
  docker.io/library/redis:7.4-alpine redis-server --appendonly yes --requirepass dev

cd server

# Generate a development key set (JSON on stdout, VAPID public key on stderr)
dotnet run --project src/GoldfishSend.Api -- keygen > ../goldfish-dev-keys.json

# Export the keys and connection strings (bash; needs jq)
eval "$(jq -r '.Goldfish.Keys | to_entries[] | "export Goldfish__Keys__\(.key)=\(.value|@sh)"' ../goldfish-dev-keys.json)"
export ConnectionStrings__MySql='Server=127.0.0.1;Port=3306;Database=goldfish;User ID=goldfish;Password=dev'
export ConnectionStrings__Redis='127.0.0.1:6379,password=dev'

# Run (the "http" launch profile listens on http://localhost:5234 in the Development environment)
dotnet run --project src/GoldfishSend.Api

curl -s http://localhost:5234/v1/info
```

Don't commit `goldfish-dev-keys.json`, and never reuse development keys in production.

To test against a local ntfy on `http://localhost`, set `Goldfish__Push__DangerouslyAllowInsecureLoopback=true`.
This turns off parts of the SSRF protection, and the server refuses to start with it in Production.

Tests: `dotnet test`. The integration tests use Testcontainers. With podman, start the socket first:

```bash
systemctl --user start podman.socket
export DOCKER_HOST=unix://$XDG_RUNTIME_DIR/podman/podman.sock TESTCONTAINERS_RYUK_DISABLED=true
```

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

All keys are 32 bytes, base64url. Generate a full set with `GoldfishSend.Api keygen`. See
[Keys and what losing them means](#keys-and-what-losing-them-means).

| Key | Default | Meaning |
|---|---|---|
| `Pepper` | (none) | HMAC key that turns a `sendSecret` into a mailbox id. |
| `SealSalt` | (none) | HKDF salt for the per-mailbox endpoint sealing keys. |
| `EpochKek` | (none) | Key-encryption key that wraps the daily epoch keys stored in MySQL. |
| `VapidPrivateKey` | (none) | P-256 private scalar used to sign VAPID (RFC 8292) JWTs. Its public key is published by `/v1/info`. |
| `VapidSubject` | `mailto:admin@example.invalid` | The VAPID `sub` claim: a `mailto:` or `https:` contact for push providers. Set it to something you control. |

### `Goldfish:Messages`

| Key | Default | Meaning |
|---|---|---|
| `DefaultTtlSeconds` | `259200` (72 h) | TTL when the sender sends no `GF-TTL` header. |
| `MaxTtlSeconds` | `1209600` (14 d) | Upper clamp for `GF-TTL`. It also sets epoch key retention (`ceil(MaxTtl / 1 day) + 1` days), so it bounds how long a held message's key exists. |
| `MinTtlSeconds` | `60` | Lower clamp for `GF-TTL`. |
| `DeliveryParallelism` | `32` | Concurrent deliveries per worker process, for both the stream and retry workers. |
| `IdempotencyWindowSeconds` | `86400` (24 h) | How long a `GF-Idempotency-Key` is remembered. The key and the message are written in one atomic Redis script. |
| `MaxHeldPerMailbox` | `500` | The most undelivered messages held per mailbox. Further sends get `507 mailbox_full`. This bounds the storage a dead endpoint or hostile contact can use. |

### `Goldfish:Mailboxes`

| Key | Default | Meaning |
|---|---|---|
| `LifetimeDays` | `90` | Expiry granted at creation and by each refresh. |
| `VerificationMinutes` | `10` | How long a new mailbox or endpoint rotation can wait for verification before it's purged. It's also the TTL of the verification push. |
| `MaxVerifyAttempts` | `5` | Wrong verification codes allowed per mailbox. |
| `MaxBatch` | `100` | Maximum items per owner batch request (verify, rotate, refresh, delete). |

### `Goldfish:Pow`

| Key | Default | Meaning |
|---|---|---|
| `BaseDifficulty` | `20` | Leading zero bits required for mailbox creation (and the IP-limit bypass on sends). |
| `MaxExtraDifficulty` | `6` | Maximum bits added automatically under load. |
| `ChallengeTtlSeconds` | `300` | Lifetime of a single-use challenge. |
| `LoadThresholdPerMinute` | `120` | Server-wide mailbox creations per minute before difficulty starts rising (+1 bit per doubling). `0` disables the automatic increase. |

### `Goldfish:Push` (outbound requests to push servers)

| Key | Default | Meaning |
|---|---|---|
| `AllowedPorts` | `[443]` | Ports allowed in endpoint URLs besides the scheme default. |
| `AllowIpLiterals` | `false` | Allow endpoints whose host is an IP address instead of a DNS name. |
| `BlockedHosts` | `[]` | Hostnames (and their subdomains) that may never be endpoints. Put this server's own names here; the compose file adds `GOLDFISH_DOMAIN`. |
| `ExtraBlockedRanges` | `[]` | Extra CIDRs to refuse at connect time, for example this server's public addresses. Private, loopback, link-local, CGNAT, multicast, ULA, NAT64, 6to4, Teredo and documentation ranges are always refused. |
| `ConnectTimeoutSeconds` | `5` | TCP + TLS connect timeout. |
| `RequestTimeoutSeconds` | `10` | Hard deadline per push request, covering connect, headers and response. The body is never read. Each worker job gets this plus 15 s. |
| `MaxConnectionsPerHost` | `16` | Connection pool size per push host. In-flight requests per host are capped at 4× this. |
| `CircuitBreakerFailures` | `5` | Failures for one push host, **across the cluster**, within 1 minute that open its circuit. |
| `CircuitBreakerOpenSeconds` | `30` | How long an open circuit stays open. Every node honours it. |
| `DangerouslyAllowInsecureLoopback` | `false` | Testing only: allows `http://` and loopback endpoints and relaxes the SSRF filter. Startup fails outside the Development environment. |

### `Goldfish:Invites`

| Key | Default | Meaning |
|---|---|---|
| `DefaultTtlSeconds` | `900` | Invite lifetime when no `GF-TTL` is sent. |
| `MinTtlSeconds` | `60` | Lower clamp. |
| `MaxTtlSeconds` | `86400` | Upper clamp. |

### `Goldfish:Network`

| Key | Default | Meaning |
|---|---|---|
| `TrustedProxies` | `[]` | IPs or CIDRs whose `X-Forwarded-For` is trusted (one hop). Empty means XFF is ignored and the TCP peer is the client. Behind Caddy in compose, this is set to the caddy/api network's subnet. |

### `Goldfish:RateLimits`

A dictionary of GCRA policies: `Limit` events per `PeriodSeconds`, with bursts of up to `Burst`. Subjects are
HMACed with a daily random key, which lives only in the ephemeral Redis, before they reach Redis. Every limit is shared
cluster-wide. A partial override is fine: any field you leave out (or set to `0`) keeps its default.
"IP" subjects are an IPv4 /32 or IPv6 /64. "Network" subjects are an IPv4 /24 or IPv6 /48, which stops one
allocation from multiplying its quota by rotating addresses.

| Policy | Subject | Default (`Limit` / `PeriodSeconds`, `Burst`) | Applies to |
|---|---|---|---|
| `send-ip` | client IP (/32 or /64) | 60 / 60 s, burst 20 | `POST /v1/messages`. A valid PoW (`GF-PoW` header) bypasses it. |
| `send-mailbox` | mailbox | 30 / 60 s, burst 30 | `POST /v1/messages`, protects recipients from a hostile contact |
| `send-mailbox-day` | mailbox | 1000 / 86400 s, burst 1000 | `POST /v1/messages` |
| `send-global` | whole server | 2000 / 1 s, burst 4000 | `POST /v1/messages`, the overall accept ceiling. Charged last, only for messages about to be accepted, so junk can't drain it. |
| `create-ip` | client IP | 10 / 3600 s, burst 10 | `POST /v1/mailboxes` (fails closed if Redis is down) |
| `create-net` | client network | 100 / 3600 s, burst 50 | `POST /v1/mailboxes` (fails closed) |
| `pow-ip` | client IP | 30 / 60 s, burst 30 | `POST /v1/pow/challenge` |
| `pow-net` | client network | 300 / 60 s, burst 100 | `POST /v1/pow/challenge` |
| `owner-ip` | client IP | 30 / 60 s, burst 30 | Owner operations (verify, rotate, refresh, delete) |
| `rotate-mailbox` | mailbox | 10 / 86400 s, burst 5 | `PUT /v1/mailboxes/endpoint`. Each rotation pushes to a new URL, so it's budgeted per mailbox. |
| `invite-create-ip` | client IP | 20 / 3600 s, burst 10 | `POST /v1/invites` (fails closed) |
| `invite-create-net` | client network | 100 / 3600 s, burst 30 | `POST /v1/invites` (fails closed) |
| `invite-create-global` | whole server | 5 / 1 s, burst 50 | `POST /v1/invites`. Bounds the Redis memory invites can take, at most 5/s × 4 KiB × `Invites:MaxTtlSeconds`. |
| `invite-fetch-ip` | client IP | 60 / 60 s, burst 20 | `GET /v1/invites/{id}` |
| `push-host` | push-service host | 50 / 1 s, burst 50 | Outbound pushes to one push host, from all workers together |

Example: `Goldfish__RateLimits__send-ip__Limit=120`, `…__PeriodSeconds=60`, `…__Burst=40`.

### Fixed limits (not configurable)

Kestrel caps request bodies at 16 KiB, headers at 16 KiB / 50 headers and the request line at 4 KiB, with a
30 s request timeout. Messages are capped at 3983 bytes and invites at 4096 bytes (see the protocol's size
budget).

## Deployment with Docker Compose

The stack in [`../deploy`](../deploy) runs five containers on three networks:

| Service | Networks | Notes |
|---|---|---|
| `caddy` | `public` | The only published service (80/tcp, 443/tcp, 443/udp). Automatic Let's Encrypt, TLS 1.3, HSTS, 16 KiB body limit, no access logs. Only `/v1/*` is proxied; `/healthz`, `/readyz` and everything else get 404. |
| `api` | `public`, `internal` | `Goldfish__Roles=api`. Trusts `X-Forwarded-For` only from the `public` subnet. Uses `public` for outbound verification pushes. |
| `worker` | `internal`, `egress` | `Goldfish__Roles=worker`. `egress` gives it outbound internet for push servers. |
| `mysql` | `internal` | MySQL 8.4, no binlog, fsync on every commit, no query logs, performance_schema off. |
| `redis` | `internal` | Redis 7.4, AOF only, `noeviction`, `default` user disabled, an ACL-restricted `goldfish` app user, dangerous commands removed. |

`internal` is a Docker `internal: true` network with no route out. All app containers run with a read-only
root filesystem, `no-new-privileges`, all capabilities dropped (Caddy keeps only `NET_BIND_SERVICE`), and core
dumps disabled.

### Steps

1. **DNS and firewall.** Point an A (and AAAA) record for your domain at the host. Open 80/tcp, 443/tcp and
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
   Copy the four keys into `goldfish.env` (`Goldfish__Keys__Pepper=…` and so on), set
   `Goldfish__Keys__VapidSubject`, and **back them up offline now** (see below).
4. **Start.**
   ```bash
   docker compose up -d
   docker compose ps                  # api, worker, mysql and redis should become "healthy"
   curl -s https://push.example.com/v1/info
   ```
5. **Point clients** at `https://<your domain>`. They fetch the VAPID public key from `/v1/info`.

Podman works too: `podman compose` (backed by docker-compose or podman-compose) and `podman build`.

**Upgrading:** `git pull && docker compose up -d --build`. Migrations run automatically at startup.

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
- **Rootful Docker:** with IPv6 traffic and no IPv6 on the bridge network, `docker-proxy` forwards IPv6
  clients from the bridge gateway address, so they all share one rate-limit bucket. Enable IPv6 on the `public`
  network (`enable_ipv6: true` plus an IPv6 subnet) or don't publish on IPv6.
- **Rootless Podman:** use the `pasta` network backend (the default since Podman 5), which preserves source
  addresses. `slirp4netns` with the default port handler does not.

## Operations

### Keys and what losing them means

Back up `Pepper`, `SealSalt`, `EpochKek`, `VapidPrivateKey` offline and encrypted (for example an
`age`-encrypted file in two places, or a password manager). They are not stored anywhere else, and a database
backup is useless without them (by design).

| Key | If it's lost or changed | If it leaks |
|---|---|---|
| `Pepper` | **Every mailbox is orphaned.** Ids no longer match, so sends return 404 and owners can't manage mailboxes. Every user has to re-pair with every contact. | Together with a DB dump, someone who also holds a `sendSecret` can find its row. On its own it reveals nothing. |
| `SealSalt` | **Every mailbox is orphaned.** Endpoints can't be unsealed, so nothing can be delivered. Every user has to re-pair. | Endpoints still need each mailbox's `sendSecret` to unseal. |
| `EpochKek` | **All queued and held messages are lost.** The stored epoch keys can't be unwrapped. The current code also fails at startup when the `epoch_keys` rows don't match the KEK. To recover, run `DELETE FROM epoch_keys; DELETE FROM pending_messages;` and restart. Mailboxes are unaffected. | Together with a DB dump that still holds the epoch keys, held messages can be unwrapped to their E2E ciphertext (still end-to-end encrypted). |
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
  Framework request logging (`Microsoft.AspNetCore`, `System.Net.Http`) is pinned to Warning in compose. The push
  client bypasses `IHttpClientFactory`, so its URL logging is never in the pipeline.
- **MySQL**: general log, slow log and binlog are off, the error log is at verbosity 2, and performance_schema
  (which keeps statement texts in memory) is off.
- **Redis**: slowlog is disabled, `MONITOR` is removed and the ACL log is small.
- **Container logs** use the json-file driver, rotated at 3 × 10 MB per container.

Outside this stack, check the host: firewall or conntrack logging, journald forwarding, and your provider's
flow logs. Don't put a CDN or WAF in front of the server. It would see every client IP and the traffic timing.

### Data on disk

- **MySQL** deletes rows on delivery and expiry, but InnoDB pages, redo and undo logs and free blocks can keep
  old bytes for a while. Crypto-shredding covers this: held messages are encrypted under daily keys that
  are deleted `ceil(MaxTtl / 1 day) + 1` days later.
  **Limitation:** epoch keys are wrapped by the static `EpochKek` and stored in the same MySQL. Someone who has both
  an old disk image or backup *and* the KEK can still recover shredded epochs. Shredding protects against later
  compromise of storage alone. So keep the KEK out of backups, and keep database backups no longer than `MaxTtl`.
- **Ephemeral Redis** (rate limits, PoW, breakers) has no persistence at all, so it leaves nothing on disk.
- **Redis AOF** (main instance) is an append-only log. Deleted queue entries (opaque mailbox ids, ciphertext and
  timestamps) and invite blobs stay in the AOF until the next rewrite. Rewrites happen automatically as the file grows, but on a quiet server that can
  take days, so compact it hourly from the host's crontab:
  ```cron
  0 * * * * cd /path/to/deploy && docker compose exec -T redis sh -c 'REDISCLI_AUTH="$REDIS_PASSWORD" redis-cli --no-auth-warning --user goldfish BGREWRITEAOF' >/dev/null
  ```
- Deleted files aren't wiped from the underlying disk. Use **full-disk encryption** (LUKS) on the host, plus
  encrypted swap or no swap, since keys live in process memory. Core dumps are disabled in the containers.

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
Secrets are only ever sent in bodies or headers, never in URLs. The one exception is the one-time invite id.

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
| POST | `/v1/invites` | none | Upload a one-time invite blob |
| GET | `/v1/invites/{id}` | none | Fetch and delete an invite blob |
| GET | `/healthz`, `/readyz` | internal only | Liveness and readiness |
