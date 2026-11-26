namespace GoldfishSend.Core.Options;

public sealed class GoldfishOptions {
    public const string Section = "Goldfish";

    /// <summary>A comma-separated list of the roles this process runs: <c>api</c>, <c>worker</c>.</summary>
    public string Roles { get; set; } = "api,worker";

    public KeyOptions Keys { get; set; } = new();
    public MessageOptions Messages { get; set; } = new();
    public MailboxOptions Mailboxes { get; set; } = new();
    public PowOptions Pow { get; set; } = new();
    public PushOptions Push { get; set; } = new();
    public InviteOptions Invites { get; set; } = new();
    public NetworkOptions Network { get; set; } = new();
    public EpochKeyStore EpochKeyStore { get; set; } = EpochKeyStore.MySql;
    public Dictionary<string, RatePolicy> RateLimits { get; set; } = new();

    public bool HasRole(string role) {
        return Roles.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Contains(role, StringComparer.OrdinalIgnoreCase);
    }
}

/// <summary>All values are base64url, 32 bytes (<c>ServerKey</c>: 96). Generate them with <c>GoldfishSend.Api keygen</c>.</summary>
public sealed class KeyOptions {
    /// <summary>The HMAC key for mailbox ids. Changing it orphans every mailbox.</summary>
    public string Pepper { get; set; } = "";
    /// <summary>The HKDF salt for endpoint sealing keys. Changing it orphans every mailbox.</summary>
    public string SealSalt { get; set; } = "";
    /// <summary>The key-encryption key for the daily epoch keys that protect queued and held messages.</summary>
    public string EpochKek { get; set; } = "";
    /// <summary>The P-256 private scalar for VAPID. Changing it breaks distributors that pinned the old key.</summary>
    public string VapidPrivateKey { get; set; } = "";
    /// <summary>
    /// The server's identity and gateway key: 96 bytes, an ML-KEM-768 seed then a P-256 scalar. It never expires. Changing
    /// it makes every client report "server identity changed".
    /// </summary>
    public string ServerKey { get; set; } = "";
    public string VapidSubject { get; set; } = "mailto:admin@example.invalid";
}

public sealed class MessageOptions {
    public int DefaultTtlSeconds { get; set; } = 72 * 3600;
    public int MaxTtlSeconds { get; set; } = 14 * 24 * 3600;
    public int MinTtlSeconds { get; set; } = 60;
    public int DeliveryParallelism { get; set; } = 32;
    /// <summary>
    /// How long a <c>GF-Idempotency-Key</c> is remembered, in the ephemeral Redis (±10% jitter). Short on purpose: retries
    /// happen within minutes, and a long window would mean a long-lived per-mailbox activity record.
    /// </summary>
    public int IdempotencyWindowSeconds { get; set; } = 3600;
    /// <summary>
    /// The most undelivered messages held for one mailbox. Further sends get <c>507 mailbox_full</c> (scope
    /// <c>mailbox</c>) until the recipient's device comes back. This bounds what a hostile contact or a dead endpoint can use.
    /// </summary>
    public int MaxHeldPerMailbox { get; set; } = 500;
    /// <summary>
    /// The most undelivered messages held in total. Once reached, new messages for mailboxes that are already holding
    /// (or whose endpoint is gone) get <c>507 mailbox_full</c> (scope <c>global</c>). Healthy mailboxes keep working, and
    /// messages that fail after being accepted are still held (a small overshoot), so nothing accepted is ever dropped.
    /// 0 means no limit.
    /// </summary>
    public int MaxHeldTotal { get; set; } = 500_000;
    /// <summary>The TTL ceiling for messages sent to a mailbox whose push endpoint is gone.</summary>
    public int GoneMaxTtlSeconds { get; set; } = 3 * 24 * 3600;
    /// <summary>
    /// The hot-queue (Redis stream) length above which new messages go straight to the MySQL held-message table
    /// (due immediately). They also go there if Redis refuses the write (out of memory). Messages are delivered either way.
    /// </summary>
    public int MaxStreamLength { get; set; } = 50_000;
    /// <summary>
    /// How often, in minutes, a worker has the main Redis rewrite its append-only file. The AOF is a log: a queue entry
    /// (mailbox id, arrival time to the millisecond, and the blob holding the message's endpoint seal key) stays on disk
    /// after delivery until the next rewrite, and Redis alone only rewrites once the file has doubled, which on a quiet
    /// server takes days. Skipped if that Redis has no AOF. 0 leaves rewrites to Redis.
    /// </summary>
    public int AofRewriteMinutes { get; set; } = 5;
}

public sealed class MailboxOptions {
    public int LifetimeDays { get; set; } = 90;
    public int VerificationMinutes { get; set; } = 10;
    public int MaxVerifyAttempts { get; set; } = 5;
    public int MaxBatch { get; set; } = 100;
}

/// <summary>
/// The Argon2id proof of work (docs/protocol.md). One challenge costs about <c>2^difficulty</c> Argon2 calls of
/// <see cref="MemoryKiB"/> each to solve, and one to verify.
/// </summary>
public sealed class PowOptions {
    /// <summary>
    /// Leading zero bits for mailbox creation at no load: 2^8 = 256 Argon2 calls, roughly 5-15 s on a mid-range phone at
    /// 16 MiB, and about 3 core-seconds for an attacker with native Argon2. The app's mailbox pool hides it most of the time.
    /// </summary>
    public int BaseDifficulty { get; set; } = 8;
    /// <summary>
    /// Fixed difficulty for send-limit challenges (<c>?purpose=send</c>): 64 calls. They only pay past the per-IP and
    /// per-network send limits, and the app caps what it will solve for another server tightly.
    /// </summary>
    public int SendDifficulty { get; set; } = 6;
    /// <summary>Argon2 memory per call. The app solves on up to 4 threads, so it holds up to 4x this.</summary>
    public int MemoryKiB { get; set; } = 16 * 1024;
    public int Iterations { get; set; } = 1;
    public int ChallengeTtlSeconds { get; set; } = 300;
    /// <summary>How far back creations count toward load. Counters live in the ephemeral Redis for this long plus a minute.</summary>
    public int LoadWindowMinutes { get; set; } = 5;
    /// <summary>
    /// Creations from one network (IPv4 /24, IPv6 /48) in the load window before that network's difficulty rises. It
    /// gains a bit each time this doubles, up to <see cref="MaxNetworkExtraDifficulty"/>.
    /// </summary>
    public int NetworkLoadThreshold { get; set; } = 5;
    /// <summary>
    /// The same for a whole IPv6 /32, which can hold an ISP's customers: 10x looser. It catches one actor spreading over
    /// many /48s. A network gets the larger of its own and its /32's extra bits.
    /// </summary>
    public int AllocationLoadThreshold { get; set; } = 50;
    public int MaxNetworkExtraDifficulty { get; set; } = 6;
    /// <summary>Verified creations per minute, server-wide, before everyone's difficulty rises (by up to <see cref="MaxGlobalExtraDifficulty"/>).</summary>
    public int GlobalLoadThresholdPerMinute { get; set; } = 120;
    public int MaxGlobalExtraDifficulty { get; set; } = 2;
    /// <summary>
    /// Argon2 verifications running at once per process. 0 means one per two CPUs (at least one), which leaves the rest for
    /// the gateway and the API even when junk keeps every slot busy. One network (/24 or /48) may hold at most a quarter of
    /// them and one IPv6 /32 at most half (at least one each), so junk from one place can't take them all.
    /// </summary>
    public int MaxConcurrentVerifications { get; set; }
    /// <summary>
    /// Extra <c>pow-net</c> and <c>pow-alloc</c> tokens charged to the network that was issued a challenge when a wrong
    /// solution to it costs a verification. Junk solutions then soon stop the network that asked for them getting more
    /// challenges, while an honest client (which never sends one) pays nothing. 0 turns it off.
    /// </summary>
    public int InvalidSolutionPenalty { get; set; } = 10;
}

public sealed class PushOptions {
    public int[] AllowedPorts { get; set; } = [443];
    public bool AllowIpLiterals { get; set; }
    /// <summary>Hostnames (and their subdomains) that may never be endpoints, for example this server's own names.</summary>
    public string[] BlockedHosts { get; set; } = [];
    /// <summary>Extra CIDRs to refuse, for example this server's own public addresses.</summary>
    public string[] ExtraBlockedRanges { get; set; } = [];
    /// <summary>
    /// Well-known push services (and their subdomains) that never count against the new-push-host budgets
    /// (<c>newhost-*</c>). Those budgets remember the hosts they've seen only in the ephemeral Redis, so without this
    /// list a restart of it would put every user behind the small server-wide budget. Setting it replaces the defaults.
    /// </summary>
    public string[] KnownHosts { get; set; } = [
        "ntfy.sh", "fcm.googleapis.com", "updates.push.services.mozilla.com", "web.push.apple.com",
    ];
    public int ConnectTimeoutSeconds { get; set; } = 5;
    /// <summary>
    /// How long a push server may take to answer once connected. The push deadline is
    /// <c>min(RequestTimeoutSeconds, ConnectTimeoutSeconds + ResponseHeadersTimeoutSeconds)</c>. Real push services answer
    /// in well under a second, so a short value stops tarpits from holding delivery slots.
    /// </summary>
    public int ResponseHeadersTimeoutSeconds { get; set; } = 3;
    public int RequestTimeoutSeconds { get; set; } = 10;
    public int MaxConnectionsPerHost { get; set; } = 16;
    /// <summary>Concurrent pushes to one mailbox, cluster-wide. One mailbox (say, one pointing at a tarpit) can't hold more slots than this.</summary>
    public int MaxInFlightPerMailbox { get; set; } = 4;
    /// <summary>Concurrent pushes to one host per process. Kept well below DeliveryParallelism, so one slow host can't take every slot.</summary>
    public int MaxInFlightPerHost { get; set; } = 4;
    /// <summary>
    /// Concurrent pushes per process to hosts (grouped by base domain) that recently timed out. This "slow lane" keeps
    /// tarpits, including ones spread across wildcard subdomains, from taking every slot.
    /// </summary>
    public int SlowLaneSlots { get; set; } = 4;
    /// <summary>
    /// Circuit breaker: once a host has had at least <see cref="CircuitBreakerMinVolume"/> pushes in a minute, at least
    /// <see cref="CircuitBreakerFailureRatio"/> of them failed at the transport level or with 5xx, and the failures
    /// came from at least <see cref="CircuitBreakerMinEndpoints"/> distinct endpoints, every node pauses that host for
    /// <see cref="CircuitBreakerOpenSeconds"/>. Rejections of one subscription (4xx, 429) never count, so one subscriber
    /// can't pause a shared push service for everyone.
    /// </summary>
    public int CircuitBreakerMinVolume { get; set; } = 20;
    public double CircuitBreakerFailureRatio { get; set; } = 0.5;
    public int CircuitBreakerMinEndpoints { get; set; } = 3;
    public int CircuitBreakerOpenSeconds { get; set; } = 30;
    /// <summary>
    /// TESTING ONLY. It allows http:// and loopback endpoints and turns off parts of the SSRF protection.
    /// It's refused at startup in the Production environment.
    /// </summary>
    public bool DangerouslyAllowInsecureLoopback { get; set; }
}

public sealed class InviteOptions {
    public int DefaultTtlSeconds { get; set; } = 900;
    public int MinTtlSeconds { get; set; } = 60;
    public int MaxTtlSeconds { get; set; } = 86400;
    /// <summary>
    /// The most invites stored at once. Each is at most 4 KiB, so this bounds invite memory (default ≈ 80 MiB).
    /// Uploads beyond it get <c>429</c> (scope <c>global</c>) until older invites are fetched or expire.
    /// </summary>
    public int MaxLiveInvites { get; set; } = 20_000;
    /// <summary>
    /// The most live invites one network (IPv4 /24, IPv6 /48) may hold, so a few networks can't fill
    /// <see cref="MaxLiveInvites"/> for everyone. Counted until each invite would expire, even once fetched. Uploads beyond
    /// it get <c>429</c> (scope <c>network</c>). 0 turns it off.
    /// </summary>
    public int MaxLivePerNetwork { get; set; } = 400;
    /// <summary>The same for an IPv6 /32, which can hold a whole ISP's customers. 0 turns it off.</summary>
    public int MaxLivePerAllocation { get; set; } = 2_000;
}

public enum EpochKeyStore {
    /// <summary>Wrapped epoch keys live in MySQL. Held messages survive any restart. Deleted keys may linger in InnoDB files.</summary>
    MySql,
    /// <summary>
    /// Wrapped epoch keys live only in the non-persistent ephemeral Redis. Shredding is real (nothing on disk), but
    /// restarting that Redis loses every queued and held message.
    /// </summary>
    Ephemeral,
}

public sealed class NetworkOptions {
    /// <summary>Reverse proxies whose X-Forwarded-For header is trusted (IPs or CIDRs).</summary>
    public string[] TrustedProxies { get; set; } = [];

    /**
     * How many proxy hops to unwrap from X-Forwarded-For. 1 for a single reverse proxy (Caddy, Traefik). Use 2 when
     * Traefik itself sits behind a load balancer, and add that load balancer's addresses to <see cref="TrustedProxies"/> too:
     * each hop is only believed if the hop in front of it is trusted.
     */
    public int ForwardLimit { get; set; } = 1;

    /// <summary>
    /// Gateway requests per second per client (IPv4 address or IPv6 /64) on each API node, before any decryption. 0 turns
    /// it off. Onion clients all share the Tor container's address unless <see cref="OnionCircuitEndpoint"/> is set, so
    /// without it raise this if a large onion user base hits it.
    /// </summary>
    public double GatewayRequestsPerSecond { get; set; } = 50;
    public int GatewayBurst { get; set; } = 200;

    /// <summary>
    /// The gateway bucket of a whole network (IPv4 /24, IPv6 /48), and of an IPv6 /32, as multiples of a client's. Every
    /// request is charged at all three, so one allocation can't multiply its decryption budget by rotating addresses.
    /// </summary>
    public int GatewayNetworkFactor { get; set; } = 4;
    public int GatewayAllocationFactor { get; set; } = 20;

    /// <summary>
    /// How many clients, networks and /32s the gateway flood guard tracks on each API node (each table, about 200 bytes
    /// an entry). A client that finds no room is charged only at its network and /32 (one network may hold at most 256
    /// clients, one /32 at most 64 networks). Only an IPv4 network that finds the network table full shares one overflow
    /// bucket, <see cref="GatewayOverflowFactor"/> times the size of a client's, until idle entries expire.
    /// </summary>
    public int GatewayMaxClients { get; set; } = 100_000;
    public int GatewayOverflowFactor { get; set; } = 20;

    /// <summary>
    /// Optional, off by default: an <c>ip:port</c> for a second listener that only Tor connects to, with
    /// <c>HiddenServiceExportCircuitID haproxy</c> on, so each connection starts with a PROXY protocol line naming its Tor
    /// circuit. The gateway flood guard then gives every circuit its own bucket inside one onion-wide bucket
    /// (<see cref="GatewayOnionFactor"/>), so one onion client can't use up the bucket all of them would otherwise share.
    /// Bind it to an address only the Tor container can reach: whoever connects can name any circuit. Connections without
    /// a valid header are dropped, and only <c>/v1/gw</c> and <c>/v1/key</c> are served on it.
    /// </summary>
    public string OnionCircuitEndpoint { get; set; } = "";
    public int GatewayOnionFactor { get; set; } = 20;
}

/// <summary>GCRA policy: <see cref="Limit"/> events per <see cref="PeriodSeconds"/>, with up to <see cref="Burst"/> at once.</summary>
public sealed class RatePolicy {
    public int Limit { get; set; }
    public int PeriodSeconds { get; set; }
    public int Burst { get; set; }

    public RatePolicy() { }

    public RatePolicy(int limit, int periodSeconds, int burst) {
        Limit = limit;
        PeriodSeconds = periodSeconds;
        Burst = burst;
    }

    public double EmissionIntervalMs => PeriodSeconds * 1000.0 / Math.Max(1, Limit);
}
