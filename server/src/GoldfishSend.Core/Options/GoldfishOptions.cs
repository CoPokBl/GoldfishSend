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
}

public sealed class MailboxOptions {
    public int LifetimeDays { get; set; } = 90;
    public int VerificationMinutes { get; set; } = 10;
    public int MaxVerifyAttempts { get; set; } = 5;
    public int MaxBatch { get; set; } = 100;
}

public sealed class PowOptions {
    public int BaseDifficulty { get; set; } = 20;
    public int MaxExtraDifficulty { get; set; } = 6;
    public int ChallengeTtlSeconds { get; set; } = 300;
    /// <summary>Mailbox creations per minute, server-wide, before difficulty starts rising.</summary>
    public int LoadThresholdPerMinute { get; set; } = 120;
}

public sealed class PushOptions {
    public int[] AllowedPorts { get; set; } = [443];
    public bool AllowIpLiterals { get; set; }
    /// <summary>Hostnames (and their subdomains) that may never be endpoints, for example this server's own names.</summary>
    public string[] BlockedHosts { get; set; } = [];
    /// <summary>Extra CIDRs to refuse, for example this server's own public addresses.</summary>
    public string[] ExtraBlockedRanges { get; set; } = [];
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
    /// it off. Onion clients all share the Tor container's address, so raise it if a large onion user base hits it.
    /// </summary>
    public double GatewayRequestsPerSecond { get; set; } = 50;
    public int GatewayBurst { get; set; } = 200;
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
