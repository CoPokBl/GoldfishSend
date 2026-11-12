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
    public Dictionary<string, RatePolicy> RateLimits { get; set; } = new();

    public bool HasRole(string role) {
        return Roles.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Contains(role, StringComparer.OrdinalIgnoreCase);
    }
}

/// <summary>All values are base64url, 32 bytes. Generate them with <c>GoldfishSend.Api keygen</c>.</summary>
public sealed class KeyOptions {
    /// <summary>The HMAC key for mailbox ids. Changing it orphans every mailbox.</summary>
    public string Pepper { get; set; } = "";
    /// <summary>The HKDF salt for endpoint sealing keys. Changing it orphans every mailbox.</summary>
    public string SealSalt { get; set; } = "";
    /// <summary>The key-encryption key for the daily epoch keys that protect queued and held messages.</summary>
    public string EpochKek { get; set; } = "";
    /// <summary>The P-256 private scalar for VAPID. Changing it breaks distributors that pinned the old key.</summary>
    public string VapidPrivateKey { get; set; } = "";
    public string VapidSubject { get; set; } = "mailto:admin@example.invalid";
}

public sealed class MessageOptions {
    public int DefaultTtlSeconds { get; set; } = 72 * 3600;
    public int MaxTtlSeconds { get; set; } = 14 * 24 * 3600;
    public int MinTtlSeconds { get; set; } = 60;
    public int DeliveryParallelism { get; set; } = 32;
    public int IdempotencyWindowSeconds { get; set; } = 24 * 3600;
    /// <summary>
    /// The most undelivered messages held for one mailbox. Further sends get <c>507 mailbox_full</c> until the
    /// recipient's device comes back. This bounds the storage a hostile contact or a dead endpoint can consume.
    /// </summary>
    public int MaxHeldPerMailbox { get; set; } = 500;
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
    public int RequestTimeoutSeconds { get; set; } = 10;
    public int MaxConnectionsPerHost { get; set; } = 16;
    public int CircuitBreakerFailures { get; set; } = 5;
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
}

public sealed class NetworkOptions {
    /// <summary>Reverse proxies whose X-Forwarded-For header is trusted (IPs or CIDRs).</summary>
    public string[] TrustedProxies { get; set; } = [];
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
