using System.Collections.Concurrent;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using GoldfishSend.Core.Options;
using Microsoft.Extensions.Logging;
using StackExchange.Redis;

namespace GoldfishSend.Infrastructure.Redis;

public readonly record struct RateLimitDecision(bool Allowed, TimeSpan RetryAfter, string Policy = "") {
    public static readonly RateLimitDecision Allow = new(true, TimeSpan.Zero);

    /// <summary>The kind of subject that was limited: <c>ip</c>, <c>network</c>, <c>mailbox</c> or <c>global</c>.</summary>
    public string Scope => RatePolicies.ScopeOf(Policy);
}

/// <summary>
/// One bucket of an all-or-nothing check (<see cref="RateLimiter.CheckAllAsync"/>). A null <paramref name="Subject"/>
/// skips the scope (IPv4 clients have no IPv6 /32 tier). <paramref name="Cost"/> 0 is a peek: the bucket must have room
/// for one more event, but isn't charged.
/// </summary>
public readonly record struct RateScope(string Policy, byte[]? Subject, int Cost = 1);

/// <summary>
/// A distributed GCRA (generic cell rate algorithm) limiter in the ephemeral Redis. Every subject (IP prefix,
/// mailbox id) is HMACed before it reaches Redis:
/// <list type="bullet">
/// <item>Short-period buckets use a random key that rotates daily, so yesterday's buckets can't be linked to addresses.</item>
/// <item>Long-period buckets (an hour or more) use the stable <see cref="ClusterSecret"/>, so the midnight key rotation
/// can't reset them and double the budget.</item>
/// </list>
/// Stored theoretical-arrival times are stochastically rounded to whole seconds (unbiased, so budgets don't shrink), so buckets
/// written by the same request can't be matched by their exact millisecond timestamps.
/// </summary>
public sealed class RateLimiter {
    // KEYS = one bucket per scope. ARGV = per scope: emission interval (ms), burst, cost, jitter (ms).
    // All or nothing: every bucket is checked before any is charged, so a request one scope refuses (a narrow per-IP
    // limit, say) never uses up another (a network's or the server's budget). A refusal reports the scope with the
    // longest wait, so a client that waits that long isn't refused straight away by another one.
    // Uses the Redis server clock so nodes with clock skew agree.
    private const string GcraScript = """
        local t = redis.call('TIME')
        local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
        local tats = {}
        local worst, worst_i = 0, 0
        for i = 1, #KEYS do
            local ei = tonumber(ARGV[4 * i - 3])
            local burst = tonumber(ARGV[4 * i - 2])
            local cost = tonumber(ARGV[4 * i - 1])
            local tat = tonumber(redis.call('GET', KEYS[i]) or now)
            if tat < now then tat = now end
            tats[i] = tat
            local c = cost
            if c < 1 then c = 1 end
            local wait = tat + ei * c - ei * burst - now
            if wait > worst then
                worst, worst_i = wait, i
            end
        end
        if worst_i > 0 then
            return {0, math.ceil(worst), worst_i}
        end
        for i = 1, #KEYS do
            local ei = tonumber(ARGV[4 * i - 3])
            local cost = tonumber(ARGV[4 * i - 1])
            if cost > 0 then
                local new_tat = tats[i] + ei * cost
                if ei >= 1000 then
                    new_tat = math.floor((new_tat + tonumber(ARGV[4 * i])) / 1000) * 1000
                end
                redis.call('SET', KEYS[i], tostring(new_tat), 'PX', math.max(1, math.ceil(new_tat - now)))
            end
        end
        return {1, 0, 0}
        """;

    private readonly EphemeralRedis _redis;
    private readonly GoldfishOptions _options;
    private readonly ILogger<RateLimiter> _logger;
    private readonly InMemoryGcra _fallback = new();
    private readonly ConcurrentDictionary<string, byte[]> _dailyKeys = new();

    private readonly ClusterSecret _secret;

    public RateLimiter(EphemeralRedis redis, ClusterSecret secret, GoldfishOptions options, ILogger<RateLimiter> logger) {
        _redis = redis;
        _secret = secret;
        _options = options;
        _logger = logger;
    }

    /// <param name="failOpen">
    /// If Redis is unavailable: <c>true</c> falls back to a per-process limiter, and <c>false</c> denies.
    /// </param>
    public Task<RateLimitDecision> CheckAsync(string policyName, ReadOnlyMemory<byte> subject, bool failOpen = true, int cost = 1) {
        return CheckAllAsync([new RateScope(policyName, subject.ToArray(), cost)], failOpen);
    }

    /// <summary>
    /// Charges every scope only if every one of them has room, in one atomic step (see <see cref="GcraScript"/>).
    /// Scopes without a subject and switched-off policies are skipped.
    /// </summary>
    /// <param name="failOpen">
    /// If Redis is unavailable: <c>true</c> falls back to a per-process limiter, and <c>false</c> denies.
    /// </param>
    public async Task<RateLimitDecision> CheckAllAsync(IReadOnlyList<RateScope> scopes, bool failOpen = true) {
        var active = new List<(RateScope Scope, RatePolicy Policy)>(scopes.Count);
        foreach (var scope in scopes) {
            var policy = RatePolicies.Resolve(_options, scope.Policy);
            if (scope.Subject is not null && policy.Limit > 0) {
                active.Add((scope, policy));
            }
        }
        if (active.Count == 0) {
            return RateLimitDecision.Allow;
        }

        try {
            var keys = new RedisKey[active.Count];
            var args = new RedisValue[4 * active.Count];
            for (var i = 0; i < active.Count; i++) {
                var (scope, policy) = active[i];
                var hashed = RatePolicies.UsesStableKey(policy)
                    ? await _secret.HmacHexAsync("rl/" + scope.Policy, scope.Subject)
                    : await HashSubjectAsync(scope.Policy, scope.Subject);
                keys[i] = RedisKeys.RateLimit(scope.Policy, hashed);
                args[4 * i] = policy.EmissionIntervalMs;
                args[4 * i + 1] = Math.Max(1, policy.Burst);
                args[4 * i + 2] = Math.Max(0, scope.Cost);
                args[4 * i + 3] = RandomNumberGenerator.GetInt32(0, 1000);
            }
            var result = (RedisResult[])(await _redis.Db.ScriptEvaluateAsync(GcraScript, keys, args))!;
            if ((long)result[0] == 1) {
                return RateLimitDecision.Allow;
            }
            var denied = active[(int)(long)result[2] - 1].Scope.Policy;
            return new RateLimitDecision(false, TimeSpan.FromMilliseconds((long)result[1]), denied);
        } catch (Exception ex) when (ex is RedisException or TimeoutException) {
            _logger.LogWarning("Rate limiter unavailable ({Type}); failOpen={FailOpen}", ex.GetType().Name, failOpen);
            if (!failOpen) {
                return new RateLimitDecision(false, TimeSpan.FromSeconds(30), active[0].Scope.Policy);
            }
            return _fallback.CheckAll(active.Select(a => new InMemoryGcra.Scope(
                Convert.ToHexString(SHA256.HashData(Concat(a.Scope.Policy, a.Scope.Subject))), a.Policy, a.Scope.Cost,
                a.Scope.Policy)).ToList());
        }
    }

    // KEYS[1] = bucket. ARGV = emission interval (ms), cost, period (ms). Charges whatever the bucket holds, up to one
    // period ahead, so a penalty can't lock a subject out for longer than that.
    private const string PenaltyScript = """
        local t = redis.call('TIME')
        local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
        local tat = tonumber(redis.call('GET', KEYS[1]) or now)
        if tat < now then tat = now end
        local new_tat = math.min(tat + tonumber(ARGV[1]) * tonumber(ARGV[2]), now + tonumber(ARGV[3]))
        if new_tat > tat then
            redis.call('SET', KEYS[1], tostring(math.floor(new_tat)), 'PX', math.max(1, math.ceil(new_tat - now)))
        end
        return 1
        """;

    /// <summary>
    /// The Redis key of a subject's bucket, so it can be charged later without keeping the subject itself
    /// (<see cref="PenalizeAsync"/>). Null if there's no subject or the policy is off.
    /// </summary>
    public async Task<string?> BucketKeyAsync(string policyName, byte[]? subject) {
        var policy = RatePolicies.Resolve(_options, policyName);
        if (subject is null || policy.Limit <= 0) {
            return null;
        }
        var hashed = RatePolicies.UsesStableKey(policy)
            ? await _secret.HmacHexAsync("rl/" + policyName, subject)
            : await HashSubjectAsync(policyName, subject);
        return RedisKeys.RateLimit(policyName, hashed);
    }

    /// <summary>Charges <paramref name="cost"/> events to a bucket from <see cref="BucketKeyAsync"/>, even past its limit.</summary>
    public async Task PenalizeAsync(string policyName, string bucketKey, int cost) {
        var policy = RatePolicies.Resolve(_options, policyName);
        if (cost <= 0 || policy.Limit <= 0 || !bucketKey.StartsWith(RedisKeys.RateLimit(policyName, ""), StringComparison.Ordinal)) {
            return;
        }
        try {
            await _redis.Db.ScriptEvaluateAsync(PenaltyScript, [bucketKey], [policy.EmissionIntervalMs, cost, policy.PeriodSeconds * 1000L]);
        } catch (Exception ex) when (ex is RedisException or TimeoutException) {
            _logger.LogWarning("Rate limiter unavailable ({Type}); penalty skipped", ex.GetType().Name);
        }
    }

    /// <summary>
    /// The daily-keyed HMAC of a subject, exactly as short-period buckets key it. For other short-lived per-subject state
    /// in the ephemeral Redis (adaptive PoW load), which then can't be linked to addresses after the day either.
    /// </summary>
    public Task<string> DailySubjectKeyAsync(string purpose, ReadOnlyMemory<byte> subject) => HashSubjectAsync(purpose, subject);

    private async Task<string> HashSubjectAsync(string policyName, ReadOnlyMemory<byte> subject) {
        var day = DateTime.UtcNow.ToString("yyyyMMdd", CultureInfo.InvariantCulture);
        if (!_dailyKeys.TryGetValue(day, out var key)) {
            var db = _redis.Db;
            var redisKey = RedisKeys.RateLimitKey(day);
            await db.StringSetAsync(redisKey, RandomNumberGenerator.GetBytes(32), TimeSpan.FromDays(2), When.NotExists);
            key = (byte[])(await db.StringGetAsync(redisKey))!;
            foreach (var old in _dailyKeys.Keys.Where(k => k != day)) {
                _dailyKeys.TryRemove(old, out _);
            }
            _dailyKeys[day] = key;
        }
        // The daily key lives only in the (non-persistent) ephemeral Redis and expires after two days, so
        // yesterday's buckets can't be linked back to addresses later.
        // Truncated to 128 bits: plenty for bucket separation, and it keeps keys short.
        return Convert.ToHexString(HMACSHA256.HashData(key, Concat(policyName, subject.Span)), 0, 16);
    }

    private static byte[] Concat(string policyName, ReadOnlySpan<byte> subject) {
        var name = Encoding.UTF8.GetBytes(policyName);
        var buffer = new byte[name.Length + 1 + subject.Length];
        name.CopyTo(buffer, 0);
        subject.CopyTo(buffer.AsSpan(name.Length + 1));
        return buffer;
    }
}

/// <summary>A process-local GCRA, used as the Redis fallback and for per-push-host pacing.</summary>
public sealed class InMemoryGcra {
    private const int MaxEntries = 100_000;
    private readonly ConcurrentDictionary<string, double> _tat = new();

    public readonly record struct Scope(string Key, RatePolicy Policy, int Cost, string Name = "");

    /// <summary>One bucket, atomically.</summary>
    public RateLimitDecision Check(string key, RatePolicy policy, int cost = 1) {
        var now = Environment.TickCount64;
        var ei = policy.EmissionIntervalMs;
        var tolerance = ei * Math.Max(1, policy.Burst);

        if (_tat.Count > MaxEntries) {
            Prune(now);
        }

        while (true) {
            var exists = _tat.TryGetValue(key, out var tat);
            var start = exists && tat > now ? tat : now;
            var newTat = start + ei * Math.Max(1, cost);
            var allowAt = newTat - tolerance;
            if (allowAt > now) {
                return new RateLimitDecision(false, TimeSpan.FromMilliseconds(Math.Ceiling(allowAt - now)));
            }
            if (cost <= 0) {
                return RateLimitDecision.Allow;
            }
            if (exists ? _tat.TryUpdate(key, newTat, tat) : _tat.TryAdd(key, newTat)) {
                return RateLimitDecision.Allow;
            }
        }
    }

    /// <summary>
    /// All or nothing, like the Redis script: every scope is checked before any is charged. Not atomic across scopes (a
    /// concurrent request can slip in between), which only lets a burst overshoot by a request or two.
    /// </summary>
    public RateLimitDecision CheckAll(IReadOnlyList<Scope> scopes) {
        if (scopes.Count == 1) {
            return Check(scopes[0].Key, scopes[0].Policy, scopes[0].Cost) with { Policy = scopes[0].Name };
        }
        var now = Environment.TickCount64;
        if (_tat.Count > MaxEntries) {
            Prune(now);
        }

        var worst = TimeSpan.Zero;
        var denied = "";
        foreach (var scope in scopes) {
            var wait = Wait(scope, now);
            if (wait > worst) {
                worst = wait;
                denied = scope.Name;
            }
        }
        if (worst > TimeSpan.Zero) {
            return new RateLimitDecision(false, worst, denied);
        }
        foreach (var scope in scopes) {
            if (scope.Cost > 0) {
                Charge(scope, now);
            }
        }
        return RateLimitDecision.Allow;
    }

    private TimeSpan Wait(Scope scope, long now) {
        var ei = scope.Policy.EmissionIntervalMs;
        var start = _tat.TryGetValue(scope.Key, out var tat) && tat > now ? tat : now;
        var allowAt = start + ei * Math.Max(1, scope.Cost) - ei * Math.Max(1, scope.Policy.Burst);
        return allowAt > now ? TimeSpan.FromMilliseconds(Math.Ceiling(allowAt - now)) : TimeSpan.Zero;
    }

    private void Charge(Scope scope, long now) {
        var ei = scope.Policy.EmissionIntervalMs;
        _tat.AddOrUpdate(scope.Key, _ => now + ei * scope.Cost, (_, tat) => Math.Max(tat, now) + ei * scope.Cost);
    }

    public void Prune(long? now = null) {
        var t = now ?? Environment.TickCount64;
        foreach (var (key, tat) in _tat) {
            if (tat < t) {
                _tat.TryRemove(key, out _);
            }
        }
    }
}
