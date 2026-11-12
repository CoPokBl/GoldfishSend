using System.Collections.Concurrent;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using GoldfishSend.Core.Options;
using Microsoft.Extensions.Logging;
using StackExchange.Redis;

namespace GoldfishSend.Infrastructure.Redis;

public readonly record struct RateLimitDecision(bool Allowed, TimeSpan RetryAfter) {
    public static readonly RateLimitDecision Allow = new(true, TimeSpan.Zero);
}

/// <summary>
/// A distributed GCRA (generic cell rate algorithm) limiter in Redis. Every subject (IP prefix, mailbox id)
/// is HMACed with a random key that rotates daily, so Redis never holds raw identifiers and yesterday's
/// keys can't be reversed later.
/// </summary>
public sealed class RateLimiter {
    // KEYS[1] = bucket. ARGV = emission interval (ms), burst, cost.
    // Uses the Redis server clock so nodes with clock skew agree.
    private const string GcraScript = """
        local t = redis.call('TIME')
        local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
        local ei = tonumber(ARGV[1])
        local burst = tonumber(ARGV[2])
        local cost = tonumber(ARGV[3])
        local tat = tonumber(redis.call('GET', KEYS[1]) or now)
        if tat < now then tat = now end
        local new_tat = tat + ei * cost
        local allow_at = new_tat - ei * burst
        if allow_at > now then
            return {0, math.ceil(allow_at - now)}
        end
        redis.call('SET', KEYS[1], tostring(new_tat), 'PX', math.max(1, math.ceil(new_tat - now)))
        return {1, 0}
        """;

    private readonly EphemeralRedis _redis;
    private readonly GoldfishOptions _options;
    private readonly ILogger<RateLimiter> _logger;
    private readonly InMemoryGcra _fallback = new();
    private readonly ConcurrentDictionary<string, byte[]> _dailyKeys = new();

    public RateLimiter(EphemeralRedis redis, GoldfishOptions options, ILogger<RateLimiter> logger) {
        _redis = redis;
        _options = options;
        _logger = logger;
    }

    /// <param name="failOpen">
    /// If Redis is unavailable: <c>true</c> falls back to a per-process limiter, and <c>false</c> denies.
    /// </param>
    public async Task<RateLimitDecision> CheckAsync(string policyName, ReadOnlyMemory<byte> subject, bool failOpen = true, int cost = 1) {
        var policy = RatePolicies.Resolve(_options, policyName);
        if (policy.Limit <= 0) {
            return RateLimitDecision.Allow;
        }

        try {
            var hashed = await HashSubjectAsync(policyName, subject);
            var result = (RedisResult[])(await _redis.Db.ScriptEvaluateAsync(
                GcraScript,
                [RedisKeys.RateLimit(policyName, hashed)],
                [policy.EmissionIntervalMs, Math.Max(1, policy.Burst), cost]))!;
            var allowed = (long)result[0] == 1;
            return new RateLimitDecision(allowed, TimeSpan.FromMilliseconds((long)result[1]));
        } catch (Exception ex) when (ex is RedisException or TimeoutException) {
            _logger.LogWarning("Rate limiter unavailable ({Type}); failOpen={FailOpen}", ex.GetType().Name, failOpen);
            if (!failOpen) {
                return new RateLimitDecision(false, TimeSpan.FromSeconds(30));
            }
            var local = Convert.ToHexString(SHA256.HashData(Concat(policyName, subject.Span)));
            return _fallback.Check(local, policy, cost);
        }
    }

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
            var newTat = start + ei * cost;
            var allowAt = newTat - tolerance;
            if (allowAt > now) {
                return new RateLimitDecision(false, TimeSpan.FromMilliseconds(Math.Ceiling(allowAt - now)));
            }
            if (exists ? _tat.TryUpdate(key, newTat, tat) : _tat.TryAdd(key, newTat)) {
                return RateLimitDecision.Allow;
            }
        }
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
