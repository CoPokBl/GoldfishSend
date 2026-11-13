using System.Security.Cryptography;
using System.Text;
using StackExchange.Redis;

namespace GoldfishSend.Infrastructure.Redis;

/// <summary>
/// A random secret shared by every node, kept only in the non-persistent ephemeral Redis (generated on first use).
/// It keys values that must agree across the cluster but must not be computable from public data: long-period
/// rate-limit buckets, idempotency markers, per-mailbox in-flight leases, and push-host hashes. Restarting the ephemeral
/// Redis produces a new secret, which just resets that state.
/// </summary>
public sealed class ClusterSecret {
    private const string Key = "gf:secret:cluster";
    private static readonly TimeSpan CacheFor = TimeSpan.FromMinutes(5);

    private readonly EphemeralRedis _redis;
    private readonly byte[] _localFallback = RandomNumberGenerator.GetBytes(32);
    private volatile Tuple<byte[], DateTime>? _cached;

    public ClusterSecret(EphemeralRedis redis) {
        _redis = redis;
    }

    public async Task<byte[]> GetAsync() {
        var cached = _cached;
        if (cached is not null && DateTime.UtcNow - cached.Item2 < CacheFor) {
            return cached.Item1;
        }
        try {
            var db = _redis.Db;
            await db.StringSetAsync(Key, RandomNumberGenerator.GetBytes(32), when: When.NotExists);
            var value = (byte[]?)await db.StringGetAsync(Key);
            if (value is { Length: 32 }) {
                _cached = Tuple.Create(value, DateTime.UtcNow);
                return value;
            }
        } catch (Exception ex) when (ex is RedisException or TimeoutException) {
            // Fall through. A process-local secret keeps this node working, just not in agreement with the others.
        }
        return cached?.Item1 ?? _localFallback;
    }

    /// <summary>A hex HMAC of <paramref name="label"/> ‖ <paramref name="data"/>, truncated to <paramref name="bytes"/>.</summary>
    public async Task<string> HmacHexAsync(string label, ReadOnlyMemory<byte> data, int bytes = 16) {
        var key = await GetAsync();
        return Hmac(key, label, data.Span, bytes);
    }

    internal static string Hmac(byte[] key, string label, ReadOnlySpan<byte> data, int bytes) {
        var l = Encoding.UTF8.GetBytes(label);
        var buffer = new byte[l.Length + 1 + data.Length];
        l.CopyTo(buffer, 0);
        data.CopyTo(buffer.AsSpan(l.Length + 1));
        return Convert.ToHexString(HMACSHA256.HashData(key, buffer), 0, bytes);
    }
}
