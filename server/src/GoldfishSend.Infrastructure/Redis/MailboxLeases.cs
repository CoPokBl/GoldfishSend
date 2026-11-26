using System.Collections.Concurrent;
using System.Security.Cryptography;
using StackExchange.Redis;

namespace GoldfishSend.Infrastructure.Redis;

/// <summary>
/// Caps in-flight deliveries per mailbox, cluster-wide (default 4). One mailbox (for example one pointing at a tarpit)
/// can't occupy more than a few delivery slots, while a normal burst of messages to one contact still goes out in
/// parallel. Each lease is a random token in a sorted set in the ephemeral Redis, under an HMACed key, scored by when it
/// lapses. Lapsed tokens are dropped before counting, so a lease leaked by a node that died mid-push frees its slot on
/// its own schedule, however often other deliveries try the mailbox meanwhile. A process-local counter covers Redis
/// outages.
/// </summary>
public sealed class MailboxLeases {
    // KEYS[1] = lease set. ARGV = max, ttl ms, token. Redis's own clock scores every token, so nodes' clocks don't matter.
    // A refused acquire changes nothing but the lapsed tokens it clears: it mustn't keep the set alive.
    private const string AcquireScript = """
        local t = redis.call('TIME')
        local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
        redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now)
        if redis.call('ZCARD', KEYS[1]) >= tonumber(ARGV[1]) then
            return 0
        end
        redis.call('ZADD', KEYS[1], now + tonumber(ARGV[2]), ARGV[3])
        local last = redis.call('ZRANGE', KEYS[1], -1, -1, 'WITHSCORES')
        redis.call('PEXPIREAT', KEYS[1], last[2])
        return 1
        """;

    private readonly EphemeralRedis _redis;
    private readonly ClusterSecret _secret;
    private readonly int _max;
    private readonly ConcurrentDictionary<string, int> _local = new(StringComparer.Ordinal);

    public MailboxLeases(EphemeralRedis redis, ClusterSecret secret, Core.Options.GoldfishOptions options) {
        _redis = redis;
        _secret = secret;
        _max = Math.Max(1, options.Push.MaxInFlightPerMailbox);
    }

    public sealed class Lease(MailboxLeases owner, string key, string token) {
        public Task ReleaseAsync() => owner.ReleaseAsync(key, token);
    }

    /// <returns>The lease, or null if this mailbox already has the maximum number of deliveries in flight.</returns>
    public async Task<Lease?> TryAcquireAsync(byte[] mailboxId, TimeSpan ttl) {
        var key = RedisKeys.MailboxInFlight(await _secret.HmacHexAsync("mbx-lease", mailboxId));
        if (_local.AddOrUpdate(key, 1, (_, n) => n + 1) > _max) {
            Decrement(key);
            return null;
        }
        var token = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
        try {
            var ok = (long)await _redis.Db.ScriptEvaluateAsync(AcquireScript, [key], [_max, (long)ttl.TotalMilliseconds, token]);
            if (ok != 1) {
                Decrement(key);
                return null;
            }
        } catch (Exception ex) when (ex is RedisException or TimeoutException) {
            // The local count still caps this process. The script may have run even though the reply was lost, so the
            // release still removes the token; if Redis is really down, the token lapses by itself.
        }
        return new Lease(this, key, token);
    }

    private async Task ReleaseAsync(string key, string token) {
        Decrement(key);
        try {
            await _redis.Db.SortedSetRemoveAsync(key, token);
        } catch (Exception ex) when (ex is RedisException or TimeoutException) {
            // The token lapses by itself.
        }
    }

    private void Decrement(string key) {
        if (_local.AddOrUpdate(key, 0, (_, n) => n - 1) <= 0) {
            _local.TryRemove(new KeyValuePair<string, int>(key, 0));
        }
    }
}
