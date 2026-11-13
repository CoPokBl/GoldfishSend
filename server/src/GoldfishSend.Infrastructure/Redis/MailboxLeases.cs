using System.Collections.Concurrent;
using StackExchange.Redis;

namespace GoldfishSend.Infrastructure.Redis;

/// <summary>
/// Caps in-flight deliveries per mailbox, cluster-wide (default 4). One mailbox (for example one pointing at a tarpit)
/// can't occupy more than a few delivery slots, while a normal burst of messages to one contact still goes out in
/// parallel. Counters live in the ephemeral Redis under an HMACed key, and expire on their own if a node dies mid-push.
/// A process-local counter covers Redis outages.
/// </summary>
public sealed class MailboxLeases {
    // KEYS[1] = counter. ARGV = max, ttl ms.
    private const string AcquireScript = """
        local n = redis.call('INCR', KEYS[1])
        redis.call('PEXPIRE', KEYS[1], ARGV[2])
        if n > tonumber(ARGV[1]) then
            redis.call('DECR', KEYS[1])
            return 0
        end
        return 1
        """;

    private const string ReleaseScript = """
        local n = redis.call('DECR', KEYS[1])
        if n <= 0 then redis.call('DEL', KEYS[1]) end
        return n
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

    public sealed class Lease(MailboxLeases owner, string key, bool remote) {
        public Task ReleaseAsync() => owner.ReleaseAsync(key, remote);
    }

    /// <returns>The lease, or null if this mailbox already has the maximum number of deliveries in flight.</returns>
    public async Task<Lease?> TryAcquireAsync(byte[] mailboxId, TimeSpan ttl) {
        var key = RedisKeys.MailboxInFlight(await _secret.HmacHexAsync("mbx-lease", mailboxId));
        if (_local.AddOrUpdate(key, 1, (_, n) => n + 1) > _max) {
            Decrement(key);
            return null;
        }
        try {
            var ok = (long)await _redis.Db.ScriptEvaluateAsync(AcquireScript, [key], [_max, (long)ttl.TotalMilliseconds]);
            if (ok != 1) {
                Decrement(key);
                return null;
            }
            return new Lease(this, key, remote: true);
        } catch (Exception ex) when (ex is RedisException or TimeoutException) {
            // The local count still caps this process.
            return new Lease(this, key, remote: false);
        }
    }

    private async Task ReleaseAsync(string key, bool remote) {
        Decrement(key);
        if (!remote) {
            return;
        }
        try {
            await _redis.Db.ScriptEvaluateAsync(ReleaseScript, [key]);
        } catch (Exception ex) when (ex is RedisException or TimeoutException) {
            // It expires by itself.
        }
    }

    private void Decrement(string key) {
        if (_local.AddOrUpdate(key, 0, (_, n) => n - 1) <= 0) {
            _local.TryRemove(new KeyValuePair<string, int>(key, 0));
        }
    }
}
