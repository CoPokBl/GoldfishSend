using StackExchange.Redis;

namespace GoldfishSend.Infrastructure.Redis;

/// <summary>
/// One-time invite blobs, stored in the main Redis. Live invites are capped by count (each is at most
/// <c>maxInviteBytes</c>), which bounds their memory to roughly <c>MaxLiveInvites × 4 KiB</c> whatever the address space
/// of whoever is uploading. An index sorted by expiry lets the cap ignore expired invites without a scan.
/// </summary>
public sealed class EphemeralStore {
    // KEYS[1] = invite key, KEYS[2] = index. ARGV = id, blob, ttl ms, max live.
    private const string PutScript = """
        local t = redis.call('TIME')
        local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
        redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now)
        if redis.call('ZCARD', KEYS[2]) >= tonumber(ARGV[4]) then
            return 0
        end
        local ttl = tonumber(ARGV[3])
        if not redis.call('SET', KEYS[1], ARGV[2], 'PX', ttl, 'NX') then
            return 0
        end
        redis.call('ZADD', KEYS[2], now + ttl, ARGV[1])
        return 1
        """;

    private readonly IConnectionMultiplexer _redis;

    public EphemeralStore(IConnectionMultiplexer redis) {
        _redis = redis;
    }

    /// <returns><c>false</c> if the live-invite cap is reached (or the id collided).</returns>
    public async Task<bool> PutInviteAsync(byte[] id, byte[] blob, TimeSpan ttl, int maxLive) {
        var hex = Convert.ToHexString(id);
        var ok = (long)await _redis.GetDatabase().ScriptEvaluateAsync(
            PutScript, [RedisKeys.Invite(hex), RedisKeys.InviteIndex], [hex, blob, (long)ttl.TotalMilliseconds, maxLive]);
        return ok == 1;
    }

    /// <summary>Fetch-and-delete, done atomically: an invite can be claimed by exactly one device.</summary>
    public async Task<byte[]?> TakeInviteAsync(byte[] id) {
        var hex = Convert.ToHexString(id);
        var db = _redis.GetDatabase();
        var value = await db.StringGetDeleteAsync(RedisKeys.Invite(hex));
        if (!value.IsNull) {
            await db.SortedSetRemoveAsync(RedisKeys.InviteIndex, hex, CommandFlags.FireAndForget);
        }
        return value.IsNull ? null : (byte[]?)value;
    }
}
