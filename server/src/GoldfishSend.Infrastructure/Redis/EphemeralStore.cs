using StackExchange.Redis;

namespace GoldfishSend.Infrastructure.Redis;

/// <summary>One-time invite blobs, stored in the main Redis.</summary>
public sealed class EphemeralStore {
    private readonly IConnectionMultiplexer _redis;

    public EphemeralStore(IConnectionMultiplexer redis) {
        _redis = redis;
    }

    public async Task PutInviteAsync(byte[] id, byte[] blob, TimeSpan ttl) {
        await _redis.GetDatabase().StringSetAsync(RedisKeys.Invite(Convert.ToHexString(id)), blob, ttl, When.NotExists);
    }

    /// <summary>Fetch-and-delete, done atomically: an invite can be claimed by exactly one device.</summary>
    public async Task<byte[]?> TakeInviteAsync(byte[] id) {
        var value = await _redis.GetDatabase().StringGetDeleteAsync(RedisKeys.Invite(Convert.ToHexString(id)));
        return value.IsNull ? null : (byte[]?)value;
    }
}
