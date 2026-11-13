using System.Security.Cryptography;
using StackExchange.Redis;

namespace GoldfishSend.Infrastructure.Redis;

/// <summary>
/// Remembers each gateway request's KEM ciphertext for 20 minutes (twice the timestamp window), in the ephemeral Redis,
/// so a captured request can't be replayed. Only a truncated hash of the ciphertext is stored.
/// </summary>
public sealed class GatewayReplayGuard {
    public static readonly TimeSpan Window = TimeSpan.FromSeconds(1200);

    private readonly EphemeralRedis _redis;

    public GatewayReplayGuard(EphemeralRedis redis) {
        _redis = redis;
    }

    /// <summary>True the first time <paramref name="enc"/> is seen within the window.</summary>
    public async Task<bool> FirstSeenAsync(byte[] enc) {
        var id = Convert.ToHexStringLower(SHA256.HashData(enc).AsSpan(0, 16));
        return await _redis.Db.StringSetAsync(RedisKeys.GatewayReplay(id), 1, Window, When.NotExists);
    }
}
