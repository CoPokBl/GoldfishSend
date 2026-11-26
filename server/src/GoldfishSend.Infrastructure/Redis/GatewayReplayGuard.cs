using System.Security.Cryptography;
using StackExchange.Redis;

namespace GoldfishSend.Infrastructure.Redis;

/// <summary>
/// Remembers each gateway request's KEM ciphertext in the ephemeral Redis for longer than its timestamp can stay
/// acceptable, so a captured request can't be replayed. Only a truncated hash of the ciphertext is stored.
/// </summary>
public sealed class GatewayReplayGuard {
    /// <summary>How far a request's timestamp may be from the server's clock, either way, in whole seconds.</summary>
    public const int TimestampWindowSeconds = 600;

    /// <summary>
    /// Allowance for API nodes whose clocks disagree: a request first seen by a node running behind can be replayed to
    /// one running ahead.
    /// </summary>
    public const int ClockDriftAllowanceSeconds = 60;

    /// <summary>
    /// A request first seen at the earliest moment its timestamp is accepted stays acceptable for twice the window,
    /// plus one second because the server's clock is floored to whole seconds, plus the drift between nodes. The
    /// entry has to outlive all of that, or a replay at the far edge gets through.
    /// </summary>
    public static readonly TimeSpan Retention = TimeSpan.FromSeconds(2 * TimestampWindowSeconds + 1 + ClockDriftAllowanceSeconds);

    private readonly EphemeralRedis _redis;

    public GatewayReplayGuard(EphemeralRedis redis) {
        _redis = redis;
    }

    /// <summary>True the first time <paramref name="enc"/> is seen within <see cref="Retention"/>.</summary>
    public async Task<bool> FirstSeenAsync(byte[] enc) {
        var id = Convert.ToHexStringLower(SHA256.HashData(enc).AsSpan(0, 16));
        return await _redis.Db.StringSetAsync(RedisKeys.GatewayReplay(id), 1, Retention, When.NotExists);
    }
}
