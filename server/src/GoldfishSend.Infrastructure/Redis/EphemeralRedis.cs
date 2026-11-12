using StackExchange.Redis;

namespace GoldfishSend.Infrastructure.Redis;

/// <summary>
/// The Redis holding short-lived, abuse-control state: rate-limit buckets and their daily HMAC keys, PoW
/// challenges, and push-host circuit breakers. Run it **without persistence** (no AOF, no RDB). Otherwise its
/// write log becomes a record of client activity. It's configured as <c>ConnectionStrings:RedisEphemeral</c>,
/// and falls back to the main Redis if unset (fine for development, not recommended for production).
/// </summary>
public sealed class EphemeralRedis {
    public IConnectionMultiplexer Connection { get; }
    public bool IsSeparate { get; }

    public EphemeralRedis(IConnectionMultiplexer connection, bool isSeparate) {
        Connection = connection;
        IsSeparate = isSeparate;
    }

    public IDatabase Db => Connection.GetDatabase();
}
