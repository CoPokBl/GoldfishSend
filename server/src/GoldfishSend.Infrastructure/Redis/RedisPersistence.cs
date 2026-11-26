using StackExchange.Redis;

namespace GoldfishSend.Infrastructure.Redis;

/// <summary>
/// What each Redis writes to disk (<c>INFO persistence</c>), and AOF compaction (<c>BGREWRITEAOF</c>). The client only
/// sends those in admin mode, so they go over separate admin-mode connections, opened on first use and used for nothing
/// else; the application's own connections stay out of admin mode. The server's ACL (deploy/redis.conf) still decides
/// what any connection may run: INFO on both Redis instances, BGREWRITEAOF only on the main one.
/// </summary>
public sealed class RedisPersistence : IDisposable {
    private readonly Lazy<ConnectionMultiplexer> _main;
    private readonly Lazy<ConnectionMultiplexer>? _ephemeral;

    public RedisPersistence(string mainConfiguration, string? ephemeralConfiguration) {
        _main = new Lazy<ConnectionMultiplexer>(() => ServiceCollectionExtensions.Connect(mainConfiguration, admin: true));
        _ephemeral = string.IsNullOrWhiteSpace(ephemeralConfiguration)
            ? null
            : new Lazy<ConnectionMultiplexer>(() => ServiceCollectionExtensions.Connect(ephemeralConfiguration, admin: true));
    }

    /// <returns>
    /// Whether the main Redis (or the separate ephemeral one) has its append-only file on, or <c>null</c> if it wouldn't
    /// say or there's no separate ephemeral Redis.
    /// </returns>
    public async Task<bool?> AofEnabledAsync(bool ephemeral = false) {
        return Field(await InfoAsync(ephemeral), "aof_enabled") switch {
            "1" => true,
            "0" => false,
            _ => null,
        };
    }

    /// <summary>The <c>INFO persistence</c> text, or <c>null</c> if the server refused or couldn't be reached.</summary>
    public async Task<string?> InfoAsync(bool ephemeral = false) {
        var connection = ephemeral ? _ephemeral : _main;
        if (connection is null) {
            return null;
        }
        try {
            return await Server(connection.Value).InfoRawAsync("persistence");
        } catch (Exception ex) when (ex is RedisException or TimeoutException) {
            return null;
        }
    }

    /// <summary>Asks the main Redis to rewrite its AOF. Redis answers at once and rewrites in a forked child.</summary>
    /// <exception cref="RedisServerException">Refused, for example because a rewrite is already running.</exception>
    public Task RewriteAofAsync() => Server(_main.Value).SaveAsync(SaveType.BackgroundRewriteAppendOnlyFile);

    // Redis Cluster isn't supported (server/README.md), so there is one server.
    private static IServer Server(ConnectionMultiplexer connection) => connection.GetServers()[0];

    public static string? Field(string? info, string name) {
        if (info is null) {
            return null;
        }
        foreach (var line in info.Split('\n')) {
            var trimmed = line.TrimEnd('\r');
            if (trimmed.Length > name.Length && trimmed[name.Length] == ':' && trimmed.StartsWith(name, StringComparison.Ordinal)) {
                return trimmed[(name.Length + 1)..];
            }
        }
        return null;
    }

    public void Dispose() {
        if (_main.IsValueCreated) {
            _main.Value.Dispose();
        }
        if (_ephemeral is { IsValueCreated: true }) {
            _ephemeral.Value.Dispose();
        }
    }
}
