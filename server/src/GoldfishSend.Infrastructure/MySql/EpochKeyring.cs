using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Globalization;
using System.Security.Cryptography;
using Dapper;
using GoldfishSend.Core.Crypto;
using GoldfishSend.Core.Options;
using GoldfishSend.Infrastructure.Redis;
using Microsoft.Extensions.Logging;
using StackExchange.Redis;

namespace GoldfishSend.Infrastructure.MySql;

/// <summary>
/// Daily data-encryption keys for queued and held messages. Each key is random, stored wrapped by the configured KEK,
/// and deleted once no message could still need it.
///
/// What deletion buys depends on <see cref="EpochKeyStore"/>:
/// <list type="bullet">
/// <item><b>MySql</b> (default): held messages survive any restart. But a deleted key row can linger in InnoDB redo,
/// undo and free pages until overwritten, so someone with an image of the disk <i>and</i> the KEK may recover recent
/// "shredded" epochs. Full-disk encryption and redo/undo log encryption narrow this. See server/README.md.</item>
/// <item><b>Ephemeral</b>: keys live only in the non-persistent ephemeral Redis, so deletion is real and nothing is ever on
/// disk. The cost: restarting that Redis makes every queued and held message undecryptable (they get dropped).</item>
/// </list>
/// </summary>
public sealed class EpochKeyring {
    private static readonly byte[] AadPrefix = "gf/epoch"u8.ToArray();

    private readonly Db _db;
    private readonly EphemeralRedis _redis;
    private readonly byte[] _kek;
    private readonly EpochKeyStore _store;
    private readonly int _retentionDays;
    private readonly ILogger<EpochKeyring> _logger;
    private readonly ConcurrentDictionary<int, byte[]> _cache = new();

    public EpochKeyring(Db db, EphemeralRedis redis, byte[] kek, GoldfishOptions options, ILogger<EpochKeyring> logger) {
        _db = db;
        _redis = redis;
        _kek = kek;
        _store = options.EpochKeyStore;
        _logger = logger;
        // A message accepted at the very end of epoch E with the max TTL can still be pending (max TTL) later.
        _retentionDays = (int)Math.Ceiling(options.Messages.MaxTtlSeconds / 86400.0) + 1;
    }

    public static int EpochOf(DateTime utc) => (int)(utc.Date - DateTime.UnixEpoch).TotalDays;

    public static int CurrentEpoch => EpochOf(DateTime.UtcNow);

    private int OldestKept => CurrentEpoch - _retentionDays;

    public async Task<(int Epoch, byte[] Key)> GetCurrentAsync(CancellationToken ct = default) {
        var epoch = CurrentEpoch;
        var key = await GetAsync(epoch, create: true, ct);
        return (epoch, key!);
    }

    /// <returns>The key, or <c>null</c> if the epoch has been shredded (or never existed).</returns>
    public Task<byte[]?> GetAsync(int epoch, CancellationToken ct = default) => GetAsync(epoch, create: false, ct);

    private async Task<byte[]?> GetAsync(int epoch, bool create, CancellationToken ct) {
        if (epoch < OldestKept) {
            return null;
        }
        if (_cache.TryGetValue(epoch, out var cached)) {
            return cached;
        }

        byte[]? wrapped;
        if (create) {
            var fresh = RandomNumberGenerator.GetBytes(32);
            var wrappedFresh = SecretBox.Seal(_kek, fresh, Aad(epoch));
            CryptographicOperations.ZeroMemory(fresh);
            wrapped = await PutIfAbsentAndGetAsync(epoch, wrappedFresh, ct);
        } else {
            wrapped = await ReadAsync(epoch, ct);
        }
        if (wrapped is null) {
            return null;
        }

        byte[] key;
        try {
            key = SecretBox.Open(_kek, wrapped, Aad(epoch));
        } catch (CryptographicException) {
            throw new InvalidOperationException(
                "Epoch key unwrap failed: Goldfish:Keys:EpochKek doesn't match the key that wrapped the stored epoch keys. " +
                "Restore the previous EpochKek, or, accepting that held messages are lost, delete all rows from " +
                "epoch_keys and pending_messages.");
        }
        return _cache.GetOrAdd(epoch, key);
    }

    /// <summary>Creates today's and tomorrow's keys and shreds keys past retention (from the store and this process).</summary>
    public async Task RotateAsync(CancellationToken ct = default) {
        var current = CurrentEpoch;
        await GetAsync(current, create: true, ct);
        await GetAsync(current + 1, create: true, ct);

        var deleted = 0;
        if (_store == EpochKeyStore.MySql) {
            await using var conn = await _db.OpenAsync(ct);
            deleted = await conn.ExecuteAsync(new CommandDefinition(
                "DELETE FROM epoch_keys WHERE epoch < @oldest", new { oldest = OldestKept }, cancellationToken: ct));
        }
        // Redis-stored keys carry their own TTL, set at creation (retention + 1 day).
        EvictExpired();
        if (deleted > 0) {
            _logger.LogInformation("Shredded {Count} expired epoch key(s)", deleted);
        }
    }

    /// <summary>Wipes cached keys past retention from this process's memory. Every role calls it periodically.</summary>
    public void EvictExpired() {
        var oldest = OldestKept;
        foreach (var epoch in _cache.Keys.Where(e => e < oldest)) {
            if (_cache.TryRemove(epoch, out var key)) {
                CryptographicOperations.ZeroMemory(key);
            }
        }
    }

    private async Task<byte[]?> ReadAsync(int epoch, CancellationToken ct) {
        if (_store == EpochKeyStore.Ephemeral) {
            return (byte[]?)await _redis.Db.StringGetAsync(RedisKey(epoch));
        }
        await using var conn = await _db.OpenAsync(ct);
        return await conn.ExecuteScalarAsync<byte[]?>(new CommandDefinition(
            "SELECT wrapped_key FROM epoch_keys WHERE epoch = @epoch", new { epoch }, cancellationToken: ct));
    }

    private async Task<byte[]?> PutIfAbsentAndGetAsync(int epoch, byte[] wrapped, CancellationToken ct) {
        if (_store == EpochKeyStore.Ephemeral) {
            var db = _redis.Db;
            var ttl = TimeSpan.FromDays(_retentionDays + 2);
            await db.StringSetAsync(RedisKey(epoch), wrapped, ttl, When.NotExists);
            return (byte[]?)await db.StringGetAsync(RedisKey(epoch));
        }
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(new CommandDefinition(
            "INSERT IGNORE INTO epoch_keys (epoch, wrapped_key) VALUES (@epoch, @wrapped)",
            new { epoch, wrapped }, cancellationToken: ct));
        return await conn.ExecuteScalarAsync<byte[]?>(new CommandDefinition(
            "SELECT wrapped_key FROM epoch_keys WHERE epoch = @epoch", new { epoch }, cancellationToken: ct));
    }

    private static string RedisKey(int epoch) => "gf:epoch:" + epoch.ToString(CultureInfo.InvariantCulture);

    private static byte[] Aad(int epoch) {
        var aad = new byte[AadPrefix.Length + 4];
        AadPrefix.CopyTo(aad, 0);
        BinaryPrimitives.WriteInt32BigEndian(aad.AsSpan(AadPrefix.Length), epoch);
        return aad;
    }
}
