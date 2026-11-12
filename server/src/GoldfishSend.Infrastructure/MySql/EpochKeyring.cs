using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using Dapper;
using GoldfishSend.Core.Crypto;
using GoldfishSend.Core.Options;
using Microsoft.Extensions.Logging;

namespace GoldfishSend.Infrastructure.MySql;

/// <summary>
/// Daily data-encryption keys for queued and held messages. Each key is random, stored wrapped by the
/// configured KEK, and deleted once no message could still need it. Deleting a key makes every remnant
/// of its messages unreadable: crypto-shredding.
/// </summary>
public sealed class EpochKeyring {
    private static readonly byte[] AadPrefix = "gf/epoch"u8.ToArray();

    private readonly Db _db;
    private readonly byte[] _kek;
    private readonly int _retentionDays;
    private readonly ILogger<EpochKeyring> _logger;
    private readonly ConcurrentDictionary<int, byte[]> _cache = new();

    public EpochKeyring(Db db, byte[] kek, GoldfishOptions options, ILogger<EpochKeyring> logger) {
        _db = db;
        _kek = kek;
        _logger = logger;
        // A message accepted at the very end of epoch E with the max TTL can still be pending (max TTL) later.
        _retentionDays = (int)Math.Ceiling(options.Messages.MaxTtlSeconds / 86400.0) + 1;
    }

    public static int EpochOf(DateTime utc) => (int)(utc.Date - DateTime.UnixEpoch).TotalDays;

    public static int CurrentEpoch => EpochOf(DateTime.UtcNow);

    public async Task<(int Epoch, byte[] Key)> GetCurrentAsync(CancellationToken ct = default) {
        var epoch = CurrentEpoch;
        var key = await GetAsync(epoch, create: true, ct);
        return (epoch, key!);
    }

    /// <returns>The key, or <c>null</c> if the epoch has been shredded (or never existed).</returns>
    public Task<byte[]?> GetAsync(int epoch, CancellationToken ct = default) => GetAsync(epoch, create: false, ct);

    private async Task<byte[]?> GetAsync(int epoch, bool create, CancellationToken ct) {
        if (_cache.TryGetValue(epoch, out var cached)) {
            return cached;
        }

        await using var conn = await _db.OpenAsync(ct);
        if (create) {
            var fresh = RandomNumberGenerator.GetBytes(32);
            var wrappedFresh = SecretBox.Seal(_kek, fresh, Aad(epoch));
            CryptographicOperations.ZeroMemory(fresh);
            await conn.ExecuteAsync(new CommandDefinition(
                "INSERT IGNORE INTO epoch_keys (epoch, wrapped_key) VALUES (@epoch, @wrapped)",
                new { epoch, wrapped = wrappedFresh }, cancellationToken: ct));
        }

        var wrapped = await conn.ExecuteScalarAsync<byte[]?>(new CommandDefinition(
            "SELECT wrapped_key FROM epoch_keys WHERE epoch = @epoch", new { epoch }, cancellationToken: ct));
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

    /// <summary>Creates today's and tomorrow's keys and shreds keys past retention.</summary>
    public async Task RotateAsync(CancellationToken ct = default) {
        var current = CurrentEpoch;
        await GetAsync(current, create: true, ct);
        await GetAsync(current + 1, create: true, ct);

        var oldest = current - _retentionDays;
        await using var conn = await _db.OpenAsync(ct);
        var deleted = await conn.ExecuteAsync(new CommandDefinition(
            "DELETE FROM epoch_keys WHERE epoch < @oldest", new { oldest }, cancellationToken: ct));
        foreach (var epoch in _cache.Keys.Where(e => e < oldest)) {
            if (_cache.TryRemove(epoch, out var key)) {
                CryptographicOperations.ZeroMemory(key);
            }
        }
        if (deleted > 0) {
            _logger.LogInformation("Shredded {Count} expired epoch key(s)", deleted);
        }
    }

    private static byte[] Aad(int epoch) {
        var aad = new byte[AadPrefix.Length + 4];
        AadPrefix.CopyTo(aad, 0);
        BinaryPrimitives.WriteInt32BigEndian(aad.AsSpan(AadPrefix.Length), epoch);
        return aad;
    }
}
