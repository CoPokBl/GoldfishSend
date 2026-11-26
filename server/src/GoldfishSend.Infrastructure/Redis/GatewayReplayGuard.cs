using System.Buffers.Binary;
using System.Security.Cryptography;
using StackExchange.Redis;

namespace GoldfishSend.Infrastructure.Redis;

/// <summary>
/// Remembers each gateway request's KEM ciphertext in the ephemeral Redis for longer than its timestamp can stay
/// acceptable (<see cref="Retention"/>), so a captured request can't be replayed.
/// <para>
/// Anyone can make a request that gets this far (the server key is public), before any rate limit, so the memory it
/// takes must not grow with traffic: otherwise a flood would push the ephemeral Redis into evicting rate-limit buckets
/// and PoW challenges. So it's a Bloom filter per two-minute slice, a fixed-size bitmap of <see cref="SliceBits"/> bits
/// (2 MiB), at most <see cref="Slices"/> of them (24 MiB in all). A slice that has taken more than
/// <see cref="SliceCapacity"/> requests (over 4,000 a second, across the cluster) is no longer trusted to say
/// "seen", since its false-positive rate would climb. While a flood lasts, replays of requests from that slice aren't
/// caught: a weaker guarantee for a while instead of refusing honest requests or evicting abuse-control state. With every
/// slice at capacity an honest request is wrongly called a replay about once in 500, and at ordinary load about once in
/// millions (the app retries a <c>409 replay</c> once, with a fresh request). Only bits derived from a hash of the
/// ciphertext are stored.
/// </para>
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
    public const int RetentionSeconds = 2 * TimestampWindowSeconds + 1 + ClockDriftAllowanceSeconds;

    /// <inheritdoc cref="RetentionSeconds"/>
    public static readonly TimeSpan Retention = TimeSpan.FromSeconds(RetentionSeconds);

    public const int SliceSeconds = 120;
    /// <summary>Enough slices to cover <see cref="Retention"/>, plus one for the partly elapsed current slice.</summary>
    public const int Slices = (RetentionSeconds + SliceSeconds - 1) / SliceSeconds + 1;
    public const int SliceBits = 1 << 24;
    public const int SliceCapacity = 500_000;
    private const int Hashes = 4;

    // KEYS = (bitmap, counter) per slice, the current slice first. ARGV = capacity, key TTL (s), then the bit offsets.
    // Returns 1 the first time, 0 for a replay.
    private const string Script = """
        local cap = tonumber(ARGV[1])
        for j = 1, #KEYS, 2 do
            local n = tonumber(redis.call('GET', KEYS[j + 1]) or '0')
            if n > 0 and n <= cap then
                local seen = true
                for h = 3, #ARGV do
                    if redis.call('GETBIT', KEYS[j], ARGV[h]) == 0 then
                        seen = false
                        break
                    end
                end
                if seen then
                    return 0
                end
            end
        end
        for h = 3, #ARGV do
            redis.call('SETBIT', KEYS[1], ARGV[h], 1)
        end
        redis.call('INCR', KEYS[2])
        for j = 1, 2 do
            if redis.call('TTL', KEYS[j]) < 0 then
                redis.call('EXPIRE', KEYS[j], ARGV[2])
            end
        end
        return 1
        """;

    private readonly EphemeralRedis _redis;
    private readonly TimeProvider _time;

    public GatewayReplayGuard(EphemeralRedis redis, TimeProvider? time = null) {
        _redis = redis;
        _time = time ?? TimeProvider.System;
    }

    /// <summary>True the first time <paramref name="enc"/> is seen within <see cref="Retention"/>.</summary>
    public async Task<bool> FirstSeenAsync(byte[] enc) {
        var slice = _time.GetUtcNow().ToUnixTimeSeconds() / SliceSeconds;
        var keys = new RedisKey[2 * Slices];
        for (var i = 0; i < Slices; i++) {
            keys[2 * i] = RedisKeys.GatewayReplay(slice - i);
            keys[2 * i + 1] = RedisKeys.GatewayReplayCount(slice - i);
        }
        var args = new RedisValue[2 + Hashes];
        args[0] = SliceCapacity;
        args[1] = (Slices + 1) * SliceSeconds;
        var offsets = Offsets(enc);
        for (var h = 0; h < Hashes; h++) {
            args[2 + h] = offsets[h];
        }
        return (long)await _redis.Db.ScriptEvaluateAsync(Script, keys, args) == 1;
    }

    /// <summary>The filter's bit positions for a ciphertext: independent slices of its SHA-256.</summary>
    internal static long[] Offsets(byte[] enc) {
        var hash = SHA256.HashData(enc);
        var offsets = new long[Hashes];
        for (var h = 0; h < Hashes; h++) {
            offsets[h] = BinaryPrimitives.ReadUInt32BigEndian(hash.AsSpan(4 * h)) & (SliceBits - 1);
        }
        return offsets;
    }
}
