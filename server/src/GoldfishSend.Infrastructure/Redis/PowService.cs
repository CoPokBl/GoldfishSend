using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using GoldfishSend.Core.Crypto;
using GoldfishSend.Core.Options;
using StackExchange.Redis;

namespace GoldfishSend.Infrastructure.Redis;

public sealed record PowChallenge(byte[] Challenge, int Difficulty, DateTimeOffset ExpiresAt);

/// <summary>
/// Issues single-use proof-of-work challenges. Difficulty rises by one bit each time server-wide demand
/// doubles past the configured threshold, so a flood of mailbox creations gets more expensive for everyone
/// creating them.
/// </summary>
public sealed class PowService {
    private readonly EphemeralRedis _redis;
    private readonly PowOptions _options;

    public PowService(EphemeralRedis redis, GoldfishOptions options) {
        _redis = redis;
        _options = options.Pow;
    }

    public async Task<int> CurrentDifficultyAsync() {
        var db = _redis.Db;
        var minute = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 60;
        var recent = (long)await db.StringGetAsync(RedisKeys.PowLoad(minute)) + (long)await db.StringGetAsync(RedisKeys.PowLoad(minute - 1));
        return DifficultyFor(recent);
    }

    internal int DifficultyFor(long recentPerTwoMinutes) {
        var perMinute = recentPerTwoMinutes / 2.0;
        var extra = 0;
        if (perMinute > _options.LoadThresholdPerMinute && _options.LoadThresholdPerMinute > 0) {
            extra = (int)Math.Floor(Math.Log2(perMinute / _options.LoadThresholdPerMinute)) + 1;
        }
        return Math.Min(ProofOfWork.MaxDifficulty, _options.BaseDifficulty + Math.Min(extra, _options.MaxExtraDifficulty));
    }

    public async Task<PowChallenge> IssueAsync() {
        var difficulty = await CurrentDifficultyAsync();
        var challenge = RandomNumberGenerator.GetBytes(ProofOfWork.ChallengeSize);
        var ttl = TimeSpan.FromSeconds(_options.ChallengeTtlSeconds);
        await _redis.Db.StringSetAsync(
            RedisKeys.Pow(Convert.ToHexString(challenge)), difficulty.ToString(CultureInfo.InvariantCulture), ttl);
        return new PowChallenge(challenge, difficulty, DateTimeOffset.UtcNow + ttl);
    }

    /// <summary>Atomically consumes the challenge (GETDEL), so each solution can be redeemed at most once.</summary>
    /// <param name="countsTowardLoad">
    /// Only mailbox creations drive adaptive difficulty. PoW paid to get past a send limit doesn't, so
    /// heavy senders can't make onboarding harder for everyone.
    /// </param>
    public async Task<bool> RedeemAsync(byte[] challenge, byte[] nonce, bool countsTowardLoad = true) {
        if (challenge.Length != ProofOfWork.ChallengeSize || nonce.Length != ProofOfWork.NonceSize) {
            return false;
        }
        var db = _redis.Db;
        var stored = await db.StringGetDeleteAsync(RedisKeys.Pow(Convert.ToHexString(challenge)));
        if (stored.IsNull || !int.TryParse((string?)stored, NumberStyles.None, CultureInfo.InvariantCulture, out var difficulty)) {
            return false;
        }
        var ok = ProofOfWork.Verify(challenge, nonce, difficulty);
        if (ok && countsTowardLoad) {
            var minute = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 60;
            var key = RedisKeys.PowLoad(minute);
            await db.StringIncrementAsync(key);
            await db.KeyExpireAsync(key, TimeSpan.FromMinutes(3));
        }
        return ok;
    }
}
