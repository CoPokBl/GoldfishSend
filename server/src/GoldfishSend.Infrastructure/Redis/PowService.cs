using System.Globalization;
using System.Security.Cryptography;
using GoldfishSend.Core.Crypto;
using GoldfishSend.Core.Options;
using GoldfishSend.Infrastructure.Services;
using Microsoft.Extensions.Logging;
using StackExchange.Redis;

namespace GoldfishSend.Infrastructure.Redis;

public sealed record PowChallenge(byte[] Challenge, PowParameters Parameters, DateTimeOffset ExpiresAt);

public enum PowRedemption {
    Ok,
    /// <summary>Unknown, expired or already used challenge, or a wrong nonce.</summary>
    Invalid,
    /// <summary>Every verification slot is busy. The challenge was put back, so the same solution can be retried.</summary>
    Busy,
}

/// <summary>
/// Issues and redeems single-use Argon2id challenges (<see cref="ProofOfWork"/>).
/// <para>
/// Difficulty adapts to load (<see cref="PowDifficulty"/>): each network's own recent creations raise its difficulty, and
/// verified creations server-wide add a small capped amount for everyone. Load counters are per-minute buckets in the
/// ephemeral Redis that expire after the load window. The network ones are keyed like short-period rate-limit buckets
/// (a daily-keyed HMAC of the prefix), and none of them refers to a mailbox.
/// </para>
/// </summary>
public sealed class PowService {
    /// <summary>How long a redemption may wait for a verification slot before it's told to retry.</summary>
    private static readonly TimeSpan SlotWait = TimeSpan.FromMilliseconds(250);
    private const string NetworkPurpose = "pow-load";

    private readonly EphemeralRedis _redis;
    private readonly RateLimiter _limiter;
    private readonly PowOptions _options;
    private readonly ILogger<PowService> _logger;

    public PowService(EphemeralRedis redis, RateLimiter limiter, GoldfishOptions options, ILogger<PowService> logger) {
        _redis = redis;
        _limiter = limiter;
        _options = options.Pow;
        _logger = logger;
        var highest = new PowParameters(
            _options.BaseDifficulty + _options.MaxNetworkExtraDifficulty + _options.MaxGlobalExtraDifficulty,
            _options.MemoryKiB, _options.Iterations);
        if (!highest.IsValid || _options.BaseDifficulty < 0 || _options.MaxNetworkExtraDifficulty < 0
            || _options.MaxGlobalExtraDifficulty < 0) {
            throw new InvalidOperationException(
                $"Goldfish:Pow is out of range: difficulty 0-{ProofOfWork.MaxDifficulty}, MemoryKiB " +
                $"{ProofOfWork.MinMemoryKiB}-{ProofOfWork.MaxMemoryKiB}, Iterations 1-{ProofOfWork.MaxIterations}");
        }
        var slots = _options.MaxConcurrentVerifications > 0 ? _options.MaxConcurrentVerifications : Environment.ProcessorCount;
        VerificationSlots = new SemaphoreSlim(slots, slots);
    }

    /// <summary>Bounds concurrent Argon2 verifications (CPU, and <c>MemoryKiB</c> each). Public for tests.</summary>
    public SemaphoreSlim VerificationSlots { get; }

    private static long Minute => DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 60;
    private int Window => Math.Max(1, _options.LoadWindowMinutes);
    private TimeSpan CounterTtl => TimeSpan.FromMinutes(Window + 1);

    /// <summary>The difficulty a challenge issued to <paramref name="client"/> would get now.</summary>
    public async Task<int> DifficultyForAsync(ClientSubject client) {
        var network = await _limiter.DailySubjectKeyAsync(NetworkPurpose, client.Network);
        var minute = Minute;
        var keys = new RedisKey[2 * Window];
        for (var i = 0; i < Window; i++) {
            keys[i] = RedisKeys.PowNetworkLoad(network, minute - i);
            keys[Window + i] = RedisKeys.PowLoad(minute - i);
        }
        var values = await _redis.Db.StringGetAsync(keys);
        long networkCount = 0, globalCount = 0;
        for (var i = 0; i < Window; i++) {
            networkCount += (long)values[i];
            globalCount += (long)values[Window + i];
        }
        return PowDifficulty.For(_options, networkCount, globalCount);
    }

    public async Task<PowChallenge> IssueAsync(ClientSubject client) {
        var parameters = new PowParameters(await DifficultyForAsync(client), _options.MemoryKiB, _options.Iterations);
        var challenge = RandomNumberGenerator.GetBytes(ProofOfWork.ChallengeSize);
        var ttl = TimeSpan.FromSeconds(_options.ChallengeTtlSeconds);
        var expiresAt = DateTimeOffset.UtcNow + ttl;
        // The parameters are stored with the challenge, so a config change can't invalidate solutions in flight.
        await _redis.Db.StringSetAsync(RedisKeys.Pow(Convert.ToHexString(challenge)), Encode(parameters, expiresAt), ttl);
        return new PowChallenge(challenge, parameters, expiresAt);
    }

    /// <summary>
    /// Cheap checks first: the sizes, then an atomic GETDEL of the challenge (so each is redeemed at most once, and only
    /// challenges this server issued, under the PowPerIp and PowPerNetwork limits, cost an Argon2 call). Only then is the
    /// Argon2 hash checked, in a bounded number of slots. When they're all busy it returns <see cref="PowRedemption.Busy"/>
    /// quickly instead of queueing, and puts the challenge back.
    /// <para>Redeeming never counts toward load: see <see cref="CountCreationAsync"/> and <see cref="CountVerifiedAsync"/>.</para>
    /// </summary>
    public async Task<PowRedemption> RedeemAsync(byte[] challenge, byte[] nonce, CancellationToken ct = default) {
        if (challenge.Length != ProofOfWork.ChallengeSize || nonce.Length != ProofOfWork.NonceSize) {
            return PowRedemption.Invalid;
        }
        var key = RedisKeys.Pow(Convert.ToHexString(challenge));
        var stored = await _redis.Db.StringGetDeleteAsync(key);
        if ((stored.IsNull ? null : Decode(stored!)) is not (var parameters, var expiresAt)
            || !parameters.IsValid || expiresAt < DateTimeOffset.UtcNow) {
            return PowRedemption.Invalid;
        }

        bool acquired;
        try {
            acquired = await VerificationSlots.WaitAsync(SlotWait, ct);
        } catch (OperationCanceledException) {
            acquired = false;
        }
        if (!acquired) {
            await PutBackAsync(key, stored!, expiresAt);
            return PowRedemption.Busy;
        }
        try {
            return ProofOfWork.Verify(challenge, nonce, parameters) ? PowRedemption.Ok : PowRedemption.Invalid;
        } finally {
            VerificationSlots.Release();
        }
    }

    /// <summary>
    /// Counts a mailbox creation that passed the rate limits toward its network's load. It can only raise the difficulty
    /// for that network, so it's counted whether or not the mailbox is ever verified: a flood slows the flooder.
    /// </summary>
    public async Task CountCreationAsync(ClientSubject client) {
        try {
            var network = await _limiter.DailySubjectKeyAsync(NetworkPurpose, client.Network);
            await IncrementAsync(RedisKeys.PowNetworkLoad(network, Minute), 1);
        } catch (Exception ex) when (ex is RedisException or TimeoutException) {
            _logger.LogWarning("PoW load counter unavailable ({Type})", ex.GetType().Name);
        }
    }

    /// <summary>
    /// Counts newly verified mailboxes toward the server-wide load. Raising everyone's difficulty takes real push endpoints
    /// and a round trip per mailbox, not just proofs of work.
    /// </summary>
    public async Task CountVerifiedAsync(int mailboxes) {
        if (mailboxes <= 0) {
            return;
        }
        try {
            await IncrementAsync(RedisKeys.PowLoad(Minute), mailboxes);
        } catch (Exception ex) when (ex is RedisException or TimeoutException) {
            _logger.LogWarning("PoW load counter unavailable ({Type})", ex.GetType().Name);
        }
    }

    private async Task IncrementAsync(string key, long by) {
        var batch = _redis.Db.CreateBatch();
        var increment = batch.StringIncrementAsync(key, by);
        var expire = batch.KeyExpireAsync(key, CounterTtl);
        batch.Execute();
        await Task.WhenAll(increment, expire);
    }

    private async Task PutBackAsync(string key, RedisValue stored, DateTimeOffset expiresAt) {
        var left = expiresAt - DateTimeOffset.UtcNow;
        if (left <= TimeSpan.Zero) {
            return;
        }
        try {
            await _redis.Db.StringSetAsync(key, stored, left, When.NotExists);
        } catch (Exception ex) when (ex is RedisException or TimeoutException) {
            _logger.LogWarning("Could not put back a PoW challenge ({Type})", ex.GetType().Name);
        }
    }

    private static string Encode(PowParameters p, DateTimeOffset expiresAt) => string.Create(CultureInfo.InvariantCulture,
        $"{p.Difficulty}:{p.MemoryKiB}:{p.Iterations}:{expiresAt.ToUnixTimeMilliseconds()}");

    private static (PowParameters, DateTimeOffset)? Decode(string value) {
        var parts = value.Split(':');
        if (parts.Length != 4
            || !int.TryParse(parts[0], NumberStyles.None, CultureInfo.InvariantCulture, out var difficulty)
            || !int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var memory)
            || !int.TryParse(parts[2], NumberStyles.None, CultureInfo.InvariantCulture, out var iterations)
            || !long.TryParse(parts[3], NumberStyles.None, CultureInfo.InvariantCulture, out var expires)) {
            return null;
        }
        return (new PowParameters(difficulty, memory, iterations), DateTimeOffset.FromUnixTimeMilliseconds(expires));
    }
}
