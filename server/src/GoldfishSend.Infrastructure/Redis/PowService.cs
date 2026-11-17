using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using GoldfishSend.Core.Crypto;
using GoldfishSend.Core.Options;
using GoldfishSend.Infrastructure.Services;
using Microsoft.Extensions.Logging;
using StackExchange.Redis;

namespace GoldfishSend.Infrastructure.Redis;

public sealed record PowChallenge(byte[] Challenge, PowParameters Parameters, PowPurpose Purpose, TimeSpan Ttl, DateTimeOffset ExpiresAt);

public enum PowRedemption {
    Ok,
    /// <summary>Unknown, expired, already used or wrong-purpose challenge, or a wrong nonce.</summary>
    Invalid,
    /// <summary>No verification slot (or this network's share of them) came free. The challenge was put back.</summary>
    Busy,
}

/// <summary>
/// Issues and redeems single-use Argon2id challenges (<see cref="ProofOfWork"/>).
/// <para>
/// Creation challenges adapt to load (<see cref="PowDifficulty"/>): each network's own recent creations (and its IPv6
/// /32's) raise its difficulty, and verified creations server-wide add a small capped amount for everyone. Load counters
/// are per-minute buckets in the ephemeral Redis that expire after the load window. The network ones are keyed like
/// short-period rate-limit buckets (a daily-keyed HMAC of the prefix), and none of them refers to a mailbox. Send
/// challenges have a fixed difficulty.
/// </para>
/// </summary>
public sealed class PowService {
    /// <summary>How long a redemption may wait for a verification slot before it's told to retry.</summary>
    private static readonly TimeSpan SlotWait = TimeSpan.FromMilliseconds(250);
    private static readonly TimeSpan ShareRetry = TimeSpan.FromMilliseconds(20);
    private const string NetworkPurpose = "pow-load";
    private const string AllocationPurpose = "pow-load-alloc";

    private readonly EphemeralRedis _redis;
    private readonly RateLimiter _limiter;
    private readonly PowOptions _options;
    private readonly ILogger<PowService> _logger;
    private readonly int _networkShare;
    private readonly int _allocationShare;

    public PowService(EphemeralRedis redis, RateLimiter limiter, GoldfishOptions options, ILogger<PowService> logger) {
        _redis = redis;
        _limiter = limiter;
        _options = options.Pow;
        _logger = logger;
        var highest = new PowParameters(PowDifficulty.Highest(_options), _options.MemoryKiB, _options.Iterations);
        if (!highest.IsValid || _options.BaseDifficulty < 0 || _options.MaxNetworkExtraDifficulty < 0
            || _options.MaxGlobalExtraDifficulty < 0) {
            throw new InvalidOperationException(
                $"Goldfish:Pow is out of range: difficulty at full load 0-{ProofOfWork.MaxDifficulty}, MemoryKiB " +
                $"{ProofOfWork.MinMemoryKiB}-{ProofOfWork.MaxMemoryKiB}, Iterations 1-{ProofOfWork.MaxIterations}, " +
                $"expected work at most {ProofOfWork.MaxWorkKiB} KiB");
        }
        if (!SendParameters.IsValidForSend) {
            throw new InvalidOperationException(
                $"Goldfish:Pow:SendDifficulty is out of range: at most {ProofOfWork.MaxSendDifficulty} bits and " +
                $"{ProofOfWork.MaxSendWorkKiB} KiB of expected work");
        }
        var slots = _options.MaxConcurrentVerifications > 0 ? _options.MaxConcurrentVerifications : Environment.ProcessorCount;
        VerificationSlots = new SemaphoreSlim(slots, slots);
        _networkShare = Math.Max(1, slots / 4);
        _allocationShare = Math.Max(1, slots / 2);
    }

    /// <summary>Bounds concurrent Argon2 verifications (CPU, and <c>MemoryKiB</c> each). Public for tests.</summary>
    public SemaphoreSlim VerificationSlots { get; }

    /// <summary>How many of the slots each network and IPv6 /32 holds right now. Public for tests.</summary>
    public FairShares Shares { get; } = new();

    private PowParameters SendParameters => new(_options.SendDifficulty, _options.MemoryKiB, _options.Iterations);

    private static long Minute => DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 60;
    private int Window => Math.Max(1, _options.LoadWindowMinutes);
    private TimeSpan CounterTtl => TimeSpan.FromMinutes(Window + 1);

    /// <summary>The difficulty a creation challenge issued to <paramref name="client"/> would get now.</summary>
    public async Task<int> DifficultyForAsync(ClientSubject client) {
        var network = await _limiter.DailySubjectKeyAsync(NetworkPurpose, client.Network);
        var allocation = client.Allocation is null ? null : await _limiter.DailySubjectKeyAsync(AllocationPurpose, client.Allocation);
        var minute = Minute;
        var keys = new RedisKey[3 * Window];
        for (var i = 0; i < Window; i++) {
            keys[i] = RedisKeys.PowNetworkLoad(network, minute - i);
            keys[Window + i] = RedisKeys.PowLoad(minute - i);
            // IPv4 clients have no /32 tier: read the network key again (counted as 0 below), keeping one round trip.
            keys[2 * Window + i] = allocation is null ? keys[i] : RedisKeys.PowNetworkLoad(allocation, minute - i);
        }
        var values = await _redis.Db.StringGetAsync(keys);
        long networkCount = 0, globalCount = 0, allocationCount = 0;
        for (var i = 0; i < Window; i++) {
            networkCount += (long)values[i];
            globalCount += (long)values[Window + i];
            allocationCount += allocation is null ? 0 : (long)values[2 * Window + i];
        }
        return PowDifficulty.For(_options, networkCount, allocationCount, globalCount);
    }

    public async Task<PowChallenge> IssueAsync(ClientSubject client, PowPurpose purpose = PowPurpose.Create) {
        var parameters = purpose == PowPurpose.Send
            ? SendParameters
            : new PowParameters(await DifficultyForAsync(client), _options.MemoryKiB, _options.Iterations);
        var challenge = RandomNumberGenerator.GetBytes(ProofOfWork.ChallengeSize);
        var ttl = TimeSpan.FromSeconds(_options.ChallengeTtlSeconds);
        var expiresAt = DateTimeOffset.UtcNow + ttl;
        // The parameters are stored with the challenge, so a config change can't invalidate solutions in flight.
        await _redis.Db.StringSetAsync(RedisKeys.Pow(Convert.ToHexString(challenge)), Encode(parameters, purpose, expiresAt), ttl);
        return new PowChallenge(challenge, parameters, purpose, ttl, expiresAt);
    }

    /// <summary>
    /// Cheap checks first: the sizes, then an atomic GETDEL of the challenge (so each is redeemed at most once, and only
    /// challenges this server issued, under the PowPerIp, PowPerNetwork and PowPerAllocation limits, cost an Argon2
    /// call). Only then is the Argon2 hash checked, in a bounded number of slots of which one network may hold only a fair
    /// share. When none comes free quickly it returns <see cref="PowRedemption.Busy"/> instead of queueing, and puts the
    /// challenge back.
    /// <para>A creation needs a creation challenge. A send accepts either kind (a creation challenge costs at least as much).</para>
    /// <para>Redeeming never counts toward load: see <see cref="CountCreationAsync"/> and <see cref="CountVerifiedAsync"/>.</para>
    /// </summary>
    public async Task<PowRedemption> RedeemAsync(
        byte[] challenge, byte[] nonce, ClientSubject client, PowPurpose purpose, CancellationToken ct = default) {
        if (challenge.Length != ProofOfWork.ChallengeSize || nonce.Length != ProofOfWork.NonceSize) {
            return PowRedemption.Invalid;
        }
        var key = RedisKeys.Pow(Convert.ToHexString(challenge));
        var stored = await _redis.Db.StringGetDeleteAsync(key);
        if ((stored.IsNull ? null : Decode(stored!)) is not (var parameters, var issuedFor, var expiresAt)
            || !parameters.IsValid || expiresAt < DateTimeOffset.UtcNow || (purpose == PowPurpose.Create && issuedFor != PowPurpose.Create)) {
            return PowRedemption.Invalid;
        }

        var shares = ShareKeys(client);
        if (!await AcquireAsync(shares, ct)) {
            await PutBackAsync(key, stored!, expiresAt);
            return PowRedemption.Busy;
        }
        try {
            return ProofOfWork.Verify(challenge, nonce, parameters) ? PowRedemption.Ok : PowRedemption.Invalid;
        } finally {
            VerificationSlots.Release();
            Shares.Exit(shares);
        }
    }

    /// <summary>The client's fair shares, then a slot, all within <see cref="SlotWait"/>.</summary>
    private async Task<bool> AcquireAsync(IReadOnlyList<(string, int)> shares, CancellationToken ct) {
        var clock = Stopwatch.StartNew();
        var entered = false;
        try {
            while (!(entered = Shares.TryEnter(shares))) {
                if (clock.Elapsed + ShareRetry > SlotWait) {
                    return false;
                }
                await Task.Delay(ShareRetry, ct);
            }
            var left = SlotWait - clock.Elapsed;
            if (await VerificationSlots.WaitAsync(left > TimeSpan.Zero ? left : TimeSpan.Zero, ct)) {
                return true;
            }
        } catch (OperationCanceledException) {
            // Treated as busy.
        }
        if (entered) {
            Shares.Exit(shares);
        }
        return false;
    }

    /// <summary>
    /// In-memory keys for the fair shares: the network (/24 or /48) and, for IPv6, the /32. The raw prefixes never leave
    /// this process, and an entry exists only while that subject holds a slot.
    /// </summary>
    private List<(string, int)> ShareKeys(ClientSubject client) {
        var keys = new List<(string, int)> { ("n" + Convert.ToHexString(client.Network), _networkShare) };
        if (client.Allocation is not null) {
            keys.Add(("a" + Convert.ToHexString(client.Allocation), _allocationShare));
        }
        return keys;
    }

    /// <summary>
    /// Counts a mailbox creation that passed the rate limits toward its network's (and IPv6 /32's) load. It can only raise
    /// the difficulty for that network, so it's counted whether or not the mailbox is ever verified: a flood slows the
    /// flooder.
    /// </summary>
    public async Task CountCreationAsync(ClientSubject client) {
        try {
            var network = await _limiter.DailySubjectKeyAsync(NetworkPurpose, client.Network);
            await IncrementAsync(RedisKeys.PowNetworkLoad(network, Minute), 1);
            if (client.Allocation is not null) {
                var allocation = await _limiter.DailySubjectKeyAsync(AllocationPurpose, client.Allocation);
                await IncrementAsync(RedisKeys.PowNetworkLoad(allocation, Minute), 1);
            }
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

    private static string Encode(PowParameters p, PowPurpose purpose, DateTimeOffset expiresAt) => string.Create(
        CultureInfo.InvariantCulture,
        $"{p.Difficulty}:{p.MemoryKiB}:{p.Iterations}:{expiresAt.ToUnixTimeMilliseconds()}:{(purpose == PowPurpose.Send ? "s" : "c")}");

    private static (PowParameters, PowPurpose, DateTimeOffset)? Decode(string value) {
        var parts = value.Split(':');
        if (parts.Length != 5
            || !int.TryParse(parts[0], NumberStyles.None, CultureInfo.InvariantCulture, out var difficulty)
            || !int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var memory)
            || !int.TryParse(parts[2], NumberStyles.None, CultureInfo.InvariantCulture, out var iterations)
            || !long.TryParse(parts[3], NumberStyles.None, CultureInfo.InvariantCulture, out var expires)
            || parts[4] is not ("c" or "s")) {
            return null;
        }
        return (new PowParameters(difficulty, memory, iterations), parts[4] == "s" ? PowPurpose.Send : PowPurpose.Create,
            DateTimeOffset.FromUnixTimeMilliseconds(expires));
    }
}
