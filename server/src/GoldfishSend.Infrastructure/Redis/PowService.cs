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
/// <para>
/// A challenge remembers (as those same HMACs) the network that asked for it. A creation counts toward that network's
/// load as well as the redeeming one's, so challenges fetched from a quiet network can't be spent at base difficulty
/// from a busy one. A wrong solution costs the asking network extra challenge budget (<see cref="PowOptions.InvalidSolutionPenalty"/>).
/// The redeemer need not be the asker, so a client whose address changes (a new Tor circuit) can still use its challenge.
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
        var slots = _options.MaxConcurrentVerifications > 0
            ? _options.MaxConcurrentVerifications
            : Math.Max(1, Environment.ProcessorCount / 2);
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
        return await DifficultyForAsync(await LoadKeysAsync(client));
    }

    private async Task<int> DifficultyForAsync(LoadKeys load) {
        var minute = Minute;
        var keys = new RedisKey[3 * Window];
        for (var i = 0; i < Window; i++) {
            keys[i] = RedisKeys.PowNetworkLoad(load.Network, minute - i);
            keys[Window + i] = RedisKeys.PowLoad(minute - i);
            // IPv4 clients have no /32 tier: read the network key again (counted as 0 below), keeping one round trip.
            keys[2 * Window + i] = load.Allocation is null ? keys[i] : RedisKeys.PowNetworkLoad(load.Allocation, minute - i);
        }
        var values = await _redis.Db.StringGetAsync(keys);
        long networkCount = 0, globalCount = 0, allocationCount = 0;
        for (var i = 0; i < Window; i++) {
            networkCount += (long)values[i];
            globalCount += (long)values[Window + i];
            allocationCount += load.Allocation is null ? 0 : (long)values[2 * Window + i];
        }
        return PowDifficulty.For(_options, networkCount, allocationCount, globalCount);
    }

    public async Task<PowChallenge> IssueAsync(ClientSubject client, PowPurpose purpose = PowPurpose.Create) {
        var issuer = new Issuer(
            await LoadKeysAsync(client),
            await _limiter.BucketKeyAsync(RatePolicies.PowPerNetwork, client.Network),
            await _limiter.BucketKeyAsync(RatePolicies.PowPerAllocation, client.Allocation));
        var parameters = purpose == PowPurpose.Send
            ? SendParameters
            : new PowParameters(await DifficultyForAsync(issuer.Load), _options.MemoryKiB, _options.Iterations);
        var challenge = RandomNumberGenerator.GetBytes(ProofOfWork.ChallengeSize);
        var ttl = TimeSpan.FromSeconds(_options.ChallengeTtlSeconds);
        var expiresAt = DateTimeOffset.UtcNow + ttl;
        // The parameters are stored with the challenge, so a config change can't invalidate solutions in flight.
        await _redis.Db.StringSetAsync(RedisKeys.Pow(Convert.ToHexString(challenge)), Encode(parameters, purpose, expiresAt, issuer), ttl);
        return new PowChallenge(challenge, parameters, purpose, ttl, expiresAt);
    }

    /// <summary>
    /// Cheap checks first: the sizes, then an atomic GETDEL of the challenge (so each is redeemed at most once, and only
    /// challenges this server issued, under the PowPerIp, PowPerNetwork and PowPerAllocation limits, cost an Argon2
    /// call). Only then is the Argon2 hash checked, in a bounded number of slots of which one network may hold only a fair
    /// share. When none comes free quickly it returns <see cref="PowRedemption.Busy"/> instead of queueing, and puts the
    /// challenge back.
    /// <para>A creation needs a creation challenge. A send accepts either kind (a creation challenge costs at least as much).</para>
    /// <para>
    /// A valid creation counts toward the load of the network the challenge was issued to and of the redeeming one (once
    /// if they're the same), whatever the rate limits then decide, so a flood slows the flooder. Server-wide load counts
    /// verified mailboxes instead (<see cref="CountVerifiedAsync"/>). Sends never count.
    /// </para>
    /// </summary>
    public async Task<PowRedemption> RedeemAsync(
        byte[] challenge, byte[] nonce, ClientSubject client, PowPurpose purpose, CancellationToken ct = default) {
        if (challenge.Length != ProofOfWork.ChallengeSize || nonce.Length != ProofOfWork.NonceSize) {
            return PowRedemption.Invalid;
        }
        var key = RedisKeys.Pow(Convert.ToHexString(challenge));
        var stored = await _redis.Db.StringGetDeleteAsync(key);
        if ((stored.IsNull ? null : Decode(stored!)) is not (var parameters, var issuedFor, var expiresAt, var issuer)
            || !parameters.IsValid || expiresAt < DateTimeOffset.UtcNow || (purpose == PowPurpose.Create && issuedFor != PowPurpose.Create)) {
            return PowRedemption.Invalid;
        }

        var shares = ShareKeys(client);
        if (!await AcquireAsync(shares, ct)) {
            await PutBackAsync(key, stored!, expiresAt);
            return PowRedemption.Busy;
        }
        bool valid;
        try {
            valid = ProofOfWork.Verify(challenge, nonce, parameters);
        } finally {
            VerificationSlots.Release();
            Shares.Exit(shares);
        }
        if (!valid) {
            await PenalizeAsync(issuer);
            return PowRedemption.Invalid;
        }
        if (purpose == PowPurpose.Create) {
            await CountCreationAsync(issuer.Load, client);
        }
        return PowRedemption.Ok;
    }

    private async Task PenalizeAsync(Issuer issuer) {
        var cost = _options.InvalidSolutionPenalty;
        if (cost <= 0) {
            return;
        }
        if (issuer.NetworkBucket is { } network) {
            await _limiter.PenalizeAsync(RatePolicies.PowPerNetwork, network, cost);
        }
        if (issuer.AllocationBucket is { } allocation) {
            await _limiter.PenalizeAsync(RatePolicies.PowPerAllocation, allocation, cost);
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

    /// <summary>The network's (and IPv6 /32's) load-counter keys: daily-keyed HMACs of the prefixes.</summary>
    private async Task<LoadKeys> LoadKeysAsync(ClientSubject client) {
        return new LoadKeys(
            await _limiter.DailySubjectKeyAsync(NetworkPurpose, client.Network),
            client.Allocation is null ? null : await _limiter.DailySubjectKeyAsync(AllocationPurpose, client.Allocation));
    }

    /// <summary>
    /// Counts a creation toward the issuing and the redeeming networks' (and IPv6 /32s') load. It can only raise the
    /// difficulty for those networks, so it's counted whether or not the mailbox is ever created or verified.
    /// </summary>
    private async Task CountCreationAsync(LoadKeys issuer, ClientSubject redeemer) {
        try {
            var own = await LoadKeysAsync(redeemer);
            var keys = new HashSet<string>(StringComparer.Ordinal) { issuer.Network, own.Network };
            foreach (var allocation in new[] { issuer.Allocation, own.Allocation }) {
                if (allocation is not null) {
                    keys.Add(allocation);
                }
            }
            foreach (var key in keys) {
                await IncrementAsync(RedisKeys.PowNetworkLoad(key, Minute), 1);
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

    internal readonly record struct LoadKeys(string Network, string? Allocation);

    /// <summary>Who a challenge was issued to, as HMACs only: its load counters and its pow-net and pow-alloc buckets.</summary>
    internal readonly record struct Issuer(LoadKeys Load, string? NetworkBucket, string? AllocationBucket);

    internal static string Encode(PowParameters p, PowPurpose purpose, DateTimeOffset expiresAt, Issuer issuer) => string.Create(
        CultureInfo.InvariantCulture,
        $"{p.Difficulty}:{p.MemoryKiB}:{p.Iterations}:{expiresAt.ToUnixTimeMilliseconds()}:{(purpose == PowPurpose.Send ? "s" : "c")}" +
        $"|{issuer.Load.Network}|{issuer.Load.Allocation}|{issuer.NetworkBucket}|{issuer.AllocationBucket}");

    internal static (PowParameters, PowPurpose, DateTimeOffset, Issuer)? Decode(string value) {
        var fields = value.Split('|');
        var parts = fields[0].Split(':');
        if (fields.Length != 5 || fields[1].Length == 0 || parts.Length != 5
            || !int.TryParse(parts[0], NumberStyles.None, CultureInfo.InvariantCulture, out var difficulty)
            || !int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var memory)
            || !int.TryParse(parts[2], NumberStyles.None, CultureInfo.InvariantCulture, out var iterations)
            || !long.TryParse(parts[3], NumberStyles.None, CultureInfo.InvariantCulture, out var expires)
            || parts[4] is not ("c" or "s")) {
            return null;
        }
        static string? Optional(string field) => field.Length == 0 ? null : field;
        var issuer = new Issuer(new LoadKeys(fields[1], Optional(fields[2])), Optional(fields[3]), Optional(fields[4]));
        return (new PowParameters(difficulty, memory, iterations), parts[4] == "s" ? PowPurpose.Send : PowPurpose.Create,
            DateTimeOffset.FromUnixTimeMilliseconds(expires), issuer);
    }
}
