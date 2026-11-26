using System.Security.Cryptography;
using GoldfishSend.Core.Options;
using GoldfishSend.Core.Protocol;
using GoldfishSend.Infrastructure.Redis;
using Microsoft.Extensions.Logging;
using StackExchange.Redis;

namespace GoldfishSend.Infrastructure.Services;

/// <summary>
/// One-time invite drops. The blob is encrypted by the client under a key that only travels in the QR code or
/// link fragment, so the server holds ciphertext it can't read, for at most the TTL, until the first fetch deletes it.
/// </summary>
public sealed class InviteService {
    private static readonly byte[] GlobalSubject = "global"u8.ToArray();

    // KEYS = one share index per client scope (network, IPv6 /32). ARGV = member, ttl ms, then each key's cap. An index
    // holds one random member per live invite, scored by its expiry. All or nothing: a scope at its cap refuses the invite
    // without taking a share from the others.
    private const string ShareScript = """
        local t = redis.call('TIME')
        local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
        local ttl = tonumber(ARGV[2])
        for i = 1, #KEYS do
            redis.call('ZREMRANGEBYSCORE', KEYS[i], '-inf', now)
            if redis.call('ZCARD', KEYS[i]) >= tonumber(ARGV[2 + i]) then
                return 0
            end
        end
        for i = 1, #KEYS do
            redis.call('ZADD', KEYS[i], now + ttl, ARGV[1])
            if redis.call('PTTL', KEYS[i]) < ttl then
                redis.call('PEXPIRE', KEYS[i], ttl)
            end
        end
        return 1
        """;

    private readonly EphemeralStore _store;
    private readonly RateLimiter _limiter;
    private readonly EphemeralRedis _ephemeral;
    private readonly ClusterSecret _secret;
    private readonly InviteOptions _options;
    private readonly ILogger<InviteService> _logger;

    public InviteService(
        EphemeralStore store, RateLimiter limiter, EphemeralRedis ephemeral, ClusterSecret secret, GoldfishOptions options,
        ILogger<InviteService> logger) {
        _store = store;
        _limiter = limiter;
        _ephemeral = ephemeral;
        _secret = secret;
        _options = options.Invites;
        _logger = logger;
    }

    public async Task<ServiceResult<byte[]>> CreateAsync(byte[] blob, int? ttlSeconds, ClientSubject client) {
        if (blob.Length == 0) {
            return ServiceError.InvalidRequest;
        }
        if (blob.Length > ProtocolLimits.MaxInviteBytes) {
            return ServiceError.TooLarge;
        }
        // All or nothing, so a request refused by a narrow limit doesn't use up a wider one (the server-wide budget
        // above all). The live-invite cap below is the hard memory bound. The rates only shape abuse.
        var limit = await _limiter.CheckAllAsync([
            new RateScope(RatePolicies.InviteCreateGlobal, GlobalSubject),
            new RateScope(RatePolicies.InviteCreatePerAllocation, client.Allocation),
            new RateScope(RatePolicies.InviteCreatePerNetwork, client.Network),
            new RateScope(RatePolicies.InviteCreatePerIp, client.Host),
        ], failOpen: false);
        if (!limit.Allowed) {
            return ServiceError.RateLimited(limit);
        }
        var ttl = TimeSpan.FromSeconds(Math.Clamp(ttlSeconds ?? _options.DefaultTtlSeconds, _options.MinTtlSeconds, _options.MaxTtlSeconds));
        var share = await TakeShareAsync(client, ttl);
        if (share is null) {
            return ServiceError.RateLimited(new RateLimitDecision(false, TimeSpan.FromMinutes(5), RatePolicies.InviteCreatePerNetwork));
        }
        var id = RandomNumberGenerator.GetBytes(ProtocolLimits.InviteIdSize);
        if (!await _store.PutInviteAsync(id, blob, ttl, _options.MaxLiveInvites)) {
            await share.Value.ReleaseAsync();
            return ServiceError.RateLimited(new RateLimitDecision(false, TimeSpan.FromMinutes(5), RatePolicies.InviteCreateGlobal));
        }
        return id;
    }

    public async Task<ServiceResult<byte[]>> TakeAsync(byte[] id, ClientSubject client) {
        if (id.Length != ProtocolLimits.InviteIdSize) {
            return ServiceError.NotFound;
        }
        var limit = await _limiter.CheckAllAsync([
            new RateScope(RatePolicies.InviteFetchPerNetwork, client.Network),
            new RateScope(RatePolicies.InviteFetchPerIp, client.Host),
        ]);
        if (!limit.Allowed) {
            return ServiceError.RateLimited(limit);
        }
        var blob = await _store.TakeInviteAsync(id);
        return blob is null ? ServiceError.NotFound : blob;
    }

    /// <summary>
    /// Each network (and IPv6 /32) may hold only a share of <see cref="InviteOptions.MaxLiveInvites"/> at once, so a few
    /// networks uploading long-lived invites can't fill the cap and stop everyone else making invites. The share indexes
    /// live in the ephemeral Redis, keyed by an HMAC of the prefix, and hold only random members and expiry times, nothing
    /// that links to an invite. A share is held until the invite would expire, even if it's fetched sooner.
    /// </summary>
    /// <returns>The share taken, or null if a scope is at its cap. A default share (nothing taken) when shares are off.</returns>
    private async Task<Share?> TakeShareAsync(ClientSubject client, TimeSpan ttl) {
        var keys = new List<RedisKey>(2);
        var caps = new List<RedisValue>(2);
        if (_options.MaxLivePerNetwork > 0) {
            keys.Add(RedisKeys.InviteShare(await _secret.HmacHexAsync("inv-net", client.Network)));
            caps.Add(_options.MaxLivePerNetwork);
        }
        if (_options.MaxLivePerAllocation > 0 && client.Allocation is not null) {
            keys.Add(RedisKeys.InviteShare(await _secret.HmacHexAsync("inv-alloc", client.Allocation)));
            caps.Add(_options.MaxLivePerAllocation);
        }
        if (keys.Count == 0) {
            return new Share();
        }
        var member = Convert.ToHexString(RandomNumberGenerator.GetBytes(8));
        try {
            var taken = (long)await _ephemeral.Db.ScriptEvaluateAsync(
                ShareScript, keys.ToArray(), [member, (long)ttl.TotalMilliseconds, .. caps]);
            return taken == 1 ? new Share(_ephemeral, keys.ToArray(), member) : null;
        } catch (Exception ex) when (ex is RedisException or TimeoutException) {
            // The rate limits above fail closed, so they have just been charged with Redis up. Uploading without a share
            // is still bounded by MaxLiveInvites.
            _logger.LogWarning("Invite shares unavailable ({Type})", ex.GetType().Name);
            return new Share();
        }
    }

    private readonly record struct Share(EphemeralRedis? Redis = null, RedisKey[]? Keys = null, string Member = "") {
        public async Task ReleaseAsync() {
            if (Redis is null || Keys is null) {
                return;
            }
            try {
                foreach (var key in Keys) {
                    await Redis.Db.SortedSetRemoveAsync(key, Member);
                }
            } catch (Exception ex) when (ex is RedisException or TimeoutException) {
                // It expires with the invite's TTL anyway.
            }
        }
    }
}
