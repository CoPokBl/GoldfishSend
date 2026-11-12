using System.Security.Cryptography;
using GoldfishSend.Core.Options;
using GoldfishSend.Core.Protocol;
using GoldfishSend.Infrastructure.Redis;

namespace GoldfishSend.Infrastructure.Services;

/// <summary>
/// One-time invite drops. The blob is encrypted by the client under a key that only travels in the QR code or
/// link fragment, so the server holds ciphertext it can't read, for at most the TTL, until the first fetch deletes it.
/// </summary>
public sealed class InviteService {
    private readonly EphemeralStore _store;
    private readonly RateLimiter _limiter;
    private readonly InviteOptions _options;

    public InviteService(EphemeralStore store, RateLimiter limiter, GoldfishOptions options) {
        _store = store;
        _limiter = limiter;
        _options = options.Invites;
    }

    public async Task<ServiceResult<byte[]>> CreateAsync(byte[] blob, int? ttlSeconds, ClientSubject client) {
        if (blob.Length == 0) {
            return ServiceError.InvalidRequest;
        }
        if (blob.Length > ProtocolLimits.MaxInviteBytes) {
            return ServiceError.TooLarge;
        }
        // Per host, then per network, then globally. The global budget bounds the Redis memory invites can take
        // (5/s × 4 KiB × the max TTL), whatever address space an attacker controls.
        foreach (var (policy, subject) in new[] {
                     (RatePolicies.InviteCreatePerIp, client.Host),
                     (RatePolicies.InviteCreatePerNetwork, client.Network),
                     (RatePolicies.InviteCreateGlobal, "global"u8.ToArray()),
                 }) {
            var limit = await _limiter.CheckAsync(policy, subject, failOpen: false);
            if (!limit.Allowed) {
                return ServiceError.RateLimited(limit.RetryAfter);
            }
        }
        var ttl = Math.Clamp(ttlSeconds ?? _options.DefaultTtlSeconds, _options.MinTtlSeconds, _options.MaxTtlSeconds);
        var id = RandomNumberGenerator.GetBytes(ProtocolLimits.InviteIdSize);
        await _store.PutInviteAsync(id, blob, TimeSpan.FromSeconds(ttl));
        return id;
    }

    public async Task<ServiceResult<byte[]>> TakeAsync(byte[] id, ClientSubject client) {
        if (id.Length != ProtocolLimits.InviteIdSize) {
            return ServiceError.NotFound;
        }
        var limit = await _limiter.CheckAsync(RatePolicies.InviteFetchPerIp, client.Host);
        if (!limit.Allowed) {
            return ServiceError.RateLimited(limit.RetryAfter);
        }
        var blob = await _store.TakeInviteAsync(id);
        return blob is null ? ServiceError.NotFound : blob;
    }
}
