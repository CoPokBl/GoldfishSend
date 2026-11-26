using System.Security.Cryptography;
using GoldfishSend.Core.Crypto;
using GoldfishSend.Core.Net;
using GoldfishSend.Core.Options;
using GoldfishSend.Core.Protocol;
using GoldfishSend.Infrastructure.MySql;
using GoldfishSend.Infrastructure.Push;
using GoldfishSend.Infrastructure.Redis;
using Microsoft.Extensions.Logging;

namespace GoldfishSend.Infrastructure.Services;

public sealed record MailboxCredential(byte[] SendSecret, byte[] OwnerSecret) {
    public override string ToString() => "MailboxCredential { <redacted> }";
}

/// <param name="EndpointGone">The server can't currently reach the push endpoint of at least one of these mailboxes. Re-register push and rotate.</param>
public sealed record MailboxStatus(DateOnly ExpiresAt, bool EndpointGone);

public sealed record NewEndpoint(string Url, byte[] P256dh, byte[] Auth) {
    public override string ToString() => "NewEndpoint { <redacted> }";
}

public sealed class MailboxService {
    private static readonly byte[] GlobalSubject = "global"u8.ToArray();
    private static readonly byte[] NewHostSubject = "newhost"u8.ToArray();

    private readonly MailboxCrypto _crypto;
    private readonly MailboxRepository _mailboxes;
    private readonly EndpointValidator _validator;
    private readonly PushClient _push;
    private readonly PowService _pow;
    private readonly RateLimiter _limiter;
    private readonly DeliverySignal _signal;
    private readonly GoldfishOptions _options;
    private readonly ILogger<MailboxService> _logger;
    private readonly EphemeralRedis _ephemeral;
    private readonly ClusterSecret _secret;

    /// <summary>
    /// The size of a short text message's body, so a verification push carries what a message would. The Web Push layer
    /// then pads every push to the same few sizes (<see cref="WebPushCrypto.PaddedRecordLength"/>), and the push TTL is
    /// a fresh message's, so a push provider can't count mailbox creations (a proxy for how many contacts a device has)
    /// by size or TTL. The code is the first 16 bytes of the body, and the rest is random.
    /// </summary>
    public const int VerificationBodySize = 512;

    public MailboxService(
        MailboxCrypto crypto, MailboxRepository mailboxes, EndpointValidator validator, PushClient push, PowService pow,
        RateLimiter limiter, DeliverySignal signal, GoldfishOptions options, ILogger<MailboxService> logger,
        EphemeralRedis ephemeral, ClusterSecret secret) {
        _crypto = crypto;
        _mailboxes = mailboxes;
        _validator = validator;
        _push = push;
        _pow = pow;
        _limiter = limiter;
        _signal = signal;
        _options = options;
        _logger = logger;
        _ephemeral = ephemeral;
        _secret = secret;
    }

    private DateOnly NewExpiry() => Expiry(DateOnly.FromDateTime(DateTime.UtcNow), _options.Mailboxes, RandomNumberGenerator.GetInt32);

    private DateTime VerifyDeadline() => Deadline(DateTime.UtcNow, _options.Mailboxes, RandomNumberGenerator.GetInt32);

    /// <summary>
    /// A mailbox's expiry: <see cref="MailboxOptions.LifetimeDays"/> from <paramref name="today"/>, less a random 0 to
    /// <see cref="MailboxOptions.ExpiryJitterDays"/> days (never below one day). <paramref name="roll"/> is
    /// <c>RandomNumberGenerator.GetInt32(from, to)</c>, exclusive upper bound.
    /// </summary>
    internal static DateOnly Expiry(DateOnly today, MailboxOptions options, Func<int, int, int> roll) {
        var lifetime = Math.Max(1, options.LifetimeDays);
        var jitter = Math.Clamp(options.ExpiryJitterDays, 0, lifetime - 1);
        return today.AddDays(lifetime - roll(0, jitter + 1));
    }

    /// <summary>
    /// The verification deadline: <see cref="MailboxOptions.VerificationMinutes"/> from <paramref name="now"/>, plus a
    /// random 0 to as long again, to the second.
    /// </summary>
    internal static DateTime Deadline(DateTime now, MailboxOptions options, Func<int, int, int> roll) {
        var seconds = Math.Max(1, options.VerificationMinutes) * 60;
        return now.AddSeconds(seconds + roll(0, seconds));
    }

    /// <summary>Per-mailbox code hash: <c>SHA256(code ‖ mailboxId)</c>, so equal codes never show as equal rows.</summary>
    internal static byte[] VerifyHash(ReadOnlySpan<byte> code, ReadOnlySpan<byte> mailboxId) {
        Span<byte> buffer = stackalloc byte[code.Length + mailboxId.Length];
        code.CopyTo(buffer);
        mailboxId.CopyTo(buffer[code.Length..]);
        return SHA256.HashData(buffer);
    }

    public async Task<ServiceResult<bool>> CreateAsync(
        byte[] powChallenge, byte[] powNonce, byte[] sendSecret, byte[] ownerHash, NewEndpoint endpoint, ClientSubject client,
        CancellationToken ct) {
        if (sendSecret.Length != MailboxCrypto.SecretSize || ownerHash.Length != 32) {
            return ServiceError.InvalidRequest;
        }
        if (ValidateEndpoint(endpoint) is { } endpointError) {
            return endpointError;
        }

        // The proof of work is checked first: requests without one never touch the address budgets, so junk from a shared
        // address (Tor exit, CGNAT) can't lock everyone behind it out of creating mailboxes. A valid one counts toward the
        // load of the network that asked for it and of this one (PowService.RedeemAsync), even if a limit below refuses
        // the creation, so a flood slows the flooder.
        if (ServiceError.FromPow(await _pow.RedeemAsync(powChallenge, powNonce, client, PowPurpose.Create, ct)) is { } powError) {
            return powError;
        }
        // All or nothing: a creation refused by a narrow limit doesn't use up the network's or the server's budget.
        var limit = await _limiter.CheckAllAsync([
            new RateScope(RatePolicies.CreateGlobal, GlobalSubject),
            new RateScope(RatePolicies.CreatePerAllocation, client.Allocation),
            new RateScope(RatePolicies.CreatePerNetwork, client.Network),
            new RateScope(RatePolicies.CreatePerIp, client.Host),
        ], failOpen: false);
        if (!limit.Allowed) {
            return ServiceError.RateLimited(limit);
        }

        var id = _crypto.MailboxId(sendSecret);
        var sealKey = _crypto.SealKey(sendSecret);
        var record = new EndpointRecord(endpoint.Url, endpoint.P256dh, endpoint.Auth);
        var code = RandomNumberGenerator.GetBytes(PushEnvelope.VerificationCodeSize);
        try {
            var sealedEndpoint = MailboxCrypto.SealEndpoint(sealKey, record, id);
            var inserted = await _mailboxes.InsertPendingAsync(
                id, ownerHash, sealedEndpoint, VerifyHash(code, id), VerifyDeadline(), NewExpiry(), ct);
            if (!inserted) {
                return ServiceError.MailboxExists;
            }

            if (await SendVerificationAsync(record, MailboxCrypto.Tag(sendSecret), code, client, ct) is { } pushError) {
                await _mailboxes.DeleteAsync(id, ct);
                return pushError;
            }
            return true;
        } finally {
            CryptographicOperations.ZeroMemory(sealKey);
            CryptographicOperations.ZeroMemory(code);
        }
    }

    public async Task<ServiceResult<bool>> RotateAsync(
        IReadOnlyList<MailboxCredential> items, NewEndpoint endpoint, ClientSubject client, CancellationToken ct) {
        if (await CheckOwnerBatchAsync(items, client) is { } error) {
            return error;
        }
        if (ValidateEndpoint(endpoint) is { } endpointError) {
            return endpointError;
        }

        var (rows, ids, ownerError) = await LoadOwnedAsync(items, ct);
        if (ownerError is not null) {
            return await OwnerFailureAsync(ownerError, client);
        }
        // Rotation is for live mailboxes. A brand-new one must finish (or redo) creation, which costs PoW.
        if (rows.Any(r => r.State == MailboxState.PendingVerification)) {
            return ServiceError.NotFound;
        }
        // Each rotation makes us POST to a new, arbitrary URL, so it's budgeted per mailbox as well as per IP. All or
        // nothing, so a batch refused for one mailbox doesn't spend the others' budgets.
        var rotate = await _limiter.CheckAllAsync(ids.Select(id => new RateScope(RatePolicies.RotatePerMailbox, id)).ToList());
        if (!rotate.Allowed) {
            return ServiceError.RateLimited(rotate);
        }

        var record = new EndpointRecord(endpoint.Url, endpoint.P256dh, endpoint.Auth);
        var code = RandomNumberGenerator.GetBytes(PushEnvelope.VerificationCodeSize);
        try {
            var pending = new List<(byte[], byte[], byte[], DateTime)>(items.Count);
            for (var i = 0; i < items.Count; i++) {
                var sealKey = _crypto.SealKey(items[i].SendSecret);
                pending.Add((ids[i], MailboxCrypto.SealEndpoint(sealKey, record, ids[i]), VerifyHash(code, ids[i]), VerifyDeadline()));
                CryptographicOperations.ZeroMemory(sealKey);
            }
            if (await _mailboxes.BeginRotationAsync(pending, ct) != items.Count) {
                return ServiceError.NotFound;
            }

            if (await SendVerificationAsync(record, MailboxCrypto.Tag(items[0].SendSecret), code, client, ct) is { } pushError) {
                await _mailboxes.CancelRotationAsync(ids, ct);
                return pushError;
            }
            return true;
        } finally {
            CryptographicOperations.ZeroMemory(code);
        }
    }

    public async Task<ServiceResult<MailboxStatus>> VerifyAsync(
        IReadOnlyList<MailboxCredential> items, byte[] code, ClientSubject client, CancellationToken ct) {
        if (code.Length != PushEnvelope.VerificationCodeSize) {
            return ServiceError.InvalidRequest;
        }
        if (await CheckOwnerBatchAsync(items, client) is { } error) {
            return error;
        }
        var (rows, ids, ownerError) = await LoadOwnedAsync(items, ct);
        if (ownerError is not null) {
            return await OwnerFailureAsync(ownerError, client);
        }

        var max = _options.Mailboxes.MaxVerifyAttempts;
        // Spend the attempt atomically first, so concurrent guesses can't go over the cap.
        if (await _mailboxes.ConsumeVerifyAttemptAsync(ids, max, ct) != ids.Count) {
            return await OwnerFailureAsync(ServiceError.VerificationFailed, client);
        }

        var hashes = new List<(byte[] Id, byte[] VerifyHash)>(rows.Count);
        var allMatch = true;
        foreach (var row in rows) {
            var expected = VerifyHash(code, row.Id);
            allMatch &= row.VerifyHash is not null && CryptographicOperations.FixedTimeEquals(expected, row.VerifyHash);
            hashes.Add((row.Id, expected));
        }
        if (!allMatch) {
            return await OwnerFailureAsync(ServiceError.VerificationFailed, client);
        }

        // The completion re-checks the hash inside the transaction, which closes the race with a concurrent rotation.
        var expiry = NewExpiry();
        if (!await _mailboxes.CompleteVerificationAsync(hashes, max, expiry, ct)) {
            return await OwnerFailureAsync(ServiceError.VerificationFailed, client);
        }
        // New mailboxes (not rotations) drive the server-wide PoW load. Only a count goes to Redis, nothing about the mailbox
        // or the client. The completion succeeds once per code, so a mailbox is counted once.
        await _pow.CountVerifiedAsync(rows.Count(r => r.State == MailboxState.PendingVerification));
        await _signal.NotifyRetryAsync();
        // Verification makes every listed mailbox active again.
        return new MailboxStatus(expiry, EndpointGone: false);
    }

    public async Task<ServiceResult<MailboxStatus>> RefreshAsync(IReadOnlyList<MailboxCredential> items, ClientSubject client, CancellationToken ct) {
        if (await CheckOwnerBatchAsync(items, client) is { } error) {
            return error;
        }
        var (rows, ids, ownerError) = await LoadOwnedAsync(items, ct);
        if (ownerError is not null) {
            return await OwnerFailureAsync(ownerError, client);
        }
        var expiry = NewExpiry();
        await _mailboxes.RefreshAsync(ids, expiry, ct);
        // Tells the client its push endpoint is unreachable, so it can re-register and rotate instead of waiting forever.
        return new MailboxStatus(expiry, rows.Any(r => r.State == MailboxState.EndpointGone));
    }

    public async Task<ServiceResult<bool>> DeleteAsync(IReadOnlyList<MailboxCredential> items, ClientSubject client, CancellationToken ct) {
        if (await CheckOwnerBatchAsync(items, client) is { } error) {
            return error;
        }
        var (_, ids, ownerError) = await LoadOwnedAsync(items, ct);
        if (ownerError is not null) {
            return await OwnerFailureAsync(ownerError, client);
        }
        await _mailboxes.DeleteManyAsync(ids, ct);
        return true;
    }

    private ServiceError? ValidateEndpoint(NewEndpoint endpoint) {
        if (endpoint.Auth.Length != WebPushCrypto.AuthSecretSize || !WebPushCrypto.IsValidPublicKey(endpoint.P256dh)) {
            return ServiceError.InvalidRequest;
        }
        return _validator.TryValidate(endpoint.Url, out _) ? null : ServiceError.InvalidEndpoint;
    }

    private async Task<ServiceError?> CheckOwnerBatchAsync(IReadOnlyList<MailboxCredential> items, ClientSubject client) {
        if (items.Count == 0 || items.Count > _options.Mailboxes.MaxBatch) {
            return ServiceError.InvalidRequest;
        }
        foreach (var item in items) {
            if (item.SendSecret.Length != MailboxCrypto.SecretSize || item.OwnerSecret.Length != MailboxCrypto.SecretSize) {
                return ServiceError.InvalidRequest;
            }
        }
        // The network and /32 budgets are always charged. The per-address budget is only peeked here, and charged when the
        // request fails ownership or verification (OwnerFailureAsync). Legitimate owners behind a shared address are
        // therefore never locked out by someone else's junk, while guessing stays limited.
        var limit = await _limiter.CheckAllAsync([
            new RateScope(RatePolicies.OwnerPerAllocation, client.Allocation),
            new RateScope(RatePolicies.OwnerPerNetwork, client.Network),
            new RateScope(RatePolicies.OwnerPerIp, client.Host, Cost: 0),
        ]);
        return limit.Allowed ? null : ServiceError.RateLimited(limit);
    }

    private async Task<ServiceError> OwnerFailureAsync(ServiceError error, ClientSubject client) {
        await _limiter.CheckAsync(RatePolicies.OwnerPerIp, client.Host);
        return error;
    }

    /// <summary>
    /// Loads the mailboxes and checks ownership. Any unknown mailbox or owner mismatch fails the whole batch
    /// with <c>404</c>, so callers can't tell "doesn't exist" apart from "not yours".
    /// </summary>
    private async Task<(IReadOnlyList<MailboxRow> Rows, List<byte[]> Ids, ServiceError? Error)> LoadOwnedAsync(
        IReadOnlyList<MailboxCredential> items, CancellationToken ct) {
        var ids = items.Select(i => _crypto.MailboxId(i.SendSecret)).ToList();
        if (ids.Select(Convert.ToHexString).Distinct().Count() != ids.Count) {
            return ([], ids, ServiceError.InvalidRequest);
        }

        var rows = await _mailboxes.GetManyAsync(ids, ct);
        var byId = rows.ToDictionary(r => Convert.ToHexString(r.Id));
        var ordered = new List<MailboxRow>(items.Count);
        var ok = true;
        for (var i = 0; i < items.Count; i++) {
            if (!byId.TryGetValue(Convert.ToHexString(ids[i]), out var row)) {
                ok = false;
                continue;
            }
            ok &= MailboxCrypto.OwnerMatches(items[i].OwnerSecret, row.OwnerHash);
            ordered.Add(row);
        }
        return ok ? (ordered, ids, null) : ([], ids, ServiceError.NotFound);
    }

    /// <returns>Null when the push service accepted it, otherwise the error to return.</returns>
    private async Task<ServiceError?> SendVerificationAsync(
        EndpointRecord record, byte[] tag, byte[] code, ClientSubject client, CancellationToken ct) {
        // Every create or rotation makes us POST to a URL the client chose. Push hosts no mailbox has used before have
        // their own small budgets, so this can't be turned into a bulk "send requests to arbitrary sites" service. Hosts
        // are grouped by registrable domain, so a wildcard domain counts once. The client's network and /32 pay for every
        // attempt. The server-wide budget is only checked here and charged once the host has accepted the push, so junk or
        // unreachable host names can't drain it for everyone. Well-known push services never count as new, so a restart
        // of the ephemeral Redis (which forgets every seen host) doesn't put all users behind the server-wide budget.
        var host = Uri.TryCreate(record.Url, UriKind.Absolute, out var uri) ? uri.IdnHost.ToLowerInvariant() : "";
        var seenKey = RedisKeys.HostSeen(await _secret.HmacHexAsync(
            "host-seen", System.Text.Encoding.UTF8.GetBytes(HostGrouping.BaseDomain(host))));
        var seen = HostGrouping.IsWithin(host, _options.Push.KnownHosts);
        if (!seen) {
            try {
                seen = await _ephemeral.Db.KeyExistsAsync(seenKey);
            } catch (Exception ex) when (ex is StackExchange.Redis.RedisException or TimeoutException) {
                // Treat as unseen (charged below).
            }
        }
        if (!seen) {
            var budget = await _limiter.CheckAllAsync([
                new RateScope(RatePolicies.NewHostGlobal, NewHostSubject, Cost: 0),
                new RateScope(RatePolicies.NewHostPerAllocation, client.Allocation),
                new RateScope(RatePolicies.NewHostPerNetwork, client.Network),
            ]);
            if (!budget.Allowed) {
                return ServiceError.RateLimited(budget);
            }
        }

        var body = new byte[VerificationBodySize];
        code.CopyTo(body, 0);
        RandomNumberGenerator.Fill(body.AsSpan(code.Length));
        var envelope = PushEnvelope.Build(PushType.Verification, tag, body);
        try {
            // The TTL a message sent now with the default TTL would get on its first push. The app ignores a code that
            // arrives after the verification deadline, so the longer TTL costs nothing.
            var now = DateTime.UtcNow;
            var ttl = (int)(HeldExpiry.At(now, _options.Messages.DefaultTtlSeconds) - now).TotalSeconds;
            var result = await _push.SendAsync(record, envelope, ttl, ct);
            if (result.Status != PushStatus.Delivered) {
                _logger.LogInformation("Verification push not accepted: {Status}", result.Status);
            }
            switch (result.Status) {
                case PushStatus.Delivered:
                    if (!seen) {
                        try {
                            await _ephemeral.Db.StringSetAsync(seenKey, 1, TimeSpan.FromDays(30));
                        } catch (Exception ex) when (ex is StackExchange.Redis.RedisException or TimeoutException) {
                            // Only affects the new-host budget.
                        }
                        // The verdict doesn't matter: the push has gone. Concurrent first pushes can overshoot by a few.
                        await _limiter.CheckAsync(RatePolicies.NewHostGlobal, NewHostSubject);
                    }
                    return null;
                case PushStatus.Deferred:
                    // We held it back ourselves (the push service is paused or paced), so it isn't the client's fault.
                    return ServiceError.Unavailable with { RetryAfter = result.RetryAfter ?? TimeSpan.FromSeconds(30) };
                default:
                    return ServiceError.EndpointUnreachable;
            }
        } finally {
            CryptographicOperations.ZeroMemory(envelope);
            CryptographicOperations.ZeroMemory(body);
        }
    }
}
