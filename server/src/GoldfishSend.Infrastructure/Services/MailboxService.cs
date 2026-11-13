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
    /// Verification pushes are padded to the size of a typical message so a push provider can't count mailbox creations
    /// (a proxy for how many contacts a device has) by size. The code is the first 16 bytes of the body.
    /// </summary>
    public const int VerificationBodySize = 1024;

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

    private DateOnly NewExpiry() => DateOnly.FromDateTime(DateTime.UtcNow).AddDays(_options.Mailboxes.LifetimeDays);

    /// <summary>The verification deadline, with up to a minute of jitter so batch members don't share a timestamp.</summary>
    private DateTime VerifyDeadline() {
        return DateTime.UtcNow.AddMinutes(_options.Mailboxes.VerificationMinutes).AddSeconds(RandomNumberGenerator.GetInt32(0, 60));
    }

    /// <summary>Per-mailbox code hash: <c>SHA256(code ‖ mailboxId)</c>. One code shared by a batch still gives every row a different value.</summary>
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
        // address (Tor exit, CGNAT) can't lock everyone behind it out of creating mailboxes.
        if (!await _pow.RedeemAsync(powChallenge, powNonce)) {
            return ServiceError.PowInvalid;
        }
        foreach (var (policy, subject) in new[] {
                     (RatePolicies.CreateGlobal, "global"u8.ToArray()),
                     (RatePolicies.CreatePerNetwork, client.Network),
                     (RatePolicies.CreatePerIp, client.Host),
                 }) {
            var limit = await _limiter.CheckAsync(policy, subject, failOpen: false);
            if (!limit.Allowed) {
                return ServiceError.RateLimited(limit);
            }
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

            if (await SendVerificationAsync(record, MailboxCrypto.Tag(sendSecret), code, ct) is { } pushError) {
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
        // Each rotation makes us POST to a new, arbitrary URL, so it's budgeted per mailbox as well as per IP.
        foreach (var id in ids) {
            var decision = await _limiter.CheckAsync(RatePolicies.RotatePerMailbox, id);
            if (!decision.Allowed) {
                return ServiceError.RateLimited(decision);
            }
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

            if (await SendVerificationAsync(record, MailboxCrypto.Tag(items[0].SendSecret), code, ct) is { } pushError) {
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
        // The network budget is always charged. The per-address budget is only peeked here, and charged when the
        // request fails ownership or verification (OwnerFailureAsync). Legitimate owners behind a shared address are
        // therefore never locked out by someone else's junk, while guessing stays limited.
        var net = await _limiter.CheckAsync(RatePolicies.OwnerPerNetwork, client.Network);
        if (!net.Allowed) {
            return ServiceError.RateLimited(net);
        }
        var ip = await _limiter.CheckAsync(RatePolicies.OwnerPerIp, client.Host, cost: 0);
        return ip.Allowed ? null : ServiceError.RateLimited(ip);
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
    private async Task<ServiceError?> SendVerificationAsync(EndpointRecord record, byte[] tag, byte[] code, CancellationToken ct) {
        // Every create or rotation makes us POST to a URL the client chose. Hosts no mailbox has used before get their own
        // small server-wide budget, so this can't be turned into a bulk "send requests to arbitrary sites" service.
        var host = Uri.TryCreate(record.Url, UriKind.Absolute, out var uri) ? uri.IdnHost.ToLowerInvariant() : "";
        var seenKey = RedisKeys.HostSeen(await _secret.HmacHexAsync("host-seen", System.Text.Encoding.UTF8.GetBytes(host)));
        var seen = false;
        try {
            seen = await _ephemeral.Db.KeyExistsAsync(seenKey);
        } catch (Exception ex) when (ex is StackExchange.Redis.RedisException or TimeoutException) {
            // Treat as unseen (charged below).
        }
        if (!seen) {
            var budget = await _limiter.CheckAsync(RatePolicies.NewHostGlobal, "newhost"u8.ToArray());
            if (!budget.Allowed) {
                return ServiceError.RateLimited(budget);
            }
        }

        var body = new byte[VerificationBodySize];
        code.CopyTo(body, 0);
        RandomNumberGenerator.Fill(body.AsSpan(code.Length));
        var envelope = PushEnvelope.Build(PushType.Verification, tag, body);
        try {
            var ttl = _options.Mailboxes.VerificationMinutes * 60;
            var result = await _push.SendAsync(record, envelope, ttl, ct);
            if (result.Status != PushStatus.Delivered) {
                _logger.LogInformation("Verification push not accepted: {Status}", result.Status);
            }
            switch (result.Status) {
                case PushStatus.Delivered:
                    try {
                        await _ephemeral.Db.StringSetAsync(seenKey, 1, TimeSpan.FromDays(30));
                    } catch (Exception ex) when (ex is StackExchange.Redis.RedisException or TimeoutException) {
                        // Only affects the new-host budget.
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
