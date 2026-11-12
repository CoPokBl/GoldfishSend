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

    public MailboxService(
        MailboxCrypto crypto, MailboxRepository mailboxes, EndpointValidator validator, PushClient push, PowService pow,
        RateLimiter limiter, DeliverySignal signal, GoldfishOptions options, ILogger<MailboxService> logger) {
        _crypto = crypto;
        _mailboxes = mailboxes;
        _validator = validator;
        _push = push;
        _pow = pow;
        _limiter = limiter;
        _signal = signal;
        _options = options;
        _logger = logger;
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

        foreach (var (policy, subject) in new[] { (RatePolicies.CreatePerIp, client.Host), (RatePolicies.CreatePerNetwork, client.Network) }) {
            var limit = await _limiter.CheckAsync(policy, subject, failOpen: false);
            if (!limit.Allowed) {
                return ServiceError.RateLimited(limit);
            }
        }
        if (!await _pow.RedeemAsync(powChallenge, powNonce)) {
            return ServiceError.PowInvalid;
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

            if (!await SendVerificationAsync(record, MailboxCrypto.Tag(sendSecret), code, ct)) {
                await _mailboxes.DeleteAsync(id, ct);
                return ServiceError.EndpointUnreachable;
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
            return ownerError;
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

            if (!await SendVerificationAsync(record, MailboxCrypto.Tag(items[0].SendSecret), code, ct)) {
                await _mailboxes.CancelRotationAsync(ids, ct);
                return ServiceError.EndpointUnreachable;
            }
            return true;
        } finally {
            CryptographicOperations.ZeroMemory(code);
        }
    }

    public async Task<ServiceResult<DateOnly>> VerifyAsync(
        IReadOnlyList<MailboxCredential> items, byte[] code, ClientSubject client, CancellationToken ct) {
        if (code.Length != PushEnvelope.VerificationCodeSize) {
            return ServiceError.InvalidRequest;
        }
        if (await CheckOwnerBatchAsync(items, client) is { } error) {
            return error;
        }
        var (rows, ids, ownerError) = await LoadOwnedAsync(items, ct);
        if (ownerError is not null) {
            return ownerError;
        }

        var max = _options.Mailboxes.MaxVerifyAttempts;
        // Spend the attempt atomically first, so concurrent guesses can't go over the cap.
        if (await _mailboxes.ConsumeVerifyAttemptAsync(ids, max, ct) != ids.Count) {
            return ServiceError.VerificationFailed;
        }

        var hashes = new List<(byte[] Id, byte[] VerifyHash)>(rows.Count);
        var allMatch = true;
        foreach (var row in rows) {
            var expected = VerifyHash(code, row.Id);
            allMatch &= row.VerifyHash is not null && CryptographicOperations.FixedTimeEquals(expected, row.VerifyHash);
            hashes.Add((row.Id, expected));
        }
        if (!allMatch) {
            return ServiceError.VerificationFailed;
        }

        // The completion re-checks the hash inside the transaction, which closes the race with a concurrent rotation.
        var expiry = NewExpiry();
        if (!await _mailboxes.CompleteVerificationAsync(hashes, max, expiry, ct)) {
            return ServiceError.VerificationFailed;
        }
        await _signal.NotifyRetryAsync();
        return expiry;
    }

    public async Task<ServiceResult<DateOnly>> RefreshAsync(IReadOnlyList<MailboxCredential> items, ClientSubject client, CancellationToken ct) {
        if (await CheckOwnerBatchAsync(items, client) is { } error) {
            return error;
        }
        var (_, ids, ownerError) = await LoadOwnedAsync(items, ct);
        if (ownerError is not null) {
            return ownerError;
        }
        var expiry = NewExpiry();
        await _mailboxes.RefreshAsync(ids, expiry, ct);
        return expiry;
    }

    public async Task<ServiceResult<bool>> DeleteAsync(IReadOnlyList<MailboxCredential> items, ClientSubject client, CancellationToken ct) {
        if (await CheckOwnerBatchAsync(items, client) is { } error) {
            return error;
        }
        var (_, ids, ownerError) = await LoadOwnedAsync(items, ct);
        if (ownerError is not null) {
            return ownerError;
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
        var limit = await _limiter.CheckAsync(RatePolicies.OwnerPerIp, client.Host);
        return limit.Allowed ? null : ServiceError.RateLimited(limit);
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

    private async Task<bool> SendVerificationAsync(EndpointRecord record, byte[] tag, byte[] code, CancellationToken ct) {
        var envelope = PushEnvelope.Build(PushType.Verification, tag, code);
        try {
            var ttl = _options.Mailboxes.VerificationMinutes * 60;
            var result = await _push.SendAsync(record, envelope, ttl, ct);
            if (result.Status != PushStatus.Delivered) {
                _logger.LogInformation("Verification push not accepted: {Status}", result.Status);
            }
            return result.Status == PushStatus.Delivered;
        } finally {
            CryptographicOperations.ZeroMemory(envelope);
        }
    }
}
