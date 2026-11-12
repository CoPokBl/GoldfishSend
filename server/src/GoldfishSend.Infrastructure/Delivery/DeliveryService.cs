using System.Diagnostics.Metrics;
using System.Security.Cryptography;
using GoldfishSend.Core;
using GoldfishSend.Core.Crypto;
using GoldfishSend.Infrastructure.MySql;
using GoldfishSend.Infrastructure.Push;
using Microsoft.Extensions.Logging;

namespace GoldfishSend.Infrastructure.Delivery;

public enum DeliveryOutcomeKind {
    /// <summary>Handed to the push server. Forget the message.</summary>
    Delivered,
    /// <summary>It can never be delivered (expired, mailbox deleted, rejected, or the key was shredded). Forget the message.</summary>
    Dropped,
    /// <summary>Temporary failure. Try again at <see cref="DeliveryOutcome.NextAttemptAt"/>.</summary>
    Retry,
    /// <summary>The mailbox can't receive right now (endpoint gone or awaiting verification). Hold until the owner fixes it or the TTL ends.</summary>
    Hold,
}

public readonly record struct DeliveryOutcome(DeliveryOutcomeKind Kind, DateTime NextAttemptAt = default);

/// <summary>One delivery attempt. It's shared by the hot-queue worker and the retry worker.</summary>
public sealed class DeliveryService {
    /// <summary>How often a held message re-checks its mailbox even without a wake-up.</summary>
    private static readonly TimeSpan HoldRecheck = TimeSpan.FromHours(1);

    private readonly MailboxRepository _mailboxes;
    private readonly EpochKeyring _keyring;
    private readonly PushClient _push;
    private readonly ILogger<DeliveryService> _logger;
    private readonly Counter<long> _outcomes;

    public DeliveryService(
        MailboxRepository mailboxes, EpochKeyring keyring, PushClient push, Meter meter, ILogger<DeliveryService> logger) {
        _mailboxes = mailboxes;
        _keyring = keyring;
        _push = push;
        _logger = logger;
        _outcomes = meter.CreateCounter<long>("goldfish.delivery.outcomes");
    }

    public async Task<DeliveryOutcome> AttemptAsync(DeliveryJob job, CancellationToken ct) {
        var outcome = await AttemptCoreAsync(job, ct);
        _outcomes.Add(1, new KeyValuePair<string, object?>("outcome", outcome.Kind.ToString()));
        return outcome;
    }

    private async Task<DeliveryOutcome> AttemptCoreAsync(DeliveryJob job, CancellationToken ct) {
        var now = DateTime.UtcNow;
        if (job.ExpiresAt <= now) {
            return new DeliveryOutcome(DeliveryOutcomeKind.Dropped);
        }

        var mailbox = await _mailboxes.GetAsync(job.MailboxId, ct);
        if (mailbox is null) {
            return new DeliveryOutcome(DeliveryOutcomeKind.Dropped);
        }
        if (mailbox.State != MailboxState.Active) {
            return Hold(job, now);
        }

        var epochKey = await _keyring.GetAsync(job.KeyEpoch, ct);
        if (epochKey is null) {
            _logger.LogWarning("Dropping a message whose epoch key has been shredded");
            return new DeliveryOutcome(DeliveryOutcomeKind.Dropped);
        }

        byte[] sealKey;
        byte[] envelope;
        try {
            (sealKey, envelope) = JobCodec.Open(epochKey, job.Id, job.Blob);
        } catch (CryptographicException) {
            _logger.LogWarning("Dropping a message that failed authentication");
            return new DeliveryOutcome(DeliveryOutcomeKind.Dropped);
        }

        try {
            Core.Protocol.EndpointRecord endpoint;
            try {
                endpoint = MailboxCrypto.UnsealEndpoint(sealKey, mailbox.SealedEndpoint, mailbox.Id);
            } catch (Exception ex) when (ex is CryptographicException or FormatException) {
                _logger.LogWarning("Dropping a message: mailbox endpoint failed to unseal");
                return new DeliveryOutcome(DeliveryOutcomeKind.Dropped);
            }

            var ttl = (int)Math.Max(0, (job.ExpiresAt - now).TotalSeconds);
            var result = await _push.SendAsync(endpoint, envelope, ttl, ct);
            switch (result.Status) {
                case PushStatus.Delivered:
                    return new DeliveryOutcome(DeliveryOutcomeKind.Delivered);
                case PushStatus.Gone:
                    await _mailboxes.MarkEndpointGoneAsync(mailbox.Id, mailbox.SealedEndpoint, ct);
                    return Hold(job, now);
                case PushStatus.Rejected:
                    return new DeliveryOutcome(DeliveryOutcomeKind.Dropped);
                default:
                    var next = now + Backoff.Next(job.Attempts + 1, result.RetryAfter);
                    // If the message would expire before the next try, it's undeliverable within its TTL.
                    return next >= job.ExpiresAt
                        ? new DeliveryOutcome(DeliveryOutcomeKind.Dropped)
                        : new DeliveryOutcome(DeliveryOutcomeKind.Retry, next);
            }
        } finally {
            CryptographicOperations.ZeroMemory(sealKey);
            CryptographicOperations.ZeroMemory(envelope);
        }
    }

    private static DeliveryOutcome Hold(DeliveryJob job, DateTime now) {
        var next = now + HoldRecheck;
        return new DeliveryOutcome(DeliveryOutcomeKind.Hold, next < job.ExpiresAt ? next : job.ExpiresAt);
    }
}
