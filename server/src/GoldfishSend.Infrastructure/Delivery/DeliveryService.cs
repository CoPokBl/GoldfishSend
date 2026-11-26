using System.Diagnostics.Metrics;
using System.Security.Cryptography;
using GoldfishSend.Core;
using GoldfishSend.Core.Crypto;
using GoldfishSend.Core.Options;
using GoldfishSend.Infrastructure.MySql;
using GoldfishSend.Infrastructure.Push;
using GoldfishSend.Infrastructure.Redis;
using Microsoft.Extensions.Logging;

namespace GoldfishSend.Infrastructure.Delivery;

public enum DeliveryOutcomeKind {
    /// <summary>Handed to the push server. Forget the message.</summary>
    Delivered,
    /// <summary>It can never be delivered (expired, mailbox deleted, rejected, or the key was shredded). Forget the message.</summary>
    Dropped,
    /// <summary>Try again at <see cref="DeliveryOutcome.NextAttemptAt"/>.</summary>
    Retry,
    /// <summary>
    /// The mailbox can't receive right now (endpoint gone or awaiting verification). Park until its expiry. Verification,
    /// endpoint rotation or a re-probe wakes it earlier.
    /// </summary>
    Hold,
}

/// <param name="CountsAsAttempt">
/// False for local deferrals (pacing, caps, circuit open, mailbox busy). Those mustn't escalate the message's backoff.
/// </param>
/// <param name="HeldEndpoint">
/// For <see cref="DeliveryOutcomeKind.Hold"/>: the sealed endpoint the mailbox had when this attempt read it. Whoever
/// parks the message checks it against the mailbox afterwards (<see cref="PendingMessageRepository.RecheckHeldAsync"/>).
/// </param>
public readonly record struct DeliveryOutcome(
    DeliveryOutcomeKind Kind, DateTime NextAttemptAt = default, bool CountsAsAttempt = true, byte[]? HeldEndpoint = null);

/// <summary>One delivery attempt. It's shared by the hot-queue worker and the retry worker.</summary>
public sealed class DeliveryService {
    private readonly MailboxRepository _mailboxes;
    private readonly PendingMessageRepository _pending;
    private readonly EpochKeyring _keyring;
    private readonly PushClient _push;
    private readonly MailboxLeases _leases;
    private readonly DeliverySignal _signal;
    private readonly TimeSpan _leaseTtl;
    private readonly ILogger<DeliveryService> _logger;
    private readonly Counter<long> _outcomes;

    public DeliveryService(
        MailboxRepository mailboxes, PendingMessageRepository pending, EpochKeyring keyring, PushClient push, MailboxLeases leases,
        DeliverySignal signal, GoldfishOptions options, Meter meter, ILogger<DeliveryService> logger) {
        _mailboxes = mailboxes;
        _pending = pending;
        _keyring = keyring;
        _push = push;
        _leases = leases;
        _signal = signal;
        _logger = logger;
        _leaseTtl = TimeSpan.FromSeconds(options.Push.RequestTimeoutSeconds + 20);
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
        if (mailbox.State == MailboxState.PendingVerification) {
            return Park(job, mailbox);
        }

        var epochKey = await _keyring.GetAsync(job.KeyEpoch, ct);
        if (epochKey is null) {
            _logger.LogWarning("Dropping a message whose epoch key has been shredded");
            return new DeliveryOutcome(DeliveryOutcomeKind.Dropped);
        }

        byte[] sealKey;
        byte[] envelope;
        try {
            (sealKey, envelope) = JobCodec.Open(epochKey, job.Id, job.MailboxId, job.ExpiresAt, job.Blob);
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

            // A few deliveries per mailbox at a time, cluster-wide.
            var lease = await _leases.TryAcquireAsync(job.MailboxId, _leaseTtl);
            if (lease is null) {
                // This mailbox already has its share of pushes in flight (usually a burst). Come back shortly.
                return Defer(job, now, TimeSpan.FromMilliseconds(250));
            }
            PushResult result;
            try {
                var ttl = (int)Math.Max(0, (job.ExpiresAt - now).TotalSeconds);
                result = await _push.SendAsync(endpoint, envelope, ttl, ct, job.MailboxId);
            } finally {
                await lease.ReleaseAsync();
            }

            switch (result.Status) {
                case PushStatus.Delivered:
                    if (mailbox.State == MailboxState.EndpointGone) {
                        // The "dead" endpoint works again (a re-probe, or a new message got through): wake everything held.
                        if (await _mailboxes.MarkRecoveredAsync(mailbox.Id, mailbox.SealedEndpoint, ct)) {
                            await _pending.WakeMailboxAsync(mailbox.Id, ct);
                            await _signal.NotifyRetryAsync();
                        }
                    }
                    return new DeliveryOutcome(DeliveryOutcomeKind.Delivered);
                case PushStatus.Gone:
                    // A no-op if the endpoint was replaced meanwhile. The parked message is then woken by the recheck
                    // that follows parking, since the mailbox no longer has the endpoint that failed.
                    await _mailboxes.MarkEndpointGoneAsync(mailbox.Id, mailbox.SealedEndpoint, ct);
                    return Park(job, mailbox);
                case PushStatus.Rejected:
                    return new DeliveryOutcome(DeliveryOutcomeKind.Dropped);
                case PushStatus.Deferred:
                    return Defer(job, now, result.RetryAfter ?? TimeSpan.FromSeconds(1));
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

    /// <summary>
    /// Parked until expiry. Something else (verification, rotation, re-probe) wakes it if the mailbox recovers, and the
    /// recheck after parking catches a recovery that committed while this attempt was running.
    /// </summary>
    private static DeliveryOutcome Park(DeliveryJob job, MailboxRow mailbox) =>
        new(DeliveryOutcomeKind.Hold, job.ExpiresAt, HeldEndpoint: mailbox.SealedEndpoint);

    /// <summary>A local deferral: it retries soon, without counting as an attempt.</summary>
    private static DeliveryOutcome Defer(DeliveryJob job, DateTime now, TimeSpan delay) {
        var jitter = TimeSpan.FromMilliseconds(Random.Shared.Next(0, (int)Math.Min(1000, Math.Max(100, delay.TotalMilliseconds))));
        var next = now + delay + jitter;
        return next >= job.ExpiresAt
            ? new DeliveryOutcome(DeliveryOutcomeKind.Dropped)
            : new DeliveryOutcome(DeliveryOutcomeKind.Retry, next, CountsAsAttempt: false);
    }
}
