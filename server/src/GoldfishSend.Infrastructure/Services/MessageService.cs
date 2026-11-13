using System.Diagnostics.Metrics;
using System.Security.Cryptography;
using GoldfishSend.Core.Crypto;
using GoldfishSend.Core.Options;
using GoldfishSend.Core.Protocol;
using GoldfishSend.Infrastructure.Delivery;
using GoldfishSend.Infrastructure.MySql;
using GoldfishSend.Infrastructure.Redis;

namespace GoldfishSend.Infrastructure.Services;

public sealed record PowToken(byte[] Challenge, byte[] Nonce) {
    public override string ToString() => "PowToken { <redacted> }";
}

public sealed class MessageService {
    private static readonly byte[] GlobalSubject = "global"u8.ToArray();

    private readonly MailboxCrypto _crypto;
    private readonly MailboxRepository _mailboxes;
    private readonly PendingMessageRepository _pending;
    private readonly EpochKeyring _keyring;
    private readonly MessageQueue _queue;
    private readonly IdempotencyStore _idempotency;
    private readonly HeldQuota _heldQuota;
    private readonly RateLimiter _limiter;
    private readonly PowService _pow;
    private readonly DeliverySignal _signal;
    private readonly GoldfishOptions _options;
    private readonly Counter<long> _accepted;
    private readonly Counter<long> _spilled;

    public MessageService(
        MailboxCrypto crypto, MailboxRepository mailboxes, PendingMessageRepository pending, EpochKeyring keyring, MessageQueue queue,
        IdempotencyStore idempotency, HeldQuota heldQuota, RateLimiter limiter, PowService pow, DeliverySignal signal,
        GoldfishOptions options, Meter meter) {
        _crypto = crypto;
        _mailboxes = mailboxes;
        _pending = pending;
        _keyring = keyring;
        _queue = queue;
        _idempotency = idempotency;
        _heldQuota = heldQuota;
        _limiter = limiter;
        _pow = pow;
        _signal = signal;
        _options = options;
        _accepted = meter.CreateCounter<long>("goldfish.messages.accepted");
        _spilled = meter.CreateCounter<long>("goldfish.messages.spilled");
    }

    public int ClampTtl(int? requested) {
        var ttl = requested ?? _options.Messages.DefaultTtlSeconds;
        return Math.Clamp(ttl, _options.Messages.MinTtlSeconds, _options.Messages.MaxTtlSeconds);
    }

    /// <returns>The message id. A duplicate idempotency key returns the original id.</returns>
    public async Task<ServiceResult<byte[]>> AcceptAsync(
        byte[] sendSecret, byte[] body, int? ttlSeconds, byte[]? idempotencyKey, PowToken? pow, ClientSubject client,
        CancellationToken ct) {
        if (sendSecret.Length != MailboxCrypto.SecretSize
            || (idempotencyKey is not null && idempotencyKey.Length != ProtocolLimits.IdempotencyKeySize)
            || body.Length == 0) {
            return ServiceError.InvalidRequest;
        }
        if (body.Length > ProtocolLimits.MaxMessageBytes) {
            return ServiceError.TooLarge;
        }

        // Client limits run widest first (network, then address), so one allocation can't multiply its budget by rotating
        // addresses. Shared-address users (Tor, CGNAT) who hit either can pay with a proof of work instead.
        foreach (var (policy, subject) in new[] { (RatePolicies.SendPerNetwork, client.Network), (RatePolicies.SendPerIp, client.Host) }) {
            var decision = await _limiter.CheckAsync(policy, subject);
            if (!decision.Allowed) {
                if (pow is null || !await _pow.RedeemAsync(pow.Challenge, pow.Nonce, countsTowardLoad: false)) {
                    return ServiceError.RateLimited(decision);
                }
                break; // A valid PoW pays for this request at every client scope.
            }
        }

        // Caps how many token lookups can reach MySQL, whatever the source.
        var lookup = await _limiter.CheckAsync(RatePolicies.SendLookupGlobal, GlobalSubject);
        if (!lookup.Allowed) {
            return ServiceError.RateLimited(lookup);
        }

        var mailboxId = _crypto.MailboxId(sendSecret);
        var mailbox = await _mailboxes.GetAsync(mailboxId, ct);
        // Messages to a mailbox whose endpoint went away are still accepted and held. Never-verified mailboxes don't exist yet.
        if (mailbox is null || mailbox.State == MailboxState.PendingVerification) {
            return ServiceError.NotFound;
        }

        // These limits protect the recipient from a hostile contact flooding them.
        foreach (var policy in new[] { RatePolicies.SendPerMailboxDaily, RatePolicies.SendPerMailbox }) {
            var decision = await _limiter.CheckAsync(policy, mailboxId);
            if (!decision.Allowed) {
                return ServiceError.RateLimited(decision);
            }
        }

        // Bounded holding: an offline or dead recipient can't be used to fill our disk.
        var perMailboxCap = _options.Messages.MaxHeldPerMailbox;
        var held = perMailboxCap > 0 ? await _mailboxes.CountHeldAsync(mailboxId, perMailboxCap, ct) : 0;
        if (perMailboxCap > 0 && held >= perMailboxCap) {
            return ServiceError.MailboxFull;
        }
        // Server-wide held quota. It only refuses mailboxes that are already holding (or whose endpoint is gone), because
        // those messages would add to the backlog. Healthy mailboxes deliver straight away and are never refused here.
        var gone = mailbox.State == MailboxState.EndpointGone;
        if ((gone || held > 0) && await _heldQuota.IsExceededAsync(ct)) {
            return ServiceError.StorageFull;
        }

        // Charged last, only for messages that are about to be accepted. Junk can't drain the shared budget.
        var global = await _limiter.CheckAsync(RatePolicies.SendGlobal, GlobalSubject);
        if (!global.Allowed) {
            return ServiceError.RateLimited(global);
        }

        var messageId = RandomNumberGenerator.GetBytes(ProtocolLimits.MessageIdSize);
        if (idempotencyKey is not null) {
            var window = TimeSpan.FromSeconds(_options.Messages.IdempotencyWindowSeconds);
            var reservation = await _idempotency.ReserveAsync(mailboxId, idempotencyKey, messageId, window);
            if (reservation.State == IdempotencyState.Done) {
                return reservation.MessageId;
            }
            // Pending: an earlier attempt may have crashed before queueing. Queue again under its id (at-least-once).
            messageId = reservation.MessageId;
        }

        var ttl = ClampTtl(ttlSeconds);
        if (gone) {
            ttl = Math.Min(ttl, Math.Max(_options.Messages.MinTtlSeconds, _options.Messages.GoneMaxTtlSeconds));
        }
        var expiresAt = WholeSeconds(DateTime.UtcNow.AddSeconds(ttl));

        var sealKey = _crypto.SealKey(sendSecret);
        var envelope = PushEnvelope.Build(PushType.Message, MailboxCrypto.Tag(sendSecret), body);
        try {
            var (epoch, epochKey) = await _keyring.GetCurrentAsync(ct);
            var blob = JobCodec.Seal(epochKey, messageId, mailboxId, expiresAt, sealKey, envelope);
            var job = new DeliveryJob(messageId, mailboxId, epoch, blob, expiresAt, Attempts: 0);
            if (await _queue.TryEnqueueAsync(job, _options.Messages.MaxStreamLength)) {
                _signal.NotifyQueueLocal();
            } else {
                // The hot queue is full (a backlog) or Redis is out of memory: hand the job straight to the durable
                // held-message table, due now. It's delivered the same way, just through the retry worker.
                await _pending.UpsertAsync(job.Id, job.MailboxId, job.KeyEpoch, job.Blob, 0, DateTime.UtcNow, job.ExpiresAt, ct);
                await _signal.NotifyRetryAsync();
                _spilled.Add(1);
            }
        } finally {
            CryptographicOperations.ZeroMemory(sealKey);
            CryptographicOperations.ZeroMemory(envelope);
        }

        if (idempotencyKey is not null) {
            await _idempotency.MarkDoneAsync(mailboxId, idempotencyKey, messageId);
        }
        _accepted.Add(1);
        return messageId;
    }

    /// <summary>MySQL DATETIME has whole-second precision, and the expiry is bound into the job's AAD, so it must round-trip exactly.</summary>
    internal static DateTime WholeSeconds(DateTime utc) {
        return new DateTime(utc.Ticks - utc.Ticks % TimeSpan.TicksPerSecond, DateTimeKind.Utc);
    }
}
