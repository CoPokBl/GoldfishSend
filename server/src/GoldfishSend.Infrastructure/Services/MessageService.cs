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

        var limited = await ChargeClientAsync(client, pow, cost: 1);
        if (limited is not null) {
            return limited;
        }
        return await AcceptItemAsync(sendSecret, body, ttlSeconds, idempotencyKey, ct);
    }

    /// <summary>
    /// <c>POST /v1/messages/batch</c>. The client (IP and network) buckets are charged
    /// <see cref="MessageBatch.ClientCost"/> tokens once for the whole batch, and a valid PoW pays for all of it. Each item is
    /// then handled exactly like a single send: lookup, per-mailbox, held-quota and global limits, and idempotency.
    /// </summary>
    /// <returns>One result per item, in order, or an error for the whole batch (only a client rate limit).</returns>
    public async Task<ServiceResult<IReadOnlyList<ServiceResult<byte[]>>>> AcceptBatchAsync(
        IReadOnlyList<BatchItem> items, PowToken? pow, ClientSubject client, CancellationToken ct) {
        if (items.Count is < 1 or > MessageBatch.MaxItems) {
            return ServiceError.InvalidRequest;
        }
        var limited = await ChargeClientAsync(client, pow, MessageBatch.ClientCost(items.Count));
        if (limited is not null) {
            return limited;
        }
        // Sequential on purpose: a batch is at most 32 items, and the per-mailbox and global buckets then see the same
        // order of events as single sends would produce.
        var results = new List<ServiceResult<byte[]>>(items.Count);
        foreach (var item in items) {
            results.Add(await AcceptItemAsync(item.SendSecret, item.Blob, item.TtlSeconds, item.IdempotencyKey, ct));
        }
        return results;
    }

    /// <summary>
    /// Client limits: the IPv6 /32, the network and the address, all or nothing, so a request refused by one never
    /// uses up another (and one allocation can't multiply its budget by rotating addresses). Shared-address users (Tor,
    /// CGNAT) who hit any of them can pay with a proof of work instead.
    /// </summary>
    private async Task<ServiceError?> ChargeClientAsync(ClientSubject client, PowToken? pow, int cost) {
        var decision = await _limiter.CheckAllAsync([
            new RateScope(RatePolicies.SendPerAllocation, client.Allocation, cost),
            new RateScope(RatePolicies.SendPerNetwork, client.Network, cost),
            new RateScope(RatePolicies.SendPerIp, client.Host, cost),
        ]);
        if (decision.Allowed) {
            return null;
        }
        if (pow is null) {
            return ServiceError.RateLimited(decision);
        }
        // Paying a send limit never counts toward the creation load, so heavy senders can't make onboarding harder.
        return await _pow.RedeemAsync(pow.Challenge, pow.Nonce, client, PowPurpose.Send) switch {
            PowRedemption.Busy => ServiceError.PowBusy,
            PowRedemption.Invalid => ServiceError.RateLimited(decision),
            _ => null, // A valid PoW pays for this request at every client scope.
        };
    }

    private async Task<ServiceResult<byte[]>> AcceptItemAsync(
        byte[] sendSecret, byte[] body, int? ttlSeconds, byte[]? idempotencyKey, CancellationToken ct) {
        // Caps how many token lookups can reach MySQL, whatever the source. Charged per item, so a batch can't probe
        // mailboxes any faster than single sends.
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

        // A retry of a message that was already queued gets its original id, even once the mailbox is full or its rate
        // limit is spent (likely, if the push server is down). Answering 507 or 429 would tell the sender an accepted
        // message wasn't. Nothing is queued again, so the recipient's budgets aren't charged.
        if (idempotencyKey is not null && await _idempotency.GetDoneAsync(mailboxId, idempotencyKey) is { } original) {
            return original;
        }

        // These limits protect the recipient from a hostile contact flooding them. Only peeked here (a spent budget
        // saves the held-count query), and charged below with the global budget once the message will be accepted.
        var recipient = await _limiter.CheckAllAsync(RecipientScopes(mailboxId, cost: 0));
        if (!recipient.Allowed) {
            return ServiceError.RateLimited(recipient);
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

        // Charged last, only for messages that are about to be accepted, and all or nothing: junk can't drain the shared
        // budget, and a message the server-wide budget refuses doesn't use up the recipient's.
        var charged = await _limiter.CheckAllAsync([
            ..RecipientScopes(mailboxId, cost: 1),
            new RateScope(RatePolicies.SendGlobal, GlobalSubject),
        ]);
        if (!charged.Allowed) {
            return ServiceError.RateLimited(charged);
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
        var expiresAt = HeldExpiry.At(DateTime.UtcNow, ttl);

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
                await _pending.UpsertAsync(
                    job.Id, job.MailboxId, job.KeyEpoch, job.Blob, 0, HeldExpiry.DueNow(DateTime.UtcNow), job.ExpiresAt, ct);
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

    private static RateScope[] RecipientScopes(byte[] mailboxId, int cost) => [
        new RateScope(RatePolicies.SendPerMailboxDaily, mailboxId, cost),
        new RateScope(RatePolicies.SendPerMailbox, mailboxId, cost),
    ];
}
