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
    private readonly EpochKeyring _keyring;
    private readonly MessageQueue _queue;
    private readonly RateLimiter _limiter;
    private readonly PowService _pow;
    private readonly DeliverySignal _signal;
    private readonly GoldfishOptions _options;
    private readonly Counter<long> _accepted;

    public MessageService(
        MailboxCrypto crypto, MailboxRepository mailboxes, EpochKeyring keyring, MessageQueue queue,
        RateLimiter limiter, PowService pow, DeliverySignal signal, GoldfishOptions options, Meter meter) {
        _crypto = crypto;
        _mailboxes = mailboxes;
        _keyring = keyring;
        _queue = queue;
        _limiter = limiter;
        _pow = pow;
        _signal = signal;
        _options = options;
        _accepted = meter.CreateCounter<long>("goldfish.messages.accepted");
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

        // Limits are checked from narrowest to widest, so a single abusive client exhausts only its own budget.
        // Shared-IP users (Tor, CGNAT) who hit the per-IP limit can pay with a proof of work instead.
        var perIp = await _limiter.CheckAsync(RatePolicies.SendPerIp, client.Host);
        if (!perIp.Allowed && (pow is null || !await _pow.RedeemAsync(pow.Challenge, pow.Nonce, countsTowardLoad: false))) {
            return ServiceError.RateLimited(perIp.RetryAfter);
        }

        var mailboxId = _crypto.MailboxId(sendSecret);
        var mailbox = await _mailboxes.GetAsync(mailboxId, ct);
        // Messages to a mailbox whose endpoint went away are still accepted and held. Never-verified mailboxes don't exist yet.
        if (mailbox is null || mailbox.State == MailboxState.PendingVerification) {
            return ServiceError.NotFound;
        }

        // These limits protect the recipient from a hostile contact flooding them.
        foreach (var policy in new[] { RatePolicies.SendPerMailbox, RatePolicies.SendPerMailboxDaily }) {
            var decision = await _limiter.CheckAsync(policy, mailboxId);
            if (!decision.Allowed) {
                return ServiceError.RateLimited(decision.RetryAfter);
            }
        }

        // Bounded holding: an offline or dead recipient can't be used to fill our disk.
        var cap = _options.Messages.MaxHeldPerMailbox;
        if (cap > 0 && await _mailboxes.CountHeldAsync(mailboxId, cap, ct) >= cap) {
            return ServiceError.MailboxFull;
        }

        // Charged last, only for messages that are about to be accepted. Junk can't drain the shared budget.
        var global = await _limiter.CheckAsync(RatePolicies.SendGlobal, GlobalSubject);
        if (!global.Allowed) {
            return ServiceError.RateLimited(global.RetryAfter);
        }

        var messageId = RandomNumberGenerator.GetBytes(ProtocolLimits.MessageIdSize);
        var sealKey = _crypto.SealKey(sendSecret);
        var envelope = PushEnvelope.Build(PushType.Message, MailboxCrypto.Tag(sendSecret), body);
        try {
            var (epoch, epochKey) = await _keyring.GetCurrentAsync(ct);
            var blob = JobCodec.Seal(epochKey, messageId, sealKey, envelope);
            var expiresAt = DateTime.UtcNow.AddSeconds(ClampTtl(ttlSeconds));
            var window = TimeSpan.FromSeconds(_options.Messages.IdempotencyWindowSeconds);
            var existing = await _queue.EnqueueAsync(
                new DeliveryJob(messageId, mailboxId, epoch, blob, expiresAt, Attempts: 0), idempotencyKey, window);
            if (existing is not null) {
                return existing;
            }
        } finally {
            CryptographicOperations.ZeroMemory(sealKey);
            CryptographicOperations.ZeroMemory(envelope);
        }

        _signal.NotifyQueueLocal();
        _accepted.Add(1);
        return messageId;
    }
}
