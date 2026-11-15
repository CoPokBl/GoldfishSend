using System.Security.Cryptography;
using StackExchange.Redis;

namespace GoldfishSend.Infrastructure.Redis;

public enum IdempotencyState {
    /// <summary>Nothing recorded. The caller reserved the key and must queue <see cref="IdempotencyReservation.MessageId"/>.</summary>
    Reserved,
    /// <summary>A request with this key is queued or in progress, and possibly crashed before queueing. Queue it again under the same id.</summary>
    Pending,
    /// <summary>Already queued. Return the original id and do nothing.</summary>
    Done,
}

public readonly record struct IdempotencyReservation(IdempotencyState State, byte[] MessageId);

/// <summary>
/// Send idempotency, kept in the non-persistent ephemeral Redis. The key is an HMAC of mailbox id ‖ idempotency key
/// under the cluster secret, with a short, jittered TTL. That leaves no on-disk record of per-mailbox activity.
///
/// Protocol: reserve as "pending" → queue → mark "done". A retry that sees "done" gets the original id. A retry that sees
/// "pending" (still in flight, or crashed before queueing) queues again under the same message id. So the outcome is
/// at-least-once and never a false success: the worst case is a duplicate push of identical ciphertext, which the
/// client's Signal session rejects as a duplicate.
/// </summary>
public sealed class IdempotencyStore {
    private const byte Pending = (byte)'p';
    private const byte Done = (byte)'d';

    private readonly EphemeralRedis _redis;
    private readonly ClusterSecret _secret;

    public IdempotencyStore(EphemeralRedis redis, ClusterSecret secret) {
        _redis = redis;
        _secret = secret;
    }

    public async Task<IdempotencyReservation> ReserveAsync(byte[] mailboxId, byte[] idempotencyKey, byte[] newMessageId, TimeSpan window) {
        var key = await KeyAsync(mailboxId, idempotencyKey);
        var ttl = Jitter(window);
        var db = _redis.Db;
        if (await db.StringSetAsync(key, Value(Pending, newMessageId), ttl, When.NotExists)) {
            return new IdempotencyReservation(IdempotencyState.Reserved, newMessageId);
        }
        var existing = (byte[]?)await db.StringGetAsync(key);
        if (existing is null || existing.Length != 1 + newMessageId.Length) {
            // Expired in between, or unreadable: treat it as fresh.
            await db.StringSetAsync(key, Value(Pending, newMessageId), ttl);
            return new IdempotencyReservation(IdempotencyState.Reserved, newMessageId);
        }
        var id = existing[1..];
        return new IdempotencyReservation(existing[0] == Done ? IdempotencyState.Done : IdempotencyState.Pending, id);
    }

    /// <returns>The original message id if a send with this key was already queued, otherwise null. Changes nothing.</returns>
    public async Task<byte[]?> GetDoneAsync(byte[] mailboxId, byte[] idempotencyKey) {
        var existing = (byte[]?)await _redis.Db.StringGetAsync(await KeyAsync(mailboxId, idempotencyKey));
        return existing is { Length: > 1 } && existing[0] == Done ? existing[1..] : null;
    }

    public async Task MarkDoneAsync(byte[] mailboxId, byte[] idempotencyKey, byte[] messageId) {
        var key = await KeyAsync(mailboxId, idempotencyKey);
        // SET ... XX KEEPTTL, through a script so it works on any client API version.
        await _redis.Db.ScriptEvaluateAsync(
            "if redis.call('EXISTS', KEYS[1]) == 1 then return redis.call('SET', KEYS[1], ARGV[1], 'KEEPTTL') end return nil",
            [key], [Value(Done, messageId)]);
    }

    private async Task<RedisKey> KeyAsync(byte[] mailboxId, byte[] idempotencyKey) {
        var data = new byte[mailboxId.Length + idempotencyKey.Length];
        mailboxId.CopyTo(data, 0);
        idempotencyKey.CopyTo(data, mailboxId.Length);
        return RedisKeys.Idempotency(await _secret.HmacHexAsync("idem", data));
    }

    private static byte[] Value(byte state, byte[] id) {
        var v = new byte[1 + id.Length];
        v[0] = state;
        id.CopyTo(v, 1);
        return v;
    }

    private static TimeSpan Jitter(TimeSpan window) {
        var factor = 0.9 + RandomNumberGenerator.GetInt32(0, 2001) / 10000.0;
        return TimeSpan.FromMilliseconds(Math.Max(1000, window.TotalMilliseconds * factor));
    }
}
