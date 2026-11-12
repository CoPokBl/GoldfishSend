using System.Globalization;
using GoldfishSend.Infrastructure.Delivery;
using Microsoft.Extensions.Logging;
using StackExchange.Redis;

namespace GoldfishSend.Infrastructure.Redis;

public sealed record QueueEntry(RedisValue EntryId, DeliveryJob? Job);

/// <summary>
/// The hot queue: a Redis stream with one consumer group shared by every worker node. Each entry is delivered
/// to exactly one consumer. Entries live for as long as one delivery attempt takes, and are then acknowledged
/// and deleted, or moved to MySQL for retry. Entries held by a crashed node are reclaimed with XAUTOCLAIM.
/// </summary>
public sealed class MessageQueue {
    private const string FieldId = "id";
    private const string FieldMailbox = "mbx";
    private const string FieldEpoch = "ep";
    private const string FieldBlob = "blob";
    private const string FieldExpires = "exp";

    // KEYS[1] = idempotency key ("" if none), KEYS[2] = stream.
    // ARGV = message id, idempotency window (s), mailbox id, epoch, blob, expiry (unix s).
    // Reserving the key and appending to the stream happen atomically, so a crash can't leave a reservation
    // pointing at a message that was never queued. Returns the earlier message id for a duplicate, else nil.
    private const string EnqueueScript = """
        if KEYS[1] ~= '' then
            local existing = redis.call('GET', KEYS[1])
            if existing then return existing end
        end
        redis.call('XADD', KEYS[2], '*', 'id', ARGV[1], 'mbx', ARGV[3], 'ep', ARGV[4], 'blob', ARGV[5], 'exp', ARGV[6])
        if KEYS[1] ~= '' then
            redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
        end
        return false
        """;

    private readonly IConnectionMultiplexer _redis;
    private readonly ILogger<MessageQueue> _logger;

    public MessageQueue(IConnectionMultiplexer redis, ILogger<MessageQueue> logger) {
        _redis = redis;
        _logger = logger;
    }

    public async Task EnsureGroupAsync() {
        try {
            await _redis.GetDatabase().StreamCreateConsumerGroupAsync(RedisKeys.Queue, RedisKeys.QueueGroup, "0-0", createStream: true);
        } catch (RedisServerException ex) when (ex.Message.Contains("BUSYGROUP", StringComparison.Ordinal)) {
            // Already exists.
        }
    }

    /// <returns>The id of an earlier message with the same idempotency key, or <c>null</c> if this one was queued.</returns>
    public async Task<byte[]?> EnqueueAsync(DeliveryJob job, byte[]? idempotencyKey, TimeSpan idempotencyWindow) {
        var db = _redis.GetDatabase();
        RedisKey idemKey = idempotencyKey is null
            ? ""
            : RedisKeys.Idempotency(Convert.ToHexString(job.MailboxId, 0, 16), Convert.ToHexString(idempotencyKey));
        var result = await db.ScriptEvaluateAsync(EnqueueScript, [idemKey, RedisKeys.Queue], [
            job.Id,
            (long)idempotencyWindow.TotalSeconds,
            job.MailboxId,
            job.KeyEpoch,
            job.Blob,
            new DateTimeOffset(job.ExpiresAt, TimeSpan.Zero).ToUnixTimeSeconds(),
        ]);
        if (!result.IsNull && result.Resp2Type == ResultType.BulkString) {
            return (byte[]?)result;
        }
        await _redis.GetSubscriber().PublishAsync(RedisChannel.Literal(RedisKeys.WakeQueue), 1, CommandFlags.FireAndForget);
        return null;
    }

    public async Task<IReadOnlyList<QueueEntry>> ReadNewAsync(string consumer, int count) {
        var entries = await _redis.GetDatabase().StreamReadGroupAsync(RedisKeys.Queue, RedisKeys.QueueGroup, consumer, ">", count);
        return entries.Select(Decode).ToList();
    }

    /// <summary>
    /// Takes over entries that another (probably crashed) consumer has held for longer than <paramref name="minIdle"/>.
    /// Pass the returned cursor back in to continue the scan. A cursor of <c>0-0</c> means the scan is complete.
    /// </summary>
    public async Task<(IReadOnlyList<QueueEntry> Entries, RedisValue NextCursor)> ClaimStaleAsync(
        string consumer, TimeSpan minIdle, RedisValue cursor, int count) {
        var result = await _redis.GetDatabase().StreamAutoClaimAsync(
            RedisKeys.Queue, RedisKeys.QueueGroup, consumer, (long)minIdle.TotalMilliseconds, cursor, count);
        return (result.ClaimedEntries.Select(Decode).ToList(), result.NextStartId);
    }

    /// <summary>Acknowledges and deletes in one go, so the payload doesn't linger in the stream.</summary>
    public async Task CompleteAsync(RedisValue entryId) {
        var db = _redis.GetDatabase();
        var batch = db.CreateBatch();
        var ack = batch.StreamAcknowledgeAsync(RedisKeys.Queue, RedisKeys.QueueGroup, entryId);
        var del = batch.StreamDeleteAsync(RedisKeys.Queue, [entryId]);
        batch.Execute();
        await Task.WhenAll(ack, del);
    }

    /// <summary>Removes consumers left by departed nodes: ones that have nothing pending and have been idle for over an hour.</summary>
    public async Task<int> RemoveIdleConsumersAsync(string self) {
        var db = _redis.GetDatabase();
        var removed = 0;
        foreach (var consumer in await db.StreamConsumerInfoAsync(RedisKeys.Queue, RedisKeys.QueueGroup)) {
            if (consumer.Name != self && consumer.PendingMessageCount == 0 && consumer.IdleTimeInMilliseconds > 3_600_000) {
                await db.StreamDeleteConsumerAsync(RedisKeys.Queue, RedisKeys.QueueGroup, consumer.Name);
                removed++;
            }
        }
        return removed;
    }

    public async Task<long> LengthAsync() {
        return await _redis.GetDatabase().StreamLengthAsync(RedisKeys.Queue);
    }

    private QueueEntry Decode(StreamEntry entry) {
        try {
            byte[]? id = null, mailbox = null, blob = null;
            int? epoch = null;
            long? expires = null;
            foreach (var value in entry.Values) {
                switch ((string?)value.Name) {
                    case FieldId: id = value.Value; break;
                    case FieldMailbox: mailbox = value.Value; break;
                    case FieldBlob: blob = value.Value; break;
                    case FieldEpoch: epoch = (int)value.Value; break;
                    case FieldExpires: expires = long.Parse((string)value.Value!, CultureInfo.InvariantCulture); break;
                }
            }
            if (id is null || mailbox is null || blob is null || epoch is null || expires is null) {
                return new QueueEntry(entry.Id, null);
            }
            return new QueueEntry(entry.Id, new DeliveryJob(
                id, mailbox, epoch.Value, blob, DateTimeOffset.FromUnixTimeSeconds(expires.Value).UtcDateTime, Attempts: 0));
        } catch (Exception ex) when (ex is FormatException or InvalidCastException or OverflowException) {
            _logger.LogWarning("Dropping malformed queue entry");
            return new QueueEntry(entry.Id, null);
        }
    }
}
