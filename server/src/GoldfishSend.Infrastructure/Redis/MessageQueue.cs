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

    // KEYS[1] = stream. ARGV = max length, then the fields. Refuses (returns 0) once the stream is at its bound, so a
    // backlog spills to MySQL instead of filling Redis memory.
    private const string BoundedAddScript = """
        if redis.call('XLEN', KEYS[1]) >= tonumber(ARGV[1]) then
            return 0
        end
        redis.call('XADD', KEYS[1], '*', 'id', ARGV[2], 'mbx', ARGV[3], 'ep', ARGV[4], 'blob', ARGV[5], 'exp', ARGV[6])
        return 1
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

    /// <summary>Appends to the hot queue.</summary>
    /// <returns>
    /// <c>false</c> if the stream is at <paramref name="maxLength"/> or Redis refused the write (out of memory). The caller
    /// must then store the job durably elsewhere.
    /// </returns>
    public async Task<bool> TryEnqueueAsync(DeliveryJob job, int maxLength) {
        try {
            var added = (long)await _redis.GetDatabase().ScriptEvaluateAsync(BoundedAddScript, [RedisKeys.Queue], [
                maxLength,
                job.Id,
                job.MailboxId,
                job.KeyEpoch,
                job.Blob,
                new DateTimeOffset(job.ExpiresAt, TimeSpan.Zero).ToUnixTimeSeconds(),
            ]);
            if (added != 1) {
                return false;
            }
        } catch (RedisServerException ex) when (ex.Message.Contains("OOM", StringComparison.Ordinal)) {
            _logger.LogWarning("Queue Redis is out of memory; spilling to MySQL");
            return false;
        }
        await _redis.GetSubscriber().PublishAsync(RedisChannel.Literal(RedisKeys.WakeQueue), 1, CommandFlags.FireAndForget);
        return true;
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
