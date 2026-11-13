using System.Threading.Channels;
using GoldfishSend.Core.Options;
using GoldfishSend.Infrastructure.MySql;
using GoldfishSend.Infrastructure.Push;
using GoldfishSend.Infrastructure.Redis;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using StackExchange.Redis;

namespace GoldfishSend.Infrastructure.Delivery;

/// <summary>
/// A reader feeding N continuous consumers through a small bounded channel. A slow push host ties up one consumer,
/// never a whole batch. Every job also has a hard timeout, so nothing can hold a slot forever.
/// </summary>
public abstract class PumpWorker<T> : BackgroundService {
    private readonly ILogger _logger;

    protected int Parallelism { get; }
    protected TimeSpan JobTimeout { get; }

    protected PumpWorker(GoldfishOptions options, ILogger logger) {
        _logger = logger;
        Parallelism = Math.Max(1, options.Messages.DeliveryParallelism);
        // Push timeout plus headroom for the database and Redis calls around it.
        JobTimeout = TimeSpan.FromSeconds(options.Push.RequestTimeoutSeconds + 15);
    }

    /// <summary>One-time setup, retried until it succeeds (Redis may still be starting).</summary>
    protected virtual Task InitializeAsync(CancellationToken ct) => Task.CompletedTask;

    /// <summary>Writes work into the channel until cancelled.</summary>
    protected abstract Task ProduceAsync(ChannelWriter<T> writer, CancellationToken ct);

    protected abstract Task HandleAsync(T item, CancellationToken ct);

    protected override async Task ExecuteAsync(CancellationToken ct) {
        while (!ct.IsCancellationRequested) {
            try {
                await InitializeAsync(ct);
                break;
            } catch (OperationCanceledException) when (ct.IsCancellationRequested) {
                return;
            } catch (Exception ex) {
                _logger.LogWarning("{Worker} initialisation failed ({Error}); retrying", GetType().Name, ex.GetType().Name);
                await Delay(TimeSpan.FromSeconds(2), ct);
            }
        }

        var channel = Channel.CreateBounded<T>(new BoundedChannelOptions(Parallelism) {
            SingleWriter = true,
            FullMode = BoundedChannelFullMode.Wait,
        });
        var consumers = Enumerable.Range(0, Parallelism).Select(_ => ConsumeAsync(channel.Reader, ct)).ToArray();

        while (!ct.IsCancellationRequested) {
            try {
                await ProduceAsync(channel.Writer, ct);
            } catch (OperationCanceledException) when (ct.IsCancellationRequested) {
                break;
            } catch (Exception ex) {
                _logger.LogError(ex, "{Worker} producer failed; backing off", GetType().Name);
                await Delay(TimeSpan.FromSeconds(2), ct);
            }
        }
        channel.Writer.TryComplete();
        await Task.WhenAll(consumers);
    }

    private async Task ConsumeAsync(ChannelReader<T> reader, CancellationToken ct) {
        try {
            await foreach (var item in reader.ReadAllAsync(ct)) {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeout.CancelAfter(JobTimeout);
                try {
                    await HandleAsync(item, timeout.Token);
                } catch (OperationCanceledException) when (ct.IsCancellationRequested) {
                    return;
                } catch (Exception ex) {
                    // Whatever wasn't completed is picked up again: stream entries by XAUTOCLAIM, MySQL rows when their lease expires.
                    _logger.LogError("{Worker} job failed: {Error}", GetType().Name, ex.GetType().Name);
                }
            }
        } catch (OperationCanceledException) when (ct.IsCancellationRequested) {
            // Shutdown.
        }
    }

    protected static Task Delay(TimeSpan delay, CancellationToken ct) {
        return Task.Delay(delay, ct).ContinueWith(_ => { }, CancellationToken.None);
    }
}

/// <summary>
/// Drains the hot Redis stream. Every node joins the same consumer group, so each entry goes to exactly one node.
/// On success the entry is acknowledged and deleted. Otherwise it moves to MySQL for durable retry, and only then is
/// acknowledged, so a crash at any point loses nothing. Entries held by a dead node are reclaimed after a minute.
/// </summary>
public sealed class StreamDeliveryWorker : PumpWorker<QueueEntry> {
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(1);

    /// <summary>
    /// How long an entry may sit unacknowledged before another node takes it over. It's well above the worst case for a
    /// healthy node (one full channel ahead of it plus its own job), so a slow-but-alive node isn't duplicated. Delivery
    /// is at-least-once regardless; clients drop duplicates.
    /// </summary>
    private TimeSpan ReclaimIdle => TimeSpan.FromTicks(Math.Max(TimeSpan.FromMinutes(1).Ticks, JobTimeout.Ticks * 4));

    private readonly MessageQueue _queue;
    private readonly DeliveryService _delivery;
    private readonly PendingMessageRepository _pending;
    private readonly DeliverySignal _signal;
    private readonly ILogger<StreamDeliveryWorker> _logger;

    public static string ConsumerName { get; } = $"{Environment.MachineName}-{Environment.ProcessId}-{Guid.NewGuid():N}";

    public StreamDeliveryWorker(
        MessageQueue queue, DeliveryService delivery, PendingMessageRepository pending, DeliverySignal signal,
        GoldfishOptions options, ILogger<StreamDeliveryWorker> logger) : base(options, logger) {
        _queue = queue;
        _delivery = delivery;
        _pending = pending;
        _signal = signal;
        _logger = logger;
    }

    protected override async Task InitializeAsync(CancellationToken ct) {
        await _queue.EnsureGroupAsync();
        await _signal.SubscribeAsync();
    }

    protected override async Task ProduceAsync(ChannelWriter<QueueEntry> writer, CancellationToken ct) {
        var lastReclaim = DateTime.MinValue;
        while (!ct.IsCancellationRequested) {
            if (DateTime.UtcNow - lastReclaim > ReclaimIdle) {
                lastReclaim = DateTime.UtcNow;
                await ReclaimAsync(writer, ct);
            }

            var batch = await _queue.ReadNewAsync(ConsumerName, Parallelism);
            if (batch.Count == 0) {
                await _signal.Queue.WaitAsync(PollInterval, ct);
                continue;
            }
            foreach (var entry in batch) {
                await writer.WriteAsync(entry, ct);
            }
        }
    }

    /// <summary>Walks the whole pending list with the XAUTOCLAIM cursor, so recovery after a crash is quick.</summary>
    private async Task ReclaimAsync(ChannelWriter<QueueEntry> writer, CancellationToken ct) {
        RedisValue cursor = "0-0";
        var total = 0;
        do {
            var (entries, next) = await _queue.ClaimStaleAsync(ConsumerName, ReclaimIdle, cursor, 100);
            foreach (var entry in entries) {
                await writer.WriteAsync(entry, ct);
            }
            total += entries.Count;
            cursor = next;
        } while (cursor != "0-0" && !ct.IsCancellationRequested);
        if (total > 0) {
            _logger.LogInformation("Reclaimed {Count} stale queue entries", total);
        }
    }

    protected override async Task HandleAsync(QueueEntry entry, CancellationToken ct) {
        if (entry.Job is not { } job) {
            await _queue.CompleteAsync(entry.EntryId);
            return;
        }

        var outcome = await _delivery.AttemptAsync(job, ct);
        if (outcome.Kind is DeliveryOutcomeKind.Retry or DeliveryOutcomeKind.Hold) {
            var attempts = outcome.Kind == DeliveryOutcomeKind.Retry && outcome.CountsAsAttempt ? job.Attempts + 1 : job.Attempts;
            await _pending.UpsertAsync(job.Id, job.MailboxId, job.KeyEpoch, job.Blob, attempts, outcome.NextAttemptAt, job.ExpiresAt, ct);
        }
        await _queue.CompleteAsync(entry.EntryId);
    }
}

/// <summary>
/// Retries held and failed messages from MySQL until delivery or expiry. <c>FOR UPDATE SKIP LOCKED</c> plus a lease
/// lets any number of nodes run this at once without overlapping.
/// </summary>
public sealed class RetryWorker : PumpWorker<PendingMessageRow> {
    // Short, because local deferrals (a busy mailbox, pacing) come back in well under a second. The claim query only
    // reads due rows through an index, so polling is cheap.
    private static readonly TimeSpan PollInterval = TimeSpan.FromMilliseconds(500);

    private readonly PendingMessageRepository _pending;
    private readonly DeliveryService _delivery;
    private readonly DeliverySignal _signal;
    private readonly TimeSpan _lease;

    public RetryWorker(
        PendingMessageRepository pending, DeliveryService delivery, DeliverySignal signal, GoldfishOptions options,
        ILogger<RetryWorker> logger) : base(options, logger) {
        _pending = pending;
        _delivery = delivery;
        _signal = signal;
        // Claimed rows wait at most one channel's worth of jobs (about one job timeout) before running. Five job timeouts
        // covers that wait plus the job itself with a wide margin, so a live node's claim never lapses and gets duplicated.
        _lease = JobTimeout * 5;
    }

    protected override Task InitializeAsync(CancellationToken ct) => _signal.SubscribeAsync();

    protected override async Task ProduceAsync(ChannelWriter<PendingMessageRow> writer, CancellationToken ct) {
        while (!ct.IsCancellationRequested) {
            var due = await _pending.ClaimDueAsync(Parallelism, _lease, ct);
            if (due.Count == 0) {
                await _signal.Retry.WaitAsync(PollInterval, ct);
                continue;
            }
            foreach (var row in due) {
                await writer.WriteAsync(row, ct);
            }
        }
    }

    protected override async Task HandleAsync(PendingMessageRow row, CancellationToken ct) {
        var job = new DeliveryJob(row.Id, row.MailboxId, row.KeyEpoch, row.Payload, DateTime.SpecifyKind(row.ExpiresAt, DateTimeKind.Utc), row.Attempts);
        var outcome = await _delivery.AttemptAsync(job, ct);
        switch (outcome.Kind) {
            case DeliveryOutcomeKind.Delivered:
            case DeliveryOutcomeKind.Dropped:
                await _pending.DeleteAsync(row.Id, ct);
                break;
            case DeliveryOutcomeKind.Retry:
                await _pending.RescheduleAsync(row.Id, outcome.CountsAsAttempt ? row.Attempts + 1 : row.Attempts, outcome.NextAttemptAt, ct);
                break;
            case DeliveryOutcomeKind.Hold:
                await _pending.RescheduleAsync(row.Id, row.Attempts, outcome.NextAttemptAt, ct);
                break;
        }
    }
}

/// <summary>
/// Housekeeping. Every node rotates its epoch-key cache and prunes local guard state. The cluster-wide
/// sweeps (expired messages, purged mailboxes, departed stream consumers) run on one node at a time,
/// under a Redis lease.
/// </summary>
public sealed class MaintenanceWorker : BackgroundService {
    private static readonly TimeSpan Interval = TimeSpan.FromMinutes(1);
    private const string LockKey = "gf:lock:maintenance";

    private readonly EpochKeyring _keyring;
    private readonly MailboxRepository _mailboxes;
    private readonly PendingMessageRepository _pending;
    private readonly MessageQueue _queue;
    private readonly DeliverySignal _signal;
    private readonly IConnectionMultiplexer _redis;
    private readonly ILogger<MaintenanceWorker> _logger;
    private readonly string _token = Guid.NewGuid().ToString("N");

    public MaintenanceWorker(
        EpochKeyring keyring, MailboxRepository mailboxes, PendingMessageRepository pending, MessageQueue queue, DeliverySignal signal,
        IConnectionMultiplexer redis, ILogger<MaintenanceWorker> logger) {
        _keyring = keyring;
        _mailboxes = mailboxes;
        _pending = pending;
        _queue = queue;
        _signal = signal;
        _redis = redis;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken ct) {
        while (!ct.IsCancellationRequested) {
            try {
                await _keyring.RotateAsync(ct);

                // The lease is shorter than the interval, so a crashed leader is replaced within a minute.
                var db = _redis.GetDatabase();
                if (await db.StringSetAsync(LockKey, _token, Interval - TimeSpan.FromSeconds(5), When.NotExists)) {
                    var expired = await _pending.DeleteExpiredAsync(ct);
                    var purged = await _mailboxes.PurgeAsync(ct);
                    var consumers = await _queue.RemoveIdleConsumersAsync(StreamDeliveryWorker.ConsumerName);
                    // Endpoints that looked gone get probed again with backoff: their oldest held message is retried.
                    var reprobes = await _mailboxes.ClaimDueReprobesAsync(200, ct);
                    if (reprobes.Count > 0) {
                        await _pending.PokeOldestAsync(reprobes, ct);
                        await _signal.NotifyRetryAsync();
                    }
                    if (expired > 0 || purged > 0 || consumers > 0) {
                        _logger.LogInformation("Maintenance: {Expired} expired message(s), {Purged} mailbox(es), {Consumers} idle consumer(s) removed",
                            expired, purged, consumers);
                    }
                }
            } catch (OperationCanceledException) when (ct.IsCancellationRequested) {
                break;
            } catch (Exception ex) {
                _logger.LogError(ex, "Maintenance pass failed");
            }
            try {
                await Task.Delay(Interval, ct);
            } catch (OperationCanceledException) {
                break;
            }
        }
    }
}

/// <summary>
/// Runs on every role, the API included. It prunes process-local caches that would otherwise only grow: push-host guard
/// state (every new host in a verification push adds an entry) and epoch keys past retention (so shredded keys don't
/// linger in this process's memory).
/// </summary>
public sealed class CachePruner : BackgroundService {
    private static readonly TimeSpan Interval = TimeSpan.FromMinutes(1);

    private readonly HostGuards _guards;
    private readonly EpochKeyring _keyring;
    private readonly ILogger<CachePruner> _logger;

    public CachePruner(HostGuards guards, EpochKeyring keyring, ILogger<CachePruner> logger) {
        _guards = guards;
        _keyring = keyring;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken ct) {
        while (!ct.IsCancellationRequested) {
            try {
                _guards.Prune();
                _keyring.EvictExpired();
            } catch (Exception ex) {
                _logger.LogError(ex, "Cache pruning failed");
            }
            try {
                await Task.Delay(Interval, ct);
            } catch (OperationCanceledException) {
                break;
            }
        }
    }
}
