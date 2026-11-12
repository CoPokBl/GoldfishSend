using StackExchange.Redis;

namespace GoldfishSend.Infrastructure.Redis;

/// <summary>A coalescing async auto-reset event: any number of Set() calls wake at most one pending wait.</summary>
public sealed class AsyncSignal {
    private readonly SemaphoreSlim _semaphore = new(0, 1);

    public void Set() {
        try {
            _semaphore.Release();
        } catch (SemaphoreFullException) {
            // Already signalled.
        }
    }

    public async Task WaitAsync(TimeSpan timeout, CancellationToken ct) {
        try {
            await _semaphore.WaitAsync(timeout, ct);
        } catch (OperationCanceledException) when (ct.IsCancellationRequested) {
            // Shutdown.
        }
    }
}

/// <summary>
/// Wakes delivery workers as soon as work arrives. An in-process signal handles the local fast path, and Redis
/// pub/sub reaches workers on other nodes. Workers also poll on a timer, so a lost signal only adds latency.
/// </summary>
public sealed class DeliverySignal {
    private readonly IConnectionMultiplexer _redis;
    private int _subscribed;

    public AsyncSignal Queue { get; } = new();
    public AsyncSignal Retry { get; } = new();

    public DeliverySignal(IConnectionMultiplexer redis) {
        _redis = redis;
    }

    public async Task SubscribeAsync() {
        if (Interlocked.Exchange(ref _subscribed, 1) == 1) {
            return;
        }
        var sub = _redis.GetSubscriber();
        await sub.SubscribeAsync(RedisChannel.Literal(RedisKeys.WakeQueue), (_, _) => Queue.Set());
        await sub.SubscribeAsync(RedisChannel.Literal(RedisKeys.WakeRetry), (_, _) => Retry.Set());
    }

    public void NotifyQueueLocal() => Queue.Set();

    public async Task NotifyRetryAsync() {
        Retry.Set();
        await _redis.GetSubscriber().PublishAsync(RedisChannel.Literal(RedisKeys.WakeRetry), 1, CommandFlags.FireAndForget);
    }
}
