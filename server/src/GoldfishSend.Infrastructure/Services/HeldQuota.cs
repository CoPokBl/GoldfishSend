using GoldfishSend.Core.Options;
using GoldfishSend.Infrastructure.MySql;

namespace GoldfishSend.Infrastructure.Services;

/// <summary>
/// The server-wide held-message quota. COUNT(*) on the held table is too costly for every send, so the total is cached
/// and refreshed at most every 15 seconds. The quota is therefore approximate, which is fine for a storage bound.
/// </summary>
public sealed class HeldQuota {
    private static readonly TimeSpan RefreshEvery = TimeSpan.FromSeconds(15);

    private readonly PendingMessageRepository _pending;
    private readonly int _max;
    private readonly SemaphoreSlim _refresh = new(1, 1);
    private long _count;
    private DateTime _countedAt = DateTime.MinValue;

    public HeldQuota(PendingMessageRepository pending, GoldfishOptions options) {
        _pending = pending;
        _max = options.Messages.MaxHeldTotal;
    }

    public async Task<bool> IsExceededAsync(CancellationToken ct) {
        if (_max <= 0) {
            return false;
        }
        if (DateTime.UtcNow - _countedAt > RefreshEvery && await _refresh.WaitAsync(0, ct)) {
            try {
                _count = await _pending.CountAsync(ct);
                _countedAt = DateTime.UtcNow;
            } finally {
                _refresh.Release();
            }
        }
        return Interlocked.Read(ref _count) >= _max;
    }

    /// <summary>For tests: forget the cached count.</summary>
    internal void Invalidate() => _countedAt = DateTime.MinValue;
}
