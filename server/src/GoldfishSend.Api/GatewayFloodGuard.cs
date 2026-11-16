using System.Collections.Concurrent;
using System.Security.Cryptography;
using GoldfishSend.Core.Options;
using GoldfishSend.Infrastructure.Services;

namespace GoldfishSend.Api;

/// <summary>
/// A per-node, in-memory token bucket per client (IPv4 address or IPv6 /64) in front of the gateway. Opening a request
/// costs ~0.3 ms of CPU (ML-KEM decapsulation plus P-256), and that happens before any endpoint's rate limit, so this caps
/// how much decryption work one client can demand. It's generous: real clients make a few requests a minute. Clients
/// are keyed by an HMAC under a per-process random key, and idle buckets are dropped after a minute. The table is capped:
/// once full, new clients share one larger overflow bucket, so rotating through addresses can't grow memory.
/// </summary>
public sealed class GatewayFloodGuard {
    private readonly double _rate;
    private readonly double _burst;
    private readonly byte[] _key = RandomNumberGenerator.GetBytes(32);
    private readonly ConcurrentDictionary<string, Bucket> _buckets = new();
    private readonly TimeProvider _time;
    private readonly int _maxClients;
    private readonly Bucket _overflow;
    private readonly double _overflowFactor;
    private int _count;
    private long _lastSweep;

    public GatewayFloodGuard(GoldfishOptions options, TimeProvider? time = null) {
        _rate = Math.Max(0, options.Network.GatewayRequestsPerSecond);
        _burst = Math.Max(1, options.Network.GatewayBurst);
        _time = time ?? TimeProvider.System;
        _maxClients = Math.Max(1, options.Network.GatewayMaxClients);
        _overflowFactor = Math.Max(1, options.Network.GatewayOverflowFactor);
        _overflow = new Bucket { Tokens = _burst * _overflowFactor, Updated = _time.GetTimestamp() };
    }

    /// <summary>Clients currently tracked (for tests).</summary>
    public int TrackedClients => Volatile.Read(ref _count);

    private sealed class Bucket {
        public double Tokens;
        public long Updated;
    }

    /// <summary>Takes one token for this client. False means it's over the limit.</summary>
    public bool TryAcquire(ClientSubject client) {
        if (_rate <= 0) {
            return true;
        }
        var now = _time.GetTimestamp();
        var frequency = (double)_time.TimestampFrequency;
        Sweep(now, frequency);

        var id = Convert.ToHexString(HMACSHA256.HashData(_key, client.Host).AsSpan(0, 16));
        var factor = 1.0;
        if (!_buckets.TryGetValue(id, out var bucket)) {
            if (Volatile.Read(ref _count) >= _maxClients) {
                bucket = _overflow;
                factor = _overflowFactor;
            } else {
                var fresh = new Bucket { Tokens = _burst, Updated = now };
                bucket = _buckets.GetOrAdd(id, fresh);
                if (ReferenceEquals(bucket, fresh)) {
                    Interlocked.Increment(ref _count);
                }
            }
        }
        lock (bucket) {
            var elapsed = (now - bucket.Updated) / frequency;
            bucket.Tokens = Math.Min(_burst * factor, bucket.Tokens + elapsed * _rate * factor);
            bucket.Updated = now;
            if (bucket.Tokens < 1) {
                return false;
            }
            bucket.Tokens -= 1;
            return true;
        }
    }

    private void Sweep(long now, double frequency) {
        var last = Interlocked.Read(ref _lastSweep);
        if ((now - last) / frequency < 30 || Interlocked.CompareExchange(ref _lastSweep, now, last) != last) {
            return;
        }
        foreach (var (id, bucket) in _buckets) {
            if ((now - Volatile.Read(ref bucket.Updated)) / frequency > 60 && _buckets.TryRemove(id, out _)) {
                Interlocked.Decrement(ref _count);
            }
        }
    }
}
