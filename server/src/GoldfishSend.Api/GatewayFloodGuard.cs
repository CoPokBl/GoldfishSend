using System.Collections.Concurrent;
using System.Security.Cryptography;
using GoldfishSend.Core.Options;
using GoldfishSend.Infrastructure.Services;

namespace GoldfishSend.Api;

/// <summary>
/// A per-node, in-memory token bucket per client (IPv4 address or IPv6 /64) in front of the gateway. Opening a request
/// costs ~0.3 ms of CPU (ML-KEM decapsulation plus P-256), and that happens before any endpoint's rate limit, so this caps
/// how much decryption work one client can demand. It's generous: real clients make a few requests a minute. Clients
/// are keyed by an HMAC under a per-process random key, and idle buckets are dropped after a minute.
/// </summary>
public sealed class GatewayFloodGuard {
    private readonly double _rate;
    private readonly double _burst;
    private readonly byte[] _key = RandomNumberGenerator.GetBytes(32);
    private readonly ConcurrentDictionary<string, Bucket> _buckets = new();
    private readonly TimeProvider _time;
    private long _lastSweep;

    public GatewayFloodGuard(GoldfishOptions options, TimeProvider? time = null) {
        _rate = Math.Max(0, options.Network.GatewayRequestsPerSecond);
        _burst = Math.Max(1, options.Network.GatewayBurst);
        _time = time ?? TimeProvider.System;
    }

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
        var bucket = _buckets.GetOrAdd(id, _ => new Bucket { Tokens = _burst, Updated = now });
        lock (bucket) {
            var elapsed = (now - bucket.Updated) / frequency;
            bucket.Tokens = Math.Min(_burst, bucket.Tokens + elapsed * _rate);
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
            if ((now - Volatile.Read(ref bucket.Updated)) / frequency > 60) {
                _buckets.TryRemove(id, out _);
            }
        }
    }
}
