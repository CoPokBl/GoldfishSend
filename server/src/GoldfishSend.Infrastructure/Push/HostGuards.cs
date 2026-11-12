using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using GoldfishSend.Core.Options;
using GoldfishSend.Infrastructure.Redis;
using StackExchange.Redis;

namespace GoldfishSend.Infrastructure.Push;

public readonly record struct GateResult(HostGuards.Lease? Lease, TimeSpan? RetryAfter);

/// <summary>
/// Protects push services from us, and us from slow push services:
/// <list type="bullet">
/// <item>Pacing per host is a Redis GCRA, so the whole cluster shares one budget per push service.</item>
/// <item>The circuit breaker counts failures per host in Redis. Once the cluster sees N failures in a minute,
/// every node backs off together. A local copy of the "open" state saves a round trip per push.</item>
/// <item>Concurrency is capped per process, the natural unit for connection pools.</item>
/// </list>
/// If the ephemeral Redis is unavailable, it falls back to process-local behaviour.
/// </summary>
public sealed class HostGuards {
    private static readonly byte[] FingerprintKey = RandomNumberGenerator.GetBytes(32);
    private static readonly TimeSpan FailureWindow = TimeSpan.FromMinutes(1);

    private readonly PushOptions _options;
    private readonly RateLimiter _limiter;
    private readonly EphemeralRedis _redis;
    private readonly ConcurrentDictionary<string, HostState> _hosts = new(StringComparer.Ordinal);

    public HostGuards(GoldfishOptions options, RateLimiter limiter, EphemeralRedis redis) {
        _options = options.Push;
        _limiter = limiter;
        _redis = redis;
    }

    public async Task<GateResult> TryEnterAsync(string host) {
        var state = _hosts.GetOrAdd(host, h => new HostState(HostKey(h)));
        state.LastUsed = Environment.TickCount64;

        var now = Environment.TickCount64;
        var openUntil = Interlocked.Read(ref state.OpenUntil);
        if (openUntil > now) {
            return new GateResult(null, TimeSpan.FromMilliseconds(openUntil - now));
        }
        try {
            if (await _redis.Db.KeyTimeToLiveAsync(OpenKey(state)) is { } remaining && remaining > TimeSpan.Zero) {
                Interlocked.Exchange(ref state.OpenUntil, now + (long)remaining.TotalMilliseconds);
                return new GateResult(null, remaining);
            }
        } catch (Exception ex) when (ex is RedisException or TimeoutException) {
            // Local state only.
        }

        var pace = await _limiter.CheckAsync(RatePolicies.PushPerHost, Encoding.UTF8.GetBytes(host));
        if (!pace.Allowed) {
            return new GateResult(null, pace.RetryAfter);
        }

        if (Interlocked.Increment(ref state.InFlight) > _options.MaxConnectionsPerHost * 4) {
            Interlocked.Decrement(ref state.InFlight);
            return new GateResult(null, TimeSpan.FromSeconds(1));
        }
        return new GateResult(new Lease(this, state), null);
    }

    /// <summary>
    /// Holds the exact state object that was entered, so pruning can't make Exit touch a different
    /// (fresh) entry and push its counters negative.
    /// </summary>
    public sealed class Lease {
        private readonly HostGuards _owner;
        private readonly HostState _state;
        private int _exited;

        internal Lease(HostGuards owner, HostState state) {
            _owner = owner;
            _state = state;
        }

        public Task ExitAsync(bool success) {
            return Interlocked.Exchange(ref _exited, 1) == 0 ? _owner.ExitAsync(_state, success) : Task.CompletedTask;
        }
    }

    private async Task ExitAsync(HostState state, bool success) {
        Interlocked.Decrement(ref state.InFlight);
        var hadFailures = Interlocked.Exchange(ref state.LocalFailures, success ? 0 : state.LocalFailures + 1) > 0;
        try {
            var db = _redis.Db;
            if (success) {
                // Only talk to Redis when there's something to reset.
                if (hadFailures) {
                    await db.KeyDeleteAsync(FailKey(state), CommandFlags.FireAndForget);
                }
                return;
            }
            var failures = await db.StringIncrementAsync(FailKey(state));
            if (failures == 1) {
                await db.KeyExpireAsync(FailKey(state), FailureWindow, CommandFlags.FireAndForget);
            }
            if (failures >= _options.CircuitBreakerFailures) {
                var open = TimeSpan.FromSeconds(_options.CircuitBreakerOpenSeconds);
                await db.StringSetAsync(OpenKey(state), 1, open);
                await db.KeyDeleteAsync(FailKey(state), CommandFlags.FireAndForget);
                Interlocked.Exchange(ref state.OpenUntil, Environment.TickCount64 + (long)open.TotalMilliseconds);
            }
        } catch (Exception ex) when (ex is RedisException or TimeoutException) {
            if (!success && Interlocked.Read(ref state.LocalFailures) >= _options.CircuitBreakerFailures) {
                Interlocked.Exchange(ref state.OpenUntil, Environment.TickCount64 + _options.CircuitBreakerOpenSeconds * 1000L);
                Interlocked.Exchange(ref state.LocalFailures, 0);
            }
        }
    }

    /// <summary>Drops local state for hosts that have been idle for 10 minutes, so the table can't grow without bound.</summary>
    public void Prune() {
        var cutoff = Environment.TickCount64 - 600_000;
        foreach (var (host, state) in _hosts) {
            if (state.LastUsed < cutoff && Interlocked.Read(ref state.InFlight) == 0) {
                _hosts.TryRemove(host, out _);
            }
        }
    }

    /// <summary>A per-process, unlinkable host label for logs: enough to spot a misbehaving host without recording it.</summary>
    public static string Fingerprint(string host) {
        return Convert.ToHexString(HMACSHA256.HashData(FingerprintKey, Encoding.UTF8.GetBytes(host)), 0, 4);
    }

    // Cluster-wide key for a host. Push-service hostnames are shared infrastructure, not per-user data.
    private static string HostKey(string host) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("gf/host/" + host)), 0, 12);

    private static RedisKey FailKey(HostState state) => $"gf:cb:fail:{state.Key}";

    private static RedisKey OpenKey(HostState state) => $"gf:cb:open:{state.Key}";

    internal sealed class HostState(string key) {
        public readonly string Key = key;
        public long InFlight;
        public long LocalFailures;
        public long OpenUntil;
        public long LastUsed;
    }
}
