using System.Collections.Concurrent;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using GoldfishSend.Core.Net;
using GoldfishSend.Core.Options;
using GoldfishSend.Infrastructure.Redis;
using StackExchange.Redis;

namespace GoldfishSend.Infrastructure.Push;

/// <summary>Why a push attempt ended, as far as host health is concerned.</summary>
public enum HostOutcome {
    /// <summary>The push service answered (any 2xx, 3xx or 4xx). The host is healthy, even if it refused one subscription.</summary>
    Healthy,
    /// <summary>Connection failure, TLS failure, timeout or 5xx: the host itself may be in trouble.</summary>
    HostFailure,
}

public readonly record struct GateResult(HostGuards.Lease? Lease, TimeSpan? RetryAfter);

/// <summary>
/// Protects push services from us, and us (and other users) from slow or hostile push services:
/// <list type="bullet">
/// <item><b>Circuit breaker</b> (cluster-wide, in the ephemeral Redis): a host is paused only when, within a minute, it had
/// enough pushes, a high enough share of host-level failures (transport errors, timeouts, 5xx), and those failures came
/// from several distinct endpoints. One subscriber's rejections (4xx, 429, 401/403) never count, so one attacker
/// can't pause a shared push service for everyone.</item>
/// <item><b>Pacing</b>: a per-mailbox outbound share sits in front of the per-host budget (both cluster-wide), so a few
/// mailboxes can't consume a shared push service's whole budget.</item>
/// <item><b>In-flight cap</b> per host per process, well below the delivery parallelism, so one host can't take every slot.</item>
/// <item><b>Slow lane</b>: hosts whose base domain recently timed out share a small, separate pool of slots. That catches
/// tarpits spread across wildcard subdomains.</item>
/// </list>
/// Every denial here is a local deferral: it doesn't count as a failed attempt or escalate the message's backoff.
/// </summary>
public sealed class HostGuards {
    private static readonly byte[] FingerprintKey = RandomNumberGenerator.GetBytes(32);
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(1);
    private static readonly TimeSpan SlowFor = TimeSpan.FromMinutes(10);

    // KEYS: attempts, failures, failing endpoints, open flag. ARGV: failed (0/1), endpoint hash, window ms, min volume,
    // ratio, min distinct endpoints, open ms. Returns 1 if this call opened the circuit.
    private const string BreakerScript = """
        local n = redis.call('INCR', KEYS[1])
        if n == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[3]) end
        if ARGV[1] ~= '1' then return 0 end
        local f = redis.call('INCR', KEYS[2])
        if f == 1 then redis.call('PEXPIRE', KEYS[2], ARGV[3]) end
        redis.call('SADD', KEYS[3], ARGV[2])
        if redis.call('PTTL', KEYS[3]) < 0 then redis.call('PEXPIRE', KEYS[3], ARGV[3]) end
        if n >= tonumber(ARGV[4]) and (f / n) >= tonumber(ARGV[5]) and redis.call('SCARD', KEYS[3]) >= tonumber(ARGV[6]) then
            redis.call('SET', KEYS[4], '1', 'PX', ARGV[7])
            redis.call('DEL', KEYS[1], KEYS[2], KEYS[3])
            return 1
        end
        return 0
        """;

    private readonly PushOptions _options;
    private readonly RateLimiter _limiter;
    private readonly EphemeralRedis _redis;
    private readonly ClusterSecret _secret;
    private readonly SemaphoreSlim _slowLane;
    private readonly ConcurrentDictionary<string, HostState> _hosts = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, long> _slowBases = new(StringComparer.Ordinal);

    public HostGuards(GoldfishOptions options, RateLimiter limiter, EphemeralRedis redis, ClusterSecret secret) {
        _options = options.Push;
        _limiter = limiter;
        _redis = redis;
        _secret = secret;
        _slowLane = new SemaphoreSlim(Math.Max(1, _options.SlowLaneSlots));
    }

    /// <param name="mailboxId">The mailbox being delivered to, for its fair share. Null for verification pushes.</param>
    public async Task<GateResult> TryEnterAsync(string host, byte[]? mailboxId = null) {
        var keys = await KeysAsync(host);
        var state = _hosts.GetOrAdd(host, _ => new HostState(keys.HostKey));
        state.LastUsed = Environment.TickCount64;
        var now = Environment.TickCount64;

        var openUntil = Interlocked.Read(ref state.OpenUntil);
        if (openUntil > now) {
            return new GateResult(null, TimeSpan.FromMilliseconds(openUntil - now));
        }
        try {
            if (await _redis.Db.KeyTimeToLiveAsync(OpenKey(keys.HostKey)) is { } remaining && remaining > TimeSpan.Zero) {
                Interlocked.Exchange(ref state.OpenUntil, now + (long)remaining.TotalMilliseconds);
                return new GateResult(null, remaining);
            }
        } catch (Exception ex) when (ex is RedisException or TimeoutException) {
            // Local state only.
        }

        if (mailboxId is not null) {
            var share = await _limiter.CheckAsync(RatePolicies.PushPerMailbox, mailboxId);
            if (!share.Allowed) {
                return new GateResult(null, share.RetryAfter);
            }
        }
        var pace = await _limiter.CheckAsync(RatePolicies.PushPerHost, Encoding.UTF8.GetBytes(host));
        if (!pace.Allowed) {
            return new GateResult(null, pace.RetryAfter);
        }

        var slow = await IsSlowAsync(keys.BaseKey);
        if (slow && !_slowLane.Wait(0)) {
            return new GateResult(null, TimeSpan.FromSeconds(5));
        }
        if (Interlocked.Increment(ref state.InFlight) > Math.Max(1, _options.MaxInFlightPerHost)) {
            Interlocked.Decrement(ref state.InFlight);
            if (slow) {
                _slowLane.Release();
            }
            return new GateResult(null, TimeSpan.FromSeconds(1));
        }
        return new GateResult(new Lease(this, state, keys, slow), null);
    }

    /// <summary>
    /// Holds the exact state object that was entered, so pruning can't make Exit touch a different
    /// (fresh) entry and push its counters negative.
    /// </summary>
    public sealed class Lease {
        private readonly HostGuards _owner;
        private readonly HostState _state;
        private readonly HostKeys _keys;
        private readonly bool _slowLane;
        private int _exited;

        internal Lease(HostGuards owner, HostState state, HostKeys keys, bool slowLane) {
            _owner = owner;
            _state = state;
            _keys = keys;
            _slowLane = slowLane;
        }

        /// <param name="endpointUrl">Used (as a keyed hash) to count distinct failing endpoints.</param>
        /// <param name="timedOut">The push hit its deadline, which puts the host's base domain into the slow lane.</param>
        public Task ExitAsync(HostOutcome outcome, string endpointUrl, bool timedOut) {
            if (Interlocked.Exchange(ref _exited, 1) != 0) {
                return Task.CompletedTask;
            }
            Interlocked.Decrement(ref _state.InFlight);
            if (_slowLane) {
                _owner._slowLane.Release();
            }
            return _owner.RecordAsync(_state, _keys, outcome, endpointUrl, timedOut);
        }
    }

    private async Task RecordAsync(HostState state, HostKeys keys, HostOutcome outcome, string endpointUrl, bool timedOut) {
        var failed = outcome == HostOutcome.HostFailure;
        if (timedOut) {
            _slowBases[keys.BaseKey] = Environment.TickCount64 + (long)SlowFor.TotalMilliseconds;
        }
        try {
            var db = _redis.Db;
            if (timedOut) {
                await db.StringSetAsync(SlowKey(keys.BaseKey), 1, SlowFor, flags: CommandFlags.FireAndForget);
            }
            var endpointHash = await _secret.HmacHexAsync("ep", Encoding.UTF8.GetBytes(endpointUrl), 8);
            var opened = (long)await db.ScriptEvaluateAsync(BreakerScript,
                [CountKey(keys.HostKey), FailKey(keys.HostKey), EndpointsKey(keys.HostKey), OpenKey(keys.HostKey)],
                [
                    failed ? "1" : "0", endpointHash, (long)Window.TotalMilliseconds, _options.CircuitBreakerMinVolume,
                    _options.CircuitBreakerFailureRatio.ToString(CultureInfo.InvariantCulture), _options.CircuitBreakerMinEndpoints,
                    _options.CircuitBreakerOpenSeconds * 1000L,
                ]);
            if (opened == 1) {
                Interlocked.Exchange(ref state.OpenUntil, Environment.TickCount64 + _options.CircuitBreakerOpenSeconds * 1000L);
            }
        } catch (Exception ex) when (ex is RedisException or TimeoutException) {
            LocalBreaker(state, failed, endpointUrl);
        }
    }

    /// <summary>The same rule as the Redis breaker, per process, for when the ephemeral Redis is unavailable.</summary>
    private void LocalBreaker(HostState state, bool failed, string endpointUrl) {
        lock (state) {
            var now = Environment.TickCount64;
            if (now - state.WindowStart > Window.TotalMilliseconds) {
                state.WindowStart = now;
                state.WindowCount = 0;
                state.WindowFailures = 0;
                state.FailingEndpoints.Clear();
            }
            state.WindowCount++;
            if (!failed) {
                return;
            }
            state.WindowFailures++;
            if (state.FailingEndpoints.Count < 64) {
                state.FailingEndpoints.Add(endpointUrl.GetHashCode(StringComparison.Ordinal));
            }
            if (state.WindowCount >= _options.CircuitBreakerMinVolume
                && (double)state.WindowFailures / state.WindowCount >= _options.CircuitBreakerFailureRatio
                && state.FailingEndpoints.Count >= _options.CircuitBreakerMinEndpoints) {
                Interlocked.Exchange(ref state.OpenUntil, now + _options.CircuitBreakerOpenSeconds * 1000L);
                state.WindowCount = 0;
                state.WindowFailures = 0;
                state.FailingEndpoints.Clear();
            }
        }
    }

    private async Task<bool> IsSlowAsync(string baseKey) {
        var now = Environment.TickCount64;
        if (_slowBases.TryGetValue(baseKey, out var until)) {
            if (until > now) {
                return true;
            }
            _slowBases.TryRemove(baseKey, out _);
        }
        try {
            if (await _redis.Db.KeyExistsAsync(SlowKey(baseKey))) {
                _slowBases[baseKey] = now + 60_000; // Cache briefly. Redis holds the real expiry.
                return true;
            }
        } catch (Exception ex) when (ex is RedisException or TimeoutException) {
            // Local knowledge only.
        }
        return false;
    }

    /// <summary>Drops local state for hosts that have been idle for 10 minutes, so the tables can't grow without bound.</summary>
    public void Prune() {
        var now = Environment.TickCount64;
        var cutoff = now - 600_000;
        foreach (var (host, state) in _hosts) {
            if (state.LastUsed < cutoff && Interlocked.Read(ref state.InFlight) == 0) {
                _hosts.TryRemove(host, out _);
            }
        }
        foreach (var (key, until) in _slowBases) {
            if (until < now) {
                _slowBases.TryRemove(key, out _);
            }
        }
    }

    /// <summary>A per-process, unlinkable host label for logs: enough to spot a misbehaving host without recording it.</summary>
    public static string Fingerprint(string host) {
        return Convert.ToHexString(HMACSHA256.HashData(FingerprintKey, Encoding.UTF8.GetBytes(host)), 0, 4);
    }

    /// <summary>
    /// Cluster-wide keys for a host and its base domain, HMACed with the cluster secret so the ephemeral Redis doesn't
    /// reveal which (possibly personal) push hosts are in use.
    /// </summary>
    private async Task<HostKeys> KeysAsync(string host) {
        var secret = await _secret.GetAsync();
        return new HostKeys(
            ClusterSecret.Hmac(secret, "host", Encoding.UTF8.GetBytes(host), 12),
            ClusterSecret.Hmac(secret, "base", Encoding.UTF8.GetBytes(HostGrouping.BaseDomain(host)), 12));
    }

    private static RedisKey CountKey(string k) => $"gf:cb:n:{k}";
    private static RedisKey FailKey(string k) => $"gf:cb:f:{k}";
    private static RedisKey EndpointsKey(string k) => $"gf:cb:e:{k}";
    private static RedisKey OpenKey(string k) => $"gf:cb:open:{k}";
    private static RedisKey SlowKey(string k) => $"gf:slow:{k}";

    internal readonly record struct HostKeys(string HostKey, string BaseKey);

    internal sealed class HostState(string key) {
        public readonly string Key = key;
        public long InFlight;
        public long OpenUntil;
        public long LastUsed;
        public long WindowStart;
        public int WindowCount;
        public int WindowFailures;
        public readonly HashSet<int> FailingEndpoints = [];
    }
}
