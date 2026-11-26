using System.Collections.Concurrent;
using System.Security.Cryptography;
using GoldfishSend.Core.Options;
using GoldfishSend.Infrastructure.Services;

namespace GoldfishSend.Api;

/// <summary>
/// Per-node, in-memory token buckets in front of the gateway. Opening a request costs ~0.3 ms of CPU (ML-KEM
/// decapsulation plus P-256), and that happens before any endpoint's rate limit, so this caps how much decryption work
/// one client, one network and one IPv6 allocation can demand. Every request takes a token from each of its tiers, all
/// or nothing:
/// <list type="bullet">
/// <item>the client (IPv4 address or IPv6 /64, or one Tor circuit on the onion listener),</item>
/// <item>its network (IPv4 /24 or IPv6 /48), <see cref="NetworkOptions.GatewayNetworkFactor"/> times a client's size
/// (all onion circuits share one bucket, <see cref="NetworkOptions.GatewayOnionFactor"/> times a client's),</item>
/// <item>its IPv6 /32, <see cref="NetworkOptions.GatewayAllocationFactor"/> times a client's.</item>
/// </list>
/// It's generous: real clients make a few requests a minute. Keys are HMACs under a per-process random key, and idle
/// buckets are dropped after a minute. Memory is bounded: each table holds at most
/// <see cref="NetworkOptions.GatewayMaxClients"/> entries, one network at most <see cref="HostsPerNetwork"/> clients and
/// one /32 at most <see cref="NetworksPerAllocation"/> networks. A client that finds no room is charged only at its
/// wider tiers, so an attacker rotating through addresses fills its own network's and /32's buckets, never a stranger's.
/// Only an IPv4 network that finds its table full (which takes ~100,000 /24s) falls back to one shared overflow bucket.
/// </summary>
public sealed class GatewayFloodGuard {
    /// <summary>An IPv4 /24 holds 256 addresses. A /48 with more active /64s than that shares its network's bucket.</summary>
    public const int HostsPerNetwork = 256;
    /// <summary>A /32 with more /48s active at once than this charges the rest only at the /32 tier.</summary>
    public const int NetworksPerAllocation = 64;

    private static readonly TimeSpan IdleAfter = TimeSpan.FromSeconds(60);

    private readonly double _rate;
    private readonly double _burst;
    private readonly byte[] _key = RandomNumberGenerator.GetBytes(32);
    private readonly TimeProvider _time;
    private readonly int _maxEntries;
    private readonly double _networkFactor;
    private readonly double _allocationFactor;
    private readonly double _overflowFactor;
    private readonly Table _hosts;
    private readonly Table _networks;
    private readonly Table _allocations;
    private readonly Bucket _overflow;
    private readonly Bucket _onion;
    private long _lastSweep;

    public GatewayFloodGuard(GoldfishOptions options, TimeProvider? time = null) {
        var network = options.Network;
        _rate = Math.Max(0, network.GatewayRequestsPerSecond);
        _burst = Math.Max(1, network.GatewayBurst);
        _time = time ?? TimeProvider.System;
        _maxEntries = Math.Max(1, network.GatewayMaxClients);
        _networkFactor = Math.Max(1, network.GatewayNetworkFactor);
        _allocationFactor = Math.Max(1, network.GatewayAllocationFactor);
        _overflowFactor = Math.Max(1, network.GatewayOverflowFactor);
        _hosts = new Table(_maxEntries);
        _networks = new Table(_maxEntries);
        _allocations = new Table(_maxEntries);
        var now = _time.GetTimestamp();
        _overflow = new Bucket(_overflowFactor, _burst, now, null);
        _onion = new Bucket(Math.Max(1, network.GatewayOnionFactor), _burst, now, null);
    }

    /// <summary>Clients currently tracked (for tests).</summary>
    public int TrackedClients => _hosts.Count;

    /// <summary>Networks currently tracked (for tests).</summary>
    public int TrackedNetworks => _networks.Count;

    private sealed class Bucket(double factor, double burst, long now, Bucket? parent) {
        public readonly double Factor = factor;
        public readonly Bucket? Parent = parent;
        public double Tokens = burst * factor;
        public long Updated = now;
        /// <summary>Entries in the next narrower table that have this bucket as their parent.</summary>
        public int Children;
    }

    private sealed class Table(int max) {
        public readonly ConcurrentDictionary<string, Bucket> Entries = new();
        public readonly int Max = max;
        public int Count;
    }

    /// <summary>Takes one token for this client at every tier. False means one of them is over its limit.</summary>
    /// <param name="circuit">The Tor circuit, on the onion listener with circuit ids on. It stands in for the address.</param>
    public bool TryAcquire(ClientSubject client, ulong? circuit = null) {
        if (_rate <= 0) {
            return true;
        }
        var now = _time.GetTimestamp();
        Sweep(now);

        Bucket? network;
        if (circuit is not null) {
            network = _onion;
        } else {
            var allocation = client.Allocation is null
                ? null
                : GetOrAdd(_allocations, "a" + Id(client.Allocation), _allocationFactor, null, int.MaxValue, now);
            network = GetOrAdd(_networks, "n" + Id(client.Network), _networkFactor, allocation, NetworksPerAllocation, now);
            if (network is null) {
                // No room for the network: it's charged at its /32 alone (its clients get no entries of their own either,
                // which keeps the /32's child count about networks). IPv4 has no wider tier, so it shares the overflow.
                if (allocation is not null) {
                    return TakeAll(now, allocation, null, null);
                }
                network = _overflow;
            }
        }
        var hostId = circuit is { } c ? "c" + c.ToString("x16", System.Globalization.CultureInfo.InvariantCulture) : "h" + Id(client.Host);
        var host = GetOrAdd(_hosts, hostId, 1, network, HostsPerNetwork, now);

        return TakeAll(now, host, network, network.Parent);
    }

    /// <summary>One token from each bucket given, or none if any is empty.</summary>
    private bool TakeAll(long now, Bucket? host, Bucket? network, Bucket? allocation) {
        // Narrowest first, the same order every time, so nested locks can't deadlock.
        Span<Bucket?> tiers = [host, network, allocation];
        Span<Bucket?> chain = [null, null, null];
        var held = 0;
        try {
            foreach (var bucket in tiers) {
                if (bucket is not null) {
                    Monitor.Enter(bucket);
                    chain[held++] = bucket;
                }
            }
            var frequency = (double)_time.TimestampFrequency;
            for (var i = 0; i < held; i++) {
                var bucket = chain[i]!;
                var elapsed = Math.Max(0, now - bucket.Updated) / frequency;
                bucket.Tokens = Math.Min(_burst * bucket.Factor, bucket.Tokens + elapsed * _rate * bucket.Factor);
                bucket.Updated = Math.Max(bucket.Updated, now);
            }
            for (var i = 0; i < held; i++) {
                if (chain[i]!.Tokens < 1) {
                    return false;
                }
            }
            for (var i = 0; i < held; i++) {
                chain[i]!.Tokens -= 1;
            }
            return true;
        } finally {
            for (var i = held - 1; i >= 0; i--) {
                Monitor.Exit(chain[i]!);
            }
        }
    }

    private string Id(byte[] prefix) => Convert.ToHexString(HMACSHA256.HashData(_key, prefix).AsSpan(0, 16));

    /// <summary>The entry, or a new (full) one if the table and the parent have room. Null otherwise.</summary>
    private Bucket? GetOrAdd(Table table, string id, double factor, Bucket? parent, int perParent, long now) {
        if (table.Entries.TryGetValue(id, out var existing)) {
            return existing;
        }
        if (Volatile.Read(ref table.Count) >= table.Max || (parent is not null && Volatile.Read(ref parent.Children) >= perParent)) {
            return null;
        }
        var fresh = new Bucket(factor, _burst, now, parent);
        var bucket = table.Entries.GetOrAdd(id, fresh);
        if (ReferenceEquals(bucket, fresh)) {
            Interlocked.Increment(ref table.Count);
            if (parent is not null) {
                Interlocked.Increment(ref parent.Children);
            }
        }
        return bucket;
    }

    private void Sweep(long now) {
        var frequency = (double)_time.TimestampFrequency;
        var last = Interlocked.Read(ref _lastSweep);
        if ((now - last) / frequency < 30 || Interlocked.CompareExchange(ref _lastSweep, now, last) != last) {
            return;
        }
        // Narrowest first: a parent is only ever as idle as its most recent child.
        foreach (var table in new[] { _hosts, _networks, _allocations }) {
            foreach (var (id, bucket) in table.Entries) {
                if ((now - Volatile.Read(ref bucket.Updated)) / frequency > IdleAfter.TotalSeconds && table.Entries.TryRemove(id, out _)) {
                    Interlocked.Decrement(ref table.Count);
                    if (bucket.Parent is { } parent) {
                        Interlocked.Decrement(ref parent.Children);
                    }
                }
            }
        }
    }
}
