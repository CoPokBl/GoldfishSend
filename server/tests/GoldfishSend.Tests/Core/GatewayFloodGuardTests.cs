using System.Net;
using GoldfishSend.Api;
using GoldfishSend.Core.Options;
using GoldfishSend.Infrastructure.Services;

namespace GoldfishSend.Tests.Core;

public sealed class GatewayFloodGuardTests {
    private sealed class ManualTime : TimeProvider {
        public long Now = 1;
        public override long TimestampFrequency => 1000;
        public override long GetTimestamp() => Now;
    }

    private static GoldfishOptions Options(int maxClients, int networkFactor = 4, int allocationFactor = 20) {
        var o = new GoldfishOptions();
        o.Network.GatewayRequestsPerSecond = 1;
        o.Network.GatewayBurst = 2;
        o.Network.GatewayMaxClients = maxClients;
        o.Network.GatewayOverflowFactor = 3;
        o.Network.GatewayNetworkFactor = networkFactor;
        o.Network.GatewayAllocationFactor = allocationFactor;
        o.Network.GatewayOnionFactor = 5;
        return o;
    }

    /// <summary>The <paramref name="n"/>th /64 of 2001:db8:0:<paramref name="net"/>::/48... (or of /48 number net).</summary>
    private static ClientSubject V6(int n, int net = 0, int alloc = 0) =>
        ClientSubject.From(IPAddress.Parse($"2001:{0xdb8 + alloc:x}:{net:x}:{n:x}::1"));

    private static ClientSubject V4(string address) => ClientSubject.From(IPAddress.Parse(address));

    private static int Allowed(GatewayFloodGuard guard, IEnumerable<ClientSubject> clients) {
        return clients.Count(c => guard.TryAcquire(c));
    }

    [Fact]
    public void RotatingSlash64s_CannotGrowTheTablePastTheCap() {
        var guard = new GatewayFloodGuard(Options(100), new ManualTime());
        for (var i = 0; i < 10_000; i++) {
            guard.TryAcquire(V6(i % 60_000, net: i / 200));
        }
        Assert.Equal(100, guard.TrackedClients);
        Assert.True(guard.TrackedNetworks <= 100);
    }

    [Fact]
    public void RotatingSlash64s_InOneSlash48_AreHeldToTheNetworksBucket() {
        // Before, every /64 had its own bucket, so a /56 (256 /64s) got 256 clients' worth of decryption.
        var guard = new GatewayFloodGuard(Options(100_000), new ManualTime());
        Assert.Equal(2 * 4, Allowed(guard, Enumerable.Range(0, 1000).Select(i => V6(i))));
    }

    [Fact]
    public void ManySlash48s_InOneSlash32_AreHeldToTheAllocationsBucket() {
        var guard = new GatewayFloodGuard(Options(100_000, networkFactor: 4, allocationFactor: 10), new ManualTime());
        Assert.Equal(2 * 10, Allowed(guard, Enumerable.Range(0, 1000).Select(i => V6(0, net: i))));
        // Another /32 is untouched.
        Assert.True(guard.TryAcquire(V6(0, alloc: 1)));
    }

    [Fact]
    public void AnAttackerFillingTheTable_OnlyOverflowsIntoItsOwnBuckets() {
        var guard = new GatewayFloodGuard(Options(50), new ManualTime());
        // The attacker's /48s fill the client table (and its /32 bucket).
        for (var i = 0; i < 5000; i++) {
            guard.TryAcquire(V6(i % 200, net: i / 200));
        }
        Assert.Equal(50, guard.TrackedClients);
        Assert.False(guard.TryAcquire(V6(9999, net: 3)), "the attacker is out of tokens");

        // A newcomer from another allocation gets no client entry, but its own network's bucket is full.
        Assert.True(guard.TryAcquire(V6(1, alloc: 7)));
        Assert.True(guard.TryAcquire(V4("192.0.2.10")));
        Assert.True(guard.TryAcquire(V4("192.0.2.11")));
    }

    [Fact]
    public void Ipv4Addresses_ShareTheirSlash24s_Bucket() {
        var guard = new GatewayFloodGuard(Options(100_000), new ManualTime());
        Assert.Equal(2 * 4, Allowed(guard, Enumerable.Range(1, 200).Select(i => V4($"198.51.100.{i}"))));
        Assert.True(guard.TryAcquire(V4("198.51.101.1")));
    }

    [Fact]
    public void RefusedRequests_DontSpendTheWiderBuckets() {
        // All or nothing: one address hammering past its own limit leaves its neighbours their share of the /24.
        var guard = new GatewayFloodGuard(Options(100_000), new ManualTime());
        for (var i = 0; i < 100; i++) {
            guard.TryAcquire(V4("203.0.113.1"));
        }
        Assert.Equal(2 * 4 - 2, Allowed(guard, Enumerable.Range(2, 100).Select(i => V4($"203.0.113.{i}"))));
    }

    [Fact]
    public void OnionCircuits_HaveTheirOwnBuckets_InsideOneOnionBucket() {
        var guard = new GatewayFloodGuard(Options(100_000), new ManualTime());
        var tor = V4("172.30.251.4");
        // One circuit can't use more than a client's share...
        Assert.Equal(2, Enumerable.Range(0, 10).Count(_ => guard.TryAcquire(tor, circuit: 1)));
        // ...so other circuits still get through, up to the onion-wide bucket (5x a client's).
        Assert.Equal(2 * 5 - 2, Enumerable.Range(2, 50).Count(c => guard.TryAcquire(tor, circuit: (ulong)c)));
        // Plain clients from the Tor container's own address aren't affected.
        Assert.True(guard.TryAcquire(tor));
    }

    [Fact]
    public void TokensRefill_AtEveryTier() {
        var time = new ManualTime();
        var guard = new GatewayFloodGuard(Options(100_000), time);
        Assert.Equal(8, Allowed(guard, Enumerable.Range(1, 50).Select(i => V4($"198.51.100.{i}"))));
        time.Now += 1000;
        Assert.Equal(4, Allowed(guard, Enumerable.Range(51, 50).Select(i => V4($"198.51.100.{i}"))));
    }

    [Fact]
    public void IdleClients_FreeTheirSlots() {
        var time = new ManualTime();
        var guard = new GatewayFloodGuard(Options(2), time);
        guard.TryAcquire(V6(1));
        guard.TryAcquire(V6(2));
        Assert.Equal(2, guard.TrackedClients);

        time.Now += 61_000;
        guard.TryAcquire(V6(3));
        Assert.Equal(1, guard.TrackedClients);
        Assert.Equal(1, guard.TrackedNetworks);
    }
}
