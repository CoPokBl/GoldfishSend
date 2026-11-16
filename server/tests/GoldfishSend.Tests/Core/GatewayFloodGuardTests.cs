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

    private static GoldfishOptions Options(int maxClients) {
        var o = new GoldfishOptions();
        o.Network.GatewayRequestsPerSecond = 1;
        o.Network.GatewayBurst = 2;
        o.Network.GatewayMaxClients = maxClients;
        o.Network.GatewayOverflowFactor = 3;
        return o;
    }

    private static ClientSubject V6(int n) =>
        ClientSubject.From(IPAddress.Parse($"2001:db8:{n >> 16:x}:{n & 0xffff:x}::1"));

    [Fact]
    public void RotatingSlash64s_CannotGrowTheTablePastTheCap() {
        var guard = new GatewayFloodGuard(Options(100), new ManualTime());
        for (var i = 0; i < 10_000; i++) {
            guard.TryAcquire(V6(i));
        }
        Assert.Equal(100, guard.TrackedClients);
    }

    [Fact]
    public void NewClients_ShareTheOverflowBucket_WhileTrackedOnesKeepTheirOwn() {
        var guard = new GatewayFloodGuard(Options(2), new ManualTime());
        Assert.True(guard.TryAcquire(V6(1)));
        Assert.True(guard.TryAcquire(V6(2)));

        // The overflow bucket holds burst x factor = 6 tokens for every client seen after the table filled.
        var allowed = 0;
        for (var i = 100; i < 120; i++) {
            if (guard.TryAcquire(V6(i))) {
                allowed++;
            }
        }
        Assert.Equal(6, allowed);
        Assert.True(guard.TryAcquire(V6(1)), "a tracked client keeps its own bucket");
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
    }
}
