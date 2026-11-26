using System.Net;
using System.Security.Cryptography;
using GoldfishSend.Core.Net;
using GoldfishSend.Infrastructure.Delivery;
using GoldfishSend.Infrastructure.Push;
using GoldfishSend.Infrastructure.Redis;
using GoldfishSend.Infrastructure.Services;

namespace GoldfishSend.Tests.Core;

public sealed class HostGroupingTests {
    [Theory]
    [InlineData("a1.evil.example", "evil.example")]
    [InlineData("a2.b.evil.example", "evil.example")]
    [InlineData("push.example.co.uk", "example.co.uk")]
    [InlineData("ntfy.sh", "ntfy.sh")]
    [InlineData("fcm.googleapis.com", "googleapis.com")]
    [InlineData("localhost", "localhost")]
    [InlineData("127.0.0.1", "127.0.0.1")]
    [InlineData("Push.Example.COM.", "example.com")]
    public void BaseDomain_GroupsWildcardSubdomains(string host, string expected) {
        Assert.Equal(expected, HostGrouping.BaseDomain(host));
    }
}

public sealed class GatewayReplayGuardTests {
    [Fact]
    public void Retention_OutlivesTheWholeAcceptanceWindow() {
        // Seen first with a timestamp just inside the window on one side, a replay stays acceptable until the floored
        // clock passes the other side: twice the window plus one second. Nodes' clocks can also disagree.
        var acceptable = TimeSpan.FromSeconds(2 * GatewayReplayGuard.TimestampWindowSeconds + 1);
        Assert.True(GatewayReplayGuard.Retention >= acceptable + TimeSpan.FromSeconds(30));
        Assert.Equal(GatewayReplayGuard.TimestampWindowSeconds, GoldfishSend.Api.GatewayMiddleware.TimestampWindowSeconds);
    }
}

public sealed class PushTtlTests {
    [Theory]
    [InlineData(0, 0)]
    [InlineData(30, 60)]
    [InlineData(599, 60)]
    [InlineData(600, 600)]
    [InlineData(3601, 3600)]
    [InlineData(259200, 259200)]
    [InlineData(259199, 86400)]
    [InlineData(2_000_000, 1_209_600)]
    public void Coarse_RoundsDownToFixedBuckets(int seconds, int expected) {
        Assert.Equal(expected, PushTtl.Coarse(seconds));
    }
}

public sealed class PushClassificationTests {
    [Theory]
    [InlineData(201, PushStatus.Delivered)]
    [InlineData(301, PushStatus.Transient)]
    [InlineData(302, PushStatus.Transient)]
    [InlineData(307, PushStatus.Transient)]
    [InlineData(404, PushStatus.Gone)]
    [InlineData(410, PushStatus.Gone)]
    [InlineData(401, PushStatus.Transient)]
    [InlineData(429, PushStatus.Transient)]
    [InlineData(503, PushStatus.Transient)]
    [InlineData(400, PushStatus.Rejected)]
    public void Classify(int code, PushStatus expected) {
        using var response = new HttpResponseMessage((HttpStatusCode)code);
        Assert.Equal(expected, PushClient.Classify(response).Status);
    }
}

public sealed class JobCodecTests {
    [Fact]
    public void Blob_IsBoundToMailboxAndExpiry() {
        var key = RandomNumberGenerator.GetBytes(32);
        var id = RandomNumberGenerator.GetBytes(16);
        var mailbox = RandomNumberGenerator.GetBytes(32);
        var expires = MessageService.WholeSeconds(DateTime.UtcNow.AddDays(1));
        var envelope = new byte[20];
        var blob = JobCodec.Seal(key, id, mailbox, expires, RandomNumberGenerator.GetBytes(32), envelope);

        var (_, opened) = JobCodec.Open(key, id, mailbox, expires, blob);
        Assert.Equal(envelope, opened);
        Assert.ThrowsAny<CryptographicException>(() => JobCodec.Open(key, id, RandomNumberGenerator.GetBytes(32), expires, blob));
        Assert.ThrowsAny<CryptographicException>(() => JobCodec.Open(key, id, mailbox, expires.AddDays(7), blob));
    }

    [Fact]
    public void WholeSeconds_Truncates() {
        var t = new DateTime(2026, 11, 13, 10, 0, 0, 999, DateTimeKind.Utc);
        Assert.Equal(new DateTime(2026, 11, 13, 10, 0, 0, DateTimeKind.Utc), MessageService.WholeSeconds(t));
    }
}

public sealed class SsrfExtraRangesTests {
    [Theory]
    [InlineData("192.31.196.1")]
    [InlineData("192.175.48.6")]
    [InlineData("192.52.193.1")]
    [InlineData("2620:4f:8000::1")]
    public void As112AndAmtRanges_AreBlocked(string ip) {
        Assert.False(new IpRangeFilter().IsAllowed(IPAddress.Parse(ip)));
    }
}
