using System.Net;
using System.Security.Cryptography;
using GoldfishSend.Core.Net;
using GoldfishSend.Infrastructure.Delivery;
using GoldfishSend.Infrastructure.Push;
using GoldfishSend.Infrastructure.Services;

namespace GoldfishSend.Tests.Core;

public sealed class HostGroupingTests {
    [Theory]
    [InlineData("a1.evil.example", "evil.example")]
    [InlineData("a2.b.evil.example", "evil.example")]
    [InlineData("push.example.co.uk", "example.co.uk")]
    [InlineData("ntfy.sh", "ntfy.sh")]
    [InlineData("localhost", "localhost")]
    [InlineData("127.0.0.1", "127.0.0.1")]
    [InlineData("[2001:db8::1]", "[2001:db8::1]")]
    [InlineData("Push.Example.COM.", "example.com")]
    // Short registrable names under a two-letter TLD are still one domain.
    [InlineData("a1.q7z.de", "q7z.de")]
    [InlineData("a2.ab.io", "ab.io")]
    [InlineData("x.y.example.com.au", "example.com.au")]
    // Shared hosting suffixes (the PSL's private section): every customer is its own domain.
    [InlineData("alice.ts.net", "alice.ts.net")]
    [InlineData("ntfy.bob.ts.net", "bob.ts.net")]
    [InlineData("a.b.duckdns.org", "b.duckdns.org")]
    [InlineData("fcm.googleapis.com", "fcm.googleapis.com")]
    [InlineData("x.trycloudflare.com", "x.trycloudflare.com")]
    // Wildcard and exception rules: *.ck and !www.ck.
    [InlineData("a.b.ck", "a.b.ck")]
    [InlineData("a.www.ck", "www.ck")]
    // A public suffix itself, and an unlisted TLD (the implicit "*" rule).
    [InlineData("co.uk", "co.uk")]
    [InlineData("a.b.example.invalidtld", "example.invalidtld")]
    // Internationalised rules match the ASCII form hosts arrive in (公司.cn).
    [InlineData("a.example.xn--55qx5d.cn", "example.xn--55qx5d.cn")]
    public void BaseDomain_IsTheRegistrableDomain(string host, string expected) {
        Assert.Equal(expected, HostGrouping.BaseDomain(host));
    }

    [Theory]
    [InlineData("ntfy.sh", true)]
    [InlineData("eu.ntfy.sh", true)]
    [InlineData("NTFY.SH.", true)]
    [InlineData("notntfy.sh", false)]
    [InlineData("ntfy.sh.evil.example", false)]
    [InlineData("", false)]
    public void IsWithin_MatchesNamesAndTheirSubdomains(string host, bool expected) {
        Assert.Equal(expected, HostGrouping.IsWithin(host, ["ntfy.sh", "web.push.apple.com"]));
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
        var expires = HeldExpiry.At(DateTime.UtcNow, 86400);
        var envelope = new byte[20];
        var blob = JobCodec.Seal(key, id, mailbox, expires, RandomNumberGenerator.GetBytes(32), envelope);

        var (_, opened) = JobCodec.Open(key, id, mailbox, expires, blob);
        Assert.Equal(envelope, opened);
        Assert.ThrowsAny<CryptographicException>(() => JobCodec.Open(key, id, RandomNumberGenerator.GetBytes(32), expires, blob));
        Assert.ThrowsAny<CryptographicException>(() => JobCodec.Open(key, id, mailbox, expires.AddDays(7), blob));
    }

}

public sealed class HeldExpiryTests {
    private static readonly DateTime Now = new(2026, 11, 13, 10, 17, 42, 999, DateTimeKind.Utc);

    [Fact]
    public void LongTtls_RoundDownToTheHour() {
        Assert.Equal(new DateTime(2026, 11, 16, 10, 0, 0, DateTimeKind.Utc), HeldExpiry.At(Now, 72 * 3600));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(60)]
    [InlineData(600)]
    [InlineData(3599)]
    [InlineData(86400)]
    [InlineData(14 * 86400)]
    public void Expiry_IsWholeSeconds_NeverLate_AndLosesAtMostAQuarterOfTheTtl(int ttl) {
        var exact = Now.AddSeconds(ttl);
        var expiry = HeldExpiry.At(Now, ttl);
        Assert.Equal(0, expiry.Ticks % TimeSpan.TicksPerSecond);
        Assert.Equal(DateTimeKind.Utc, expiry.Kind);
        Assert.True(expiry <= exact);
        Assert.True(exact - expiry < TimeSpan.FromSeconds(Math.Max(1, Math.Min(ttl / 4, 3600))));
        Assert.True(expiry > Now);
    }

    [Fact]
    public void MessagesAcceptedInTheSameHour_ShareTheirExpiry() {
        // A group fan-out (or anything else) in one hour can't be told apart by its stored expiry.
        var a = HeldExpiry.At(new DateTime(2026, 11, 13, 10, 0, 1, DateTimeKind.Utc), 86400);
        var b = HeldExpiry.At(new DateTime(2026, 11, 13, 10, 59, 58, DateTimeKind.Utc), 86400);
        Assert.Equal(a, b);
    }

    [Fact]
    public void DueNow_DropsTheSeconds_ButIsNeverInTheFuture() {
        var due = HeldExpiry.DueNow(Now);
        Assert.Equal(new DateTime(2026, 11, 13, 10, 17, 0, DateTimeKind.Utc), due);
        Assert.True(due <= Now);
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
