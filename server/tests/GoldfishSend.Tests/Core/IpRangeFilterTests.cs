using System.Net;
using GoldfishSend.Core.Net;

namespace GoldfishSend.Tests.Core;

public sealed class IpRangeFilterTests {
    private static readonly IpRangeFilter Filter = new();

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("127.255.255.254")]
    [InlineData("10.1.2.3")]
    [InlineData("172.16.0.1")]
    [InlineData("172.31.255.255")]
    [InlineData("192.168.1.1")]
    [InlineData("169.254.169.254")]
    [InlineData("100.64.0.1")]
    [InlineData("100.127.255.255")]
    [InlineData("0.0.0.0")]
    [InlineData("0.1.2.3")]
    [InlineData("192.0.0.170")]
    [InlineData("192.0.2.1")]
    [InlineData("192.88.99.1")]
    [InlineData("198.18.0.1")]
    [InlineData("198.51.100.1")]
    [InlineData("203.0.113.1")]
    [InlineData("224.0.0.1")]
    [InlineData("239.255.255.250")]
    [InlineData("240.0.0.1")]
    [InlineData("255.255.255.255")]
    [InlineData("::1")]
    [InlineData("::")]
    [InlineData("fe80::1")]
    [InlineData("fe80::1%2")]
    [InlineData("fc00::1")]
    [InlineData("fd12::1")]
    [InlineData("::ffff:127.0.0.1")]
    [InlineData("::ffff:10.0.0.1")]
    [InlineData("::ffff:169.254.169.254")]
    [InlineData("::127.0.0.1")]
    [InlineData("64:ff9b::7f00:1")]
    [InlineData("64:ff9b:1::1")]
    [InlineData("2002:7f00:1::1")]
    [InlineData("2002:808:808::1")]
    [InlineData("2001:0::1")]
    [InlineData("2001:0:4136:e378:8000:63bf:3fff:fdd2")]
    [InlineData("2001:db8::1")]
    [InlineData("2001:10::1")]
    [InlineData("3fff::1")]
    [InlineData("ff02::1")]
    [InlineData("ff0e::1")]
    [InlineData("100::1")]
    [InlineData("fec0::1")]
    public void Blocked(string address) {
        Assert.False(Filter.IsAllowed(IPAddress.Parse(address)));
    }

    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("1.1.1.1")]
    [InlineData("93.184.216.34")]
    [InlineData("100.63.255.255")]
    [InlineData("100.128.0.0")]
    [InlineData("172.15.255.255")]
    [InlineData("172.32.0.0")]
    [InlineData("11.0.0.1")]
    [InlineData("223.255.255.254")]
    [InlineData("2606:4700:4700::1111")]
    [InlineData("2001:4860:4860::8888")]
    [InlineData("2a00:1450:4001:80b::200e")]
    [InlineData("::ffff:8.8.8.8")]
    public void Allowed(string address) {
        Assert.True(Filter.IsAllowed(IPAddress.Parse(address)));
    }

    [Fact]
    public void ExtraBlockedRange_IsBlocked() {
        var filter = new IpRangeFilter(["8.8.8.0/24", "2606:4700::/32"]);
        Assert.False(filter.IsAllowed(IPAddress.Parse("8.8.8.8")));
        Assert.False(filter.IsAllowed(IPAddress.Parse("::ffff:8.8.8.8")));
        Assert.False(filter.IsAllowed(IPAddress.Parse("2606:4700:4700::1111")));
        Assert.True(filter.IsAllowed(IPAddress.Parse("8.8.4.4")));
        Assert.True(filter.IsAllowed(IPAddress.Parse("1.1.1.1")));
        Assert.True(filter.IsAllowed(IPAddress.Parse("2001:4860:4860::8888")));
        // Defaults still apply.
        Assert.False(filter.IsAllowed(IPAddress.Parse("10.0.0.1")));
    }

    [Fact]
    public void ExtraBlockedRange_SingleHost() {
        var filter = new IpRangeFilter(["1.1.1.1/32"]);
        Assert.False(filter.IsAllowed(IPAddress.Parse("1.1.1.1")));
        Assert.True(filter.IsAllowed(IPAddress.Parse("1.1.1.2")));
    }

    [Fact]
    public void ExtraBlockedRange_Invalid_Throws() {
        Assert.ThrowsAny<FormatException>(() => new IpRangeFilter(["not-a-cidr"]));
    }

    [Fact]
    public void DangerouslyAllowLoopback_AllowsLoopbackOnly() {
        var filter = new IpRangeFilter(dangerouslyAllowLoopback: true);
        Assert.True(filter.IsAllowed(IPAddress.Parse("127.0.0.1")));
        Assert.True(filter.IsAllowed(IPAddress.Parse("127.1.2.3")));
        Assert.True(filter.IsAllowed(IPAddress.Parse("::1")));
        Assert.True(filter.IsAllowed(IPAddress.Parse("::ffff:127.0.0.1")));
        Assert.False(filter.IsAllowed(IPAddress.Parse("10.0.0.1")));
        Assert.False(filter.IsAllowed(IPAddress.Parse("192.168.1.1")));
        Assert.False(filter.IsAllowed(IPAddress.Parse("169.254.169.254")));
        Assert.False(filter.IsAllowed(IPAddress.Parse("0.0.0.0")));
        Assert.False(filter.IsAllowed(IPAddress.Parse("fe80::1")));
        Assert.True(filter.IsAllowed(IPAddress.Parse("8.8.8.8")));
    }

    [Fact]
    public void DefaultFilter_BlocksLoopback() {
        Assert.False(new IpRangeFilter(dangerouslyAllowLoopback: false).IsAllowed(IPAddress.Loopback));
        Assert.False(new IpRangeFilter(dangerouslyAllowLoopback: false).IsAllowed(IPAddress.IPv6Loopback));
    }

    [Fact]
    public void GlobalUnicastWithScopeId_IsBlocked() {
        var address = IPAddress.Parse("2606:4700:4700::1111");
        address.ScopeId = 3;
        Assert.False(Filter.IsAllowed(address));
    }
}
