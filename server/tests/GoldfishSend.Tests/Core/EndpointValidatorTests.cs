using GoldfishSend.Core.Net;
using GoldfishSend.Core.Options;

namespace GoldfishSend.Tests.Core;

public sealed class EndpointValidatorTests {
    private static EndpointValidator Create(Action<PushOptions>? configure = null) {
        var options = new PushOptions();
        configure?.Invoke(options);
        var filter = new IpRangeFilter(options.ExtraBlockedRanges, options.DangerouslyAllowInsecureLoopback);
        return new EndpointValidator(options, filter);
    }

    private static readonly EndpointValidator Default = Create();

    [Theory]
    [InlineData("https://ntfy.sh/upABC?up=1")]
    [InlineData("https://push.example.com:443/x")]
    [InlineData("https://push.example.com/x")]
    [InlineData("https://PUSH.Example.COM/x")]
    [InlineData("https://fcm.googleapis.com/fcm/send/abc:def")]
    [InlineData("https://updates.push.services.mozilla.com/wpush/v2/gAAAA")]
    [InlineData("https://ntfy.sh./upABC")]
    [InlineData("https://xn--bcher-kva.example.com/x")]
    [InlineData("https://bücher.example.com/x")]
    public void Accepts(string url) {
        Assert.True(Default.TryValidate(url, out var uri));
        Assert.NotNull(uri);
        Assert.Equal("https", uri.Scheme);
    }

    [Fact]
    public void Accepts_ReturnsParsedUri() {
        Assert.True(Default.TryValidate("https://ntfy.sh/upABC?up=1", out var uri));
        Assert.Equal("ntfy.sh", uri.Host);
        Assert.Equal("/upABC", uri.AbsolutePath);
        Assert.Equal("?up=1", uri.Query);
        Assert.Equal(443, uri.Port);
    }

    [Theory]
    [InlineData("http://ntfy.sh/upABC")]
    [InlineData("ftp://ntfy.sh/upABC")]
    [InlineData("ws://ntfy.sh/upABC")]
    [InlineData("wss://ntfy.sh/upABC")]
    [InlineData("file:///etc/passwd")]
    [InlineData("gopher://ntfy.sh/upABC")]
    [InlineData("javascript:alert(1)")]
    [InlineData("data:text/plain,hi")]
    public void Rejects_NonHttpsScheme(string url) {
        Assert.False(Default.TryValidate(url, out _));
    }

    [Theory]
    [InlineData("https://user@ntfy.sh/upABC")]
    [InlineData("https://user:pass@ntfy.sh/upABC")]
    [InlineData("https://ntfy.sh@evil.example.com/upABC")]
    public void Rejects_UserInfo(string url) {
        Assert.False(Default.TryValidate(url, out _));
    }

    [Theory]
    [InlineData("https://ntfy.sh/upABC#frag")]
    [InlineData("https://ntfy.sh/upABC?up=1#x")]
    public void Rejects_Fragment(string url) {
        Assert.False(Default.TryValidate(url, out _));
    }

    [Theory]
    [InlineData("https://push.example.com:8443/x")]
    [InlineData("https://push.example.com:80/x")]
    [InlineData("https://push.example.com:22/x")]
    [InlineData("https://push.example.com:6379/x")]
    public void Rejects_NonAllowedPort(string url) {
        Assert.False(Default.TryValidate(url, out _));
    }

    [Fact]
    public void Accepts_PortInAllowedPorts() {
        var validator = Create(o => o.AllowedPorts = [443, 8443]);
        Assert.True(validator.TryValidate("https://push.example.com:8443/x", out var uri));
        Assert.Equal(8443, uri.Port);
        Assert.False(validator.TryValidate("https://push.example.com:9443/x", out _));
    }

    [Theory]
    [InlineData("https://8.8.8.8/x")]
    [InlineData("https://1.1.1.1:443/x")]
    [InlineData("https://[2606:4700:4700::1111]/x")]
    [InlineData("https://127.0.0.1/x")]
    [InlineData("https://[::1]/x")]
    [InlineData("https://169.254.169.254/latest/meta-data")]
    [InlineData("https://0x7f000001/x")]
    [InlineData("https://2130706433/x")]
    [InlineData("https://017700000001/x")]
    [InlineData("https://127.1/x")]
    public void Rejects_IpLiteralsByDefault(string url) {
        Assert.False(Default.TryValidate(url, out _));
    }

    [Fact]
    public void AllowIpLiterals_StillAppliesIpFilter() {
        var validator = Create(o => o.AllowIpLiterals = true);
        Assert.True(validator.TryValidate("https://8.8.8.8/x", out _));
        Assert.True(validator.TryValidate("https://[2606:4700:4700::1111]/x", out _));
        Assert.False(validator.TryValidate("https://127.0.0.1/x", out _));
        Assert.False(validator.TryValidate("https://10.0.0.1/x", out _));
        Assert.False(validator.TryValidate("https://169.254.169.254/x", out _));
        Assert.False(validator.TryValidate("https://[::1]/x", out _));
        Assert.False(validator.TryValidate("https://[::ffff:127.0.0.1]/x", out _));
        Assert.False(validator.TryValidate("https://[fe80::1]/x", out _));
        Assert.False(validator.TryValidate("https://0x7f000001/x", out _));
        Assert.False(validator.TryValidate("https://2130706433/x", out _));
    }

    [Theory]
    [InlineData("https://localhost/x")]
    [InlineData("https://LOCALHOST/x")]
    [InlineData("https://localhost./x")]
    [InlineData("https://foo.localhost/x")]
    public void Rejects_Localhost(string url) {
        Assert.False(Default.TryValidate(url, out _));
    }

    [Theory]
    [InlineData("https://pushserver/x")]
    [InlineData("https://intranet/x")]
    [InlineData("https://com/x")]
    public void Rejects_SingleLabelHosts(string url) {
        Assert.False(Default.TryValidate(url, out _));
    }

    [Theory]
    [InlineData("https://printer.local/x")]
    [InlineData("https://db.internal/x")]
    [InlineData("https://metadata.google.internal/x")]
    [InlineData("https://abcdefghijklmnop.onion/x")]
    [InlineData("https://router.home.arpa/x")]
    [InlineData("https://nas.localdomain/x")]
    [InlineData("https://wiki.intranet/x")]
    [InlineData("https://box.lan/x")]
    [InlineData("https://box.home/x")]
    [InlineData("https://ad.corp/x")]
    [InlineData("https://1.0.0.127.in-addr.arpa/x")]
    [InlineData("https://x.ip6.arpa/x")]
    [InlineData("https://push.test/x")]
    [InlineData("https://push.invalid/x")]
    [InlineData("https://push.example/x")]
    [InlineData("https://PRINTER.LOCAL/x")]
    [InlineData("https://printer.local./x")]
    public void Rejects_ForbiddenSuffixes(string url) {
        Assert.False(Default.TryValidate(url, out _));
    }

    [Fact]
    public void Accepts_SuffixLookalikes() {
        // Only whole labels are forbidden suffixes.
        Assert.True(Default.TryValidate("https://push.notlocal.com/x", out _));
        Assert.True(Default.TryValidate("https://my.local.example.org/x", out _));
        Assert.True(Default.TryValidate("https://push.testing.org/x", out _));
    }

    [Fact]
    public void Rejects_BlockedHostsExactAndSubdomain() {
        var validator = Create(o => o.BlockedHosts = ["relay.goldfish.org", " Self.Example.NET. ", ""]);
        Assert.False(validator.TryValidate("https://relay.goldfish.org/x", out _));
        Assert.False(validator.TryValidate("https://RELAY.goldfish.org/x", out _));
        Assert.False(validator.TryValidate("https://relay.goldfish.org./x", out _));
        Assert.False(validator.TryValidate("https://a.relay.goldfish.org/x", out _));
        Assert.False(validator.TryValidate("https://a.b.relay.goldfish.org/x", out _));
        Assert.False(validator.TryValidate("https://self.example.net/x", out _));
        Assert.False(validator.TryValidate("https://api.self.example.net/x", out _));

        // Not a subdomain, just a common suffix.
        Assert.True(validator.TryValidate("https://notrelay.goldfish.org/x", out _));
        Assert.True(validator.TryValidate("https://goldfish.org/x", out _));
        Assert.True(validator.TryValidate("https://ntfy.sh/x", out _));
    }

    [Fact]
    public void Rejects_TooLong() {
        var prefix = "https://push.example.com/";
        var ok = prefix + new string('a', 2048 - prefix.Length);
        Assert.Equal(2048, ok.Length);
        Assert.True(Default.TryValidate(ok, out _));
        Assert.False(Default.TryValidate(ok + "a", out _));
        Assert.False(Default.TryValidate(prefix + new string('a', 10000), out _));
    }

    [Fact]
    public void Rejects_UrlWhoseUtf8EncodingExceedsMaxUrlBytes() {
        // 1525 UTF-16 chars, but 3025 UTF-8 bytes: EndpointRecord.Serialize would throw on it, so the validator
        // (which enforces EndpointRecord.MaxUrlBytes) must not accept it.
        var url = "https://push.example.com/" + new string('é', 1500);
        Assert.True(url.Length <= GoldfishSend.Core.Protocol.EndpointRecord.MaxUrlBytes);
        Assert.True(System.Text.Encoding.UTF8.GetByteCount(url) > GoldfishSend.Core.Protocol.EndpointRecord.MaxUrlBytes);
        Assert.False(Default.TryValidate(url, out _));
    }

    [Fact]
    public void Rejects_HostLabelTooLong() {
        var host = string.Join('.', Enumerable.Repeat(new string('a', 63), 4)) + ".com"; // 259 chars
        Assert.False(Default.TryValidate($"https://{host}/x", out _));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("\t\n")]
    public void Rejects_NullOrEmpty(string? url) {
        Assert.False(Default.TryValidate(url, out _));
    }

    [Theory]
    [InlineData("/upABC")]
    [InlineData("upABC")]
    [InlineData("ntfy.sh/upABC")]
    [InlineData("//ntfy.sh/upABC")]
    [InlineData("../x")]
    [InlineData("https:/ntfy.sh/x")]
    [InlineData("https://")]
    [InlineData("https:///x")]
    [InlineData("not a url")]
    public void Rejects_RelativeOrMalformed(string url) {
        Assert.False(Default.TryValidate(url, out _));
    }

    [Theory]
    [InlineData("http://localhost:1234/x")]
    [InlineData("http://127.0.0.1:5000/x")]
    [InlineData("https://localhost:8443/x")]
    public void DangerouslyAllowInsecureLoopback_PermitsLoopback(string url) {
        var validator = Create(o => o.DangerouslyAllowInsecureLoopback = true);
        Assert.True(validator.TryValidate(url, out var uri));
        Assert.NotNull(uri);
    }

    [Fact]
    public void DangerouslyAllowInsecureLoopback_StillRejectsPrivateAndBadSchemes() {
        var validator = Create(o => o.DangerouslyAllowInsecureLoopback = true);
        Assert.False(validator.TryValidate("http://10.0.0.1:5000/x", out _));
        Assert.False(validator.TryValidate("http://169.254.169.254/x", out _));
        Assert.False(validator.TryValidate("ftp://localhost/x", out _));
        Assert.False(validator.TryValidate("http://user@localhost:1234/x", out _));
        Assert.False(validator.TryValidate("http://localhost:1234/x#f", out _));
        Assert.False(validator.TryValidate("http://printer.local/x", out _));
    }

    [Fact]
    public void Default_RejectsInsecureLoopbackUrls() {
        Assert.False(Default.TryValidate("http://localhost:1234/x", out _));
        Assert.False(Default.TryValidate("http://127.0.0.1:5000/x", out _));
    }
}
