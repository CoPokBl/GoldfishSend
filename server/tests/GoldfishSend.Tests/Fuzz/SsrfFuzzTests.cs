using System.Globalization;
using System.Net;
using System.Text;
using CsCheck;
using GoldfishSend.Core.Crypto;
using GoldfishSend.Core.Net;
using GoldfishSend.Core.Options;
using GoldfishSend.Infrastructure.Push;

namespace GoldfishSend.Tests.Fuzz;

/// <summary>
/// The push endpoint SSRF defences, differentially: hostile URLs and addresses go through <see cref="EndpointValidator"/>,
/// <see cref="IpRangeFilter"/> and the push client's connect-time check, and their verdicts are compared with what .NET's
/// HttpClient would actually connect to and with <see cref="SsrfOracle"/>. The property is "nothing accepted can reach an
/// address that isn't globally reachable", not string matching.
/// </summary>
public sealed class SsrfFuzzTests {
    // --- addresses ---

    private static readonly string[] V4Interesting = [
        "0.0.0.0", "0.255.255.255", "1.0.0.0", "9.255.255.255", "10.0.0.0", "10.255.255.255", "11.0.0.0", "100.63.255.255",
        "100.64.0.0", "100.127.255.255", "100.128.0.0", "126.255.255.255", "127.0.0.1", "127.255.255.255", "128.0.0.0",
        "168.63.129.16", "169.254.0.0", "169.254.169.254", "169.255.0.0", "172.15.255.255", "172.16.0.0", "172.31.255.255",
        "172.32.0.0", "192.0.0.0", "192.0.0.9", "192.0.0.170", "192.0.1.0", "192.0.2.1", "192.88.99.1", "192.167.255.255",
        "192.168.0.1", "192.169.0.0", "198.17.255.255", "198.18.0.0", "198.19.255.255", "198.20.0.0", "198.51.100.7",
        "203.0.113.9", "223.255.255.255", "224.0.0.1", "239.255.255.255", "240.0.0.1", "255.255.255.255", "1.1.1.1", "8.8.8.8",
    ];

    private static readonly string[] V6Interesting = [
        "::", "::1", "::2", "::ffff:0:1", "64:ff9b::1", "64:ff9b:1::1", "100::1", "100:0:0:1::1", "1fff:ffff::1", "2000::1",
        "2001::1", "2001:0:4136:e378:8000:63bf:80ff:fffe", "2001:1::1", "2001:1::4", "2001:2::1", "2001:3::1", "2001:4:112::1",
        "2001:10::1", "2001:20::1", "2001:1ff::1", "2001:200::1", "2001:db8::1", "2001:4860:4860::8888", "2002::1",
        "2002:7f00:1::1", "2620:4f:8000::1", "2620:4f:8001::1", "3ffe::1", "3fff::1", "3fff:1000::1", "4000::1", "5f00::1",
        "5f01::1", "fc00::1", "fd00::1", "fe80::1", "fec0::1", "ff02::1", "2606:4700:4700::1111",
    ];

    private static readonly Gen<IPAddress> V4 = Gen.Frequency(
        (3, Gen.OneOf(V4Interesting).Select(IPAddress.Parse)),
        (2, Gen.Select(Gen.OneOf(V4Interesting), Gen.Int[-3, 3]).Select((a, delta) => Offset(IPAddress.Parse(a), delta))),
        (2, Gen.UInt.Select(u => new IPAddress([(byte)(u >> 24), (byte)(u >> 16), (byte)(u >> 8), (byte)u]))));

    private static readonly Gen<IPAddress> V6 = Gen.Frequency(
        (3, Gen.OneOf(V6Interesting).Select(IPAddress.Parse)),
        (2, Gen.Select(Gen.OneOf(V6Interesting), Gen.Int[-3, 3]).Select((a, delta) => Offset(IPAddress.Parse(a), delta))),
        (2, V4.SelectMany(Embed)),
        (1, Gen.Byte.Array[16].Select(b => new IPAddress(b))),
        (1, Gen.Select(Gen.OneOf(V6Interesting), Gen.Long[1, 4]).Select((a, scope) => new IPAddress(IPAddress.Parse(a).GetAddressBytes(), scope))));

    private static readonly Gen<IPAddress> Address = Gen.Frequency((1, V4), (1, V6));

    /// <summary>An IPv4 address inside IPv6: mapped, compatible, NAT64, 6to4, Teredo (client address inverted) or ISATAP.</summary>
    private static Gen<IPAddress> Embed(IPAddress v4) {
        var b = v4.GetAddressBytes();
        var inverted = b.Select(x => (byte)~x).ToArray();
        return Gen.OneOf(
            Gen.Const(v4.MapToIPv6()),
            Gen.Const(new IPAddress([.. new byte[12], .. b])),
            Gen.Const(new IPAddress([0, 0x64, 0xff, 0x9b, .. new byte[8], .. b])),
            Gen.Const(new IPAddress([0, 0x64, 0xff, 0x9b, 0, 1, .. new byte[6], .. b])),
            Gen.Const(new IPAddress([0x20, 0x02, .. b, .. new byte[10]])),
            Gen.Const(new IPAddress([0x20, 0x01, 0, 0, 0x41, 0x36, 0xe3, 0x78, 0x80, 0, 0x63, 0xbf, .. inverted])),
            Gen.Const(new IPAddress([0x26, 0x06, 0x47, 0, 0, 0, 0, 0, 0, 0, 0x5e, 0xfe, .. b])));
    }

    private static IPAddress Offset(IPAddress address, int delta) {
        var bytes = address.GetAddressBytes();
        var value = new System.Numerics.BigInteger(bytes, isUnsigned: true, isBigEndian: true) + delta;
        var max = System.Numerics.BigInteger.One << (bytes.Length * 8);
        value = ((value % max) + max) % max;
        var raw = value.ToByteArray(isUnsigned: true, isBigEndian: true);
        return new IPAddress([.. new byte[bytes.Length - raw.Length], .. raw]);
    }

    private static readonly IpRangeFilter Filter = new();

    [Fact]
    public void IpRangeFilter_AllowsOnlyGloballyReachableAddresses() {
        Fuzz.Run(Address, address => {
            if (Filter.IsAllowed(address)) {
                Assert.True(SsrfOracle.IsGloballyReachable(address), $"{address} is allowed but not globally reachable");
            }
        }, iterations: 20_000, print: a => a.ToString());
    }

    // --- connect time ---

    private static readonly Gen<(string Host, IPAddress[] Answer)> ConnectInputs = Gen.Frequency(
        (2, Gen.Select(Gen.OneOf("push.example.org", "a.b", "x"), Address.Array[0, 5], (h, a) => (h, a))),
        (1, Address.Select(a => (a.ToString(), Array.Empty<IPAddress>()))),
        (1, Address.Select(a => ("[" + a + "]", Array.Empty<IPAddress>()))));

    [Fact]
    public void ConnectTime_UsesOnlyGloballyReachableAddresses() {
        Fuzz.Run(ConnectInputs, input => {
            var resolved = false;
            IPAddress[]? allowed = null;
            try {
                allowed = PushClient.AllowedAddressesAsync(input.Host, Filter, (_, _) => {
                    resolved = true;
                    return Task.FromResult(input.Answer);
                }, default).GetAwaiter().GetResult();
            } catch (ForbiddenDestinationException) {
            }
            var literal = IPAddress.TryParse(input.Host, out var parsed);
            Assert.Equal(!literal, resolved);
            var candidates = literal ? [parsed!] : input.Answer;
            if (allowed is null) {
                Assert.DoesNotContain(candidates, Filter.IsAllowed);
            } else {
                Assert.NotEmpty(allowed);
                Assert.All(allowed, a => Assert.True(SsrfOracle.IsGloballyReachable(a), $"{a} used for {input.Host}"));
                Assert.All(allowed, a => Assert.Contains(a, candidates));
            }
        }, iterations: 3000, print: i => $"{i.Host} -> {string.Join(",", i.Answer.Select(a => a.ToString()))}");
    }

    // --- URLs ---

    private static readonly char[] Dots = ['.', '.', '.', '.', '\u3002', '\uff0e', '\uff61'];

    private static string Digits(string s, bool fullwidth) => fullwidth ? new string(s.Select(c => char.IsAsciiDigit(c) ? (char)(0xff10 + c - '0') : c).ToArray()) : s;

    /// <summary>An IPv4 address in any notation a parser might accept: 1 to 4 parts, each decimal, octal or hex, with odd dots.</summary>
    private static Gen<string> V4Text(IPAddress address) {
        var b = address.GetAddressBytes();
        var value = (uint)(b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]);
        return Gen.Select(Gen.Int[1, 4], Gen.Int[0, 2].Array[4], Gen.Int[0, 2].Array[4], Gen.Int[0, Dots.Length - 1], Gen.Int[0, 8], Gen.Bool)
            .Select((parts, radix, zeros, dot, trailing, fullwidth) => {
                var values = parts switch {
                    1 => new ulong[] { value },
                    2 => [b[0], value & 0xffffff],
                    3 => [b[0], b[1], value & 0xffff],
                    _ => [b[0], b[1], b[2], b[3]],
                };
                var text = values.Select((v, i) => radix[i] switch {
                    0 => new string('0', zeros[i] == 2 ? 0 : 0) + v.ToString(CultureInfo.InvariantCulture),
                    1 => "0" + new string('0', zeros[i]) + Convert.ToString((long)v, 8),
                    _ => (zeros[i] == 1 ? "0X" : "0x") + new string('0', zeros[i]) + v.ToString(zeros[i] == 2 ? "X" : "x", CultureInfo.InvariantCulture),
                });
                var joined = string.Join(Dots[dot], text) + (trailing switch { 0 => ".", 1 => "..", 2 => "\u3002", _ => "" });
                return Digits(joined, fullwidth && trailing > 5);
            });
    }

    private static Gen<string> V6Text(IPAddress address) {
        var plain = address.ScopeId == 0 ? address : new IPAddress(address.GetAddressBytes());
        var full = string.Join(':', Enumerable.Range(0, 8).Select(i => ((plain.GetAddressBytes()[2 * i] << 8) | plain.GetAddressBytes()[2 * i + 1]).ToString("x4", CultureInfo.InvariantCulture)));
        var b = plain.GetAddressBytes();
        var tail = plain.ToString().Contains('.') ? plain.ToString() : $"{full[..30]}{b[12]}.{b[13]}.{b[14]}.{b[15]}";
        return Gen.Select(Gen.OneOf(plain.ToString(), full, full.ToUpperInvariant(), tail),
                Gen.OneOf("", "", "", "%25eth0", "%251", "%25lo", "%eth0", "%2525", "%25"),
                Gen.OneOf("[{0}]", "[{0}]", "[{0}]", "[{0}", "{0}]", "{0}", "[[{0}]]", "[ {0} ]"))
            .Select((text, zone, brackets) => string.Format(CultureInfo.InvariantCulture, brackets, text + zone));
    }

    private static readonly Gen<string> Label = Gen.Char['a', 'z'].Array[1, 8].Select(c => new string(c));

    private static readonly string[] Suffixes = [
        "com", "net", "org", "sh", "io", "de", "app", "localhost", "local", "localdomain", "internal", "intranet", "lan", "home",
        "corp", "home.arpa", "in-addr.arpa", "ip6.arpa", "ipv4only.arpa", "resolver.arpa", "service.arpa", "arpa", "onion",
        "test", "invalid", "example", "alt", "LOCALHOST", "Local", "xn--localhost", "nip.io",
    ];

    private static readonly Gen<string> Name = Gen.Frequency(
        (6, Gen.Select(Label.Array[0, 3], Gen.OneOf(Suffixes), Gen.Int[0, Dots.Length - 1], Gen.Int[0, 5])
            .Select((labels, suffix, dot, trailing) => string.Join(Dots[dot], labels.Append(suffix)) + (trailing == 0 ? "." : ""))),
        (2, Gen.OneOf("localhost", "LOCALHOST", "localhost.", "Localhost.Localdomain", "\u24db\u24de\u24d2\u24d0\u24db\u24d7\u24de\u24e2\u24e3",
            "\uff4c\uff4f\uff43\uff41\uff4c\uff48\uff4f\uff53\uff54", "foo.\uff4c\uff4f\uff43\uff41\uff4c", "xn--zz.com", "xn--.com",
            "1.1.1.1.1", "256.0.0.1", "1e2.0.0.1", "0x.0x.0x.0x", "127.0.0.1.nip.io", "127.0.0.1x", "a..b.com", ".a.com", "a.com..",
            "a_b.com", "-a.com", "a-.com", "push.example.org", "blocked.goldfish.app", "BLOCKED.goldfish.app.",
            "x.blocked.goldfish.app", "blocked\u3002goldfish\u3002app", "notblocked.goldfish.app", "\u0431\u0443\u043a\u0432\u0430.com")),
        (1, Gen.Select(V4, Gen.OneOf(".nip.io", ".com", ".local", "")).SelectMany((a, s) => V4Text(a).Select(t => t + s))));

    private static readonly Gen<string> Host = Gen.Frequency(
        (3, V4.SelectMany(V4Text)),
        (3, V6.SelectMany(V6Text)),
        (4, Name));

    private static readonly Gen<string> UrlGen = Gen.Select(
            Gen.Frequency((12, Gen.Const("https://")), (1, Gen.OneOf("HTTPS://", "Https://", "http://", "https:/", "https:\\\\", "https:///",
                "https:", "ftp://", "wss://", " https://", "https://\t"))),
            Gen.Frequency((12, Gen.Const("")), (1, Gen.OneOf("user@", "user:pw@", "evil.com@", "@", "127.0.0.1@", "a%40b@", "push.example.org:443@"))),
            Host,
            Gen.Frequency((8, Gen.Const("")), (2, Gen.OneOf(":443", ":", ":0443", ":00443")), (1, Gen.OneOf(":8443", ":80", ":0", ":65536", ":-1", ":443x", ":\u0664\u0664\u0663"))),
            Gen.Frequency((8, Gen.OneOf("/", "/wpush/v2/abc", "/up?x=1")), (1, Gen.OneOf("", "#frag", "\\x", "/%2e%2e/", "?@127.0.0.1", "#@127.0.0.1", "\\@127.0.0.1/", " /", "\n/"))))
        .Select((scheme, userinfo, host, port, path) => scheme + userinfo + host + port + path);

    private static readonly PushOptions LiteralsAllowed = new() { AllowIpLiterals = true, BlockedHosts = ["blocked.goldfish.app"] };
    private static readonly PushOptions Defaults = new() { BlockedHosts = ["blocked.goldfish.app"] };
    private static readonly EndpointValidator WithLiterals = new(LiteralsAllowed, Filter);
    private static readonly EndpointValidator Strict = new(Defaults, Filter);
    private static readonly VapidSigner Vapid = new(VapidSigner.GeneratePrivateKey(), "mailto:fuzz@example.org");

    [Fact]
    public void Validator_AcceptsOnlyUrlsThatConnectSafely() {
        var accepted = 0;
        Fuzz.Run(UrlGen, url => {
            if (CheckUrl(url)) {
                Interlocked.Increment(ref accepted);
            }
        }, iterations: 8000, print: u => Escape(u));
        Fuzz.AssertMix(accepted, 8000);
    }

    /// <summary>Hosts that once got past the validator (fixed), plus the classics.</summary>
    [Theory]
    [InlineData("https://127.0.0.1./")]
    [InlineData("https://127\u30020\u30020\u30021/")]
    [InlineData("https://127\uff0e0\uff0e0\uff0e1/")]
    [InlineData("https://169\uff61254\uff61169\uff61254/")]
    [InlineData("https://0x7f.1/")]
    [InlineData("https://2130706433/")]
    [InlineData("https://0177.0.0.1/")]
    [InlineData("https://[::ffff:127.0.0.1]/")]
    [InlineData("https://[::127.0.0.1]/")]
    [InlineData("https://[64:ff9b::7f00:1]/")]
    [InlineData("https://[2002:7f00:1::]/")]
    [InlineData("https://[5f00::1]/")]
    [InlineData("https://[fe80::1%25eth0]/")]
    [InlineData("https://evil.com@127.0.0.1/")]
    [InlineData("https://push.example.alt/")]
    [InlineData("https://ipv4only.arpa/")]
    [InlineData("https://256.0.0.1/")]
    [InlineData("https://1.1.1.1.1/")]
    [InlineData("https://blocked\u3002goldfish\u3002app/")]
    public void Validator_Regressions(string url) {
        Assert.False(Strict.TryValidate(url, out _));
        CheckUrl(url);
    }

    [Theory]
    [InlineData("https://[3fff:1000::1%2525]/")]
    [InlineData("https://[2001:4860::8888%251]/")]
    [InlineData("https://1.1.1.1./")]
    [InlineData("https://1\u30021\u30021\u30021/")]
    [InlineData("https://0x1.0x1.0x1.0x1\uff0e/")]
    public void Validator_RegressionsWithLiteralsAllowed(string url) {
        Assert.False(WithLiterals.TryValidate(url, out _));
        CheckUrl(url);
    }

    /// <returns>Whether any validator accepted it.</returns>
    private static bool CheckUrl(string url) {
        var any = false;
        foreach (var (validator, options) in new[] { (WithLiterals, LiteralsAllowed), (Strict, Defaults) }) {
            if (!validator.TryValidate(url, out var uri)) {
                continue;
            }
            any = true;
            Assert.Equal("https", uri.Scheme);
            Assert.Empty(uri.UserInfo);
            Assert.Equal(443, uri.Port);
            // Exactly what the push client does next must not throw.
            using (new HttpRequestMessage(HttpMethod.Post, uri)) {
                Vapid.GetAuthorizationHeader(uri, DateTimeOffset.UnixEpoch);
            }
            Assert.NotEmpty(HostGrouping.BaseDomain(uri.IdnHost));

            var (host, port) = ConnectTarget(uri);
            Assert.Equal(443, port);
            var readings = SsrfOracle.NumericReadings(host);
            if (readings.Count > 0 || SsrfOracle.EndsInNumber(host.Trim('[', ']'))) {
                Assert.True(options.AllowIpLiterals, $"IP literal {host} accepted although AllowIpLiterals is off");
                Assert.NotEmpty(readings);
                Assert.All(readings, a => Assert.True(SsrfOracle.IsGloballyReachable(a), $"{host} reads as {a}"));
            } else {
                Assert.Contains('.', host.TrimEnd('.'));
                Assert.False(SsrfOracle.IsSpecialUseName(host), $"special-use name {host}");
                var bare = host.TrimEnd('.').ToLowerInvariant();
                Assert.False(bare == "blocked.goldfish.app" || bare.EndsWith(".blocked.goldfish.app", StringComparison.Ordinal), $"blocked host {host}");
            }
        }
        return any;
    }

    /// <summary>The host and port SocketsHttpHandler hands to its connect callback for this URI: what the push client resolves.</summary>
    private static (string Host, int Port) ConnectTarget(Uri uri) {
        DnsEndPoint? seen = null;
        using var handler = new SocketsHttpHandler {
            UseProxy = false,
            ConnectCallback = (context, _) => {
                seen = context.DnsEndPoint;
                throw new IOException("not connecting");
            },
        };
        using var client = new HttpClient(handler);
        using var request = new HttpRequestMessage(HttpMethod.Post, uri) { Version = HttpVersion.Version11, VersionPolicy = HttpVersionPolicy.RequestVersionOrLower };
        try {
            client.Send(request);
        } catch (HttpRequestException) {
        }
        Assert.NotNull(seen);
        return (seen.Host, seen.Port);
    }

    private static string Escape(string s) {
        var sb = new StringBuilder();
        foreach (var c in s) {
            sb.Append(c is >= ' ' and <= '~' ? c.ToString() : $"\\u{(int)c:x4}");
        }
        return sb.ToString();
    }
}
