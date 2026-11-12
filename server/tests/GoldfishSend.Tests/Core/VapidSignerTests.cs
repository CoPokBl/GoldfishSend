using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text.Json;
using GoldfishSend.Core.Crypto;

namespace GoldfishSend.Tests.Core;

public sealed class VapidSignerTests {
    private const string Subject = "mailto:ops@example.org";
    private static readonly DateTimeOffset Now = new(2026, 11, 13, 12, 0, 0, TimeSpan.Zero);

    private static VapidSigner NewSigner(out byte[] privateKey) {
        privateKey = VapidSigner.GeneratePrivateKey();
        return new VapidSigner(privateKey, Subject);
    }

    private static string ExtractJwt(string header) {
        Assert.StartsWith("vapid t=", header);
        var parts = header["vapid ".Length..].Split(", ");
        Assert.Equal(2, parts.Length);
        Assert.StartsWith("t=", parts[0]);
        Assert.StartsWith("k=", parts[1]);
        return parts[0][2..];
    }

    private static JsonElement DecodePart(string part) {
        return JsonDocument.Parse(Base64Url.DecodeFromChars(part)).RootElement;
    }

    private static ECDsa VerifierFor(byte[] publicKey) {
        return ECDsa.Create(new ECParameters {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = publicKey[1..33], Y = publicKey[33..65] },
        });
    }

    [Fact]
    public void GeneratePrivateKey_Is32Bytes() {
        Assert.Equal(32, VapidSigner.GeneratePrivateKey().Length);
        Assert.NotEqual(VapidSigner.GeneratePrivateKey(), VapidSigner.GeneratePrivateKey());
    }

    [Fact]
    public void PublicKey_IsUncompressedPointOfPrivateKey() {
        using var signer = NewSigner(out var d);
        Assert.Equal(65, signer.PublicKey.Length);
        Assert.Equal(0x04, signer.PublicKey[0]);
        Assert.Equal(Base64Url.EncodeToString(signer.PublicKey), signer.PublicKeyBase64Url);
        Assert.DoesNotContain('=', signer.PublicKeyBase64Url);

        using var reference = ECDsa.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256, D = d });
        var q = reference.ExportParameters(false).Q;
        Assert.Equal(q.X, signer.PublicKey[1..33]);
        Assert.Equal(q.Y, signer.PublicKey[33..65]);
        Assert.True(WebPushCrypto.IsValidPublicKey(signer.PublicKey));
    }

    [Fact]
    public void Jwt_HasThreePartsAndCorrectHeader() {
        using var signer = NewSigner(out _);
        var jwt = ExtractJwt(signer.GetAuthorizationHeader(new Uri("https://push.example.com/abc"), Now));
        var parts = jwt.Split('.');
        Assert.Equal(3, parts.Length);
        Assert.All(parts, p => Assert.DoesNotContain('=', p));

        var header = DecodePart(parts[0]);
        Assert.Equal("JWT", header.GetProperty("typ").GetString());
        Assert.Equal("ES256", header.GetProperty("alg").GetString());
    }

    [Theory]
    [InlineData("https://push.example.com/abc?x=1", "https://push.example.com")]
    [InlineData("https://push.example.com:443/abc", "https://push.example.com")]
    [InlineData("https://push.example.com:8443/abc", "https://push.example.com:8443")]
    [InlineData("http://localhost:1234/x", "http://localhost:1234")]
    [InlineData("http://localhost:80/x", "http://localhost")]
    [InlineData("https://PUSH.Example.COM/abc", "https://push.example.com")]
    public void Jwt_AudienceIsOrigin(string endpoint, string expectedAud) {
        using var signer = NewSigner(out _);
        var jwt = ExtractJwt(signer.GetAuthorizationHeader(new Uri(endpoint), Now));
        var payload = DecodePart(jwt.Split('.')[1]);
        Assert.Equal(expectedAud, payload.GetProperty("aud").GetString());
    }

    [Fact]
    public void Jwt_PayloadHasExpAndSub() {
        using var signer = NewSigner(out _);
        var jwt = ExtractJwt(signer.GetAuthorizationHeader(new Uri("https://push.example.com/abc"), Now));
        var payload = DecodePart(jwt.Split('.')[1]);
        var exp = payload.GetProperty("exp").GetInt64();
        Assert.Equal(Now.AddHours(12).ToUnixTimeSeconds(), exp);
        // RFC 8292 §2: exp must be no more than 24 hours from now.
        Assert.True(exp - Now.ToUnixTimeSeconds() <= 24 * 3600);
        Assert.Equal(Subject, payload.GetProperty("sub").GetString());
        Assert.Equal(3, payload.EnumerateObject().Count());
    }

    [Fact]
    public void Jwt_SignatureVerifiesWithPublicKey() {
        using var signer = NewSigner(out _);
        var jwt = ExtractJwt(signer.GetAuthorizationHeader(new Uri("https://push.example.com/abc"), Now));
        var parts = jwt.Split('.');
        var signature = Base64Url.DecodeFromChars(parts[2]);
        Assert.Equal(64, signature.Length); // IEEE P1363 r ‖ s

        using var verifier = VerifierFor(signer.PublicKey);
        var input = System.Text.Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}");
        Assert.True(verifier.VerifyData(input, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));

        input[^1] ^= 1;
        Assert.False(verifier.VerifyData(input, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
    }

    [Fact]
    public void Jwt_SignatureDoesNotVerifyWithOtherKey() {
        using var signer = NewSigner(out _);
        using var other = NewSigner(out _);
        var parts = ExtractJwt(signer.GetAuthorizationHeader(new Uri("https://push.example.com/abc"), Now)).Split('.');
        using var verifier = VerifierFor(other.PublicKey);
        var input = System.Text.Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}");
        Assert.False(verifier.VerifyData(input, Base64Url.DecodeFromChars(parts[2]), HashAlgorithmName.SHA256));
    }

    [Fact]
    public void CreateJwt_Internal_UsesGivenAudienceAndExpiry() {
        using var signer = NewSigner(out _);
        var expires = Now.AddHours(3);
        var parts = signer.CreateJwt("https://a.example.net", expires).Split('.');
        var payload = DecodePart(parts[1]);
        Assert.Equal("https://a.example.net", payload.GetProperty("aud").GetString());
        Assert.Equal(expires.ToUnixTimeSeconds(), payload.GetProperty("exp").GetInt64());
    }

    [Fact]
    public void AuthorizationHeader_HasVapidFormatWithPublicKey() {
        using var signer = NewSigner(out _);
        var header = signer.GetAuthorizationHeader(new Uri("https://push.example.com/abc"), Now);
        Assert.Matches(@"^vapid t=[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+, k=[A-Za-z0-9_-]+$", header);
        Assert.EndsWith($", k={signer.PublicKeyBase64Url}", header);
    }

    [Fact]
    public void AuthorizationHeader_IsCachedPerAudience() {
        using var signer = NewSigner(out _);
        var a1 = signer.GetAuthorizationHeader(new Uri("https://push.example.com/one"), Now);
        var a2 = signer.GetAuthorizationHeader(new Uri("https://push.example.com/two?x"), Now.AddHours(5));
        Assert.Same(a1, a2);

        var b = signer.GetAuthorizationHeader(new Uri("https://other.example.com/one"), Now);
        Assert.NotEqual(a1, b);
    }

    [Fact]
    public void AuthorizationHeader_IsRenewedNearExpiry() {
        using var signer = NewSigner(out _);
        var uri = new Uri("https://push.example.com/one");
        var first = signer.GetAuthorizationHeader(uri, Now);
        // Expires at Now+12h, renewed once less than 1h remains.
        var stillCached = signer.GetAuthorizationHeader(uri, Now.AddHours(10).AddMinutes(59));
        Assert.Same(first, stillCached);
        var renewed = signer.GetAuthorizationHeader(uri, Now.AddHours(11).AddMinutes(1));
        Assert.NotEqual(first, renewed);
        var payload = DecodePart(ExtractJwt(renewed).Split('.')[1]);
        Assert.Equal(Now.AddHours(23).AddMinutes(1).ToUnixTimeSeconds(), payload.GetProperty("exp").GetInt64());
    }

    [Fact]
    public void SameKey_ProducesSamePublicKey() {
        var d = VapidSigner.GeneratePrivateKey();
        using var a = new VapidSigner(d, Subject);
        using var b = new VapidSigner(d, "https://example.org/contact");
        Assert.Equal(a.PublicKey, b.PublicKey);
    }

    [Theory]
    [InlineData("ops@example.org")]
    [InlineData("http://example.org")]
    [InlineData("")]
    [InlineData("MAILTO:ops@example.org")]
    public void Constructor_RejectsBadSubject(string subject) {
        Assert.Throws<ArgumentException>(() => new VapidSigner(VapidSigner.GeneratePrivateKey(), subject));
    }

    [Theory]
    [InlineData("mailto:ops@example.org")]
    [InlineData("https://example.org/contact")]
    public void Constructor_AcceptsGoodSubject(string subject) {
        using var signer = new VapidSigner(VapidSigner.GeneratePrivateKey(), subject);
        Assert.NotNull(signer.PublicKey);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(31)]
    [InlineData(33)]
    [InlineData(65)]
    public void Constructor_RejectsBadKeyLength(int length) {
        Assert.Throws<ArgumentException>(() => new VapidSigner(new byte[length], Subject));
    }

    [Fact]
    public void Constructor_RejectsZeroScalar() {
        Assert.ThrowsAny<CryptographicException>(() => new VapidSigner(new byte[32], Subject));
    }
}
