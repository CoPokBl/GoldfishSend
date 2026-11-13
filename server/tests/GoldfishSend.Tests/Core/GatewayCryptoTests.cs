using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using GoldfishSend.Core.Crypto;
using GoldfishSend.Core.Protocol;

namespace GoldfishSend.Tests.Core;

public sealed class GatewayCryptoTests {
    /// <summary>The interop test key from docs/protocol.md: bytes 0x00..0x5f.</summary>
    public static readonly byte[] TestSecret = Enumerable.Range(0, 96).Select(i => (byte)i).ToArray();

    // Known answers for the test key, cross-checked with the OpenSSL 3.5 CLI (genpkey ML-KEM-768 hexseed, and ec for the
    // P-256 point). The app's tests and docs/test-vectors use the same key, so either side drifting fails.
    private const string TestBlobSha256 = "a97384aa454bf6724048784fb8a6b745c3978f52120f5729eb11e50589037a41";
    private const string TestFingerprint = "xbEXX4E5yV8WWKo4_9R4peZP2OQbggdFnKCqHc6gX9g";

    private static byte[] Inner(string path = "/v1/info", byte[]? body = null) =>
        GatewayCodec.EncodeRequest(new InnerRequest("GET", 1_700_000_000, path, [], body ?? []));

    [Fact]
    public void Sizes_MatchTheSpec() {
        Assert.Equal(1250, GatewayCrypto.BlobSize);
        Assert.Equal(1153, GatewayCrypto.EncSize);
        Assert.Equal(1178, GatewayCrypto.RequestOverhead);
        Assert.Equal(48, GatewayCrypto.ResponseOverhead);
    }

    [Fact]
    public void TestKey_HasKnownBlobAndFingerprint() {
        var key = new ServerKey(TestSecret);
        Assert.Equal(GatewayCrypto.BlobSize, key.Blob.Length);
        Assert.Equal(1, key.Blob[0]);
        Assert.Equal(TestBlobSha256, Convert.ToHexStringLower(SHA256.HashData(key.Blob)));
        Assert.Equal(TestFingerprint, key.FingerprintBase64Url);
        Assert.Equal(key.Fingerprint[..8], key.KeyId);

        // fp = SHA-256("gf/server-key/v1" ‖ blob)
        Assert.Equal(SHA256.HashData([.. "gf/server-key/v1"u8, .. key.Blob]), key.Fingerprint);

        // The P-256 half is the public point of the scalar 0x40..0x5f.
        using var ec = ECDiffieHellman.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256, D = TestSecret[64..] });
        Assert.Equal(WebPushCrypto.ExportPublicKey(ec), key.Blob[^65..]);
    }

#pragma warning disable SYSLIB5006 // MLKem is experimental in .NET 10.
    /// <summary>
    /// An independent ML-KEM implementation (the platform's, OpenSSL 3.5+) agrees with BouncyCastle on the key derived
    /// from the seed, and on encapsulation. Skipped where the platform has no ML-KEM (for example the noble runtime image).
    /// </summary>
    [Fact]
    public void MlKem_AgreesWithThePlatformImplementation() {
        if (!MLKem.IsSupported) {
            return;
        }
        var key = new ServerKey(TestSecret);
        using var platform = MLKem.ImportPrivateSeed(MLKemAlgorithm.MLKem768, TestSecret[..64]);
        Assert.Equal(platform.ExportEncapsulationKey(), key.Blob[1..1185]);

        // Encapsulate with the platform and let the server open a request built from it.
        using var server = MLKem.ImportEncapsulationKey(MLKemAlgorithm.MLKem768, key.Blob[1..1185]);
        server.Encapsulate(out var ctM, out var ssM);
        using var ephemeral = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        using var serverEc = WebPushCrypto.ImportPublicKey(key.Blob[^65..]);
        var ssX = ephemeral.DeriveRawSecretAgreement(serverEc.PublicKey);
        byte[] enc = [.. ctM, .. WebPushCrypto.ExportPublicKey(ephemeral)];
        var (reqKey, respSecret) = GatewayCrypto.Schedule(key.Fingerprint, enc, ssM, ssX);
        var inner = Inner();
        var header = new byte[9];
        header[0] = 1;
        key.KeyId.CopyTo(header, 1);
        var ct = new byte[inner.Length + 16];
        using (var gcm = new AesGcm(reqKey, 16)) {
            gcm.Encrypt(new byte[12], inner, ct.AsSpan(0, inner.Length), ct.AsSpan(inner.Length), header);
        }
        Assert.Equal(ServerKey.OpenStatus.Ok, key.TryOpenRequest([.. header, .. enc, .. ct], out var opened, out var secret, out _));
        Assert.Equal(inner, opened);
        Assert.Equal(respSecret, secret);
    }
#pragma warning restore SYSLIB5006

    [Fact]
    public void RoundTrip_RequestAndResponse() {
        var key = new ServerKey(GatewayCrypto.GenerateSecret());
        var client = ServerPublicKey.TryParse(key.Blob, key.Fingerprint)!;
        var inner = Inner("/v1/messages", RandomNumberGenerator.GetBytes(4000));
        var (outer, respSecret) = client.Seal(inner);
        Assert.Equal(GatewayCrypto.RequestOverhead + inner.Length, outer.Length);

        Assert.Equal(ServerKey.OpenStatus.Ok, key.TryOpenRequest(outer, out var opened, out var serverSecret, out var enc));
        Assert.Equal(inner, opened);
        Assert.Equal(respSecret, serverSecret);
        Assert.Equal(outer[9..(9 + 1153)], enc);

        var response = GatewayCodec.EncodeResponse(new InnerResponse(200, [new("content-type", "application/json")], "{}"u8.ToArray()));
        var sealedResponse = GatewayCrypto.SealResponse(serverSecret, response);
        Assert.Equal(response.Length + GatewayCrypto.ResponseOverhead, sealedResponse.Length);
        Assert.Equal(response, GatewayCrypto.OpenResponse(respSecret, sealedResponse));

        // A replayed request gets a different response key, because the response nonce is fresh.
        var again = GatewayCrypto.SealResponse(serverSecret, response);
        Assert.NotEqual(sealedResponse[32..], again[32..]);
    }

    [Fact]
    public void EachRequest_UsesFreshKemCiphertexts() {
        var key = new ServerKey(GatewayCrypto.GenerateSecret());
        var client = ServerPublicKey.TryParse(key.Blob)!;
        var (a, sa) = client.Seal(Inner());
        var (b, sb) = client.Seal(Inner());
        Assert.NotEqual(a[9..1162], b[9..1162]);
        Assert.NotEqual(sa, sb);
    }

    [Theory]
    [InlineData(0)]           // version
    [InlineData(20)]          // ML-KEM ciphertext
    [InlineData(1100)]        // P-256 ephemeral point
    [InlineData(1170)]        // AEAD ciphertext
    [InlineData(-1)]          // tag
    public void TamperedRequest_IsMalformed(int index) {
        var key = new ServerKey(GatewayCrypto.GenerateSecret());
        var (outer, _) = ServerPublicKey.TryParse(key.Blob)!.Seal(Inner());
        var i = index < 0 ? outer.Length + index : index;
        outer[i] ^= 0x01;
        Assert.Equal(ServerKey.OpenStatus.Malformed, key.TryOpenRequest(outer, out var inner, out var secret, out _));
        Assert.Empty(inner);
        Assert.Empty(secret);
    }

    [Fact]
    public void ForeignKeyId_IsUnknownKey() {
        var key = new ServerKey(GatewayCrypto.GenerateSecret());
        var other = new ServerKey(GatewayCrypto.GenerateSecret());
        var (outer, _) = ServerPublicKey.TryParse(other.Blob)!.Seal(Inner());
        Assert.Equal(ServerKey.OpenStatus.UnknownKey, key.TryOpenRequest(outer, out _, out _, out _));
    }

    [Fact]
    public void ShortRequest_IsMalformed() {
        var key = new ServerKey(GatewayCrypto.GenerateSecret());
        var (outer, _) = ServerPublicKey.TryParse(key.Blob)!.Seal(Inner());
        Assert.Equal(ServerKey.OpenStatus.Malformed, key.TryOpenRequest(outer[..(GatewayCrypto.RequestOverhead - 1)], out _, out _, out _));
        Assert.Equal(ServerKey.OpenStatus.Malformed, key.TryOpenRequest([], out _, out _, out _));
    }

    [Fact]
    public void Response_RejectsTamperingAndTheWrongSecret() {
        var secret = RandomNumberGenerator.GetBytes(32);
        var sealedResponse = GatewayCrypto.SealResponse(secret, new byte[512]);
        Assert.NotNull(GatewayCrypto.OpenResponse(secret, sealedResponse));
        Assert.Null(GatewayCrypto.OpenResponse(RandomNumberGenerator.GetBytes(32), sealedResponse));
        foreach (var i in new[] { 0, 31, 32, sealedResponse.Length - 1 }) {
            var copy = sealedResponse.ToArray();
            copy[i] ^= 0x80;
            Assert.Null(GatewayCrypto.OpenResponse(secret, copy));
        }
        Assert.Null(GatewayCrypto.OpenResponse(secret, sealedResponse[..47]));
    }

    [Fact]
    public void PublicKey_ParsingIsStrict() {
        var key = new ServerKey(GatewayCrypto.GenerateSecret());
        Assert.NotNull(ServerPublicKey.TryParse(key.Blob, key.Fingerprint));
        Assert.Null(ServerPublicKey.TryParse(key.Blob, new byte[32]));
        Assert.Null(ServerPublicKey.TryParse(key.Blob[..^1]));
        Assert.Null(ServerPublicKey.TryParse([.. key.Blob, 0]));
        var badVersion = key.Blob.ToArray();
        badVersion[0] = 2;
        Assert.Null(ServerPublicKey.TryParse(badVersion));
        var badPoint = key.Blob.ToArray();
        badPoint[^1] ^= 0x01; // no longer on the curve
        Assert.Null(ServerPublicKey.TryParse(badPoint));
        var compressed = key.Blob.ToArray();
        compressed[1185] = 0x02;
        Assert.Null(ServerPublicKey.TryParse(compressed));
    }

    [Fact]
    public void SecretKey_ValidatesTheScalarAndLength() {
        Assert.Throws<ArgumentException>(() => new ServerKey(new byte[95]));
        var zero = GatewayCrypto.GenerateSecret();
        Array.Clear(zero, 64, 32);
        Assert.Throws<ArgumentException>(() => new ServerKey(zero));
        var tooBig = GatewayCrypto.GenerateSecret();
        Array.Fill(tooBig, (byte)0xff, 64, 32);
        Assert.Throws<ArgumentException>(() => new ServerKey(tooBig));

        var error = Assert.Throws<InvalidOperationException>(() => ServerKey.FromBase64Url(""));
        Assert.Contains("Goldfish:Keys:ServerKey", error.Message);
        Assert.Throws<InvalidOperationException>(() => ServerKey.FromBase64Url(Base64Url.EncodeToString(new byte[32])));
        Assert.Throws<InvalidOperationException>(() => ServerKey.FromBase64Url("not base64!"));
        Assert.Equal(new ServerKey(TestSecret).Fingerprint, ServerKey.FromBase64Url(Base64Url.EncodeToString(TestSecret)).Fingerprint);
    }

    [Fact]
    public void SameSecret_GivesTheSameKey() {
        var secret = GatewayCrypto.GenerateSecret();
        Assert.Equal(new ServerKey(secret).Blob, new ServerKey(secret).Blob);
    }

    [Fact]
    public void DisplayFingerprint_IsGroupedBase32() {
        Assert.Equal("MZXW 6YTB OI", GatewayCrypto.DisplayFingerprint(Encoding.ASCII.GetBytes("foobar"))); // RFC 4648 §10
        var display = new ServerKey(TestSecret).FingerprintDisplay;
        Assert.Equal(52 + 12, display.Length);
        Assert.Matches("^([A-Z2-7]{4} ){12}[A-Z2-7]{4}$", display);
    }
}
