using System.Security.Cryptography;
using GoldfishSend.Core.Crypto;
using GoldfishSend.Core.Protocol;

namespace GoldfishSend.Tests.Core;

public sealed class PushEnvelopeTests {
    private static readonly byte[] Tag = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7];

    [Fact]
    public void Constants_MatchProtocolDoc() {
        Assert.Equal(0x01, PushEnvelope.Version);
        Assert.Equal(10, PushEnvelope.HeaderSize);
        Assert.Equal(3983, PushEnvelope.MaxBodySize);
        Assert.Equal(3983, ProtocolLimits.MaxMessageBytes);
        Assert.Equal(16, PushEnvelope.VerificationCodeSize);
        Assert.Equal(0x01, (byte)PushType.Message);
        Assert.Equal(0x02, (byte)PushType.Verification);
    }

    [Fact]
    public void Build_HeaderLayout() {
        var body = new byte[] { 0x03, 0xFF, 0x00 };
        var envelope = PushEnvelope.Build(PushType.Message, Tag, body);
        Assert.Equal(new byte[] { 0x01, 0x01, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0x03, 0xFF, 0x00 }, envelope);
    }

    [Fact]
    public void Build_VerificationType() {
        var code = RandomNumberGenerator.GetBytes(16);
        var envelope = PushEnvelope.Build(PushType.Verification, Tag, code);
        Assert.Equal(26, envelope.Length);
        Assert.Equal(0x01, envelope[0]);
        Assert.Equal(0x02, envelope[1]);
        Assert.Equal(Tag, envelope[2..10]);
        Assert.Equal(code, envelope[10..]);
    }

    [Theory]
    [InlineData(PushType.Message, 0)]
    [InlineData(PushType.Message, 1)]
    [InlineData(PushType.Message, 3983)]
    [InlineData(PushType.Verification, 16)]
    public void BuildParse_RoundTrip(PushType type, int bodySize) {
        var tag = RandomNumberGenerator.GetBytes(8);
        var body = RandomNumberGenerator.GetBytes(bodySize);
        var envelope = PushEnvelope.Build(type, tag, body);
        Assert.Equal(10 + bodySize, envelope.Length);

        Assert.True(PushEnvelope.TryParse(envelope, out var parsedType, out var parsedTag, out var parsedBody));
        Assert.Equal(type, parsedType);
        Assert.Equal(tag, parsedTag);
        Assert.Equal(body, parsedBody);
    }

    [Fact]
    public void MaxEnvelope_EncryptsToExactly4096Bytes() {
        var envelope = PushEnvelope.Build(PushType.Message, Tag, new byte[PushEnvelope.MaxBodySize]);
        Assert.Equal(WebPushCrypto.MaxPlaintextSize, envelope.Length);
        using var ua = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var message = WebPushCrypto.Encrypt(envelope, WebPushCrypto.ExportPublicKey(ua), RandomNumberGenerator.GetBytes(16));
        Assert.Equal(4096, message.Length);
    }

    [Fact]
    public void Build_OversizeBody_Throws() {
        Assert.Throws<ArgumentException>(() => PushEnvelope.Build(PushType.Message, Tag, new byte[3984]));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(7)]
    [InlineData(9)]
    [InlineData(32)]
    public void Build_BadTagLength_Throws(int length) {
        Assert.Throws<ArgumentException>(() => PushEnvelope.Build(PushType.Message, new byte[length], [1]));
    }

    [Theory]
    [InlineData(0x00)]
    [InlineData(0x02)]
    [InlineData(0xFF)]
    public void TryParse_BadVersion_Rejected(byte version) {
        var envelope = PushEnvelope.Build(PushType.Message, Tag, [1, 2, 3]);
        envelope[0] = version;
        Assert.False(PushEnvelope.TryParse(envelope, out _, out var tag, out var body));
        Assert.Empty(tag);
        Assert.Empty(body);
    }

    [Theory]
    [InlineData(0x00)]
    [InlineData(0x03)]
    [InlineData(0x80)]
    [InlineData(0xFF)]
    public void TryParse_BadType_Rejected(byte type) {
        var envelope = PushEnvelope.Build(PushType.Message, Tag, [1, 2, 3]);
        envelope[1] = type;
        Assert.False(PushEnvelope.TryParse(envelope, out _, out var tag, out var body));
        Assert.Empty(tag);
        Assert.Empty(body);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(9)]
    public void TryParse_TooShort_Rejected(int length) {
        var data = new byte[length];
        if (length > 0) {
            data[0] = 0x01;
        }
        if (length > 1) {
            data[1] = 0x01;
        }
        Assert.False(PushEnvelope.TryParse(data, out _, out _, out _));
    }

    [Fact]
    public void TryParse_HeaderOnly_GivesEmptyBody() {
        var data = new byte[10];
        data[0] = 0x01;
        data[1] = 0x02;
        Assert.True(PushEnvelope.TryParse(data, out var type, out var tag, out var body));
        Assert.Equal(PushType.Verification, type);
        Assert.Equal(new byte[8], tag);
        Assert.Empty(body);
    }
}
