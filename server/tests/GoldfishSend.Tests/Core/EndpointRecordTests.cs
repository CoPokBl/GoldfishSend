using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using GoldfishSend.Core.Crypto;
using GoldfishSend.Core.Protocol;

namespace GoldfishSend.Tests.Core;

public sealed class EndpointRecordTests {
    private static EndpointRecord Sample(string url = "https://ntfy.sh/upABC?up=1") {
        var p256dh = RandomNumberGenerator.GetBytes(65);
        p256dh[0] = 0x04;
        return new EndpointRecord(url, p256dh, RandomNumberGenerator.GetBytes(16));
    }

    private static void AssertSame(EndpointRecord expected, EndpointRecord actual) {
        Assert.Equal(expected.Url, actual.Url);
        Assert.Equal(expected.P256dh, actual.P256dh);
        Assert.Equal(expected.Auth, actual.Auth);
    }

    [Fact]
    public void Serialize_Layout() {
        var record = Sample("https://a.b/c");
        var data = record.Serialize();
        var url = Encoding.UTF8.GetBytes(record.Url);
        Assert.Equal(2 + url.Length + 65 + 16, data.Length);
        Assert.Equal(url.Length, BinaryPrimitives.ReadUInt16BigEndian(data));
        Assert.Equal(url, data[2..(2 + url.Length)]);
        Assert.Equal(record.P256dh, data[(2 + url.Length)..(2 + url.Length + 65)]);
        Assert.Equal(record.Auth, data[^16..]);
    }

    [Theory]
    [InlineData("https://ntfy.sh/upABC?up=1")]
    [InlineData("")]
    [InlineData("https://push.example.com/ünïcödé/путь")]
    public void RoundTrip(string url) {
        var record = Sample(url);
        AssertSame(record, EndpointRecord.Deserialize(record.Serialize()));
    }

    [Fact]
    public void RoundTrip_MaxLengthUrl() {
        var url = "https://push.example.com/" + new string('a', EndpointRecord.MaxUrlBytes - 25);
        Assert.Equal(2048, Encoding.UTF8.GetByteCount(url));
        var record = Sample(url);
        AssertSame(record, EndpointRecord.Deserialize(record.Serialize()));
    }

    [Fact]
    public void Serialize_UrlTooLong_Throws() {
        var url = "https://push.example.com/" + new string('a', EndpointRecord.MaxUrlBytes - 24);
        Assert.Throws<ArgumentException>(() => Sample(url).Serialize());
    }

    [Fact]
    public void Serialize_UrlLimitIsInUtf8Bytes() {
        // 1100 two-byte characters: 1100 chars but 2200 bytes.
        var url = "https://x.example.com/" + new string('é', 1100);
        Assert.True(url.Length < EndpointRecord.MaxUrlBytes);
        Assert.Throws<ArgumentException>(() => Sample(url).Serialize());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public void Deserialize_Truncated_Throws(int length) {
        Assert.Throws<FormatException>(() => EndpointRecord.Deserialize(new byte[length]));
    }

    [Fact]
    public void Deserialize_MissingTrailingByte_Throws() {
        var data = Sample().Serialize();
        Assert.Throws<FormatException>(() => EndpointRecord.Deserialize(data[..^1]));
    }

    [Fact]
    public void Deserialize_ExtraTrailingByte_Throws() {
        var data = Sample().Serialize();
        Assert.Throws<FormatException>(() => EndpointRecord.Deserialize([.. data, 0x00]));
    }

    [Fact]
    public void Deserialize_LengthPrefixTooLarge_Throws() {
        var data = Sample().Serialize();
        BinaryPrimitives.WriteUInt16BigEndian(data, (ushort)(BinaryPrimitives.ReadUInt16BigEndian(data) + 1));
        Assert.Throws<FormatException>(() => EndpointRecord.Deserialize(data));
    }

    [Fact]
    public void Deserialize_LengthPrefixTooSmall_Throws() {
        var data = Sample().Serialize();
        BinaryPrimitives.WriteUInt16BigEndian(data, (ushort)(BinaryPrimitives.ReadUInt16BigEndian(data) - 1));
        Assert.Throws<FormatException>(() => EndpointRecord.Deserialize(data));
    }

    [Fact]
    public void Deserialize_UrlLengthOverMax_Throws() {
        // Self-consistent framing, but the declared URL is longer than allowed.
        var urlLength = EndpointRecord.MaxUrlBytes + 1;
        var data = new byte[2 + urlLength + 65 + 16];
        BinaryPrimitives.WriteUInt16BigEndian(data, (ushort)urlLength);
        data.AsSpan(2, urlLength).Fill((byte)'a');
        Assert.Throws<FormatException>(() => EndpointRecord.Deserialize(data));
    }

    [Fact]
    public void Deserialize_OnlyKeysNoPrefix_Throws() {
        Assert.Throws<FormatException>(() => EndpointRecord.Deserialize(new byte[65 + 16]));
    }

    [Fact]
    public void Deserialize_CopiesData() {
        var data = Sample().Serialize();
        var record = EndpointRecord.Deserialize(data);
        var before = record.Auth.ToArray();
        Array.Clear(data);
        Assert.Equal(before, record.Auth);
    }

    [Fact]
    public void ToString_IsRedacted() {
        var record = Sample("https://ntfy.sh/secret-topic-123");
        var text = record.ToString();
        Assert.Equal("EndpointRecord { <redacted> }", text);
        Assert.DoesNotContain("ntfy", text);
        Assert.DoesNotContain("secret-topic-123", text);
        Assert.DoesNotContain("System.Byte", text);
        Assert.DoesNotContain("ntfy", $"{record}");
    }
}
