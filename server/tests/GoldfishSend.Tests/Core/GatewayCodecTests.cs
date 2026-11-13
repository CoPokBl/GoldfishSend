using System.Buffers.Binary;
using GoldfishSend.Core.Protocol;

namespace GoldfishSend.Tests.Core;

public sealed class GatewayCodecTests {
    private static InnerRequest Request(string path = "/v1/messages", byte[]? body = null, params (string, string)[] headers) =>
        new("POST", 1_700_000_000, path, headers.Select(h => new KeyValuePair<string, string>(h.Item1, h.Item2)).ToList(), body ?? [1, 2, 3]);

    [Fact]
    public void Request_RoundTrips() {
        var request = Request("/v1/invites/abc?x=1", [9, 8, 7], ("content-type", "application/octet-stream"), ("gf-ttl", "60"));
        var encoded = GatewayCodec.EncodeRequest(request);
        Assert.Equal(512, encoded.Length);
        Assert.True(GatewayCodec.TryDecodeRequest(encoded, out var decoded));
        Assert.Equal("POST", decoded.Method);
        Assert.Equal(1_700_000_000, decoded.Timestamp);
        Assert.Equal("/v1/invites/abc?x=1", decoded.Path);
        Assert.Equal(request.Headers, decoded.Headers);
        Assert.Equal(request.Body, decoded.Body);
    }

    [Fact]
    public void Request_LayoutMatchesTheSpec() {
        var encoded = GatewayCodec.EncodeRequest(new InnerRequest("PUT", 0x0102030405060708, "/v1/x", [new("gf-a", "b")], [0xee]));
        byte[] expected = [
            3, 1, 2, 3, 4, 5, 6, 7, 8,  // method, timestamp
            0, 5, .. "/v1/x"u8,         // path
            1, 4, .. "gf-a"u8, 0, 1, (byte)'b', // headers
            0, 0, 0, 1, 0xee,           // body
        ];
        Assert.Equal(expected, encoded[..expected.Length]);
        Assert.All(encoded[expected.Length..], b => Assert.Equal(0, b));
    }

    [Theory]
    [InlineData(0, 512)]
    [InlineData(512, 512)]
    [InlineData(513, 1024)]
    [InlineData(2049, 4096)]
    [InlineData(8193, 17408)]
    [InlineData(17408, 17408)]
    [InlineData(17409, -1)]
    public void RequestBuckets(int length, int padded) {
        Assert.Equal(padded, GatewayCodec.PaddedRequestSize(length));
    }

    [Theory]
    [InlineData(100, 512)]
    [InlineData(17408, 17408)]
    [InlineData(17409, 20480)]
    [InlineData(40000, 40960)]
    public void ResponseBuckets(int length, int padded) {
        Assert.Equal(padded, GatewayCodec.PaddedResponseSize(length));
    }

    [Fact]
    public void Request_OverTheLargestBucket_CannotBeEncoded() {
        Assert.Throws<ArgumentException>(() => GatewayCodec.EncodeRequest(Request(body: new byte[17408])));
    }

    [Fact]
    public void Request_BodyOver16KiB_IsRejected() {
        var encoded = GatewayCodec.EncodeRequest(Request(body: new byte[16 * 1024 + 1]));
        Assert.False(GatewayCodec.TryDecodeRequest(encoded, out _));
        Assert.True(GatewayCodec.TryDecodeRequest(GatewayCodec.EncodeRequest(Request(body: new byte[16 * 1024])), out _));
    }

    [Theory]
    [InlineData("/v1/gw")]
    [InlineData("/v1/gw/")]
    [InlineData("/V1/GW")]
    [InlineData("/v1/key")]
    [InlineData("/v1/key?x=1")]
    [InlineData("/healthz")]
    [InlineData("/v2/info")]
    [InlineData("v1/info")]
    [InlineData("/v1/../healthz")]
    [InlineData("/v1/./info")]
    [InlineData("/v1//info")]
    [InlineData("/v1/in fo")]
    [InlineData("/v1/info#x")]
    [InlineData("/v1/a\\b")]
    [InlineData("/v1/%2e%2e/healthz")]
    [InlineData("/v1/é")]
    public void DisallowedPaths(string path) {
        Assert.False(GatewayCodec.IsAllowedPath(path));
        var encoded = Encode(path);
        Assert.False(GatewayCodec.TryDecodeRequest(encoded, out _));
    }

    [Theory]
    [InlineData("/v1/info")]
    [InlineData("/v1/invites/AbC-_1")]
    [InlineData("/v1/mailboxes/endpoint")]
    [InlineData("/v1/keys")]
    public void AllowedPaths(string path) {
        Assert.True(GatewayCodec.IsAllowedPath(path));
        Assert.True(GatewayCodec.TryDecodeRequest(GatewayCodec.EncodeRequest(Request(path)), out _));
    }

    [Fact]
    public void Decode_RejectsBadFields() {
        var good = GatewayCodec.EncodeRequest(Request());
        Assert.True(GatewayCodec.TryDecodeRequest(good, out _));

        foreach (var method in new byte[] { 0, 5, 255 }) {
            var copy = good.ToArray();
            copy[0] = method;
            Assert.False(GatewayCodec.TryDecodeRequest(copy, out _));
        }

        var bigTime = good.ToArray();
        bigTime[1] = 0x80;
        Assert.False(GatewayCodec.TryDecodeRequest(bigTime, out _));

        var dirtyPadding = good.ToArray();
        dirtyPadding[^1] = 1;
        Assert.False(GatewayCodec.TryDecodeRequest(dirtyPadding, out _));

        // Padding to the wrong bucket (too much, or none) is a client bug that would leak sizes.
        Assert.False(GatewayCodec.TryDecodeRequest([.. good, .. new byte[512]], out _));
        Assert.False(GatewayCodec.TryDecodeRequest(good[..^1], out _));

        Assert.False(GatewayCodec.TryDecodeRequest([], out _));
        Assert.False(GatewayCodec.TryDecodeRequest(new byte[17408 + 512], out _));
    }

    [Fact]
    public void Decode_RejectsBodyLongerThanTheMessage() {
        var encoded = GatewayCodec.EncodeRequest(Request(body: []));
        var offset = 11 + "/v1/messages".Length + 1;
        BinaryPrimitives.WriteUInt32BigEndian(encoded.AsSpan(offset), 10_000);
        Assert.False(GatewayCodec.TryDecodeRequest(encoded, out _));
    }

    [Theory]
    [InlineData("Content-Type", "x")]   // uppercase
    [InlineData("", "x")]
    [InlineData("gf_x", "x")]
    [InlineData("gf-x", "a\nb")]
    [InlineData("gf-x", "\u0001")]
    public void Decode_RejectsBadHeaders(string name, string value) {
        var encoded = RawRequest("/v1/info", [(name, value)]);
        Assert.False(GatewayCodec.TryDecodeRequest(encoded, out _));
    }

    [Fact]
    public void Decode_RejectsDuplicateAndTooManyHeaders() {
        Assert.False(GatewayCodec.TryDecodeRequest(RawRequest("/v1/info", [("gf-a", "1"), ("gf-a", "2")]), out _));
        var many = Enumerable.Range(0, 33).Select(i => ($"gf-{i}", "v")).ToArray();
        Assert.False(GatewayCodec.TryDecodeRequest(RawRequest("/v1/info", many), out _));
        var max = Enumerable.Range(0, 32).Select(i => ($"gf-{i}", "v")).ToArray();
        Assert.True(GatewayCodec.TryDecodeRequest(RawRequest("/v1/info", max), out _));
    }

    [Fact]
    public void Response_RoundTripsAndPads() {
        var response = new InnerResponse(429, [new("content-type", "application/json"), new("retry-after", "30")], new byte[5000]);
        var encoded = GatewayCodec.EncodeResponse(response);
        Assert.Equal(8192, encoded.Length);
        Assert.True(GatewayCodec.TryDecodeResponse(encoded, out var decoded));
        Assert.Equal(429, decoded.Status);
        Assert.Equal(response.Headers, decoded.Headers);
        Assert.Equal(5000, decoded.Body.Length);

        var large = GatewayCodec.EncodeResponse(new InnerResponse(200, [], new byte[30000]));
        Assert.Equal(32768, large.Length);
        Assert.True(GatewayCodec.TryDecodeResponse(large, out _));

        var badStatus = encoded.ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(badStatus, 600);
        Assert.False(GatewayCodec.TryDecodeResponse(badStatus, out _));
        var dirty = encoded.ToArray();
        dirty[^1] = 7;
        Assert.False(GatewayCodec.TryDecodeResponse(dirty, out _));
    }

    /// <summary>Encodes without the encoder's validation, to feed the decoder invalid input.</summary>
    private static byte[] RawRequest(string path, (string Name, string Value)[] headers) {
        var bytes = new List<byte> { 1 };
        bytes.AddRange(new byte[8]);
        var p = System.Text.Encoding.UTF8.GetBytes(path);
        bytes.Add((byte)(p.Length >> 8));
        bytes.Add((byte)p.Length);
        bytes.AddRange(p);
        bytes.Add((byte)headers.Length);
        foreach (var (name, value) in headers) {
            var n = System.Text.Encoding.UTF8.GetBytes(name);
            var v = System.Text.Encoding.UTF8.GetBytes(value);
            bytes.Add((byte)n.Length);
            bytes.AddRange(n);
            bytes.Add((byte)(v.Length >> 8));
            bytes.Add((byte)v.Length);
            bytes.AddRange(v);
        }
        bytes.AddRange(new byte[4]);
        var size = GatewayCodec.PaddedRequestSize(bytes.Count);
        bytes.AddRange(new byte[size - bytes.Count]);
        return [.. bytes];
    }

    private static byte[] Encode(string path) => RawRequest(path, []);
}
