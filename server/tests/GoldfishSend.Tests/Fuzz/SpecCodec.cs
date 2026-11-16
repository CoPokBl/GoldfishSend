using System.Buffers.Binary;
using System.Text;
using CsCheck;

namespace GoldfishSend.Tests.Fuzz;

/// <summary>
/// An independent reading of docs/protocol.md ("Inner request", "Inner response", "Padding"), written from the spec rather
/// than from <see cref="GoldfishSend.Core.Protocol.GatewayCodec"/>, so the two can be compared on arbitrary bytes.
/// </summary>
public static class SpecCodec {
    public sealed record Request(int Method, ulong Timestamp, string Path, (string Name, string Value)[] Headers, byte[] Body);

    public sealed record Response(int Status, (string Name, string Value)[] Headers, byte[] Body);

    private static readonly int[] Buckets = [512, 1024, 2048, 4096, 8192, 17408];

    public static int RequestBucket(int n) => Buckets.FirstOrDefault(b => n <= b, -1);

    public static int ResponseBucket(int n) => RequestBucket(n) is > 0 and var b ? b : (n + 4095) / 4096 * 4096;

    /// <summary>Why the last decode on this thread failed, for vector files and failure messages.</summary>
    [ThreadStatic]
    public static string? Why;

    private static T? Fail<T>(string why) where T : class {
        Why = why;
        return null;
    }

    public static Request? DecodeRequest(byte[] data) {
        if (data.Length > 17408) {
            return Fail<Request>("longer than the largest bucket");
        }
        var r = new Reader(data);
        var method = r.U8();
        if (method is not (>= 1 and <= 4)) {
            return Fail<Request>("method");
        }
        var timestamp = r.U64();
        var pathBytes = r.Bytes(r.U16());
        if (pathBytes is null) {
            return Fail<Request>("truncated");
        }
        if (pathBytes.Length is 0 or > 2048 || pathBytes.Any(b => b is < 0x21 or > 0x7e or (byte)'#' or (byte)'\\')) {
            return Fail<Request>("path length or characters");
        }
        var path = Encoding.ASCII.GetString(pathBytes);
        if (!PathAllowed(path)) {
            return Fail<Request>("path not allowed");
        }
        if (timestamp > long.MaxValue) {
            return Fail<Request>("timestamp above 2^63-1");
        }
        var headers = Headers(r);
        if (headers is null) {
            return Fail<Request>(Why!);
        }
        var length = r.U32();
        if (length > 16 * 1024) {
            return Fail<Request>("body over 16 KiB");
        }
        var body = r.Bytes(length);
        if (body is null) {
            return Fail<Request>("truncated");
        }
        if (!PaddedTo(data, r.Offset, RequestBucket(r.Offset))) {
            return Fail<Request>("padding");
        }
        return new Request(method.Value, timestamp!.Value, path, headers, body);
    }

    public static Response? DecodeResponse(byte[] data) {
        var r = new Reader(data);
        var status = r.U16();
        if (status is not (>= 100 and <= 599)) {
            return Fail<Response>(status is null ? "truncated" : "status");
        }
        var headers = Headers(r);
        if (headers is null) {
            return Fail<Response>(Why!);
        }
        var body = r.Bytes(r.U32());
        if (body is null) {
            return Fail<Response>("truncated");
        }
        if (!PaddedTo(data, r.Offset, ResponseBucket(r.Offset))) {
            return Fail<Response>("padding");
        }
        return new Response(status.Value, headers, body);
    }

    /// <summary>"/v1/..." only; the route part has no %, no // and no dot segments, and isn't the gateway's own routes.</summary>
    private static bool PathAllowed(string path) {
        if (!path.StartsWith("/v1/", StringComparison.Ordinal)) {
            return false;
        }
        var route = path.Split('?', 2)[0];
        if (route.Contains('%') || route.Contains("//") || route.Split('/').Any(s => s is "." or "..")) {
            return false;
        }
        var bare = route.TrimEnd('/').ToLowerInvariant();
        return bare is not ("/v1/gw" or "/v1/key");
    }

    private static (string, string)[]? Headers(Reader r) {
        var count = r.U8();
        if (count is null) {
            return Fail<(string, string)[]>("truncated");
        }
        if (count > 32) {
            return Fail<(string, string)[]>("more than 32 headers");
        }
        var list = new List<(string, string)>();
        for (var i = 0; i < count; i++) {
            var name = r.Bytes(r.U8());
            var valueLength = r.U16();
            if (valueLength > 4096) {
                return Fail<(string, string)[]>("header value over 4096 bytes");
            }
            var value = r.Bytes(valueLength);
            if (name is null || value is null) {
                return Fail<(string, string)[]>("truncated");
            }
            if (name.Length is 0 or > 64
                || name.Any(b => b is not ((>= (byte)'a' and <= (byte)'z') or (>= (byte)'0' and <= (byte)'9') or (byte)'-'))) {
                return Fail<(string, string)[]>("header name");
            }
            if (value.Any(b => b is < 0x20 or > 0x7e)) {
                return Fail<(string, string)[]>("header value characters");
            }
            var n = Encoding.ASCII.GetString(name);
            if (list.Any(h => h.Item1 == n)) {
                return Fail<(string, string)[]>("duplicate header");
            }
            list.Add((n, Encoding.ASCII.GetString(value)));
        }
        return [.. list];
    }

    private static bool PaddedTo(byte[] data, int content, int total) => total == data.Length && data.Skip(content).All(b => b == 0);

    private sealed class Reader(byte[] data) {
        public int Offset { get; private set; }
        public bool Ok { get; private set; } = true;

        private bool Take(int n) {
            if (!Ok || n < 0 || data.Length - Offset < n) {
                Ok = false;
                return false;
            }
            return true;
        }

        public int? U8() {
            if (!Take(1)) {
                return null;
            }
            return data[Offset++];
        }

        public int? U16() {
            if (!Take(2)) {
                return null;
            }
            var v = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(Offset));
            Offset += 2;
            return v;
        }

        public long? U32() {
            if (!Take(4)) {
                return null;
            }
            var v = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(Offset));
            Offset += 4;
            return v;
        }

        public ulong? U64() {
            if (!Take(8)) {
                return null;
            }
            var v = BinaryPrimitives.ReadUInt64BigEndian(data.AsSpan(Offset));
            Offset += 8;
            return v;
        }

        public byte[]? Bytes(long? n) {
            if (n is null || !Take((int)Math.Min(n.Value, int.MaxValue))) {
                Ok = false;
                return null;
            }
            var v = data.AsSpan(Offset, (int)n.Value).ToArray();
            Offset += (int)n.Value;
            return v;
        }
    }

    // --- raw encoding (no validation), to build invalid inputs on purpose ---

    public sealed record RawRequest(byte Method, ulong Timestamp, byte[] Path, (byte[] Name, byte[] Value)[] Headers, byte[] Body,
        int ExtraPadding = 0, int DirtyPaddingAt = -1, int? HeaderCount = null, uint? BodyLength = null);

    public static byte[] Encode(RawRequest r) {
        var bytes = new List<byte> { r.Method };
        bytes.AddRange(BigEndian(r.Timestamp, 8));
        bytes.AddRange(BigEndian((ulong)r.Path.Length, 2));
        bytes.AddRange(r.Path);
        AddHeaders(bytes, r.Headers, r.HeaderCount);
        bytes.AddRange(BigEndian(r.BodyLength ?? (uint)r.Body.Length, 4));
        bytes.AddRange(r.Body);
        return Pad(bytes, RequestBucket(bytes.Count), r.ExtraPadding, r.DirtyPaddingAt);
    }

    public sealed record RawResponse(ushort Status, (byte[] Name, byte[] Value)[] Headers, byte[] Body,
        int ExtraPadding = 0, int DirtyPaddingAt = -1, int? HeaderCount = null, uint? BodyLength = null);

    public static byte[] Encode(RawResponse r) {
        var bytes = new List<byte>();
        bytes.AddRange(BigEndian(r.Status, 2));
        AddHeaders(bytes, r.Headers, r.HeaderCount);
        bytes.AddRange(BigEndian(r.BodyLength ?? (uint)r.Body.Length, 4));
        bytes.AddRange(r.Body);
        return Pad(bytes, ResponseBucket(bytes.Count), r.ExtraPadding, r.DirtyPaddingAt);
    }

    private static void AddHeaders(List<byte> bytes, (byte[] Name, byte[] Value)[] headers, int? count) {
        bytes.Add((byte)(count ?? headers.Length));
        foreach (var (name, value) in headers) {
            bytes.Add((byte)name.Length);
            bytes.AddRange(name);
            bytes.AddRange(BigEndian((ulong)value.Length, 2));
            bytes.AddRange(value);
        }
    }

    private static byte[] Pad(List<byte> bytes, int bucket, int extra, int dirtyAt) {
        var total = Math.Max(bytes.Count, bucket < 0 ? bytes.Count : bucket) + extra;
        var content = bytes.Count;
        if (total > content) {
            bytes.AddRange(new byte[total - content]);
        } else if (total < content) {
            bytes.RemoveRange(Math.Max(0, total), content - Math.Max(0, total));
        }
        if (dirtyAt >= 0 && total > content) {
            bytes[content + dirtyAt % (total - content)] = 0x01;
        }
        return [.. bytes];
    }

    private static byte[] BigEndian(ulong value, int size) {
        var b = new byte[size];
        for (var i = size - 1; i >= 0; i--, value >>= 8) {
            b[i] = (byte)value;
        }
        return b;
    }

    // --- generators ---

    private static readonly string[] GoodPaths = [
        "/v1/info", "/v1/messages", "/v1/messages/batch", "/v1/invites/AAAAAAAAAAAAAAAAAAAAAA", "/v1/mailboxes/endpoint",
        "/v1/keys", "/v1/gwx", "/v1/", "/v1/.x", "/v1/..x", "/v1/info?a=%2e%2e&b=//", "/v1/info?../..", "/v1/info?",
        "/v1/info?x=1/../..", "/v1/a/b/c/d/e/f", "/v1/x?key", "/v1/gw?",
    ];

    private static readonly string[] BadPaths = [
        "/v1/gw", "/v1/gw/", "/v1/GW", "/v1/key", "/v1/Key//", "/v1/key?x", "/v1", "/v2/info", "v1/info", "/v1//info",
        "/v1/./info", "/v1/../x", "/v1/x/..", "/v1/x/.", "/v1/%2e", "/v1/a%20b", "/v1/info?#", "/v1/info#x", "/v1/a\\b",
        "/v1/a b", "/v1/\u00e9", "/v1/\u007f", "/v1/a\u0000", "/V1/info", "",
    ];

    public static readonly Gen<byte[]> PathBytes = Gen.Frequency(
        (12, Gen.OneOf(GoodPaths).Select(Encoding.UTF8.GetBytes)),
        (3, Gen.OneOf(BadPaths).Select(Encoding.UTF8.GetBytes)),
        (2, Gen.Char['!', '~'].Array[0, 40].Select(c => Encoding.ASCII.GetBytes("/v1/" + new string(c)))),
        (1, Gen.Int[2040, 2052].Select(n => Encoding.ASCII.GetBytes("/v1/" + new string('a', n - 4)))),
        (1, Gen.Byte.Array[0, 12].Select(b => (byte[])[.. "/v1/"u8, .. b])));

    private static readonly string[] GoodHeaderNames = [
        "content-type", "gf-send-token", "gf-ttl", "gf-pow", "gf-idempotency-key", "retry-after", "gf-", "-", "0", "a",
        new string('a', 64),
    ];

    private static readonly string[] BadHeaderNames = ["Content-Type", "gf_x", "gf x", "gf-\u00e9", new string('a', 65), ""];

    public static readonly Gen<(byte[], byte[])> HeaderBytes = Gen.Select(
        Gen.Frequency(
            (30, Gen.OneOf(GoodHeaderNames).Select(Encoding.UTF8.GetBytes)),
            (2, Gen.OneOf(BadHeaderNames).Select(Encoding.UTF8.GetBytes)),
            (1, Gen.Byte.Array[0, 8])),
        Gen.Frequency(
            (30, Gen.Char[' ', '~'].Array[0, 40].Select(c => Encoding.ASCII.GetBytes(new string(c)))),
            (1, Gen.Int[4090, 4100].Select(n => Encoding.ASCII.GetBytes(new string('v', n)))),
            (1, Gen.Byte.Array[0, 8])),
        (n, v) => (n, v));

    private static readonly Gen<byte[]> Body = Gen.Frequency(
        (8, Gen.Byte.Array[0, 300]),
        (1, Gen.Int[400, 520].Select(n => new byte[n])),
        (1, Gen.OneOf(16383, 16384, 16385, 8150, 4040, 1990, 990).Select(n => new byte[n])));

    public static readonly Gen<ulong> Timestamp = Gen.Frequency(
        (16, Gen.ULong[1_600_000_000, 1_900_000_000]),
        (1, Gen.OneOf(0UL, 1UL, (ulong)long.MaxValue, (ulong)long.MaxValue + 1, ulong.MaxValue)),
        (1, Gen.ULong));

    /// <summary>Mostly well-formed inner requests, with targeted invalid fields and padding.</summary>
    public static readonly Gen<RawRequest> RawRequests = Gen.Select(
        Gen.Frequency((12, Gen.Byte[1, 4]), (1, Gen.OneOf<byte>(0, 5, 255))),
        Timestamp,
        PathBytes,
        Gen.Frequency((12, HeaderBytes.Array[0, 3].Select(h => h.DistinctBy(x => Convert.ToHexString(x.Item1)).ToArray())),
            (1, HeaderBytes.Array[0, 4]), (1, HeaderBytes.Array[31, 34])),
        Body,
        Gen.Frequency((10, Gen.Const((0, -1))), (1, Gen.Select(Gen.OneOf(-1, 1, 512, -512), Gen.Const(-1), (a, b) => (a, b))),
            (1, Gen.Int[0, 100].Select(i => (0, i)))),
        Gen.Frequency((12, Gen.Const(() => (uint?)null)), (1, Gen.OneOf<uint?>(0u, 1u, 16385u, uint.MaxValue, 0x80000000u))),
        (method, ts, path, headers, body, padding, bodyLength) =>
            new RawRequest(method, ts, path, headers, body, padding.Item1, padding.Item2, BodyLength: bodyLength));

    public static readonly Gen<RawResponse> RawResponses = Gen.Select(
        Gen.Frequency((10, Gen.OneOf<ushort>(200, 202, 204, 400, 404, 409, 413, 429, 500, 503)), (1, Gen.OneOf<ushort>(0, 99, 100, 599, 600, 65535))),
        Gen.Frequency((12, HeaderBytes.Array[0, 3].Select(h => h.DistinctBy(x => Convert.ToHexString(x.Item1)).ToArray())),
            (1, HeaderBytes.Array[0, 4]), (1, HeaderBytes.Array[31, 34])),
        Gen.Frequency((8, Gen.Byte.Array[0, 300]), (1, Gen.OneOf(17396, 17397, 20000).Select(n => new byte[n]))),
        Gen.Frequency((10, Gen.Const((0, -1))), (1, Gen.Select(Gen.OneOf(-1, 1, 4096, -512), Gen.Const(-1), (a, b) => (a, b))),
            (1, Gen.Int[0, 100].Select(i => (0, i)))),
        Gen.Frequency((12, Gen.Const(() => (uint?)null)), (1, Gen.OneOf<uint?>(0u, 1u, uint.MaxValue, 0x80000000u))),
        (status, headers, body, padding, bodyLength) =>
            new RawResponse(status, headers, body, padding.Item1, padding.Item2, BodyLength: bodyLength));

    public static readonly Gen<byte[]> RequestBytes = Gen.Frequency(
        (6, RawRequests.Select(Encode)),
        (3, RawRequests.Select(Encode).SelectMany(b => Fuzz.Mutate(b, 18000))),
        (1, Gen.Byte.Array[0, 600]));

    public static readonly Gen<byte[]> ResponseBytes = Gen.Frequency(
        (6, RawResponses.Select(Encode)),
        (3, RawResponses.Select(Encode).SelectMany(b => Fuzz.Mutate(b, 25000))),
        (1, Gen.Byte.Array[0, 600]));
}
