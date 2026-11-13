using System.Buffers.Binary;
using System.Text;

namespace GoldfishSend.Core.Protocol;

public sealed record InnerRequest(string Method, long Timestamp, string Path, IReadOnlyList<KeyValuePair<string, string>> Headers, byte[] Body);

public sealed record InnerResponse(int Status, IReadOnlyList<KeyValuePair<string, string>> Headers, byte[] Body);

/// <summary>
/// The inner request and response formats of the encrypted gateway (docs/protocol.md), with their padding. Decoding is
/// strict: exact lengths, bounded fields, only zero padding up to exactly the bucket the content needs.
/// </summary>
public static class GatewayCodec {
    public static readonly int[] Buckets = [512, 1024, 2048, 4096, 8192, 17408];
    public const int MaxInnerRequest = 17408;
    public const int MaxRequestBody = 16 * 1024;
    public const int MaxPathBytes = 2048;
    public const int MaxHeaders = 32;
    public const int MaxHeaderNameBytes = 64;
    public const int MaxHeaderValueBytes = 4096;

    private static readonly string[] Methods = ["", "GET", "POST", "PUT", "DELETE"];
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    /// <summary>The padded size for an inner request of <paramref name="length"/> bytes, or -1 if it's too large.</summary>
    public static int PaddedRequestSize(int length) {
        foreach (var bucket in Buckets) {
            if (length <= bucket) {
                return bucket;
            }
        }
        return -1;
    }

    /// <summary>Responses use the same buckets, and multiples of 4096 above the largest.</summary>
    public static int PaddedResponseSize(int length) {
        var size = PaddedRequestSize(length);
        return size > 0 ? size : (length + 4095) / 4096 * 4096;
    }

    public static byte[] EncodeRequest(InnerRequest request) {
        var method = Array.IndexOf(Methods, request.Method.ToUpperInvariant());
        if (method <= 0) {
            throw new ArgumentException("Unsupported method.", nameof(request));
        }
        var path = Encoding.UTF8.GetBytes(request.Path);
        var size = 1 + 8 + 2 + path.Length + HeadersSize(request.Headers) + 4 + request.Body.Length;
        var padded = PaddedRequestSize(size);
        if (padded < 0) {
            throw new ArgumentException("The request is too large for the gateway.", nameof(request));
        }
        var buffer = new byte[padded];
        var span = buffer.AsSpan();
        span[0] = (byte)method;
        BinaryPrimitives.WriteUInt64BigEndian(span[1..], (ulong)request.Timestamp);
        BinaryPrimitives.WriteUInt16BigEndian(span[9..], (ushort)path.Length);
        path.CopyTo(span[11..]);
        var offset = 11 + path.Length;
        offset = WriteHeaders(span, offset, request.Headers);
        BinaryPrimitives.WriteUInt32BigEndian(span[offset..], (uint)request.Body.Length);
        request.Body.CopyTo(span[(offset + 4)..]);
        return buffer;
    }

    public static bool TryDecodeRequest(ReadOnlySpan<byte> data, out InnerRequest request) {
        request = null!;
        if (data.Length > MaxInnerRequest || data.Length < 1 + 8 + 2 + 1 + 4) {
            return false;
        }
        var method = data[0];
        if (method < 1 || method >= Methods.Length) {
            return false;
        }
        var timestamp = BinaryPrimitives.ReadUInt64BigEndian(data[1..]);
        if (timestamp > long.MaxValue) {
            return false;
        }
        int pathLength = BinaryPrimitives.ReadUInt16BigEndian(data[9..]);
        if (pathLength is 0 or > MaxPathBytes || 11 + pathLength > data.Length) {
            return false;
        }
        string path;
        try {
            path = StrictUtf8.GetString(data.Slice(11, pathLength));
        } catch (ArgumentException) {
            return false;
        }
        if (!IsAllowedPath(path)) {
            return false;
        }
        var offset = 11 + pathLength;
        if (!TryReadHeaders(data, ref offset, out var headers)) {
            return false;
        }
        if (offset + 4 > data.Length) {
            return false;
        }
        var bodyLength = BinaryPrimitives.ReadUInt32BigEndian(data[offset..]);
        offset += 4;
        if (bodyLength > MaxRequestBody || bodyLength > (uint)(data.Length - offset)) {
            return false;
        }
        var body = data.Slice(offset, (int)bodyLength).ToArray();
        offset += (int)bodyLength;
        if (!IsExactPadding(data, offset, PaddedRequestSize(offset))) {
            return false;
        }
        request = new InnerRequest(Methods[method], (long)timestamp, path, headers, body);
        return true;
    }

    public static byte[] EncodeResponse(InnerResponse response) {
        var size = 2 + HeadersSize(response.Headers) + 4 + response.Body.Length;
        var buffer = new byte[PaddedResponseSize(size)];
        var span = buffer.AsSpan();
        BinaryPrimitives.WriteUInt16BigEndian(span, (ushort)response.Status);
        var offset = WriteHeaders(span, 2, response.Headers);
        BinaryPrimitives.WriteUInt32BigEndian(span[offset..], (uint)response.Body.Length);
        response.Body.CopyTo(span[(offset + 4)..]);
        return buffer;
    }

    public static bool TryDecodeResponse(ReadOnlySpan<byte> data, out InnerResponse response) {
        response = null!;
        if (data.Length < 2 + 1 + 4) {
            return false;
        }
        int status = BinaryPrimitives.ReadUInt16BigEndian(data);
        if (status is < 100 or > 599) {
            return false;
        }
        var offset = 2;
        if (!TryReadHeaders(data, ref offset, out var headers) || offset + 4 > data.Length) {
            return false;
        }
        var bodyLength = BinaryPrimitives.ReadUInt32BigEndian(data[offset..]);
        offset += 4;
        if (bodyLength > (uint)(data.Length - offset)) {
            return false;
        }
        var body = data.Slice(offset, (int)bodyLength).ToArray();
        offset += (int)bodyLength;
        if (!IsExactPadding(data, offset, PaddedResponseSize(offset))) {
            return false;
        }
        response = new InnerResponse(status, headers, body);
        return true;
    }

    /// <summary>
    /// Inner paths are API paths only: "/v1/..." in printable ASCII, no fragment, no backslash, no dot segments, and never
    /// the gateway's own plaintext routes.
    /// </summary>
    public static bool IsAllowedPath(string path) {
        if (!path.StartsWith("/v1/", StringComparison.Ordinal)) {
            return false;
        }
        foreach (var c in path) {
            if (c is < '!' or > '~' or '#' or '\\') {
                return false;
            }
        }
        var query = path.IndexOf('?');
        var route = query < 0 ? path : path[..query];
        if (route.Contains("//", StringComparison.Ordinal) || route.Contains('%')) {
            return false;
        }
        foreach (var segment in route.Split('/')) {
            if (segment is "." or "..") {
                return false;
            }
        }
        var trimmed = route.TrimEnd('/');
        return !trimmed.Equals("/v1/gw", StringComparison.OrdinalIgnoreCase) && !trimmed.Equals("/v1/key", StringComparison.OrdinalIgnoreCase);
    }

    private static int HeadersSize(IReadOnlyList<KeyValuePair<string, string>> headers) {
        var size = 1;
        foreach (var (name, value) in headers) {
            size += 1 + Encoding.ASCII.GetByteCount(name) + 2 + Encoding.ASCII.GetByteCount(value);
        }
        return size;
    }

    private static int WriteHeaders(Span<byte> span, int offset, IReadOnlyList<KeyValuePair<string, string>> headers) {
        if (headers.Count > MaxHeaders) {
            throw new ArgumentException("Too many headers.");
        }
        span[offset++] = (byte)headers.Count;
        foreach (var (name, value) in headers) {
            if (!IsValidHeaderName(name) || !IsValidHeaderValue(value)) {
                throw new ArgumentException("Invalid header.");
            }
            span[offset++] = (byte)name.Length;
            offset += Encoding.ASCII.GetBytes(name, span[offset..]);
            BinaryPrimitives.WriteUInt16BigEndian(span[offset..], (ushort)value.Length);
            offset += 2;
            offset += Encoding.ASCII.GetBytes(value, span[offset..]);
        }
        return offset;
    }

    private static bool TryReadHeaders(ReadOnlySpan<byte> data, ref int offset, out IReadOnlyList<KeyValuePair<string, string>> headers) {
        headers = [];
        if (offset >= data.Length) {
            return false;
        }
        int count = data[offset++];
        if (count > MaxHeaders) {
            return false;
        }
        var list = new List<KeyValuePair<string, string>>(count);
        for (var i = 0; i < count; i++) {
            if (offset >= data.Length) {
                return false;
            }
            int nameLength = data[offset++];
            if (nameLength == 0 || offset + nameLength + 2 > data.Length) {
                return false;
            }
            var name = Encoding.ASCII.GetString(data.Slice(offset, nameLength));
            offset += nameLength;
            int valueLength = BinaryPrimitives.ReadUInt16BigEndian(data[offset..]);
            offset += 2;
            if (valueLength > MaxHeaderValueBytes || offset + valueLength > data.Length) {
                return false;
            }
            var raw = data.Slice(offset, valueLength);
            offset += valueLength;
            foreach (var b in raw) {
                if (b is < 0x20 or > 0x7e) {
                    return false;
                }
            }
            var value = Encoding.ASCII.GetString(raw);
            if (!IsValidHeaderName(name) || list.Any(h => h.Key == name)) {
                return false;
            }
            list.Add(new(name, value));
        }
        headers = list;
        return true;
    }

    public static bool IsValidHeaderName(string name) {
        if (name.Length is 0 or > MaxHeaderNameBytes) {
            return false;
        }
        foreach (var c in name) {
            if (c is not ((>= 'a' and <= 'z') or (>= '0' and <= '9') or '-')) {
                return false;
            }
        }
        return true;
    }

    private static bool IsValidHeaderValue(string value) {
        if (value.Length > MaxHeaderValueBytes) {
            return false;
        }
        foreach (var c in value) {
            if (c is < ' ' or > '~') {
                return false;
            }
        }
        return true;
    }

    private static bool IsExactPadding(ReadOnlySpan<byte> data, int contentLength, int expectedTotal) {
        return expectedTotal == data.Length && data[contentLength..].IndexOfAnyExcept((byte)0) < 0;
    }
}
