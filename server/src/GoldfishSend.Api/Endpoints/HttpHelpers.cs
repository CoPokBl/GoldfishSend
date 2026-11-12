using System.Buffers.Text;
using System.Globalization;
using GoldfishSend.Infrastructure.Services;

namespace GoldfishSend.Api.Endpoints;

internal static class HttpHelpers {
    public static byte[]? B64(string? value, int? expectedLength = null) {
        if (string.IsNullOrEmpty(value) || value.Length > 8192) {
            return null;
        }
        try {
            var bytes = Base64Url.DecodeFromChars(value);
            return expectedLength is { } n && bytes.Length != n ? null : bytes;
        } catch (FormatException) {
            return null;
        }
    }

    public static string B64(byte[] value) => Base64Url.EncodeToString(value);

    public static int? IntHeader(HttpRequest request, string name) {
        var raw = request.Headers[name].ToString();
        return int.TryParse(raw, NumberStyles.None, CultureInfo.InvariantCulture, out var value) ? value : null;
    }

    /// <summary>Reads at most <paramref name="max"/> bytes. Returns <c>null</c> if the body is larger.</summary>
    public static async Task<byte[]?> ReadBodyAsync(HttpRequest request, int max, CancellationToken ct) {
        if (request.ContentLength is { } declared && declared > max) {
            return null;
        }
        var buffer = new byte[max + 1];
        var total = 0;
        int read;
        while (total < buffer.Length && (read = await request.Body.ReadAsync(buffer.AsMemory(total), ct)) > 0) {
            total += read;
        }
        return total > max ? null : buffer[..total];
    }

    public static IResult Error(ServiceError error) {
        return new ErrorResult(error);
    }

    public static IResult Error(int status, string code) => Error(new ServiceError(status, code));

    public static ClientSubject Subject(HttpContext context) => ClientSubject.From(context.Connection.RemoteIpAddress);

    /// <summary>
    /// Raw-body endpoints require <c>application/octet-stream</c>. A browser can't send that cross-origin without
    /// a CORS preflight (which we never approve), so a web page can't make its visitors post to us.
    /// </summary>
    public static bool IsOctetStream(HttpRequest request) {
        return request.ContentType is { } type
            && type.Split(';', 2)[0].Trim().Equals("application/octet-stream", StringComparison.OrdinalIgnoreCase);
    }

    private sealed class ErrorResult(ServiceError error) : IResult {
        public async Task ExecuteAsync(HttpContext context) {
            if (error.RetryAfter is { } retry) {
                var seconds = Math.Max(1, (int)Math.Ceiling(retry.TotalSeconds));
                context.Response.Headers.RetryAfter = seconds.ToString(CultureInfo.InvariantCulture);
            }
            context.Response.StatusCode = error.Status;
            await context.Response.WriteAsJsonAsync(new ErrorResponse(error.Code, error.Scope), ApiJsonContext.Default.ErrorResponse);
        }
    }
}
