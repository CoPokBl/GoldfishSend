using System.Text.Json;
using GoldfishSend.Core.Crypto;
using GoldfishSend.Core.Protocol;
using GoldfishSend.Infrastructure.Redis;
using Microsoft.AspNetCore.Http.Features;
using StackExchange.Redis;

namespace GoldfishSend.Api;

/// <summary>
/// The encrypted gateway (docs/protocol.md, "Encrypted transport and server identity"). <c>GET /v1/key</c> serves the
/// public key blob, and <c>POST /v1/gw</c> decrypts an inner request, rewrites this HttpContext into it, runs the rest of
/// the pipeline (routing and the API endpoints), and encrypts whatever they produced. Any other <c>/v1/*</c> path is a
/// plaintext 404, so the API can't be reached around the gateway. Must run before routing.
/// </summary>
public sealed class GatewayMiddleware {
    public const int MaxOuterBody = 20 * 1024;
    public const int TimestampWindowSeconds = 600;

    private static readonly HashSet<string> OuterHeadersToKeep = new(StringComparer.OrdinalIgnoreCase) {
        "Cache-Control", "X-Content-Type-Options", "Referrer-Policy", "Content-Security-Policy",
    };

    private readonly RequestDelegate _next;
    private readonly ServerKey _key;
    private readonly GatewayReplayGuard _replay;
    private readonly GatewayFloodGuard _flood;
    private readonly TimeProvider _time;
    private readonly ILogger<GatewayMiddleware> _log;

    public GatewayMiddleware(
        RequestDelegate next, ServerKey key, GatewayReplayGuard replay, GatewayFloodGuard flood, ILogger<GatewayMiddleware> log,
        TimeProvider? time = null) {
        _next = next;
        _key = key;
        _replay = replay;
        _flood = flood;
        _log = log;
        _time = time ?? TimeProvider.System;
    }

    public async Task InvokeAsync(HttpContext context) {
        var request = context.Request;
        if (request.Path.Equals("/v1/key", StringComparison.OrdinalIgnoreCase) && HttpMethods.IsGet(request.Method)) {
            context.Response.ContentType = "application/octet-stream";
            context.Response.ContentLength = _key.Blob.Length;
            await context.Response.Body.WriteAsync(_key.Blob, context.RequestAborted);
            return;
        }
        if (request.Path.Equals("/v1/gw", StringComparison.OrdinalIgnoreCase)) {
            if (!HttpMethods.IsPost(request.Method)) {
                await PlainErrorAsync(context, 405, "method_not_allowed");
                return;
            }
            await HandleAsync(context);
            return;
        }
        if (request.Path.StartsWithSegments("/v1", StringComparison.OrdinalIgnoreCase)) {
            await PlainErrorAsync(context, 404, "not_found");
            return;
        }
        await _next(context);
    }

    private async Task HandleAsync(HttpContext context) {
        var request = context.Request;
        if (!_flood.TryAcquire(Endpoints.HttpHelpers.Subject(context))) {
            context.Response.Headers.RetryAfter = "1";
            context.Response.StatusCode = 429;
            context.Response.ContentType = "application/json; charset=utf-8";
            await context.Response.WriteAsync("{\"error\":\"rate_limited\",\"scope\":\"ip\"}", context.RequestAborted);
            return;
        }
        if (!Endpoints.HttpHelpers.IsOctetStream(request)) {
            await PlainErrorAsync(context, 400, "bad_request");
            return;
        }
        byte[]? outer;
        try {
            outer = await Endpoints.HttpHelpers.ReadBodyAsync(request, MaxOuterBody, context.RequestAborted);
        } catch (BadHttpRequestException e) when (e.StatusCode == 413) {
            outer = null;
        }
        if (outer is null || outer.Length > GatewayCrypto.RequestOverhead + GatewayCodec.MaxInnerRequest) {
            await PlainErrorAsync(context, 413, "too_large");
            return;
        }

        switch (_key.TryOpenRequest(outer, out var plaintext, out var respSecret, out var enc)) {
            case ServerKey.OpenStatus.UnknownKey:
                await PlainErrorAsync(context, 421, "unknown_key");
                return;
            case ServerKey.OpenStatus.Malformed:
                await PlainErrorAsync(context, 400, "bad_request");
                return;
        }

        // From here on every answer is encrypted, so the client can trust it.
        if (!GatewayCodec.TryDecodeRequest(plaintext, out var inner)) {
            await SealedErrorAsync(context, respSecret, 400, "bad_request");
            return;
        }
        var now = _time.GetUtcNow().ToUnixTimeSeconds();
        if (Math.Abs(now - inner.Timestamp) > TimestampWindowSeconds) {
            await SealedJsonAsync(context, respSecret, 400, w => {
                w.WriteString("error", "clock_skew");
                w.WriteNumber("serverTime", now);
            });
            return;
        }
        try {
            if (!await _replay.FirstSeenAsync(enc)) {
                await SealedErrorAsync(context, respSecret, 409, "replay");
                return;
            }
        } catch (RedisException) {
            await SealedErrorAsync(context, respSecret, 503, "unavailable");
            return;
        }

        Rewrite(context, inner);

        var buffer = new MemoryStream();
        var features = context.Features;
        var originalBody = features.Get<IHttpResponseBodyFeature>()!;
        features.Set<IHttpResponseBodyFeature>(new StreamResponseBodyFeature(buffer));
        int status;
        try {
            await _next(context);
            status = context.Response.StatusCode;
        } catch (Exception) when (context.RequestAborted.IsCancellationRequested) {
            // Aborted or timed out: the request-timeout middleware may answer with a plaintext 504. Make sure nothing the
            // endpoint set on the inner response goes out with it.
            StripToOuterHeaders(context.Response);
            throw;
        } catch (Exception e) {
            // Never let an exception's plaintext page through. The type is enough to debug, and carries no request data.
            _log.LogError("Unhandled {ExceptionType} in a gateway request.", e.GetType().FullName);
            status = 500;
            buffer.SetLength(0);
            context.Response.Headers.Clear();
            context.Response.ContentType = "application/json";
            await using var writer = new Utf8JsonWriter(buffer);
            writer.WriteStartObject();
            writer.WriteString("error", "internal");
            writer.WriteEndObject();
        } finally {
            await features.Get<IHttpResponseBodyFeature>()!.CompleteAsync();
            features.Set(originalBody);
        }
        if (status is (400 or 413 or 415) && buffer.Length == 0) {
            // Parameter binding answers unreadable JSON or a wrong content type with an empty body. Clients get the
            // documented {"error": …} body for those too. An unknown route stays a bare 404: clients detect missing
            // endpoints by it (docs/groups.md, "Server: batch send").
            await using var writer = new Utf8JsonWriter(buffer);
            writer.WriteStartObject();
            writer.WriteString("error", status switch {
                400 => "invalid_request",
                413 => "too_large",
                _ => "unsupported_media_type",
            });
            writer.WriteEndObject();
            await writer.FlushAsync();
            context.Response.ContentType = "application/json; charset=utf-8";
        }

        var innerHeaders = new List<KeyValuePair<string, string>>();
        foreach (var (name, values) in context.Response.Headers) {
            var lower = name.ToLowerInvariant();
            if ((lower is "content-type" or "retry-after" || lower.StartsWith("gf-", StringComparison.Ordinal))
                && GatewayCodec.IsValidHeaderName(lower)) {
                innerHeaders.Add(new(lower, values.ToString()));
            }
        }
        await SealedAsync(context, respSecret, new InnerResponse(status, innerHeaders, buffer.ToArray()));
    }

    /// <summary>Turns the outer gateway request into the inner one, in place. The connection (client IP) is untouched.</summary>
    private static void Rewrite(HttpContext context, InnerRequest inner) {
        var request = context.Request;
        var host = request.Host;
        request.Method = inner.Method;
        var query = inner.Path.IndexOf('?');
        request.Path = new PathString(query < 0 ? inner.Path : inner.Path[..query]);
        request.QueryString = query < 0 ? QueryString.Empty : new QueryString(inner.Path[query..]);
        request.Headers.Clear();
        request.Host = host;
        foreach (var (name, value) in inner.Headers) {
            if (name == "content-type" || name.StartsWith("gf-", StringComparison.Ordinal)) {
                request.Headers[name] = value;
            }
        }
        request.Body = new MemoryStream(inner.Body, writable: false);
        request.ContentLength = inner.Body.Length;
    }

    private static Task SealedErrorAsync(HttpContext context, byte[] respSecret, int status, string code) {
        return SealedJsonAsync(context, respSecret, status, w => w.WriteString("error", code));
    }

    private static Task SealedJsonAsync(HttpContext context, byte[] respSecret, int status, Action<Utf8JsonWriter> write) {
        var body = new MemoryStream();
        using (var writer = new Utf8JsonWriter(body)) {
            writer.WriteStartObject();
            write(writer);
            writer.WriteEndObject();
        }
        return SealedAsync(context, respSecret,
            new InnerResponse(status, [new("content-type", "application/json; charset=utf-8")], body.ToArray()));
    }

    private static async Task SealedAsync(HttpContext context, byte[] respSecret, InnerResponse inner) {
        var sealedBody = GatewayCrypto.SealResponse(respSecret, GatewayCodec.EncodeResponse(inner));
        var response = context.Response;
        StripToOuterHeaders(response);
        response.StatusCode = 200;
        response.ContentType = "application/octet-stream";
        response.ContentLength = sealedBody.Length;
        await response.Body.WriteAsync(sealedBody, context.RequestAborted);
    }

    /// <summary>Removes every response header except the fixed security headers set before the gateway.</summary>
    private static void StripToOuterHeaders(HttpResponse response) {
        foreach (var name in response.Headers.Keys.ToArray()) {
            if (!OuterHeadersToKeep.Contains(name)) {
                response.Headers.Remove(name);
            }
        }
    }

    private static async Task PlainErrorAsync(HttpContext context, int status, string code) {
        context.Response.StatusCode = status;
        context.Response.ContentType = "application/json; charset=utf-8";
        await context.Response.WriteAsync($"{{\"error\":\"{code}\"}}", context.RequestAborted);
    }
}
