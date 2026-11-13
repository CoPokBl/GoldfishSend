using System.Net.Http.Headers;
using GoldfishSend.Core.Crypto;
using GoldfishSend.Core.Protocol;
using Microsoft.AspNetCore.Mvc.Testing;

namespace GoldfishSend.Tests.Integration;

/// <summary>
/// The client side of the encrypted gateway, as an HttpClient handler: requests to <c>/v1/*</c> are sealed into
/// <c>POST /v1/gw</c> and the answers opened, so tests can keep calling endpoints by their inner paths. Outer errors
/// (400/413/421 …) are passed through unchanged, so tests can see them. Everything else goes out as is.
/// </summary>
public sealed class GatewayHandler : DelegatingHandler {
    private ServerPublicKey? _key;
    private readonly SemaphoreSlim _keyLock = new(1, 1);

    /// <summary>Set on a request to send this outer <c>X-Forwarded-For</c> (as a reverse proxy would add it).</summary>
    public static readonly HttpRequestOptionsKey<string> OuterForwardedFor = new("gf-outer-xff");

    /// <summary>Added to the clock when stamping inner requests.</summary>
    public long ClockOffsetSeconds { get; set; }

    /// <summary>The last outer request body sent, for replay tests.</summary>
    public byte[]? LastOuter { get; private set; }

    public static HttpClient Client(WebApplicationFactory<Program> factory) => Client(factory, out _);

    public static HttpClient Client(WebApplicationFactory<Program> factory, out GatewayHandler handler) {
        handler = new GatewayHandler();
        return factory.CreateDefaultClient(handler);
    }

    public async Task<ServerPublicKey> KeyAsync(Uri baseUri, CancellationToken ct) {
        if (_key is not null) {
            return _key;
        }
        await _keyLock.WaitAsync(ct);
        try {
            if (_key is null) {
                using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(baseUri, "/v1/key"));
                using var response = await base.SendAsync(request, ct);
                response.EnsureSuccessStatusCode();
                var blob = await response.Content.ReadAsByteArrayAsync(ct);
                _key = ServerPublicKey.TryParse(blob) ?? throw new InvalidOperationException("Bad server key blob.");
            }
            return _key;
        } finally {
            _keyLock.Release();
        }
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) {
        var uri = request.RequestUri!;
        var path = uri.AbsolutePath;
        if (!path.StartsWith("/v1/", StringComparison.Ordinal) || path is "/v1/key" or "/v1/gw") {
            return await base.SendAsync(request, ct);
        }
        var baseUri = new Uri(uri.GetLeftPart(UriPartial.Authority));
        var key = await KeyAsync(baseUri, ct);

        var headers = new List<KeyValuePair<string, string>>();
        foreach (var (name, values) in request.Headers) {
            headers.Add(new(name.ToLowerInvariant(), string.Join(", ", values)));
        }
        var body = Array.Empty<byte>();
        if (request.Content is not null) {
            body = await request.Content.ReadAsByteArrayAsync(ct);
            if (request.Content.Headers.ContentType is { } type) {
                headers.Add(new("content-type", type.ToString()));
            }
        }
        var inner = new InnerRequest(request.Method.Method, DateTimeOffset.UtcNow.ToUnixTimeSeconds() + ClockOffsetSeconds,
            uri.PathAndQuery, headers, body);
        var (outer, respSecret) = key.Seal(GatewayCodec.EncodeRequest(inner));
        LastOuter = outer;

        using var gw = new HttpRequestMessage(HttpMethod.Post, new Uri(baseUri, "/v1/gw")) {
            Content = GoldfishFixture.Octets(outer),
        };
        if (request.Options.TryGetValue(OuterForwardedFor, out var forwardedFor)) {
            gw.Headers.TryAddWithoutValidation("X-Forwarded-For", forwardedFor);
        }
        var response = await base.SendAsync(gw, ct);
        if ((int)response.StatusCode != 200) {
            return response;
        }
        return Open(response, await response.Content.ReadAsByteArrayAsync(ct), respSecret, request);
    }

    public static HttpResponseMessage Open(HttpResponseMessage outer, byte[] sealedBody, byte[] respSecret, HttpRequestMessage? request) {
        var plaintext = GatewayCrypto.OpenResponse(respSecret, sealedBody)
            ?? throw new InvalidOperationException("The gateway response didn't authenticate.");
        if (!GatewayCodec.TryDecodeResponse(plaintext, out var inner)) {
            throw new InvalidOperationException("Malformed inner response.");
        }
        outer.Dispose();
        var response = new HttpResponseMessage((System.Net.HttpStatusCode)inner.Status) {
            Content = new ByteArrayContent(inner.Body),
            RequestMessage = request,
        };
        foreach (var (name, value) in inner.Headers) {
            if (name == "content-type") {
                response.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(value);
            } else {
                response.Headers.TryAddWithoutValidation(name, value);
            }
        }
        return response;
    }
}
