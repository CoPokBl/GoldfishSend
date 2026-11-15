using System.Net.Http.Headers;
using GoldfishSend.Core.Crypto;
using GoldfishSend.Core.Protocol;

namespace LoadTest;

public sealed record ApiResponse(int Status, IReadOnlyList<KeyValuePair<string, string>> Headers, byte[] Body);

/// <summary>
/// The client side of the encrypted gateway, as the app does it: every API call is sealed to the server key and sent as
/// <c>POST /v1/gw</c>, and the answer is opened with the per-request response secret.
/// </summary>
public sealed class GatewayClient {
    private readonly HttpClient _http;
    private readonly ServerPublicKey _key;

    private GatewayClient(HttpClient http, ServerPublicKey key) {
        _http = http;
        _key = key;
    }

    public string Fingerprint => GatewayCrypto.Base64UrlFingerprint(_key.Fingerprint);

    /// <param name="pinnedFingerprint">The server key fingerprint (base64url) to insist on, or null to trust the first answer.</param>
    public static async Task<GatewayClient> ConnectAsync(HttpClient http, string? pinnedFingerprint, CancellationToken ct) {
        var blob = await http.GetByteArrayAsync("/v1/key", ct);
        var expected = pinnedFingerprint is null ? [] : System.Buffers.Text.Base64Url.DecodeFromChars(pinnedFingerprint);
        var key = ServerPublicKey.TryParse(blob, expected)
            ?? throw new InvalidOperationException(pinnedFingerprint is null
                ? "The server's key blob is malformed."
                : "The server's key doesn't match the pinned fingerprint.");
        return new GatewayClient(http, key);
    }

    /// <summary>
    /// Sends one inner request. Outer errors (the flood guard's 429, 400, 413 …) come back as that status with an empty
    /// body; transport failures throw.
    /// </summary>
    public async Task<ApiResponse> SendAsync(
        string method, string path, byte[]? body = null, string? contentType = null,
        IEnumerable<KeyValuePair<string, string>>? headers = null, CancellationToken ct = default) {
        var innerHeaders = new List<KeyValuePair<string, string>>();
        if (headers is not null) {
            innerHeaders.AddRange(headers);
        }
        if (contentType is not null) {
            innerHeaders.Add(new("content-type", contentType));
        }
        var inner = new InnerRequest(method, DateTimeOffset.UtcNow.ToUnixTimeSeconds(), path, innerHeaders, body ?? []);
        var (outer, respSecret) = _key.Seal(GatewayCodec.EncodeRequest(inner));

        using var content = new ByteArrayContent(outer);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        using var response = await _http.PostAsync("/v1/gw", content, ct);
        var sealedBody = await response.Content.ReadAsByteArrayAsync(ct);
        if ((int)response.StatusCode != 200) {
            return new ApiResponse((int)response.StatusCode, [], []);
        }
        var plaintext = GatewayCrypto.OpenResponse(respSecret, sealedBody)
            ?? throw new InvalidOperationException("A gateway response didn't authenticate.");
        if (!GatewayCodec.TryDecodeResponse(plaintext, out var decoded)) {
            throw new InvalidOperationException("Malformed inner response.");
        }
        return new ApiResponse(decoded.Status, decoded.Headers, decoded.Body);
    }
}
