using System.Buffers.Text;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using CsCheck;
using GoldfishSend.Api;
using GoldfishSend.Core.Crypto;
using GoldfishSend.Core.Protocol;
using GoldfishSend.Tests.Fuzz;
using static GoldfishSend.Tests.Integration.GoldfishFixture;

namespace GoldfishSend.Tests.Integration;

/// <summary>
/// Hostile input through the real pipeline (Kestrel's TestServer, the gateway, routing, binding, the endpoints, MySQL and
/// Redis). Plaintext answers must be one of the documented outer errors; once a request decrypts, every answer must be
/// encrypted, decode, and carry a JSON <c>{"error": …}</c> body, and nothing a client sends may produce a 500.
/// </summary>
[Collection(GoldfishCollection.Name)]
public sealed class ApiFuzzTests {
    private readonly GoldfishFixture _f;

    public ApiFuzzTests(GoldfishFixture fixture) {
        _f = fixture;
    }

    private Task<ServerPublicKey> KeyAsync() => _f.Gateway.KeyAsync(_f.RawClient.BaseAddress!, default);

    private static readonly Gen<string?> JsonContentType = Gen.Frequency<string?>(
        (8, "application/json"), (2, "application/json; charset=utf-8"), (1, "application/json; charset=utf-16"),
        (1, "text/plain"), (1, "application/octet-stream"), (1, null));

    public static TheoryData<string, string> JsonEndpoints => new() {
        { "POST", "/v1/mailboxes" },
        { "POST", "/v1/mailboxes/verify" },
        { "PUT", "/v1/mailboxes/endpoint" },
        { "POST", "/v1/mailboxes/refresh" },
        { "POST", "/v1/mailboxes/delete" },
    };

    private static Gen<string> DocumentFor(string path) => path switch {
        "/v1/mailboxes" => JsonGen.CreateMailbox,
        "/v1/mailboxes/verify" => JsonGen.Verify,
        "/v1/mailboxes/endpoint" => JsonGen.Rotate,
        _ => JsonGen.Batch,
    };

    [IntegrationTheory]
    [MemberData(nameof(JsonEndpoints))]
    public async Task JsonBodies_AlwaysGetAJsonError(string method, string path) {
        var gen = Gen.Select(JsonGen.Malformed(DocumentFor(path)), JsonContentType);
        await Fuzz.Fuzz.RunAsync(gen, async input => {
            var (body, type) = input;
            var content = new ByteArrayContent(body.Length > GatewayCodec.MaxRequestBody ? body[..GatewayCodec.MaxRequestBody] : body);
            if (type is not null) {
                content.Headers.ContentType = MediaTypeHeaderValue.Parse(type);
            }
            using var request = new HttpRequestMessage(new HttpMethod(method), path) { Content = content };
            using var response = await _f.Client.SendAsync(request);
            await AssertCleanAnswer(response);
        }, iterations: 120, print: i => $"{i.Item2}: {Encoding.UTF8.GetString(i.Item1)}", name: $"{nameof(JsonBodies_AlwaysGetAJsonError)}{path}");
    }

    /// <summary>Found by the fuzzer: these used to be a 500 in Development and an empty-bodied 400/415 in Production.</summary>
    [IntegrationTheory]
    [InlineData("POST", "/v1/mailboxes", "application/json", "{", 400, "invalid_request")]
    [InlineData("POST", "/v1/mailboxes", "application/json", "", 400, "invalid_request")]
    [InlineData("POST", "/v1/mailboxes/refresh", "application/json", "{\"items\":[{\"sendSecret\":true}]}", 400, "invalid_request")]
    [InlineData("POST", "/v1/mailboxes/refresh", "application/json", "{\"items\":{}}{}", 400, "invalid_request")]
    [InlineData("POST", "/v1/mailboxes/verify", "application/json", "{\"code\":1e400}", 400, "invalid_request")]
    [InlineData("PUT", "/v1/mailboxes/endpoint", "application/json; charset=utf-16", "{}", 400, "invalid_request")]
    [InlineData("POST", "/v1/mailboxes/delete", "text/plain", "{}", 415, "unsupported_media_type")]
    [InlineData("POST", "/v1/mailboxes/delete", null, "", 415, "unsupported_media_type")]
    public async Task UnreadableJson_GetsAJsonError(string method, string path, string? type, string body, int status, string error) {
        var content = new StringContent(body);
        content.Headers.ContentType = type is null ? null : MediaTypeHeaderValue.Parse(type);
        using var request = new HttpRequestMessage(new HttpMethod(method), path) { Content = content };
        using var response = await _f.Client.SendAsync(request);
        Assert.Equal(status, (int)response.StatusCode);
        Assert.Equal(error, JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement.GetProperty("error").GetString());
    }

    [IntegrationFact]
    public async Task UnknownRoutes_StayBare() {
        using var missing = await _f.Client.GetAsync("/v1/nope");
        Assert.Equal(HttpStatusCode.NotFound, missing.StatusCode);
        Assert.Empty(await missing.Content.ReadAsByteArrayAsync());
        using var method = await _f.Client.DeleteAsync("/v1/messages/batch");
        Assert.Equal(HttpStatusCode.MethodNotAllowed, method.StatusCode);
        Assert.Empty(await method.Content.ReadAsByteArrayAsync());
    }

    private static readonly string[] Routes = [
        "/v1/info", "/v1/pow/challenge", "/v1/mailboxes", "/v1/mailboxes/verify", "/v1/mailboxes/endpoint",
        "/v1/mailboxes/refresh", "/v1/mailboxes/delete", "/v1/messages", "/v1/messages/batch", "/v1/invites",
        "/v1/invites/AAAAAAAAAAAAAAAAAAAAAA", "/v1/invites/", "/v1/nope", "/v1/info?x=1&y", "/v1/info/",
    ];

    private static readonly Gen<string> HeaderValue = Gen.OneOf(
        Gen.Const(""), Gen.Const("0"), Gen.Const("-1"), Gen.Const("4294967296"), Gen.Const("99999999999999999999"),
        Gen.Const(" 60"), Gen.Const("60 "), Gen.Const("+60"), Gen.Const("0x10"), Gen.Const("1e3"), Gen.Const("."),
        Gen.Const("a.b"), Gen.Const("..."), Gen.Const(Base64Url.EncodeToString(new byte[32]) + "." + Base64Url.EncodeToString(new byte[8])),
        Gen.Const(Base64Url.EncodeToString(new byte[32])), Gen.Const(Base64Url.EncodeToString(new byte[16])),
        Gen.Const(new string('A', 4096)), Gen.Const("application/octet-stream"), Gen.Const("application/json"),
        Gen.Const("application/octet-stream; x=\"\\\""), Gen.Const(";"),
        Gen.Char['!', '~'].Array[0, 64].Select(c => new string(c)));

    private static readonly Gen<KeyValuePair<string, string>> Header = Gen.Select(
        Gen.OneOf(Gen.Const("gf-send-token"), Gen.Const("gf-idempotency-key"), Gen.Const("gf-ttl"), Gen.Const("gf-pow"),
            Gen.Const("content-type"), Gen.Const("content-length"), Gen.Const("host"), Gen.Const("transfer-encoding"),
            Gen.Const("gf-x")),
        HeaderValue, (n, v) => new KeyValuePair<string, string>(n, v));

    private static readonly Gen<byte[]> InnerBody = Gen.Frequency(
        (3, Fuzz.Fuzz.Bytes(0, 64)),
        (2, Gen.Int[1, 40].SelectMany(n => Fuzz.Fuzz.Bytes(1, 80).Array[n]).Select(blobs => MessageBatch.Encode(
            blobs.Select(b => new BatchItem(new byte[32], new byte[16], null, b)).ToList()))
            .SelectMany(b => Gen.Frequency((1, Gen.Const(b)), (2, Fuzz.Fuzz.Mutate(b))))),
        (1, Gen.Int[3980, 4100].Select(n => new byte[n])),
        (1, Gen.Const(new byte[GatewayCodec.MaxRequestBody])));

    /// <summary>Valid gateway encodings of arbitrary inner requests, and mutated ones (exercising the codec's rejects).</summary>
    private static readonly Gen<byte[]> InnerPlaintext = Gen.Select(
            Gen.OneOf(Gen.Const("GET"), Gen.Const("POST"), Gen.Const("PUT"), Gen.Const("DELETE")),
            Gen.OneOf(Routes),
            Header.Array[0, 6],
            InnerBody,
            Gen.Long[-700, 700])
        .Select((method, path, headers, body, skew) => {
            var unique = headers.DistinctBy(h => h.Key).ToArray();
            try {
                return GatewayCodec.EncodeRequest(new InnerRequest(method, DateTimeOffset.UtcNow.ToUnixTimeSeconds() + skew, path, unique, body));
            } catch (ArgumentException) {
                return GatewayCodec.EncodeRequest(new InnerRequest(method, DateTimeOffset.UtcNow.ToUnixTimeSeconds(), path, [], []));
            }
        })
        .SelectMany(inner => Gen.Frequency((4, Gen.Const(inner)), (1, Fuzz.Fuzz.Mutate(inner, GatewayCodec.MaxInnerRequest))));

    [IntegrationFact]
    public async Task InnerRequests_GetEncryptedJsonAnswers() {
        var key = await KeyAsync();
        await Fuzz.Fuzz.RunAsync(InnerPlaintext, async inner => {
            var (outer, respSecret) = key.Seal(inner);
            using var response = await _f.RawClient.PostAsync("/v1/gw", Octets(outer));
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var sealedBody = await response.Content.ReadAsByteArrayAsync();
            var plaintext = GatewayCrypto.OpenResponse(respSecret, sealedBody);
            Assert.NotNull(plaintext);
            Assert.True(GatewayCodec.TryDecodeResponse(plaintext, out var decoded), "inner response must decode");
            AssertCleanInner(decoded.Status, decoded.Headers.FirstOrDefault(h => h.Key == "content-type").Value, decoded.Body);
        }, iterations: 400, print: Fuzz.Fuzz.Hex);
    }

    private static readonly Gen<(byte[] Body, string? Type)> OuterInput = Gen.Frequency(
        (3, Fuzz.Fuzz.Bytes(0, 2000).Select(b => (b, (string?)"application/octet-stream"))),
        (1, Gen.Int[GatewayMiddleware.MaxOuterBody - 2, GatewayMiddleware.MaxOuterBody + 2000].Select(n => (new byte[n], (string?)"application/octet-stream"))),
        (1, Fuzz.Fuzz.Bytes(0, 64).Select(b => (b, (string?)null))),
        (1, Fuzz.Fuzz.Bytes(0, 64).Select(b => (b, (string?)"text/plain"))));

    [IntegrationFact]
    public async Task OuterBodies_GetPlaintextErrorsOnly() {
        var key = await KeyAsync();
        var (valid, _) = key.Seal(GatewayCodec.EncodeRequest(new InnerRequest("GET", 0, "/v1/info", [], [])));
        var prefixed = Fuzz.Fuzz.Bytes(0, 20000).Select(tail => {
            var outer = new byte[GatewayCrypto.HeaderSize + tail.Length];
            outer[0] = GatewayCrypto.Version;
            key.KeyId.CopyTo(outer, 1);
            tail.CopyTo(outer, GatewayCrypto.HeaderSize);
            return (outer, (string?)"application/octet-stream");
        });
        var mutated = Fuzz.Fuzz.Mutate(valid, 22000).Select(b => (b, (string?)"application/octet-stream"));
        Gen<(byte[] Body, string? Type)> gen = Gen.Frequency((2, OuterInput), (2, prefixed), (3, mutated));
        await Fuzz.Fuzz.RunAsync(gen, async input => {
            var content = new ByteArrayContent(input.Body);
            if (input.Type is not null) {
                content.Headers.ContentType = MediaTypeHeaderValue.Parse(input.Type);
            }
            using var response = await _f.RawClient.PostAsync("/v1/gw", content);
            var status = (int)response.StatusCode;
            if (status == 200) {
                // A mutation that left the request intact, or one the old timestamp rejects: still encrypted.
                Assert.Equal("application/octet-stream", response.Content.Headers.ContentType?.MediaType);
                return;
            }
            Assert.Contains(status, new[] { 400, 413, 421 });
            var error = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement.GetProperty("error").GetString();
            Assert.Equal(status switch { 400 => "bad_request", 413 => "too_large", _ => "unknown_key" }, error);
        }, iterations: 300, print: i => $"{i.Type}: {Fuzz.Fuzz.Hex(i.Body)}");
    }

    private static async Task AssertCleanAnswer(HttpResponseMessage response) {
        AssertCleanInner((int)response.StatusCode, response.Content.Headers.ContentType?.ToString(), await response.Content.ReadAsByteArrayAsync());
    }

    private static void AssertCleanInner(int status, string? contentType, byte[] body) {
        Assert.True(status < 500 || status is 502 or 503 or 507, $"inner status {status}: {Encoding.UTF8.GetString(body)}");
        if (status is (404 or 405) && body.Length == 0) {
            // An unknown route or method: a bare answer from routing, which clients rely on (docs/groups.md, "Fallback").
            return;
        }
        if (status is >= 400) {
            Assert.StartsWith("application/json", contentType ?? "");
            var root = JsonDocument.Parse(body).RootElement;
            Assert.Equal(JsonValueKind.String, root.GetProperty("error").ValueKind);
        }
    }
}
