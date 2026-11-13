using System.Buffers.Text;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using GoldfishSend.Core.Crypto;
using GoldfishSend.Core.Protocol;

namespace GoldfishSend.Tests.Core;

/// <summary>
/// Cross-implementation vectors for the gateway (docs/protocol.md, "Interop vectors"). This side writes
/// <c>gateway-server.json</c> (with <c>GF_WRITE_VECTORS=1</c>) and checks the app's <c>gateway-client.json</c>.
/// </summary>
public sealed class GatewayVectorTests {
    private const long Timestamp = 1_700_000_000;

    public static string VectorDir {
        get {
            var dir = new DirectoryInfo(AppContext.BaseDirectory);
            while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "docs", "protocol.md"))) {
                dir = dir.Parent;
            }
            return Path.Combine(dir?.FullName ?? throw new DirectoryNotFoundException("docs/protocol.md not found"), "docs", "test-vectors");
        }
    }

    public sealed class ClientVectorsFactAttribute : FactAttribute {
        public ClientVectorsFactAttribute() {
            if (!File.Exists(Path.Combine(VectorDir, "gateway-client.json"))) {
                Skip = "docs/test-vectors/gateway-client.json isn't there yet (the app's tests write it).";
            }
        }
    }

    [Fact]
    public void ServerVectors_AreValid() {
        var path = Path.Combine(VectorDir, "gateway-server.json");
        if (Environment.GetEnvironmentVariable("GF_WRITE_VECTORS") == "1") {
            Directory.CreateDirectory(VectorDir);
            File.WriteAllText(path, Generate());
        }
        Assert.True(File.Exists(path), "Run the tests once with GF_WRITE_VECTORS=1 to create docs/test-vectors/gateway-server.json.");
        Verify(File.ReadAllText(path), expectedExchanges: 3);
    }

    [ClientVectorsFact]
    public void ClientVectors_DecryptHere() {
        Verify(File.ReadAllText(Path.Combine(VectorDir, "gateway-client.json")), expectedExchanges: 1);
    }

    private static void Verify(string json, int expectedExchanges) {
        var root = JsonNode.Parse(json)!.AsObject();
        var secret = Base64Url.DecodeFromChars(root["serverKey"]!.GetValue<string>());
        Assert.Equal(GatewayCryptoTests.TestSecret, secret);
        var key = new ServerKey(secret);
        Assert.Equal(Convert.ToHexStringLower(key.Blob), root["blob"]!.GetValue<string>().ToLowerInvariant());
        Assert.Equal(key.FingerprintBase64Url, root["fp"]!.GetValue<string>());

        var exchanges = root["exchanges"]!.AsArray();
        Assert.True(exchanges.Count >= expectedExchanges, $"expected at least {expectedExchanges} exchanges");
        foreach (var exchange in exchanges) {
            var innerRequest = Convert.FromHexString(exchange!["innerRequest"]!.GetValue<string>());
            var outerRequest = Convert.FromHexString(exchange["outerRequest"]!.GetValue<string>());
            var innerResponse = Convert.FromHexString(exchange["innerResponse"]!.GetValue<string>());
            var outerResponse = Convert.FromHexString(exchange["outerResponse"]!.GetValue<string>());

            Assert.Equal(ServerKey.OpenStatus.Ok, key.TryOpenRequest(outerRequest, out var opened, out var respSecret, out _));
            Assert.Equal(innerRequest, opened);
            Assert.True(GatewayCodec.TryDecodeRequest(innerRequest, out _), "innerRequest must decode (and be padded exactly)");

            Assert.Equal(innerResponse, GatewayCrypto.OpenResponse(respSecret, outerResponse));
            Assert.True(GatewayCodec.TryDecodeResponse(innerResponse, out _), "innerResponse must decode (and be padded exactly)");
        }
    }

    private static string Generate() {
        var key = new ServerKey(GatewayCryptoTests.TestSecret);
        var client = ServerPublicKey.TryParse(key.Blob, key.Fingerprint)!;
        var body = Enumerable.Range(0, 4000).Select(i => (byte)(i % 251)).ToArray();
        var exchanges = new (InnerRequest Request, InnerResponse Response)[] {
            (new("GET", Timestamp, "/v1/info", [], []),
                new(200, [new("content-type", "application/json; charset=utf-8")], Encoding.UTF8.GetBytes(
                    "{\"protocol\":2,\"vapidPublicKey\":\"BOq6G0Vz8fyKkNN1Y8xFbq5HAbsvsHZ4kfl1Dp6uCzh_Q8-GrlIjFhGq_d0Nf1E8lkTMQy6h1Ovh9_OCu9J7p1A\"," +
                    "\"maxMessageBytes\":3983,\"maxInviteBytes\":4096,\"defaultTtlSeconds\":259200,\"maxTtlSeconds\":1209600,\"powDifficulty\":20}"))),
            (new("POST", Timestamp, "/v1/messages", [
                    new("gf-send-token", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"),
                    new("gf-idempotency-key", "AAECAwQFBgcICQoLDA0ODw"),
                    new("gf-ttl", "86400"),
                    new("content-type", "application/octet-stream"),
                ], body),
                new(202, [new("content-type", "application/json; charset=utf-8")], "{\"id\":\"AAECAwQFBgcICQoLDA0ODw\"}"u8.ToArray())),
            (new("POST", Timestamp, "/v1/pow/challenge", [], []),
                new(429, [new("content-type", "application/json; charset=utf-8"), new("retry-after", "30")],
                    "{\"error\":\"rate_limited\",\"scope\":\"ip\"}"u8.ToArray())),
        };

        var array = new JsonArray();
        foreach (var (request, response) in exchanges) {
            var innerRequest = GatewayCodec.EncodeRequest(request);
            var (outerRequest, _) = client.Seal(innerRequest);
            Assert.Equal(ServerKey.OpenStatus.Ok, key.TryOpenRequest(outerRequest, out _, out var respSecret, out _));
            var innerResponse = GatewayCodec.EncodeResponse(response);
            var outerResponse = GatewayCrypto.SealResponse(respSecret, innerResponse);
            array.Add(new JsonObject {
                ["innerRequest"] = Convert.ToHexStringLower(innerRequest),
                ["outerRequest"] = Convert.ToHexStringLower(outerRequest),
                ["innerResponse"] = Convert.ToHexStringLower(innerResponse),
                ["outerResponse"] = Convert.ToHexStringLower(outerResponse),
            });
        }
        var root = new JsonObject {
            ["serverKey"] = Base64Url.EncodeToString(GatewayCryptoTests.TestSecret),
            ["blob"] = Convert.ToHexStringLower(key.Blob),
            ["fp"] = key.FingerprintBase64Url,
            ["exchanges"] = array,
        };
        return root.ToJsonString(new JsonSerializerOptions { WriteIndented = true }) + "\n";
    }
}
