using System.Buffers.Text;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using CsCheck;
using GoldfishSend.Core.Crypto;
using GoldfishSend.Core.Protocol;
using GoldfishSend.Tests.Core;

namespace GoldfishSend.Tests.Fuzz;

/// <summary>
/// <c>docs/test-vectors/gateway-codec-fuzz.json</c>: generated, seeded cases for everything the app and the server both
/// implement (the inner codec and its padding, the response envelope, the key blob and its fingerprints, proof of work),
/// with the server's verdict on each. The app's <c>GatewayCodecFuzzVectorsTest</c> checks it gets the same answers.
/// <c>GF_WRITE_VECTORS=1</c> regenerates the file (from a fixed seed, so it only changes when the generators or the
/// verdicts do). Either way, every case in the committed file is checked against the server's implementation.
/// </summary>
public sealed class GatewayCodecVectorTests {
    private const string FileName = "gateway-codec-fuzz.json";
    private const uint Stream = 0x9f5e_c0de;

    [Fact]
    public void FuzzVectors_MatchTheServer() {
        var path = Path.Combine(GatewayVectorTests.VectorDir, FileName);
        if (Environment.GetEnvironmentVariable("GF_WRITE_VECTORS") == "1") {
            File.WriteAllText(path, OneCasePerLine(Generate()));
        }
        Assert.True(File.Exists(path), $"Run the tests once with GF_WRITE_VECTORS=1 to create docs/test-vectors/{FileName}.");
        Verify(JsonNode.Parse(File.ReadAllText(path))!.AsObject());
    }

    private static void Verify(JsonObject root) {
        foreach (var v in root["requests"]!.AsArray()) {
            var data = Bytes(v!["data"]!);
            var ok = GatewayCodec.TryDecodeRequest(data, out var request);
            Assert.True(ok == v["ok"]!.GetValue<bool>(), $"request {v["data"]!.ToJsonString()}");
            if (ok) {
                Assert.Equal(v["method"]!.GetValue<int>(), MethodCode(request.Method));
                Assert.Equal(v["timestamp"]!.GetValue<long>(), request.Timestamp);
                Assert.Equal(v["path"]!.GetValue<string>(), request.Path);
                Assert.Equal(Headers(v["headers"]!), request.Headers);
                Assert.Equal(Bytes(v["body"]!), request.Body);
            }
        }
        foreach (var v in root["responses"]!.AsArray()) {
            var data = Bytes(v!["data"]!);
            var ok = GatewayCodec.TryDecodeResponse(data, out var response);
            Assert.True(ok == v["ok"]!.GetValue<bool>(), $"response {v["data"]!.ToJsonString()}");
            if (ok) {
                Assert.Equal(v["status"]!.GetValue<int>(), response.Status);
                Assert.Equal(Headers(v["headers"]!), response.Headers);
                Assert.Equal(Bytes(v["body"]!), response.Body);
            }
        }
        foreach (var v in root["encodeRequests"]!.AsArray()) {
            var encoded = TryEncode(v!["method"]!.GetValue<string>(), v["timestamp"]!.GetValue<long>(), v["path"]!.GetValue<string>(),
                Headers(v["headers"]!), Bytes(v["body"]!));
            Assert.True((encoded is not null) == v["ok"]!.GetValue<bool>(), $"encode {v.ToJsonString()[..Math.Min(300, v.ToJsonString().Length)]}");
            if (encoded is not null) {
                Assert.Equal(Bytes(v["data"]!), encoded);
            }
        }
        foreach (var v in root["padding"]!.AsArray()) {
            var n = v!["n"]!.GetValue<int>();
            Assert.Equal(v["request"]!.GetValue<int>(), GatewayCodec.PaddedRequestSize(n));
            Assert.Equal(v["response"]!.GetValue<int>(), GatewayCodec.PaddedResponseSize(n));
        }
        foreach (var v in root["blobs"]!.AsArray()) {
            var blob = Convert.FromHexString(v!["blob"]!.GetValue<string>());
            var key = ServerPublicKey.TryParse(blob);
            Assert.True((key is not null) == v["ok"]!.GetValue<bool>(), $"blob {v["why"]}");
            var fp = GatewayCrypto.Fingerprint(blob);
            Assert.Equal(v["fp"]!.GetValue<string>(), Base64Url.EncodeToString(fp));
            Assert.Equal(v["keyId"]!.GetValue<string>(), Convert.ToHexStringLower(fp[..8]));
            Assert.Equal(v["display"]!.GetValue<string>(), GatewayCrypto.DisplayFingerprint(fp));
        }
        foreach (var v in root["envelopes"]!.AsArray()) {
            var opened = GatewayCrypto.OpenResponse(Convert.FromHexString(v!["respSecret"]!.GetValue<string>()),
                Convert.FromHexString(v["sealed"]!.GetValue<string>()));
            Assert.True((opened is not null) == v["ok"]!.GetValue<bool>());
            if (opened is not null) {
                Assert.Equal(v["inner"]!.GetValue<string>(), Convert.ToHexStringLower(opened));
            }
        }
        foreach (var v in root["pow"]!.AsArray()) {
            Assert.Equal(v!["ok"]!.GetValue<bool>(), ProofOfWork.Verify(Convert.FromHexString(v["challenge"]!.GetValue<string>()),
                Convert.FromHexString(v["nonce"]!.GetValue<string>()), v["difficulty"]!.GetValue<int>()));
        }
    }

    private static T[] Cases<T>(Gen<T> gen, int count, ulong offset) =>
        Enumerable.Range(0, count).Select(i => gen.Generate(new PCG(Stream, offset + (ulong)i), null!, out _)).ToArray();

    /// <summary>Keeps the file small: cases whose stored form is large are dropped, except the first few.</summary>
    private static T[] SmallCases<T>(Gen<T> gen, int count, ulong offset, Func<T, int> storedSize, int allowLarge = 4) {
        var cases = new List<T>();
        for (var i = 0UL; cases.Count < count; i++) {
            var value = gen.Generate(new PCG(Stream, offset + i), null!, out _);
            if (storedSize(value) > 300 && allowLarge-- <= 0) {
                continue;
            }
            cases.Add(value);
        }
        return [.. cases];
    }

    private static string OneCasePerLine(JsonObject root) {
        var sb = new StringBuilder("{\n");
        var first = true;
        foreach (var (name, value) in root) {
            sb.Append(first ? "" : ",\n").Append("  ").Append(JsonSerializer.Serialize(name)).Append(": ");
            first = false;
            if (value is JsonArray array) {
                sb.Append("[\n    ").AppendJoin(",\n    ", array.Select(c => c!.ToJsonString())).Append("\n  ]");
            } else {
                sb.Append(value!.ToJsonString());
            }
        }
        return sb.Append("\n}\n").ToString();
    }

    private static int Stored(byte[] data) {
        var end = data.Length;
        while (end > 0 && data[end - 1] == 0) {
            end--;
        }
        return end;
    }

    private static JsonObject Generate() {
        var requests = new JsonArray();
        foreach (var data in SmallCases(SpecCodec.RequestBytes, 300, 0, Stored)) {
            var expected = SpecCodec.DecodeRequest(data);
            var v = new JsonObject { ["data"] = Bytes(data), ["ok"] = expected is not null };
            if (expected is not null) {
                v["method"] = expected.Method;
                v["timestamp"] = (long)expected.Timestamp;
                v["path"] = expected.Path;
                v["headers"] = Headers(expected.Headers);
                v["body"] = Bytes(expected.Body);
            } else {
                v["why"] = SpecCodec.Why;
            }
            requests.Add(v);
        }

        var responses = new JsonArray();
        foreach (var data in SmallCases(SpecCodec.ResponseBytes, 250, 100_000, Stored)) {
            var expected = SpecCodec.DecodeResponse(data);
            var v = new JsonObject { ["data"] = Bytes(data), ["ok"] = expected is not null };
            if (expected is not null) {
                v["status"] = expected.Status;
                v["headers"] = Headers(expected.Headers);
                v["body"] = Bytes(expected.Body);
            } else {
                v["why"] = SpecCodec.Why;
            }
            responses.Add(v);
        }

        var encodes = new JsonArray();
        foreach (var (method, timestamp, path, headers, body) in SmallCases(EncodeInputs, 200, 200_000,
            t => Encoding.UTF8.GetByteCount(t.Item3) + t.Item4.Sum(h => h.Key.Length + h.Value.Length) + Stored(t.Item5))) {
            var encoded = TryEncode(method, timestamp, path, headers, body);
            var v = new JsonObject {
                ["method"] = method,
                ["timestamp"] = timestamp,
                ["path"] = path,
                ["headers"] = Headers(headers.Select(h => (h.Key, h.Value)).ToArray()),
                ["body"] = Bytes(body),
                ["ok"] = encoded is not null,
            };
            if (encoded is not null) {
                v["data"] = Bytes(encoded);
            }
            encodes.Add(v);
        }

        var padding = new JsonArray();
        int[] edges = [0, 1, 511, 512, 513, 1023, 1024, 1025, 2048, 2049, 4096, 4097, 8192, 8193, 17407, 17408, 17409, 20480, 20481, 65536];
        foreach (var n in edges.Concat(Cases(Gen.Int[0, 70_000], 40, 300_000))) {
            padding.Add(new JsonObject {
                ["n"] = n,
                ["request"] = GatewayCodec.PaddedRequestSize(n),
                ["response"] = GatewayCodec.PaddedResponseSize(n),
            });
        }

        var blobs = new JsonArray();
        foreach (var (blob, why) in Blobs()) {
            var fp = GatewayCrypto.Fingerprint(blob);
            blobs.Add(new JsonObject {
                ["why"] = why,
                ["blob"] = Convert.ToHexStringLower(blob),
                ["ok"] = ServerPublicKey.TryParse(blob) is not null,
                ["fp"] = Base64Url.EncodeToString(fp),
                ["keyId"] = Convert.ToHexStringLower(fp[..8]),
                ["display"] = GatewayCrypto.DisplayFingerprint(fp),
            });
        }

        var envelopes = new JsonArray();
        foreach (var (secret, sealedBody) in SmallCases(Envelopes, 30, 400_000, t => t.Item2.Length)) {
            var opened = GatewayCrypto.OpenResponse(secret, sealedBody);
            var v = new JsonObject {
                ["respSecret"] = Convert.ToHexStringLower(secret),
                ["sealed"] = Convert.ToHexStringLower(sealedBody),
                ["ok"] = opened is not null,
            };
            if (opened is not null) {
                v["inner"] = Convert.ToHexStringLower(opened);
            }
            envelopes.Add(v);
        }

        var pow = new JsonArray();
        foreach (var (challenge, nonce, difficulty) in Cases(PowCases, 60, 500_000)) {
            pow.Add(new JsonObject {
                ["challenge"] = Convert.ToHexStringLower(challenge),
                ["nonce"] = Convert.ToHexStringLower(nonce),
                ["difficulty"] = difficulty,
                ["ok"] = ProofOfWork.Verify(challenge, nonce, difficulty),
            });
        }

        return new JsonObject {
            ["comment"] = "Generated by server/tests/GoldfishSend.Tests/Fuzz/GatewayCodecVectorTests.cs (GF_WRITE_VECTORS=1). " +
                "A byte string is {hex, len}: hex followed by zero bytes up to len. ok is the server's verdict; why says what is wrong.",
            ["requests"] = requests,
            ["responses"] = responses,
            ["encodeRequests"] = encodes,
            ["padding"] = padding,
            ["blobs"] = blobs,
            ["envelopes"] = envelopes,
            ["pow"] = pow,
        };
    }

    /// <summary>Inputs to a client's request encoder. Header names have no uppercase letters: the app lowercases names.</summary>
    private static readonly Gen<(string, long, string, KeyValuePair<string, string>[], byte[])> EncodeInputs = Gen.Select(
        Gen.Frequency((10, Gen.OneOf("GET", "POST", "PUT", "DELETE")), (1, Gen.OneOf("PATCH", "get", "", "HEAD"))),
        Gen.Frequency((10, Gen.Long[1_600_000_000, 1_900_000_000]), (1, Gen.OneOf(0L, -1L, long.MinValue, long.MaxValue))),
        SpecCodec.PathBytes.Select(Encoding.UTF8.GetString),
        SpecCodec.HeaderBytes.Select(h => new KeyValuePair<string, string>(Encoding.UTF8.GetString(h.Item1), Encoding.UTF8.GetString(h.Item2)))
            .Where(h => !h.Key.Any(char.IsAsciiLetterUpper)).Array[0, 4],
        Gen.Frequency((10, Gen.Byte.Array[0, 200]), (1, Gen.OneOf(16384, 16385, 17300, 17400).Select(n => new byte[n]))));

    private static readonly Gen<(byte[], byte[])> Envelopes = Gen.Select(Fuzz.Bytes(32, 32), Fuzz.Bytes(32, 32),
            SpecCodec.RawResponses.Where(r => r.Body.Length < 2000).Select(SpecCodec.Encode), Gen.Int[0, 3])
        .SelectMany((secret, nonce, inner, kind) => {
            var sealedBody = GatewayCrypto.SealResponse(secret, inner, nonce);
            return kind switch {
                0 => Gen.Const((secret, sealedBody)),
                1 => Fuzz.Bytes(0, 60).Select(b => (secret, b)),
                _ => Fuzz.Mutate(sealedBody, 3000).Select(m => (secret, m)),
            };
        });

    private static readonly Gen<(byte[], byte[], int)> PowCases = Gen.Select(Fuzz.Bytes(32, 32), Gen.Int[0, 10], Gen.Int[0, 40])
        .Select((challenge, solveAt, difficulty) => {
            var nonce = ProofOfWork.Solve(challenge, solveAt);
            return (challenge, nonce, difficulty % 3 == 0 ? solveAt + difficulty % 2 : difficulty);
        });

    private static IEnumerable<(byte[] Blob, string Why)> Blobs() {
        var test = new ServerKey(GatewayCryptoTests.TestSecret).Blob;
        yield return (test, "the test key");
        for (var i = 0; i < 3; i++) {
            var secret = Cases(Fuzz.Bytes(96, 96), 1, 600_000 + (ulong)i)[0];
            if (GatewayCrypto.IsValidScalar(secret.AsSpan(64))) {
                yield return (new ServerKey(secret).Blob, "a random key");
            }
        }
        const int point = 1 + GatewayCrypto.MlKemPublicSize;
        yield return (With(test, 0, 0x00), "version 0");
        yield return (With(test, 0, 0x02), "version 2");
        yield return (test[..^1], "one byte short");
        yield return ([.. test, 0], "one byte long");
        yield return (new byte[GatewayCrypto.BlobSize], "all zeros");
        yield return (With(test, point, 0x02), "compressed point prefix");
        yield return (With(test, point, 0x00), "point prefix 0x00");
        yield return (With(test, test.Length - 1, (byte)(test[^1] ^ 1)), "point not on the curve");
        byte[] p = Convert.FromHexString("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
        yield return ([.. test[..(point + 1)], .. p, .. test[(point + 33)..]], "x = p");
        yield return ([.. test[..(point + 1)], .. new byte[64]], "x = y = 0");
        // ML-KEM-768 encapsulation key: 12-bit coefficients must be below q = 3329 (FIPS 203, 7.2 modulus check).
        var coefficient = test.ToArray();
        coefficient[1] = 0xff;
        coefficient[2] |= 0x0f;
        yield return (coefficient, "ML-KEM coefficient 4095");
        var q = test.ToArray();
        q[1] = 0x01;
        q[2] = (byte)((q[2] & 0xf0) | 0x0d);
        yield return (q, "ML-KEM coefficient 3329 (= q)");
        var below = test.ToArray();
        below[1] = 0x00;
        below[2] = (byte)((below[2] & 0xf0) | 0x0d);
        yield return (below, "ML-KEM coefficient 3328 (q - 1)");
        var rho = test.ToArray();
        rho[GatewayCrypto.MlKemPublicSize] ^= 0xff;
        yield return (rho, "ML-KEM rho changed (still a valid key)");
    }

    private static byte[] With(byte[] data, int index, byte value) {
        var copy = data.ToArray();
        copy[index] = value;
        return copy;
    }

    private static byte[]? TryEncode(string method, long timestamp, string path, IReadOnlyList<KeyValuePair<string, string>> headers, byte[] body) {
        try {
            var encoded = GatewayCodec.EncodeRequest(new InnerRequest(method, timestamp, path, headers, body));
            return GatewayCodec.TryDecodeRequest(encoded, out _) ? encoded : null;
        } catch (ArgumentException) {
            return null;
        }
    }

    private static int MethodCode(string method) => Array.IndexOf(["", "GET", "POST", "PUT", "DELETE"], method);

    private static JsonObject Bytes(byte[] data) =>
        new() { ["hex"] = Convert.ToHexStringLower(data[..Stored(data)]), ["len"] = data.Length };

    private static byte[] Bytes(JsonNode node) {
        var hex = Convert.FromHexString(node["hex"]!.GetValue<string>());
        var data = new byte[node["len"]!.GetValue<int>()];
        hex.CopyTo(data, 0);
        return data;
    }

    private static JsonArray Headers((string Name, string Value)[] headers) =>
        new([.. headers.Select(h => (JsonNode)new JsonArray(h.Name, h.Value))]);

    private static List<KeyValuePair<string, string>> Headers(JsonNode node) =>
        node.AsArray().Select(h => new KeyValuePair<string, string>(h![0]!.GetValue<string>(), h[1]!.GetValue<string>())).ToList();
}
