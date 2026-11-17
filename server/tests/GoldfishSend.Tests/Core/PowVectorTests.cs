using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using GoldfishSend.Core.Crypto;

namespace GoldfishSend.Tests.Core;

/// <summary>
/// <c>docs/test-vectors/pow-v2.json</c>: Argon2id proof-of-work vectors (docs/protocol.md). The app's <c>PowVectorsTest</c>
/// checks the same file with BouncyCastle for Java. <c>GF_WRITE_VECTORS=1</c> regenerates it (deterministically).
/// </summary>
public sealed class PowVectorTests {
    private const string FileName = "pow-v2.json";

    private static JsonObject Load() {
        var path = Path.Combine(GatewayVectorTests.VectorDir, FileName);
        if (Environment.GetEnvironmentVariable("GF_WRITE_VECTORS") == "1") {
            File.WriteAllText(path, Generate().ToJsonString(new JsonSerializerOptions {
                WriteIndented = true,
                Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            }) + "\n");
        }
        Assert.True(File.Exists(path), $"Run the tests once with GF_WRITE_VECTORS=1 to create docs/test-vectors/{FileName}.");
        return JsonNode.Parse(File.ReadAllText(path))!.AsObject();
    }

    [Fact]
    public void Hashes_MatchTheServer() {
        var root = Load();
        Assert.Equal(ProofOfWork.Scheme, root["scheme"]!.GetValue<string>());
        var hashes = root["hashes"]!.AsArray();
        Assert.True(hashes.Count >= 10);
        foreach (var v in hashes) {
            var challenge = Convert.FromHexString(v!["challenge"]!.GetValue<string>());
            var nonce = Convert.FromHexString(v["nonce"]!.GetValue<string>());
            var m = v["memoryKiB"]!.GetValue<int>();
            var t = v["iterations"]!.GetValue<int>();
            var hash = ProofOfWork.Hash(challenge, nonce, m, t);
            Assert.Equal(v["hash"]!.GetValue<string>(), Convert.ToHexStringLower(hash));
            var zeros = v["leadingZeroBits"]!.GetValue<int>();
            Assert.Equal(zeros, ProofOfWork.LeadingZeroBits(hash));
            Assert.True(ProofOfWork.Verify(challenge, nonce, new PowParameters(Math.Min(zeros, ProofOfWork.MaxDifficulty), m, t)));
            Assert.False(ProofOfWork.Verify(challenge, nonce, new PowParameters(zeros + 1, m, t)));
        }
    }

    [Fact]
    public void Solutions_AreTheFirstNonceFromZero() {
        foreach (var v in Load()["solutions"]!.AsArray()) {
            var challenge = Convert.FromHexString(v!["challenge"]!.GetValue<string>());
            var p = new PowParameters(v["difficulty"]!.GetValue<int>(), v["memoryKiB"]!.GetValue<int>(), v["iterations"]!.GetValue<int>());
            Assert.Equal(v["nonce"]!.GetValue<string>(), Convert.ToHexStringLower(ProofOfWork.Solve(challenge, p)));
        }
    }

    private static byte[] Challenge(int i) => SHA256.HashData(Encoding.UTF8.GetBytes($"gf/pow/v2 test vector {i}"));

    private static byte[] Nonce(ulong n) {
        var nonce = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(nonce, n);
        return nonce;
    }

    private static JsonObject Generate() {
        var cases = new List<(byte[] Challenge, byte[] Nonce, int M, int T)> {
            (new byte[32], new byte[8], 8, 1),
            (Enumerable.Range(0, 32).Select(i => (byte)i).ToArray(), Nonce(0x0102030405060708), 64, 1),
            (Enumerable.Repeat((byte)0xff, 32).ToArray(), Enumerable.Repeat((byte)0xff, 8).ToArray(), 64, 1),
            (Challenge(0), Nonce(0), 64, 2),
            (Challenge(1), Nonce(1), 1024, 1),
            (Challenge(2), Nonce(2), 1024, 3),
            (Challenge(3), Nonce(0), 16 * 1024, 1),
            (Challenge(4), Nonce(41), 16 * 1024, 1),
        };
        // Solutions with many leading zeros, so the verdict at each difficulty is exercised beyond 0 and 1.
        for (var i = 0; i < 4; i++) {
            var challenge = Challenge(10 + i);
            cases.Add((challenge, ProofOfWork.Solve(challenge, new PowParameters(4 + i, 64, 1)), 64, 1));
        }

        var hashes = new JsonArray();
        foreach (var (challenge, nonce, m, t) in cases) {
            var hash = ProofOfWork.Hash(challenge, nonce, m, t);
            hashes.Add(new JsonObject {
                ["challenge"] = Convert.ToHexStringLower(challenge),
                ["nonce"] = Convert.ToHexStringLower(nonce),
                ["memoryKiB"] = m,
                ["iterations"] = t,
                ["hash"] = Convert.ToHexStringLower(hash),
                ["leadingZeroBits"] = ProofOfWork.LeadingZeroBits(hash),
            });
        }

        var solutions = new JsonArray();
        foreach (var (i, p) in new[] { (20, new PowParameters(3, 64, 1)), (21, new PowParameters(6, 64, 1)), (22, new PowParameters(4, 256, 2)) }) {
            var challenge = Challenge(i);
            solutions.Add(new JsonObject {
                ["challenge"] = Convert.ToHexStringLower(challenge),
                ["difficulty"] = p.Difficulty,
                ["memoryKiB"] = p.MemoryKiB,
                ["iterations"] = p.Iterations,
                ["nonce"] = Convert.ToHexStringLower(ProofOfWork.Solve(challenge, p)),
            });
        }

        return new JsonObject {
            ["comment"] = "Generated by server/tests/GoldfishSend.Tests/Core/PowVectorTests.cs (GF_WRITE_VECTORS=1). " +
                "hash = Argon2id(password = \"gf/pow/v2\" || challenge || nonce, salt = challenge, m = memoryKiB, t = iterations, " +
                "p = 1, 32 bytes, version 0x13). A nonce meets difficulty d when leadingZeroBits >= d. A solution is the first " +
                "nonce, counting up from 0 (8 bytes big-endian), that meets the difficulty.",
            ["scheme"] = ProofOfWork.Scheme,
            ["hashes"] = hashes,
            ["solutions"] = solutions,
        };
    }
}
