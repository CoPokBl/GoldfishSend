using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;
using CsCheck;
using GoldfishSend.Core.Crypto;
using GoldfishSend.Core.Protocol;

namespace GoldfishSend.Tests.Fuzz;

/// <summary>The other parsers of client-supplied bytes: batch sends, proof of work, Web Push keys, and stored records.</summary>
public sealed class CodecFuzzTests {
    // --- batch send (docs/groups.md, "Server: batch send") ---

    private static readonly Gen<byte[]> BatchItemBytes = Gen.Select(
        Fuzz.Bytes(48, 48),
        Gen.Frequency((6, Gen.UInt[0, 100_000]), (1, Gen.OneOf(0u, (uint)int.MaxValue, (uint)int.MaxValue + 1, uint.MaxValue))),
        Gen.Frequency((8, Gen.Int[1, 200]), (1, Gen.OneOf(0, 3982, 3983, 3984, 65535))),
        (head, ttl, length) => {
            var item = new byte[54 + Math.Min(length, 4000)];
            head.CopyTo(item, 0);
            BinaryPrimitives.WriteUInt32BigEndian(item.AsSpan(48), ttl);
            BinaryPrimitives.WriteUInt16BigEndian(item.AsSpan(52), (ushort)length);
            return item;
        });

    private static readonly Gen<byte[]> BatchBodies = Gen.Frequency(
        (5, Gen.Int[1, 8].SelectMany(n => BatchItemBytes.Array[n]).Select(items => (byte[])[(byte)items.Length, .. items.SelectMany(i => i)])),
        (1, Gen.Int[30, 34].SelectMany(n => BatchItemBytes.Array[n]).Select(items => (byte[])[(byte)items.Length, .. items.SelectMany(i => i)])),
        (1, Gen.Select(Gen.OneOf(0, 1, 2, 33, 255), BatchItemBytes.Array[0, 3])
            .Select((count, items) => (byte[])[(byte)count, .. items.SelectMany(i => i)])),
        (3, Gen.Int[1, 8].SelectMany(n => BatchItemBytes.Array[n]).Select(items => (byte[])[(byte)items.Length, .. items.SelectMany(i => i)])
            .SelectMany(b => Fuzz.Mutate(b, 20000))),
        (1, Fuzz.Bytes(0, 200)));

    /// <summary>Straight from the spec: count 1..32, each item 54 bytes of header and a 1..3983 byte blob, nothing left over.</summary>
    private static List<(byte[] Secret, byte[] Key, uint Ttl, byte[] Blob)>? SpecBatch(byte[] body) {
        if (body.Length == 0 || body[0] is 0 or > 32) {
            return null;
        }
        var items = new List<(byte[], byte[], uint, byte[])>();
        var at = 1;
        for (var i = 0; i < body[0]; i++) {
            if (body.Length - at < 54) {
                return null;
            }
            var length = BinaryPrimitives.ReadUInt16BigEndian(body.AsSpan(at + 52));
            if (length is 0 or > 3983 || body.Length - at - 54 < length) {
                return null;
            }
            items.Add((body[at..(at + 32)], body[(at + 32)..(at + 48)], BinaryPrimitives.ReadUInt32BigEndian(body.AsSpan(at + 48)),
                body[(at + 54)..(at + 54 + length)]));
            at += 54 + length;
        }
        return at == body.Length ? items : null;
    }

    [Fact]
    public void MessageBatch_ParsesExactlyTheSpec() {
        var accepted = 0;
        Fuzz.Run(BatchBodies, body => {
            var expected = SpecBatch(body);
            var actual = MessageBatch.TryParse(body);
            Assert.Equal(expected is not null, actual is not null);
            if (actual is null) {
                return;
            }
            Interlocked.Increment(ref accepted);
            Assert.Equal(expected!.Count, actual.Count);
            for (var i = 0; i < actual.Count; i++) {
                Assert.Equal(expected[i].Secret, actual[i].SendSecret);
                Assert.Equal(expected[i].Key, actual[i].IdempotencyKey);
                Assert.Equal(expected[i].Blob, actual[i].Blob);
                Assert.Equal(expected[i].Ttl == 0 ? null : (int)Math.Min(expected[i].Ttl, int.MaxValue), actual[i].TtlSeconds);
            }
            if (expected.All(i => i.Ttl <= int.MaxValue)) {
                Assert.Equal(body, MessageBatch.Encode(actual));
            }
        }, iterations: 4000, print: Fuzz.Hex);
        Fuzz.AssertMix(accepted, 4000);
    }

    // --- proof of work ---

    private static readonly Gen<(byte[] Challenge, byte[] Nonce, int Difficulty)> PowInputs = Gen.Select(
        Gen.Frequency((8, Fuzz.Bytes(32, 32)), (1, Fuzz.Bytes(0, 40))),
        Gen.Frequency((8, Fuzz.Bytes(8, 8)), (1, Fuzz.Bytes(0, 12))),
        Gen.Frequency((6, Gen.Int[0, 12]), (1, Gen.Int[-5, 50]), (1, Gen.OneOf(int.MinValue, int.MaxValue, 40, 41))),
        (c, n, d) => (c, n, d));

    [Fact]
    public void ProofOfWork_MatchesTheSpec() {
        Fuzz.Run(PowInputs, input => {
            var (challenge, nonce, difficulty) = input;
            var expected = false;
            if (challenge.Length == 32 && nonce.Length == 8 && difficulty is >= 0 and <= ProofOfWork.MaxDifficulty) {
                var hash = new BigInteger(SHA256.HashData([.. "gf/pow/v1"u8, .. challenge, .. nonce]), isUnsigned: true, isBigEndian: true);
                expected = difficulty == 0 || hash >> (256 - difficulty) == 0;
            }
            Assert.Equal(expected, ProofOfWork.Verify(challenge, nonce, difficulty));
        }, iterations: 20_000);
    }

    [Fact]
    public void LeadingZeroBits_MatchesBigInteger() {
        var gen = Gen.Select(Gen.Int[0, 32], Fuzz.Bytes(32, 32)).Select((zeros, hash) => {
            var copy = hash.ToArray();
            for (var i = 0; i < zeros && i < 32; i++) {
                copy[i] = i == zeros - 1 ? (byte)(copy[i] >> (copy[i] % 8)) : (byte)0;
            }
            return copy;
        });
        Fuzz.Run(gen, hash => {
            var value = new BigInteger(hash, isUnsigned: true, isBigEndian: true);
            var expected = value.IsZero ? 256 : 256 - (int)value.GetBitLength();
            Assert.Equal(expected, ProofOfWork.LeadingZeroBits(hash));
        }, iterations: 5000, print: Fuzz.Hex);
    }

    // --- Web Push keys (client-supplied p256dh and auth) ---

    private static readonly BigInteger P = BigInteger.Parse("0FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", System.Globalization.NumberStyles.HexNumber);
    private static readonly BigInteger B = BigInteger.Parse("05AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", System.Globalization.NumberStyles.HexNumber);

    private static BigInteger Rhs(BigInteger x) => BigInteger.Remainder(BigInteger.ModPow(x, 3, P) - 3 * x + B + 3 * P, P);

    /// <summary>An uncompressed point is valid iff it is 65 bytes, starts with 4, has x, y &lt; p and y² = x³ - 3x + b (mod p).</summary>
    private static bool SpecPoint(byte[] point) {
        if (point.Length != 65 || point[0] != 4) {
            return false;
        }
        var x = new BigInteger(point.AsSpan(1, 32), isUnsigned: true, isBigEndian: true);
        var y = new BigInteger(point.AsSpan(33, 32), isUnsigned: true, isBigEndian: true);
        return x < P && y < P && BigInteger.ModPow(y, 2, P) == Rhs(x);
    }

    private static byte[] Coordinate(BigInteger v) {
        var raw = v.ToByteArray(isUnsigned: true, isBigEndian: true);
        return [.. new byte[32 - raw.Length], .. raw];
    }

    /// <summary>A point with a small x (so x + p still fits 32 bytes), if x³ - 3x + b is a square.</summary>
    private static byte[]? SmallXPoint(BigInteger x, bool shift) {
        var rhs = Rhs(x);
        var y = BigInteger.ModPow(rhs, (P + 1) / 4, P);
        if (BigInteger.ModPow(y, 2, P) != rhs) {
            return null;
        }
        return [4, .. Coordinate(shift ? x + P : x), .. Coordinate(y)];
    }

    private static readonly Gen<byte[]> Points = Gen.Frequency(
        (3, Gen.Int[0, 3].Select(_ => {
            using var key = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            return WebPushCrypto.ExportPublicKey(key);
        }).SelectMany(p => Gen.Frequency((2, Gen.Const(p)), (2, Fuzz.Mutate(p, 70))))),
        (2, Gen.Select(Gen.ULong, Gen.Bool).Select((x, shift) => SmallXPoint(x, shift) ?? SmallXPoint(x + 1, shift) ?? SmallXPoint(x + 2, shift) ?? [4])),
        (1, Fuzz.Bytes(65, 65).Select(b => (byte[])[4, .. b[1..]])),
        (1, Fuzz.Bytes(0, 70)));

    [Fact]
    public void WebPushKeys_AreValidExactlyWhenOnTheCurve() {
        var accepted = 0;
        Fuzz.Run(Points, point => {
            var expected = SpecPoint(point);
            Assert.Equal(expected, WebPushCrypto.IsValidPublicKey(point));
            if (expected) {
                Interlocked.Increment(ref accepted);
            }
        }, iterations: 3000, print: Fuzz.Hex);
        Fuzz.AssertMix(accepted, 3000);
    }

    private static readonly Gen<(byte[] Plaintext, byte[] Auth)> PushInputs = Gen.Select(
        Gen.Frequency((6, Fuzz.Bytes(0, 200)), (1, Gen.OneOf(0, 3993, 3994, 5000).Select(n => new byte[n]))),
        Gen.Frequency((8, Fuzz.Bytes(16, 16)), (1, Fuzz.Bytes(0, 33))),
        (p, a) => (p, a));

    [Fact]
    public void WebPushEncryption_RoundTripsOrRefusesCleanly() {
        using var device = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var p256dh = WebPushCrypto.ExportPublicKey(device);
        Fuzz.Run(PushInputs, input => {
            var (plaintext, auth) = input;
            if (plaintext.Length > WebPushCrypto.MaxPlaintextSize || auth.Length != WebPushCrypto.AuthSecretSize) {
                Assert.Throws<ArgumentException>(() => WebPushCrypto.Encrypt(plaintext, p256dh, auth));
                return;
            }
            var message = WebPushCrypto.Encrypt(plaintext, p256dh, auth);
            Assert.True(message.Length <= WebPushCrypto.RecordSize);
            Assert.Equal(plaintext, WebPushCrypto.Decrypt(message, device, auth));
        }, iterations: 600);
    }

    // --- stored and pushed records ---

    [Fact]
    public void EndpointRecord_DeserializesOrThrowsFormatException() {
        var valid = Gen.Select(Gen.String[0, 100], Fuzz.Bytes(65, 65), Fuzz.Bytes(16, 16)).Select((u, k, a) => new EndpointRecord(u, k, a).Serialize());
        var gen = Gen.Frequency((2, valid), (3, valid.SelectMany(b => Fuzz.Mutate(b, 3000))), (1, Fuzz.Bytes(0, 100)));
        Fuzz.Run(gen, data => {
            EndpointRecord record;
            try {
                record = EndpointRecord.Deserialize(data);
            } catch (FormatException) {
                return;
            }
            Assert.Equal(65, record.P256dh.Length);
            Assert.Equal(16, record.Auth.Length);
        }, iterations: 3000, print: Fuzz.Hex);
    }

    [Fact]
    public void PushEnvelope_RoundTrips() {
        var gen = Gen.Frequency(
            (2, Gen.Select(Gen.OneOf(PushType.Message, PushType.Verification), Fuzz.Bytes(8, 8), Fuzz.Bytes(0, 300))
                .Select((t, tag, body) => PushEnvelope.Build(t, tag, body))),
            (2, Fuzz.Bytes(0, 40)));
        Fuzz.Run(gen, data => {
            if (PushEnvelope.TryParse(data, out var type, out var tag, out var body)) {
                Assert.Equal(data, PushEnvelope.Build(type, tag, body));
            } else {
                Assert.True(data.Length < PushEnvelope.HeaderSize || data[0] != PushEnvelope.Version || data[1] is not (1 or 2));
            }
        }, iterations: 2000, print: Fuzz.Hex);
    }
}
