using System.Text;
using CsCheck;
using GoldfishSend.Core.Crypto;
using GoldfishSend.Core.Protocol;
using GoldfishSend.Tests.Core;

namespace GoldfishSend.Tests.Fuzz;

/// <summary>
/// The gateway's pre-authentication input (the outer request), the response envelope, and the inner codec that only a
/// decrypted request reaches. The codec is compared against <see cref="SpecCodec"/>, an independent reading of the spec.
/// </summary>
public sealed class GatewayFuzzTests {
    private static readonly ServerKey Key = new(GatewayCryptoTests.TestSecret);
    private static readonly ServerPublicKey Client = ServerPublicKey.TryParse(Key.Blob, Key.Fingerprint)!;

    [Fact]
    public void InnerRequest_DecoderMatchesTheSpec() {
        var accepted = 0;
        Fuzz.Run(SpecCodec.RequestBytes, data => {
            var expected = SpecCodec.DecodeRequest(data);
            var ok = GatewayCodec.TryDecodeRequest(data, out var actual);
            Assert.Equal(expected is not null, ok);
            if (!ok) {
                return;
            }
            Interlocked.Increment(ref accepted);
            Assert.Equal(expected!.Method, Array.IndexOf(["", "GET", "POST", "PUT", "DELETE"], actual.Method));
            Assert.Equal((long)expected.Timestamp, actual.Timestamp);
            Assert.Equal(expected.Path, actual.Path);
            Assert.Equal(expected.Headers.Select(h => new KeyValuePair<string, string>(h.Name, h.Value)), actual.Headers);
            Assert.Equal(expected.Body, actual.Body);
            // Strict decoding means exactly one encoding per request: re-encoding gives back the input.
            Assert.Equal(data, GatewayCodec.EncodeRequest(actual));
        }, iterations: 6000, print: Fuzz.Hex);
        Fuzz.AssertMix(accepted, 6000);
    }

    [Fact]
    public void InnerResponse_DecoderMatchesTheSpec() {
        var accepted = 0;
        Fuzz.Run(SpecCodec.ResponseBytes, data => {
            var expected = SpecCodec.DecodeResponse(data);
            var ok = GatewayCodec.TryDecodeResponse(data, out var actual);
            Assert.Equal(expected is not null, ok);
            if (!ok) {
                return;
            }
            Interlocked.Increment(ref accepted);
            Assert.Equal(expected!.Status, actual.Status);
            Assert.Equal(expected.Headers.Select(h => new KeyValuePair<string, string>(h.Name, h.Value)), actual.Headers);
            Assert.Equal(expected.Body, actual.Body);
            Assert.Equal(data, GatewayCodec.EncodeResponse(actual));
        }, iterations: 6000, print: Fuzz.Hex);
        Fuzz.AssertMix(accepted, 6000);
    }

    private static readonly Gen<byte[]> ValidInner = SpecCodec.RawRequests.Select(SpecCodec.Encode)
        .Where(b => GatewayCodec.TryDecodeRequest(b, out _));

    private static readonly byte[][] SpecialPoints = [
        new byte[65],
        [0x04, .. new byte[64]],
        [0x02, .. new byte[32], .. new byte[32]],
        [0x04, .. Convert.FromHexString("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"), .. new byte[32]],
        [0x04, .. Enumerable.Repeat((byte)0xff, 64)],
        [0x04, .. Convert.FromHexString("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"),
            .. Convert.FromHexString("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5")],
    ];

    /// <summary>Outer bodies: garbage, truncations, foreign key ids, bad versions, bad P-256 points, and bit flips of real requests.</summary>
    private static readonly Gen<(byte[] Outer, byte[]? Original)> OuterBodies = Gen.Frequency(
        (2, Fuzz.Bytes(0, 3000).Select(b => (b, (byte[]?)null))),
        (2, Gen.Select(ValidInner, Gen.Int[0, 5]).Select((inner, which) => {
            var (outer, _) = Client.Seal(inner);
            return (outer, (byte[]?)outer);
        }).SelectMany(t => Fuzz.Mutate(t.outer, 20000).Select(m => (m, t.Item2)))),
        (1, Gen.Select(ValidInner, Gen.Int[0, SpecialPoints.Length - 1]).Select((inner, which) => {
            var (outer, _) = Client.Seal(inner);
            SpecialPoints[which].CopyTo(outer, GatewayCrypto.HeaderSize + GatewayCrypto.MlKemCiphertextSize);
            return (outer, (byte[]?)null);
        })),
        (1, Gen.Select(ValidInner, Gen.Int[-20, 20]).Select((inner, cut) => {
            var (outer, _) = Client.Seal(inner);
            var length = Math.Clamp(GatewayCrypto.RequestOverhead + cut, 0, outer.Length);
            return (outer[..length], (byte[]?)null);
        })));

    [Fact]
    public void OuterRequest_IsOpenedOnlyWhenIntact() {
        Fuzz.Run(OuterBodies, input => {
            var (outer, original) = input;
            var status = Key.TryOpenRequest(outer, out var inner, out var respSecret, out var enc);
            var keyIdMatches = outer.Length >= GatewayCrypto.HeaderSize && outer.AsSpan(1, 8).SequenceEqual(Key.KeyId);
            if (original is not null && outer.AsSpan().SequenceEqual(original)) {
                Assert.Equal(ServerKey.OpenStatus.Ok, status);
                Assert.Equal(32, respSecret.Length);
                Assert.Equal(GatewayCrypto.EncSize, enc.Length);
                Assert.Equal(outer.Length - GatewayCrypto.RequestOverhead, inner.Length);
                return;
            }
            var expected = outer.Length >= GatewayCrypto.RequestOverhead && outer[0] == GatewayCrypto.Version && !keyIdMatches
                ? ServerKey.OpenStatus.UnknownKey
                : ServerKey.OpenStatus.Malformed;
            Assert.Equal(expected, status);
            Assert.Empty(inner);
            Assert.Empty(respSecret);
        }, iterations: 1500, print: t => Fuzz.Hex(t.Outer));
    }

    private static readonly Gen<(byte[] Secret, byte[] Sealed, byte[] Inner, bool Intact)> SealedResponses =
        Gen.Select(Fuzz.Bytes(32, 32), SpecCodec.RawResponses.Select(SpecCodec.Encode), Gen.Int[0, 3])
            .SelectMany((secret, inner, kind) => {
                var sealedBody = GatewayCrypto.SealResponse(secret, inner);
                return kind switch {
                    0 => Gen.Const((secret, sealedBody, inner, true)),
                    1 => Fuzz.Bytes(0, 100).Select(b => (secret, b, inner, false)),
                    _ => Fuzz.Mutate(sealedBody, 30000).Select(m => (secret, m, inner, m.AsSpan().SequenceEqual(sealedBody))),
                };
            });

    [Fact]
    public void ResponseEnvelope_OpensOnlyWhenIntact() {
        Fuzz.Run(SealedResponses, input => {
            var opened = GatewayCrypto.OpenResponse(input.Secret, input.Sealed);
            if (input.Intact) {
                Assert.Equal(input.Inner, opened);
            } else {
                Assert.Null(opened);
            }
        }, iterations: 2000, print: t => Fuzz.Hex(t.Sealed));
    }

    [Fact]
    public void Padding_MatchesTheSpec() {
        Fuzz.Run(Gen.Frequency((3, Gen.Int[0, 70000]), (1, Gen.OneOf(0, 1, 511, 512, 513, 17407, 17408, 17409, 20480, 20481))), n => {
            Assert.Equal(SpecCodec.RequestBucket(n), GatewayCodec.PaddedRequestSize(n));
            Assert.Equal(SpecCodec.ResponseBucket(n), GatewayCodec.PaddedResponseSize(n));
        }, iterations: 2000);
    }

    [Fact]
    public void InnerRequest_ThatEncodes_Decodes() {
        var gen = Gen.Select(Gen.OneOf("GET", "POST", "PUT", "DELETE"), SpecCodec.Timestamp, SpecCodec.PathBytes,
            SpecCodec.HeaderBytes.Array[0, 5], Gen.Byte.Array[0, 400]);
        Fuzz.Run(gen, t => {
            var (method, ts, path, headers, body) = t;
            var request = new InnerRequest(method, (long)ts, Encoding.UTF8.GetString(path),
                headers.Select(h => new KeyValuePair<string, string>(Encoding.UTF8.GetString(h.Item1), Encoding.UTF8.GetString(h.Item2))).ToList(), body);
            byte[] encoded;
            try {
                encoded = GatewayCodec.EncodeRequest(request);
            } catch (ArgumentException) {
                return;
            }
            if (GatewayCodec.TryDecodeRequest(encoded, out var decoded)) {
                Assert.Equal(request.Path, decoded.Path);
                Assert.Equal(request.Body, decoded.Body);
                Assert.Equal(request.Headers, decoded.Headers);
            }
        }, iterations: 3000);
    }
}
