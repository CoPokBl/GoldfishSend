using System.Security.Cryptography;
using GoldfishSend.Api;
using GoldfishSend.Core.Crypto;
using GoldfishSend.Core.Options;
using GoldfishSend.Core.Protocol;
using GoldfishSend.Infrastructure.Redis;
using GoldfishSend.Infrastructure.Services;

namespace GoldfishSend.Tests.Core;

public sealed class InMemoryGcraTests {
    private static readonly RatePolicy Narrow = new(1, 3600, 1);
    private static readonly RatePolicy Wide = new(3, 3600, 3);

    [Fact]
    public void CheckAll_RefusedByANarrowScope_DoesNotChargeTheWideOne() {
        var gcra = new InMemoryGcra();
        InMemoryGcra.Scope[] From(string ip) => [new("global", Wide, 1, "global"), new(ip, Narrow, 1, "ip")];

        Assert.True(gcra.CheckAll(From("a")).Allowed);
        for (var i = 0; i < 10; i++) {
            var refused = gcra.CheckAll(From("a"));
            Assert.False(refused.Allowed);
            Assert.Equal("ip", refused.Policy);
        }
        // The shared budget still has two of its three tokens.
        Assert.True(gcra.CheckAll(From("b")).Allowed);
        Assert.True(gcra.CheckAll(From("c")).Allowed);
        Assert.Equal("global", gcra.CheckAll(From("d")).Policy);
    }

    [Fact]
    public void CheckAll_PeekNeedsRoom_ButChargesNothing() {
        var gcra = new InMemoryGcra();
        for (var i = 0; i < 5; i++) {
            Assert.True(gcra.CheckAll([new("x", Narrow, 0, "x")]).Allowed);
        }
        Assert.True(gcra.CheckAll([new("x", Narrow, 1, "x")]).Allowed);
        Assert.False(gcra.CheckAll([new("x", Narrow, 0, "x")]).Allowed);
    }

    [Fact]
    public void CheckAll_ReportsTheLongestWait() {
        var gcra = new InMemoryGcra();
        var hourly = new RatePolicy(1, 3600, 1);
        var minutely = new RatePolicy(1, 60, 1);
        gcra.CheckAll([new("h", hourly, 1, "hourly"), new("m", minutely, 1, "minutely")]);
        var refused = gcra.CheckAll([new("m", minutely, 1, "minutely"), new("h", hourly, 1, "hourly")]);
        Assert.Equal("hourly", refused.Policy);
        Assert.True(refused.RetryAfter > TimeSpan.FromMinutes(59));
    }
}

public sealed class OnionCircuitsTests {
    [Theory]
    [InlineData("PROXY TCP6 fc00:dead:beef:4dad::0:1 ::1 65535 42\r", 1ul)]
    [InlineData("PROXY TCP6 fc00:dead:beef:4dad::ab:cdef ::1 65535 42\r", 0xabcdeful)]
    [InlineData("PROXY TCP6 fc00:dead:beef:4dad::ffff:ffff ::1 1 80", 0xfffffffful)]
    public void Parse_ReadsTorsCircuitId(string line, ulong expected) {
        Assert.Equal(expected, OnionCircuits.Parse(line));
    }

    [Theory]
    [InlineData("PROXY TCP4 192.0.2.1 192.0.2.2 1 80\r")]
    [InlineData("PROXY TCP6 2001:db8::1 ::1 1 80\r")]
    [InlineData("PROXY TCP6 fc00:dead:beef:4dad:1::1 ::1 1 80\r")]
    [InlineData("PROXY UNKNOWN\r")]
    [InlineData("GET / HTTP/1.1\r")]
    [InlineData("PROXY TCP6 fc00:dead:beef:4dad::1 ::1 x 80\r")]
    [InlineData("")]
    public void Parse_RefusesAnythingElse(string line) {
        Assert.Null(OnionCircuits.Parse(line));
    }
}

public sealed class PushPaddingTests {
    [Fact]
    public void VerificationPushes_AndShortMessages_HaveTheSameSize() {
        // A verification envelope and a short text message's land in the same padded size, so a push service can't tell
        // a mailbox creation from a message by length.
        var verification = PushEnvelope.Build(PushType.Verification, new byte[8], new byte[MailboxService.VerificationBodySize]);
        var message = PushEnvelope.Build(PushType.Message, new byte[8], new byte[300]);
        Assert.Equal(WebPushCrypto.PaddedRecordLength(verification.Length), WebPushCrypto.PaddedRecordLength(message.Length));
    }

    [Theory]
    [InlineData(0, 1024)]
    [InlineData(921, 1024)]
    [InlineData(922, 2048)]
    [InlineData(1945, 2048)]
    [InlineData(2969, 3072)]
    [InlineData(2970, 4096)]
    [InlineData(WebPushCrypto.MaxPlaintextSize, 4096)]
    public void Plaintexts_ArePaddedToFixedMessageSizes(int plaintext, int message) {
        Assert.Equal(message, WebPushCrypto.HeaderSize + WebPushCrypto.PaddedRecordLength(plaintext) + WebPushCrypto.TagSize);
    }

    [Fact]
    public void PaddedMessages_DecryptToThePlaintext() {
        using var device = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var auth = RandomNumberGenerator.GetBytes(16);
        // Trailing zeros in the plaintext must survive the padding being stripped.
        var plaintext = new byte[] { 1, 2, 3, 0, 0 };
        var pushed = WebPushCrypto.Encrypt(plaintext, WebPushCrypto.ExportPublicKey(device), auth);
        Assert.Equal(1024, pushed.Length);
        Assert.Equal(plaintext, WebPushCrypto.Decrypt(pushed, device, auth));
    }
}

public sealed class PowChallengeRecordTests {
    [Fact]
    public void StoredChallenge_RemembersWhoItWasIssuedTo() {
        var parameters = new PowParameters(9, 16 * 1024, 1);
        var expires = DateTimeOffset.FromUnixTimeMilliseconds(1_800_000_000_000);
        foreach (var issuer in new[] {
                     new PowService.Issuer(new PowService.LoadKeys("AA11", "BB22"), "gf:rl:pow-net:CC33", "gf:rl:pow-alloc:DD44"),
                     new PowService.Issuer(new PowService.LoadKeys("AA11", null), "gf:rl:pow-net:CC33", null),
                 }) {
            var decoded = PowService.Decode(PowService.Encode(parameters, PowPurpose.Create, expires, issuer));
            Assert.Equal((parameters, PowPurpose.Create, expires, issuer), decoded);
        }
    }

    [Theory]
    [InlineData("9:16384:1:1800000000000:c")]
    [InlineData("9:16384:1:1800000000000:c||||")]
    [InlineData("9:16384:1:1800000000000:x|AA|||")]
    public void StoredChallenge_WithoutAnIssuer_IsRefused(string stored) {
        Assert.Null(PowService.Decode(stored));
    }
}

public sealed class ReplayFilterTests {
    [Fact]
    public void Offsets_AreDeterministicAndInsideTheBitmap() {
        var enc = RandomNumberGenerator.GetBytes(1120);
        var offsets = GatewayReplayGuard.Offsets(enc);
        Assert.Equal(offsets, GatewayReplayGuard.Offsets(enc));
        Assert.All(offsets, o => Assert.InRange(o, 0, GatewayReplayGuard.SliceBits - 1));
        Assert.NotEqual(offsets, GatewayReplayGuard.Offsets(RandomNumberGenerator.GetBytes(1120)));
    }

    [Fact]
    public void Slices_CoverTheWindowWithRoomForSkew() {
        Assert.True((GatewayReplayGuard.Slices - 1) * GatewayReplayGuard.SliceSeconds >= GatewayReplayGuard.Retention.TotalSeconds);
    }
}
