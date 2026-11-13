using System.Buffers.Binary;
using GoldfishSend.Core.Options;
using GoldfishSend.Core.Protocol;
using GoldfishSend.Infrastructure.Redis;

namespace GoldfishSend.Tests.Core;

public sealed class MessageBatchTests {
    private static BatchItem Item(byte fill, int blobLength = 10, int? ttl = null) =>
        new(Enumerable.Repeat(fill, 32).ToArray(), Enumerable.Repeat((byte)(fill + 1), 16).ToArray(), ttl,
            Enumerable.Repeat((byte)(fill + 2), blobLength).ToArray());

    [Fact]
    public void RoundTrips() {
        var items = new[] { Item(1, ttl: 3600), Item(2, ProtocolLimits.MaxMessageBytes), Item(3, 1) };
        var parsed = MessageBatch.TryParse(MessageBatch.Encode(items));
        Assert.NotNull(parsed);
        Assert.Equal(3, parsed.Count);
        for (var i = 0; i < items.Length; i++) {
            Assert.Equal(items[i].SendSecret, parsed[i].SendSecret);
            Assert.Equal(items[i].IdempotencyKey, parsed[i].IdempotencyKey);
            Assert.Equal(items[i].TtlSeconds, parsed[i].TtlSeconds);
            Assert.Equal(items[i].Blob, parsed[i].Blob);
        }
    }

    [Fact]
    public void WireLayout_IsAsSpecified() {
        var body = MessageBatch.Encode([Item(7, blobLength: 3, ttl: 0x01020304)]);
        Assert.Equal(1 + 32 + 16 + 4 + 2 + 3, body.Length);
        Assert.Equal(1, body[0]);
        Assert.Equal(7, body[1]);
        Assert.Equal(8, body[33]);
        Assert.Equal(0x01020304u, BinaryPrimitives.ReadUInt32BigEndian(body.AsSpan(49)));
        Assert.Equal(3, BinaryPrimitives.ReadUInt16BigEndian(body.AsSpan(53)));
    }

    [Fact]
    public void TtlZero_MeansDefault_AndHugeTtlIsCappedForClamping() {
        Assert.Null(MessageBatch.TryParse(MessageBatch.Encode([Item(1, ttl: 0)]))![0].TtlSeconds);
        var body = MessageBatch.Encode([Item(1)]);
        BinaryPrimitives.WriteUInt32BigEndian(body.AsSpan(49), uint.MaxValue);
        Assert.Equal(int.MaxValue, MessageBatch.TryParse(body)![0].TtlSeconds);
    }

    [Fact]
    public void RejectsMalformedBodies() {
        var one = MessageBatch.Encode([Item(1)]);
        Assert.Null(MessageBatch.TryParse([]));
        Assert.Null(MessageBatch.TryParse([0]));
        Assert.Null(MessageBatch.TryParse(one[..^1])); // truncated blob
        Assert.Null(MessageBatch.TryParse(one[..40])); // truncated header
        Assert.Null(MessageBatch.TryParse([.. one, 0])); // trailing byte

        var countTooHigh = MessageBatch.Encode(Enumerable.Range(0, 32).Select(i => Item((byte)i)).ToArray());
        countTooHigh[0] = 33;
        Assert.Null(MessageBatch.TryParse(countTooHigh));
        var countTooLow = (byte[])one.Clone();
        countTooLow[0] = 2;
        Assert.Null(MessageBatch.TryParse(countTooLow));

        var emptyBlob = (byte[])one.Clone();
        BinaryPrimitives.WriteUInt16BigEndian(emptyBlob.AsSpan(53), 0);
        Assert.Null(MessageBatch.TryParse(emptyBlob[..55]));
        Assert.Null(MessageBatch.TryParse(MessageBatch.Encode([Item(1, ProtocolLimits.MaxMessageBytes + 1)])));
    }

    [Theory]
    [InlineData(1, 1)]
    [InlineData(8, 1)]
    [InlineData(9, 2)]
    [InlineData(16, 2)]
    [InlineData(32, 4)]
    public void ClientCost_IsOneTokenPerStartedGroupOfEight(int count, int cost) {
        Assert.Equal(cost, MessageBatch.ClientCost(count));
    }

    [Fact]
    public void Gcra_ChargesTheGivenCost() {
        var gcra = new InMemoryGcra();
        var policy = new RatePolicy(5, 3600, 5);
        Assert.True(gcra.Check("k", policy, cost: 4).Allowed);
        Assert.True(gcra.Check("k", policy, cost: 1).Allowed);
        Assert.False(gcra.Check("k", policy, cost: 1).Allowed);
        // A cost above the burst can never fit.
        Assert.False(gcra.Check("other", policy, cost: 6).Allowed);
    }
}
