using System.Buffers.Binary;
using GoldfishSend.Core.Crypto;

namespace GoldfishSend.Core.Protocol;

/// <param name="TtlSeconds"><c>null</c> means the server default (the wire value 0).</param>
public sealed record BatchItem(byte[] SendSecret, byte[] IdempotencyKey, int? TtlSeconds, byte[] Blob) {
    public override string ToString() => $"BatchItem {{ <redacted>, {Blob.Length} B }}";
}

/// <summary>
/// The body of <c>POST /v1/messages/batch</c> (docs/groups.md, "Server: batch send"):
/// <c>u8 count ‖ count × (sendSecret(32) ‖ idempotencyKey(16) ‖ u32 ttlSeconds ‖ u16 len ‖ blob(len))</c>, big-endian.
/// </summary>
public static class MessageBatch {
    public const int MaxItems = 32;

    /// <summary>The per-IP and per-network token cost of one batch: one token per started group of eight items.</summary>
    public const int ItemsPerClientToken = 8;

    private const int ItemHeaderSize = MailboxCrypto.SecretSize + ProtocolLimits.IdempotencyKeySize + 4 + 2;

    public static int ClientCost(int count) => (count + ItemsPerClientToken - 1) / ItemsPerClientToken;

    /// <summary>
    /// Parses strictly: the count must be 1 to <see cref="MaxItems"/>, every blob 1 to <see cref="ProtocolLimits.MaxMessageBytes"/>
    /// bytes, and the items must consume the body exactly. Anything else returns <c>null</c>.
    /// </summary>
    public static List<BatchItem>? TryParse(ReadOnlySpan<byte> body) {
        if (body.Length < 1) {
            return null;
        }
        int count = body[0];
        if (count is < 1 or > MaxItems) {
            return null;
        }
        var items = new List<BatchItem>(count);
        var offset = 1;
        for (var i = 0; i < count; i++) {
            if (body.Length - offset < ItemHeaderSize) {
                return null;
            }
            var sendSecret = body.Slice(offset, MailboxCrypto.SecretSize).ToArray();
            offset += MailboxCrypto.SecretSize;
            var idempotencyKey = body.Slice(offset, ProtocolLimits.IdempotencyKeySize).ToArray();
            offset += ProtocolLimits.IdempotencyKeySize;
            var ttl = BinaryPrimitives.ReadUInt32BigEndian(body.Slice(offset, 4));
            offset += 4;
            int len = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(offset, 2));
            offset += 2;
            if (len is < 1 or > ProtocolLimits.MaxMessageBytes || body.Length - offset < len) {
                return null;
            }
            var blob = body.Slice(offset, len).ToArray();
            offset += len;
            items.Add(new BatchItem(sendSecret, idempotencyKey, ttl == 0 ? null : (int)Math.Min(ttl, int.MaxValue), blob));
        }
        return offset == body.Length ? items : null;
    }

    /// <summary>Encodes a batch (used by tests and as the reference for clients).</summary>
    public static byte[] Encode(IReadOnlyList<BatchItem> items) {
        var size = 1 + items.Sum(i => ItemHeaderSize + i.Blob.Length);
        var buffer = new byte[size];
        buffer[0] = checked((byte)items.Count);
        var offset = 1;
        foreach (var item in items) {
            item.SendSecret.CopyTo(buffer, offset);
            offset += item.SendSecret.Length;
            item.IdempotencyKey.CopyTo(buffer, offset);
            offset += item.IdempotencyKey.Length;
            BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(offset, 4), (uint)(item.TtlSeconds ?? 0));
            offset += 4;
            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(offset, 2), checked((ushort)item.Blob.Length));
            offset += 2;
            item.Blob.CopyTo(buffer, offset);
            offset += item.Blob.Length;
        }
        return buffer;
    }
}
