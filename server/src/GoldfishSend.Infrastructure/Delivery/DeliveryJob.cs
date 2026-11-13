using System.Buffers.Binary;
using System.Security.Cryptography;
using GoldfishSend.Core.Crypto;
using GoldfishSend.Core.Protocol;

namespace GoldfishSend.Infrastructure.Delivery;

/// <summary>
/// A message waiting for delivery. <see cref="Blob"/> is
/// <c>SecretBox(epochKey, sealKey ‖ envelope, aad = id ‖ mailboxId ‖ expiresAt)</c>. That pairs the key needed to unseal
/// the recipient's endpoint with the push payload, under a key we can shred. Binding the mailbox and expiry into the AAD
/// means a database writer can't move a blob to another mailbox or extend its life.
/// </summary>
public sealed record DeliveryJob(byte[] Id, byte[] MailboxId, int KeyEpoch, byte[] Blob, DateTime ExpiresAt, int Attempts);

public static class JobCodec {
    public static byte[] Seal(
        ReadOnlySpan<byte> epochKey, ReadOnlySpan<byte> messageId, ReadOnlySpan<byte> mailboxId, DateTime expiresAt,
        ReadOnlySpan<byte> sealKey, ReadOnlySpan<byte> envelope) {
        var plain = new byte[SecretBox.KeySize + envelope.Length];
        try {
            sealKey.CopyTo(plain);
            envelope.CopyTo(plain.AsSpan(SecretBox.KeySize));
            return SecretBox.Seal(epochKey, plain, Aad(messageId, mailboxId, expiresAt));
        } finally {
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    /// <exception cref="CryptographicException">Corrupted, moved to another mailbox, re-dated, or under a different key.</exception>
    public static (byte[] SealKey, byte[] Envelope) Open(
        ReadOnlySpan<byte> epochKey, ReadOnlySpan<byte> messageId, ReadOnlySpan<byte> mailboxId, DateTime expiresAt,
        ReadOnlySpan<byte> blob) {
        var plain = SecretBox.Open(epochKey, blob, Aad(messageId, mailboxId, expiresAt));
        try {
            if (plain.Length < SecretBox.KeySize + PushEnvelope.HeaderSize) {
                throw new CryptographicException("Job payload too short.");
            }
            return (plain[..SecretBox.KeySize], plain[SecretBox.KeySize..]);
        } finally {
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    private static byte[] Aad(ReadOnlySpan<byte> messageId, ReadOnlySpan<byte> mailboxId, DateTime expiresAt) {
        var aad = new byte[messageId.Length + mailboxId.Length + 8];
        messageId.CopyTo(aad);
        mailboxId.CopyTo(aad.AsSpan(messageId.Length));
        var unix = new DateTimeOffset(DateTime.SpecifyKind(expiresAt, DateTimeKind.Utc)).ToUnixTimeSeconds();
        BinaryPrimitives.WriteInt64BigEndian(aad.AsSpan(messageId.Length + mailboxId.Length), unix);
        return aad;
    }
}
