using System.Security.Cryptography;
using GoldfishSend.Core.Crypto;
using GoldfishSend.Core.Protocol;

namespace GoldfishSend.Infrastructure.Delivery;

/// <summary>
/// A message waiting for delivery. <see cref="Blob"/> is <c>SecretBox(epochKey, sealKey ‖ envelope, aad = id)</c>.
/// That pairs the key needed to unseal the recipient's endpoint with the push payload, under a key we can shred.
/// </summary>
public sealed record DeliveryJob(byte[] Id, byte[] MailboxId, int KeyEpoch, byte[] Blob, DateTime ExpiresAt, int Attempts);

public static class JobCodec {
    public static byte[] Seal(ReadOnlySpan<byte> epochKey, ReadOnlySpan<byte> messageId, ReadOnlySpan<byte> sealKey, ReadOnlySpan<byte> envelope) {
        var plain = new byte[SecretBox.KeySize + envelope.Length];
        try {
            sealKey.CopyTo(plain);
            envelope.CopyTo(plain.AsSpan(SecretBox.KeySize));
            return SecretBox.Seal(epochKey, plain, messageId);
        } finally {
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    /// <exception cref="CryptographicException">Corrupted, or encrypted under a different key.</exception>
    public static (byte[] SealKey, byte[] Envelope) Open(ReadOnlySpan<byte> epochKey, ReadOnlySpan<byte> messageId, ReadOnlySpan<byte> blob) {
        var plain = SecretBox.Open(epochKey, blob, messageId);
        try {
            if (plain.Length < SecretBox.KeySize + PushEnvelope.HeaderSize) {
                throw new CryptographicException("Job payload too short.");
            }
            return (plain[..SecretBox.KeySize], plain[SecretBox.KeySize..]);
        } finally {
            CryptographicOperations.ZeroMemory(plain);
        }
    }
}
