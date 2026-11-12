using System.Security.Cryptography;
using GoldfishSend.Core.Protocol;

namespace GoldfishSend.Core.Crypto;

/// <summary>
/// Derivations from docs/protocol.md. The server never stores send secrets. It only stores values derived
/// from them, and endpoint records sealed under a key that only a send secret can reproduce.
/// </summary>
public sealed class MailboxCrypto {
    public const int SecretSize = 32;
    public const int IdSize = 32;
    public const int TagSize = 8;

    private static readonly byte[] IdLabel = "gf/mbx-id"u8.ToArray();
    private static readonly byte[] TagLabel = "gf/mbx-tag"u8.ToArray();
    private static readonly byte[] SealInfo = "gf/mbx-seal"u8.ToArray();

    private readonly byte[] _pepper;
    private readonly byte[] _sealSalt;

    public MailboxCrypto(byte[] pepper, byte[] sealSalt) {
        if (pepper.Length != 32 || sealSalt.Length != 32) {
            throw new ArgumentException("Pepper and seal salt must be 32 bytes.");
        }
        _pepper = pepper;
        _sealSalt = sealSalt;
    }

    /// <summary><c>HMAC-SHA256(pepper, SHA256("gf/mbx-id" ‖ sendSecret))</c></summary>
    public byte[] MailboxId(ReadOnlySpan<byte> sendSecret) {
        RequireSecret(sendSecret);
        Span<byte> inner = stackalloc byte[32];
        HashLabelled(IdLabel, sendSecret, inner);
        var id = HMACSHA256.HashData(_pepper, inner);
        CryptographicOperations.ZeroMemory(inner);
        return id;
    }

    /// <summary><c>HKDF-SHA256(ikm = sendSecret, salt = sealSalt, info = "gf/mbx-seal", 32)</c></summary>
    public byte[] SealKey(ReadOnlySpan<byte> sendSecret) {
        RequireSecret(sendSecret);
        var key = new byte[32];
        HKDF.DeriveKey(HashAlgorithmName.SHA256, sendSecret, key, _sealSalt, SealInfo);
        return key;
    }

    /// <summary><c>SHA256("gf/mbx-tag" ‖ sendSecret)[0..8]</c></summary>
    public static byte[] Tag(ReadOnlySpan<byte> sendSecret) {
        RequireSecret(sendSecret);
        Span<byte> hash = stackalloc byte[32];
        HashLabelled(TagLabel, sendSecret, hash);
        return hash[..TagSize].ToArray();
    }

    /// <summary><c>SHA256(ownerSecret)</c></summary>
    public static byte[] OwnerHash(ReadOnlySpan<byte> ownerSecret) {
        RequireSecret(ownerSecret);
        return SHA256.HashData(ownerSecret);
    }

    public static bool OwnerMatches(ReadOnlySpan<byte> ownerSecret, ReadOnlySpan<byte> storedHash) {
        if (ownerSecret.Length != SecretSize || storedHash.Length != 32) {
            return false;
        }
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(ownerSecret, hash);
        return CryptographicOperations.FixedTimeEquals(hash, storedHash);
    }

    public static byte[] SealEndpoint(ReadOnlySpan<byte> sealKey, EndpointRecord record, ReadOnlySpan<byte> mailboxId) {
        var plain = record.Serialize();
        try {
            return SecretBox.Seal(sealKey, plain, mailboxId);
        } finally {
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    /// <exception cref="CryptographicException">Wrong key or corrupted record.</exception>
    public static EndpointRecord UnsealEndpoint(ReadOnlySpan<byte> sealKey, ReadOnlySpan<byte> sealedRecord, ReadOnlySpan<byte> mailboxId) {
        var plain = SecretBox.Open(sealKey, sealedRecord, mailboxId);
        try {
            return EndpointRecord.Deserialize(plain);
        } finally {
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    private static void HashLabelled(ReadOnlySpan<byte> label, ReadOnlySpan<byte> secret, Span<byte> destination) {
        Span<byte> buffer = stackalloc byte[label.Length + secret.Length];
        label.CopyTo(buffer);
        secret.CopyTo(buffer[label.Length..]);
        SHA256.HashData(buffer, destination);
        CryptographicOperations.ZeroMemory(buffer);
    }

    private static void RequireSecret(ReadOnlySpan<byte> secret) {
        if (secret.Length != SecretSize) {
            throw new ArgumentException("Secrets must be 32 bytes.");
        }
    }
}
