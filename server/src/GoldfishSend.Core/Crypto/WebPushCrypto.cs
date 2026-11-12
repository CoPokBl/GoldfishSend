using System.Buffers.Binary;
using System.Security.Cryptography;

namespace GoldfishSend.Core.Crypto;

/// <summary>
/// RFC 8291 Web Push message encryption using the RFC 8188 "aes128gcm" content coding,
/// as a single record.
/// </summary>
public static class WebPushCrypto {
    public const int RecordSize = 4096;
    public const int PublicKeySize = 65;
    public const int AuthSecretSize = 16;
    public const int SaltSize = 16;
    public const int HeaderSize = SaltSize + 4 + 1 + PublicKeySize; // 86
    public const int TagSize = 16;

    /// <summary>The largest plaintext that fits a 4096-byte push message (4096 - 86 - 16 - 1 = 3993).</summary>
    public const int MaxPlaintextSize = RecordSize - HeaderSize - TagSize - 1;

    private static readonly byte[] KeyInfoPrefix = "WebPush: info\0"u8.ToArray();
    private static readonly byte[] CekInfo = "Content-Encoding: aes128gcm\0"u8.ToArray();
    private static readonly byte[] NonceInfo = "Content-Encoding: nonce\0"u8.ToArray();

    public static byte[] Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> uaPublic, ReadOnlySpan<byte> authSecret) {
        using var asKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        return Encrypt(plaintext, uaPublic, authSecret, asKey, salt);
    }

    /// <summary>Deterministic variant for test vectors. Never reuse <paramref name="asKey"/> or <paramref name="salt"/>.</summary>
    internal static byte[] Encrypt(
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> uaPublic,
        ReadOnlySpan<byte> authSecret,
        ECDiffieHellman asKey,
        byte[] salt) {
        if (plaintext.Length > MaxPlaintextSize) {
            throw new ArgumentException($"Plaintext exceeds {MaxPlaintextSize} bytes.", nameof(plaintext));
        }
        if (authSecret.Length != AuthSecretSize) {
            throw new ArgumentException("Auth secret must be 16 bytes.", nameof(authSecret));
        }
        if (salt.Length != SaltSize) {
            throw new ArgumentException("Salt must be 16 bytes.", nameof(salt));
        }

        var asPublic = ExportPublicKey(asKey);
        using var uaKey = ImportPublicKey(uaPublic);
        var ecdhSecret = asKey.DeriveRawSecretAgreement(uaKey.PublicKey);

        var (cek, nonce) = DeriveKeys(ecdhSecret, authSecret, uaPublic, asPublic, salt);
        try {
            var output = new byte[HeaderSize + plaintext.Length + 1 + TagSize];
            var span = output.AsSpan();

            salt.CopyTo(span);
            BinaryPrimitives.WriteUInt32BigEndian(span[SaltSize..], RecordSize);
            span[SaltSize + 4] = PublicKeySize;
            asPublic.CopyTo(span[(SaltSize + 5)..]);

            // Single (and therefore last) record: plaintext ‖ 0x02, no extra padding.
            var padded = new byte[plaintext.Length + 1];
            plaintext.CopyTo(padded);
            padded[^1] = 0x02;

            using var gcm = new AesGcm(cek, TagSize);
            gcm.Encrypt(
                nonce,
                padded,
                span.Slice(HeaderSize, padded.Length),
                span.Slice(HeaderSize + padded.Length, TagSize));
            CryptographicOperations.ZeroMemory(padded);
            return output;
        } finally {
            CryptographicOperations.ZeroMemory(ecdhSecret);
            CryptographicOperations.ZeroMemory(cek);
            CryptographicOperations.ZeroMemory(nonce);
        }
    }

    /// <summary>
    /// The user-agent side of the exchange. Production servers never call it. It's used by tests
    /// and the fake push server to prove the encryption is interoperable.
    /// </summary>
    public static byte[] Decrypt(ReadOnlySpan<byte> message, ECDiffieHellman uaKey, ReadOnlySpan<byte> authSecret) {
        if (message.Length < HeaderSize + TagSize + 1) {
            throw new CryptographicException("Message too short.");
        }

        var salt = message[..SaltSize];
        var rs = BinaryPrimitives.ReadUInt32BigEndian(message[SaltSize..]);
        var idLen = message[SaltSize + 4];
        if (idLen != PublicKeySize || rs < 18) {
            throw new CryptographicException("Unsupported header.");
        }
        var asPublic = message.Slice(SaltSize + 5, PublicKeySize);
        var body = message[HeaderSize..];
        if (body.Length > rs) {
            throw new CryptographicException("Multi-record messages are not supported.");
        }

        var uaPublic = ExportPublicKey(uaKey);
        using var asKey = ImportPublicKey(asPublic);
        var ecdhSecret = uaKey.DeriveRawSecretAgreement(asKey.PublicKey);
        var (cek, nonce) = DeriveKeys(ecdhSecret, authSecret, uaPublic, asPublic, salt);

        var padded = new byte[body.Length - TagSize];
        using (var gcm = new AesGcm(cek, TagSize)) {
            gcm.Decrypt(nonce, body[..^TagSize], body[^TagSize..], padded);
        }

        var end = padded.Length - 1;
        while (end >= 0 && padded[end] == 0) {
            end--;
        }
        if (end < 0 || padded[end] != 0x02) {
            throw new CryptographicException("Invalid padding delimiter.");
        }
        return padded[..end];
    }

    public static ECDiffieHellman ImportPublicKey(ReadOnlySpan<byte> uncompressed) {
        if (uncompressed.Length != PublicKeySize || uncompressed[0] != 0x04) {
            throw new CryptographicException("Expected an uncompressed P-256 point.");
        }
        var parameters = new ECParameters {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint {
                X = uncompressed.Slice(1, 32).ToArray(),
                Y = uncompressed.Slice(33, 32).ToArray(),
            },
        };
        // ImportParameters validates that the point is on the curve.
        return ECDiffieHellman.Create(parameters);
    }

    public static bool IsValidPublicKey(ReadOnlySpan<byte> uncompressed) {
        try {
            using var _ = ImportPublicKey(uncompressed);
            return true;
        } catch (CryptographicException) {
            return false;
        }
    }

    public static byte[] ExportPublicKey(ECDiffieHellman key) {
        var q = key.ExportParameters(false).Q;
        var result = new byte[PublicKeySize];
        result[0] = 0x04;
        q.X!.CopyTo(result, 1);
        q.Y!.CopyTo(result, 33);
        return result;
    }

    private static (byte[] Cek, byte[] Nonce) DeriveKeys(
        byte[] ecdhSecret,
        ReadOnlySpan<byte> authSecret,
        ReadOnlySpan<byte> uaPublic,
        ReadOnlySpan<byte> asPublic,
        ReadOnlySpan<byte> salt) {
        // PRK_key = HKDF-Extract(auth_secret, ecdh_secret)
        // IKM = HKDF-Expand(PRK_key, "WebPush: info" ‖ 0x00 ‖ ua_public ‖ as_public, 32)
        var keyInfo = new byte[KeyInfoPrefix.Length + PublicKeySize * 2];
        KeyInfoPrefix.CopyTo(keyInfo, 0);
        uaPublic.CopyTo(keyInfo.AsSpan(KeyInfoPrefix.Length));
        asPublic.CopyTo(keyInfo.AsSpan(KeyInfoPrefix.Length + PublicKeySize));

        Span<byte> prkKey = stackalloc byte[32];
        HKDF.Extract(HashAlgorithmName.SHA256, ecdhSecret, authSecret, prkKey);
        Span<byte> ikm = stackalloc byte[32];
        HKDF.Expand(HashAlgorithmName.SHA256, prkKey, ikm, keyInfo);

        // PRK = HKDF-Extract(salt, IKM); CEK and NONCE are expanded from PRK.
        Span<byte> prk = stackalloc byte[32];
        HKDF.Extract(HashAlgorithmName.SHA256, ikm, salt, prk);
        var cek = new byte[16];
        var nonce = new byte[12];
        HKDF.Expand(HashAlgorithmName.SHA256, prk, cek, CekInfo);
        HKDF.Expand(HashAlgorithmName.SHA256, prk, nonce, NonceInfo);

        CryptographicOperations.ZeroMemory(prkKey);
        CryptographicOperations.ZeroMemory(ikm);
        CryptographicOperations.ZeroMemory(prk);
        return (cek, nonce);
    }
}
