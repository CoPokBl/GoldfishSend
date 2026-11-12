using System.Security.Cryptography;

namespace GoldfishSend.Core.Crypto;

/// <summary>
/// AES-256-GCM authenticated encryption with a random 96-bit nonce.
/// Wire format: nonce(12) ‖ ciphertext ‖ tag(16).
/// </summary>
public static class SecretBox {
    public const int KeySize = 32;
    public const int NonceSize = 12;
    public const int TagSize = 16;
    public const int Overhead = NonceSize + TagSize;

    public static byte[] Seal(ReadOnlySpan<byte> key, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> aad) {
        if (key.Length != KeySize) {
            throw new ArgumentException("Key must be 32 bytes.", nameof(key));
        }

        var output = new byte[NonceSize + plaintext.Length + TagSize];
        var nonce = output.AsSpan(0, NonceSize);
        var ciphertext = output.AsSpan(NonceSize, plaintext.Length);
        var tag = output.AsSpan(NonceSize + plaintext.Length, TagSize);
        RandomNumberGenerator.Fill(nonce);

        using var gcm = new AesGcm(key, TagSize);
        gcm.Encrypt(nonce, plaintext, ciphertext, tag, aad);
        return output;
    }

    /// <exception cref="CryptographicException">The box was tampered with or the key/aad is wrong.</exception>
    public static byte[] Open(ReadOnlySpan<byte> key, ReadOnlySpan<byte> box, ReadOnlySpan<byte> aad) {
        if (key.Length != KeySize) {
            throw new ArgumentException("Key must be 32 bytes.", nameof(key));
        }
        if (box.Length < Overhead) {
            throw new CryptographicException("Box too short.");
        }

        var nonce = box[..NonceSize];
        var ciphertext = box[NonceSize..^TagSize];
        var tag = box[^TagSize..];
        var plaintext = new byte[ciphertext.Length];

        using var gcm = new AesGcm(key, TagSize);
        gcm.Decrypt(nonce, ciphertext, tag, plaintext, aad);
        return plaintext;
    }
}
