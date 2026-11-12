using System.Security.Cryptography;
using GoldfishSend.Core.Crypto;

namespace GoldfishSend.Tests.Core;

public sealed class SecretBoxTests {
    private static readonly byte[] Key = RandomNumberGenerator.GetBytes(32);
    private static readonly byte[] Aad = "context"u8.ToArray();

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(100)]
    [InlineData(5000)]
    public void RoundTrip(int size) {
        var plaintext = RandomNumberGenerator.GetBytes(size);
        var box = SecretBox.Seal(Key, plaintext, Aad);
        Assert.Equal(size + SecretBox.Overhead, box.Length);
        Assert.Equal(plaintext, SecretBox.Open(Key, box, Aad));
    }

    [Fact]
    public void RoundTrip_EmptyAad() {
        var box = SecretBox.Seal(Key, "hello"u8, []);
        Assert.Equal("hello"u8.ToArray(), SecretBox.Open(Key, box, []));
    }

    [Fact]
    public void Format_IsNonceCiphertextTag() {
        var plaintext = RandomNumberGenerator.GetBytes(40);
        var box = SecretBox.Seal(Key, plaintext, Aad);
        var decrypted = new byte[40];
        using var gcm = new AesGcm(Key, 16);
        gcm.Decrypt(box.AsSpan(0, 12), box.AsSpan(12, 40), box.AsSpan(52, 16), decrypted, Aad);
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Seal_UsesRandomNonce() {
        var a = SecretBox.Seal(Key, "same"u8, Aad);
        var b = SecretBox.Seal(Key, "same"u8, Aad);
        Assert.NotEqual(a[..12], b[..12]);
        Assert.NotEqual(a, b);
    }

    [Fact]
    public void Open_TamperedAnyByte_Throws() {
        var box = SecretBox.Seal(Key, RandomNumberGenerator.GetBytes(20), Aad);
        for (var i = 0; i < box.Length; i++) {
            var copy = box.ToArray();
            copy[i] ^= 0x01;
            Assert.ThrowsAny<CryptographicException>(() => SecretBox.Open(Key, copy, Aad));
        }
    }

    [Fact]
    public void Open_Truncated_Throws() {
        var box = SecretBox.Seal(Key, RandomNumberGenerator.GetBytes(20), Aad);
        Assert.ThrowsAny<CryptographicException>(() => SecretBox.Open(Key, box[..^1], Aad));
    }

    [Fact]
    public void Open_WrongKey_Throws() {
        var box = SecretBox.Seal(Key, "secret"u8, Aad);
        Assert.ThrowsAny<CryptographicException>(() => SecretBox.Open(RandomNumberGenerator.GetBytes(32), box, Aad));
    }

    [Fact]
    public void Open_WrongAad_Throws() {
        var box = SecretBox.Seal(Key, "secret"u8, Aad);
        Assert.ThrowsAny<CryptographicException>(() => SecretBox.Open(Key, box, "other"u8));
        Assert.ThrowsAny<CryptographicException>(() => SecretBox.Open(Key, box, []));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(12)]
    [InlineData(27)]
    public void Open_ShorterThanOverhead_Throws(int length) {
        Assert.ThrowsAny<CryptographicException>(() => SecretBox.Open(Key, new byte[length], Aad));
    }

    [Fact]
    public void Open_ExactlyOverheadButForged_Throws() {
        Assert.ThrowsAny<CryptographicException>(() => SecretBox.Open(Key, new byte[SecretBox.Overhead], Aad));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(16)]
    [InlineData(24)]
    [InlineData(31)]
    [InlineData(33)]
    public void BadKeyLength_Throws(int length) {
        Assert.Throws<ArgumentException>(() => SecretBox.Seal(new byte[length], "x"u8, Aad));
        Assert.Throws<ArgumentException>(() => SecretBox.Open(new byte[length], new byte[40], Aad));
    }
}
