using System.Buffers.Binary;
using System.Buffers.Text;
using System.Security.Cryptography;
using GoldfishSend.Core.Crypto;

namespace GoldfishSend.Tests.Core;

public sealed class WebPushCryptoTests {
    // RFC 8291 Appendix A.
    private const string Plaintext = "V2hlbiBJIGdyb3cgdXAsIEkgd2FudCB0byBiZSBhIHdhdGVybWVsb24";
    private const string AsPublic = "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8";
    private const string AsPrivate = "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw";
    private const string UaPublic = "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4";
    private const string UaPrivate = "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94";
    private const string Salt = "DGv6ra1nlYgDCS1FRnbzlw";
    private const string AuthSecret = "BTBZMqHH6r4Tts7J_aSIgg";
    private const string ExpectedHeader = "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8";
    private const string ExpectedCiphertext = "8pfeW0KbunFT06SuDKoJH9Ql87S1QUrdirN6GcG7sFz1y1sqLgVi1VhjVkHsUoEsbI_0LpXMuGvnzQ";

    private static byte[] B64(string s) => Base64Url.DecodeFromChars(s);

    private static ECDiffieHellman KeyFrom(string privateB64, string publicB64) {
        var pub = B64(publicB64);
        return ECDiffieHellman.Create(new ECParameters {
            Curve = ECCurve.NamedCurves.nistP256,
            D = B64(privateB64),
            Q = new ECPoint { X = pub[1..33], Y = pub[33..65] },
        });
    }

    private static byte[] EncryptVector() {
        using var asKey = KeyFrom(AsPrivate, AsPublic);
        return WebPushCrypto.Encrypt(B64(Plaintext), B64(UaPublic), B64(AuthSecret), asKey, B64(Salt));
    }

    [Fact]
    public void Constants_MatchSizeBudget() {
        Assert.Equal(86, WebPushCrypto.HeaderSize);
        Assert.Equal(3993, WebPushCrypto.MaxPlaintextSize);
    }

    [Fact]
    public void Encrypt_Rfc8291Vector_HeaderMatches() {
        var message = EncryptVector();
        var expectedHeader = B64(ExpectedHeader);
        Assert.Equal(86, expectedHeader.Length);
        Assert.Equal(Base64Url.EncodeToString(expectedHeader), Base64Url.EncodeToString(message.AsSpan(0, 86)));
    }

    [Fact]
    public void Encrypt_Rfc8291Vector_CiphertextMatches() {
        var message = EncryptVector();
        Assert.Equal(ExpectedCiphertext, Base64Url.EncodeToString(message.AsSpan(86)));
    }

    [Fact]
    public void Encrypt_Rfc8291Vector_WholeMessageMatches() {
        var message = EncryptVector();
        var expected = B64(ExpectedHeader).Concat(B64(ExpectedCiphertext)).ToArray();
        Assert.Equal(expected, message);
    }

    [Fact]
    public void Decrypt_Rfc8291Vector_YieldsPlaintext() {
        var message = B64(ExpectedHeader).Concat(B64(ExpectedCiphertext)).ToArray();
        using var uaKey = KeyFrom(UaPrivate, UaPublic);
        var plaintext = WebPushCrypto.Decrypt(message, uaKey, B64(AuthSecret));
        Assert.Equal(B64(Plaintext), plaintext);
        Assert.Equal("When I grow up, I want to be a watermelon", System.Text.Encoding.UTF8.GetString(plaintext));
    }

    [Fact]
    public void Decrypt_WithWrongAuthSecret_Throws() {
        var message = B64(ExpectedHeader).Concat(B64(ExpectedCiphertext)).ToArray();
        using var uaKey = KeyFrom(UaPrivate, UaPublic);
        var auth = B64(AuthSecret);
        auth[0] ^= 1;
        Assert.ThrowsAny<CryptographicException>(() => WebPushCrypto.Decrypt(message, uaKey, auth));
    }

    [Fact]
    public void Decrypt_WithWrongUaKey_Throws() {
        var message = B64(ExpectedHeader).Concat(B64(ExpectedCiphertext)).ToArray();
        using var other = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        Assert.ThrowsAny<CryptographicException>(() => WebPushCrypto.Decrypt(message, other, B64(AuthSecret)));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(17)]
    [InlineData(1000)]
    [InlineData(3993)]
    public void RandomRoundTrip(int size) {
        using var uaKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var uaPublic = WebPushCrypto.ExportPublicKey(uaKey);
        var auth = RandomNumberGenerator.GetBytes(16);
        var plaintext = RandomNumberGenerator.GetBytes(size);

        var message = WebPushCrypto.Encrypt(plaintext, uaPublic, auth);

        Assert.Equal(86 + size + 1 + 16, message.Length);
        Assert.Equal(4096u, BinaryPrimitives.ReadUInt32BigEndian(message.AsSpan(16)));
        Assert.Equal(65, message[20]);
        Assert.Equal(0x04, message[21]);
        Assert.Equal(plaintext, WebPushCrypto.Decrypt(message, uaKey, auth));
    }

    [Fact]
    public void Encrypt_UsesFreshSaltAndEphemeralKeyEachTime() {
        using var uaKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var uaPublic = WebPushCrypto.ExportPublicKey(uaKey);
        var auth = RandomNumberGenerator.GetBytes(16);
        var a = WebPushCrypto.Encrypt("hi"u8, uaPublic, auth);
        var b = WebPushCrypto.Encrypt("hi"u8, uaPublic, auth);
        Assert.NotEqual(a[..16], b[..16]);
        Assert.NotEqual(a[21..86], b[21..86]);
        Assert.NotEqual(a[86..], b[86..]);
    }

    [Fact]
    public void Encrypt_MaxPlaintext_ProducesExactly4096Bytes() {
        using var uaKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var auth = RandomNumberGenerator.GetBytes(16);
        var plaintext = RandomNumberGenerator.GetBytes(WebPushCrypto.MaxPlaintextSize);
        var message = WebPushCrypto.Encrypt(plaintext, WebPushCrypto.ExportPublicKey(uaKey), auth);
        Assert.Equal(4096, message.Length);
        Assert.Equal(plaintext, WebPushCrypto.Decrypt(message, uaKey, auth));
    }

    [Fact]
    public void Encrypt_Oversize_Throws() {
        using var uaKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var plaintext = new byte[WebPushCrypto.MaxPlaintextSize + 1];
        Assert.Throws<ArgumentException>(() =>
            WebPushCrypto.Encrypt(plaintext, WebPushCrypto.ExportPublicKey(uaKey), new byte[16]));
    }

    [Theory]
    [InlineData(15)]
    [InlineData(17)]
    [InlineData(0)]
    public void Encrypt_BadAuthSecretLength_Throws(int length) {
        using var uaKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        Assert.Throws<ArgumentException>(() =>
            WebPushCrypto.Encrypt("x"u8, WebPushCrypto.ExportPublicKey(uaKey), new byte[length]));
    }

    [Fact]
    public void Encrypt_BadSaltLength_Throws() {
        using var asKey = KeyFrom(AsPrivate, AsPublic);
        Assert.Throws<ArgumentException>(() =>
            WebPushCrypto.Encrypt(B64(Plaintext), B64(UaPublic), B64(AuthSecret), asKey, new byte[15]));
    }

    [Fact]
    public void Encrypt_InvalidUaPublicKey_Throws() {
        var bad = B64(UaPublic);
        bad[64] ^= 1;
        Assert.ThrowsAny<CryptographicException>(() => WebPushCrypto.Encrypt("x"u8, bad, new byte[16]));
    }

    [Theory]
    [InlineData(0)]   // salt
    [InlineData(30)]  // keyid (as_public)
    [InlineData(86)]  // first ciphertext byte
    [InlineData(-1)]  // last tag byte
    public void Decrypt_Tampered_Throws(int index) {
        var message = B64(ExpectedHeader).Concat(B64(ExpectedCiphertext)).ToArray();
        var i = index < 0 ? message.Length + index : index;
        message[i] ^= 0x01;
        using var uaKey = KeyFrom(UaPrivate, UaPublic);
        Assert.ThrowsAny<CryptographicException>(() => WebPushCrypto.Decrypt(message, uaKey, B64(AuthSecret)));
    }

    [Fact]
    public void Decrypt_TooShort_Throws() {
        using var uaKey = KeyFrom(UaPrivate, UaPublic);
        Assert.ThrowsAny<CryptographicException>(() => WebPushCrypto.Decrypt(new byte[86 + 16], uaKey, B64(AuthSecret)));
    }

    [Fact]
    public void Decrypt_BadKeyIdLength_Throws() {
        var message = B64(ExpectedHeader).Concat(B64(ExpectedCiphertext)).ToArray();
        message[20] = 64;
        using var uaKey = KeyFrom(UaPrivate, UaPublic);
        Assert.ThrowsAny<CryptographicException>(() => WebPushCrypto.Decrypt(message, uaKey, B64(AuthSecret)));
    }

    [Fact]
    public void Decrypt_BodyLargerThanRecordSize_Throws() {
        var message = B64(ExpectedHeader).Concat(B64(ExpectedCiphertext)).ToArray();
        BinaryPrimitives.WriteUInt32BigEndian(message.AsSpan(16), 18);
        using var uaKey = KeyFrom(UaPrivate, UaPublic);
        Assert.ThrowsAny<CryptographicException>(() => WebPushCrypto.Decrypt(message, uaKey, B64(AuthSecret)));
    }

    [Fact]
    public void ExportPublicKey_RoundTripsThroughImport() {
        using var key = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var pub = WebPushCrypto.ExportPublicKey(key);
        Assert.Equal(65, pub.Length);
        Assert.Equal(0x04, pub[0]);
        using var imported = WebPushCrypto.ImportPublicKey(pub);
        Assert.Equal(pub, WebPushCrypto.ExportPublicKey(imported));
    }

    [Fact]
    public void IsValidPublicKey_AcceptsVectorKeys() {
        Assert.True(WebPushCrypto.IsValidPublicKey(B64(UaPublic)));
        Assert.True(WebPushCrypto.IsValidPublicKey(B64(AsPublic)));
    }

    [Fact]
    public void IsValidPublicKey_RejectsOffCurvePoint() {
        var key = B64(UaPublic);
        key[64] ^= 0x01; // flip a Y bit: no longer on the curve
        Assert.False(WebPushCrypto.IsValidPublicKey(key));
    }

    [Fact]
    public void IsValidPublicKey_RejectsOffCurveX() {
        var key = B64(UaPublic);
        key[1] ^= 0x80;
        Assert.False(WebPushCrypto.IsValidPublicKey(key));
    }

    [Fact]
    public void IsValidPublicKey_RejectsAllZeroPoint() {
        var key = new byte[65];
        key[0] = 0x04;
        Assert.False(WebPushCrypto.IsValidPublicKey(key));
    }

    [Fact]
    public void IsValidPublicKey_RejectsCoordinatesNotReducedModP() {
        // X = p (the field prime) is out of range even though X mod p = 0.
        var key = new byte[65];
        key[0] = 0x04;
        Convert.FromHexString("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF").CopyTo(key, 1);
        Assert.False(WebPushCrypto.IsValidPublicKey(key));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(33)]
    [InlineData(64)]
    [InlineData(66)]
    public void IsValidPublicKey_RejectsWrongLength(int length) {
        var key = new byte[length];
        if (length > 0) {
            key[0] = 0x04;
        }
        Assert.False(WebPushCrypto.IsValidPublicKey(key));
    }

    [Theory]
    [InlineData(0x02)]
    [InlineData(0x03)]
    [InlineData(0x00)]
    [InlineData(0x06)]
    public void IsValidPublicKey_RejectsNonUncompressedPrefix(byte prefix) {
        var key = B64(UaPublic);
        key[0] = prefix;
        Assert.False(WebPushCrypto.IsValidPublicKey(key));
    }
}
