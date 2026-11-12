using System.Security.Cryptography;
using System.Text;
using GoldfishSend.Core.Crypto;
using GoldfishSend.Core.Protocol;

namespace GoldfishSend.Tests.Core;

public sealed class MailboxCryptoTests {
    private static readonly byte[] Pepper = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
    private static readonly byte[] SealSalt = Enumerable.Range(100, 32).Select(i => (byte)i).ToArray();
    private static readonly byte[] SendSecret = Enumerable.Range(200, 32).Select(i => (byte)i).ToArray();

    private static readonly MailboxCrypto Crypto = new(Pepper, SealSalt);

    private static byte[] Concat(string label, byte[] data) {
        return Encoding.UTF8.GetBytes(label).Concat(data).ToArray();
    }

    private static EndpointRecord SampleRecord() {
        using var key = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        return new EndpointRecord(
            "https://ntfy.sh/upABC?up=1",
            WebPushCrypto.ExportPublicKey(key),
            RandomNumberGenerator.GetBytes(16));
    }

    // Independent computations of the formulas in docs/protocol.md.

    [Fact]
    public void MailboxId_MatchesSpecFormula() {
        // HMAC-SHA256(key = serverPepper, SHA256("gf/mbx-id" ‖ sendSecret))
        var inner = SHA256.HashData(Concat("gf/mbx-id", SendSecret));
        using var hmac = new HMACSHA256(Pepper);
        var expected = hmac.ComputeHash(inner);
        Assert.Equal(expected, Crypto.MailboxId(SendSecret));
        Assert.Equal(32, expected.Length);
    }

    [Fact]
    public void SealKey_MatchesSpecFormula() {
        // HKDF-SHA256(ikm = sendSecret, salt = serverSealSalt, info = "gf/mbx-seal", L = 32), via RFC 5869 by hand.
        using var extract = new HMACSHA256(SealSalt);
        var prk = extract.ComputeHash(SendSecret);
        using var expand = new HMACSHA256(prk);
        var t1 = expand.ComputeHash(Concat("gf/mbx-seal", [0x01]));
        Assert.Equal(t1, Crypto.SealKey(SendSecret));
    }

    [Fact]
    public void Tag_MatchesSpecFormula() {
        // SHA256("gf/mbx-tag" ‖ sendSecret)[0..8]
        var expected = SHA256.HashData(Concat("gf/mbx-tag", SendSecret))[..8];
        Assert.Equal(expected, MailboxCrypto.Tag(SendSecret));
    }

    [Fact]
    public void OwnerHash_MatchesSpecFormula() {
        var ownerSecret = RandomNumberGenerator.GetBytes(32);
        Assert.Equal(SHA256.HashData(ownerSecret), MailboxCrypto.OwnerHash(ownerSecret));
    }

    [Fact]
    public void Derivations_AreDeterministic() {
        var other = new MailboxCrypto(Pepper.ToArray(), SealSalt.ToArray());
        Assert.Equal(Crypto.MailboxId(SendSecret), other.MailboxId(SendSecret));
        Assert.Equal(Crypto.SealKey(SendSecret), other.SealKey(SendSecret));
        Assert.Equal(MailboxCrypto.Tag(SendSecret), MailboxCrypto.Tag(SendSecret));
    }

    [Fact]
    public void Derivations_AreDomainSeparated() {
        var id = Crypto.MailboxId(SendSecret);
        var key = Crypto.SealKey(SendSecret);
        var tag = MailboxCrypto.Tag(SendSecret);
        Assert.NotEqual(id, key);
        Assert.NotEqual(id[..8], tag);
        Assert.NotEqual(key[..8], tag);
        Assert.NotEqual(SHA256.HashData(SendSecret)[..8], tag);
    }

    [Fact]
    public void DifferentPepper_GivesDifferentId() {
        var pepper2 = Pepper.ToArray();
        pepper2[0] ^= 1;
        var other = new MailboxCrypto(pepper2, SealSalt);
        Assert.NotEqual(Crypto.MailboxId(SendSecret), other.MailboxId(SendSecret));
        // The seal key doesn't depend on the pepper.
        Assert.Equal(Crypto.SealKey(SendSecret), other.SealKey(SendSecret));
    }

    [Fact]
    public void DifferentSealSalt_GivesDifferentSealKey() {
        var salt2 = SealSalt.ToArray();
        salt2[31] ^= 1;
        var other = new MailboxCrypto(Pepper, salt2);
        Assert.NotEqual(Crypto.SealKey(SendSecret), other.SealKey(SendSecret));
        Assert.Equal(Crypto.MailboxId(SendSecret), other.MailboxId(SendSecret));
    }

    [Fact]
    public void DifferentSecret_GivesDifferentValues() {
        var secret2 = SendSecret.ToArray();
        secret2[5] ^= 1;
        Assert.NotEqual(Crypto.MailboxId(SendSecret), Crypto.MailboxId(secret2));
        Assert.NotEqual(Crypto.SealKey(SendSecret), Crypto.SealKey(secret2));
        Assert.NotEqual(MailboxCrypto.Tag(SendSecret), MailboxCrypto.Tag(secret2));
    }

    [Fact]
    public void SealUnseal_RoundTrip() {
        var record = SampleRecord();
        var key = Crypto.SealKey(SendSecret);
        var id = Crypto.MailboxId(SendSecret);

        var sealedRecord = MailboxCrypto.SealEndpoint(key, record, id);
        Assert.Equal(SecretBox.Overhead + record.Serialize().Length, sealedRecord.Length);

        var opened = MailboxCrypto.UnsealEndpoint(key, sealedRecord, id);
        Assert.Equal(record.Url, opened.Url);
        Assert.Equal(record.P256dh, opened.P256dh);
        Assert.Equal(record.Auth, opened.Auth);
    }

    [Fact]
    public void Seal_IsRandomized() {
        var record = SampleRecord();
        var key = Crypto.SealKey(SendSecret);
        var id = Crypto.MailboxId(SendSecret);
        Assert.NotEqual(MailboxCrypto.SealEndpoint(key, record, id), MailboxCrypto.SealEndpoint(key, record, id));
    }

    [Fact]
    public void Sealed_IsSpecFormat_NonceThenAesGcmWithMailboxIdAad() {
        var record = SampleRecord();
        var key = Crypto.SealKey(SendSecret);
        var id = Crypto.MailboxId(SendSecret);
        var sealedRecord = MailboxCrypto.SealEndpoint(key, record, id);

        var plain = new byte[sealedRecord.Length - 28];
        using var gcm = new AesGcm(key, 16);
        gcm.Decrypt(sealedRecord.AsSpan(0, 12), sealedRecord.AsSpan(12, plain.Length), sealedRecord.AsSpan(12 + plain.Length), plain, id);
        Assert.Equal(record.Serialize(), plain);
    }

    [Fact]
    public void Unseal_WithWrongKey_Throws() {
        var record = SampleRecord();
        var id = Crypto.MailboxId(SendSecret);
        var sealedRecord = MailboxCrypto.SealEndpoint(Crypto.SealKey(SendSecret), record, id);

        var otherSecret = RandomNumberGenerator.GetBytes(32);
        Assert.ThrowsAny<CryptographicException>(() =>
            MailboxCrypto.UnsealEndpoint(Crypto.SealKey(otherSecret), sealedRecord, id));
    }

    [Fact]
    public void Unseal_WithWrongMailboxIdAad_Throws() {
        var record = SampleRecord();
        var key = Crypto.SealKey(SendSecret);
        var sealedRecord = MailboxCrypto.SealEndpoint(key, record, Crypto.MailboxId(SendSecret));

        var otherId = Crypto.MailboxId(RandomNumberGenerator.GetBytes(32));
        Assert.ThrowsAny<CryptographicException>(() => MailboxCrypto.UnsealEndpoint(key, sealedRecord, otherId));
        Assert.ThrowsAny<CryptographicException>(() => MailboxCrypto.UnsealEndpoint(key, sealedRecord, []));
    }

    [Fact]
    public void Unseal_Tampered_Throws() {
        var key = Crypto.SealKey(SendSecret);
        var id = Crypto.MailboxId(SendSecret);
        var sealedRecord = MailboxCrypto.SealEndpoint(key, SampleRecord(), id);
        sealedRecord[20] ^= 0x40;
        Assert.ThrowsAny<CryptographicException>(() => MailboxCrypto.UnsealEndpoint(key, sealedRecord, id));
    }

    [Fact]
    public void OwnerMatches_TrueForCorrectSecret() {
        var ownerSecret = RandomNumberGenerator.GetBytes(32);
        var hash = MailboxCrypto.OwnerHash(ownerSecret);
        Assert.True(MailboxCrypto.OwnerMatches(ownerSecret, hash));
    }

    [Fact]
    public void OwnerMatches_FalseForWrongSecret() {
        var ownerSecret = RandomNumberGenerator.GetBytes(32);
        var hash = MailboxCrypto.OwnerHash(ownerSecret);
        var wrong = ownerSecret.ToArray();
        wrong[0] ^= 1;
        Assert.False(MailboxCrypto.OwnerMatches(wrong, hash));
    }

    [Fact]
    public void OwnerMatches_FalseForBadLengths() {
        var ownerSecret = RandomNumberGenerator.GetBytes(32);
        var hash = MailboxCrypto.OwnerHash(ownerSecret);
        Assert.False(MailboxCrypto.OwnerMatches(ownerSecret[..31], hash));
        Assert.False(MailboxCrypto.OwnerMatches(ownerSecret, hash[..31]));
        Assert.False(MailboxCrypto.OwnerMatches([], []));
        Assert.False(MailboxCrypto.OwnerMatches(ownerSecret, ownerSecret)); // the secret itself isn't its hash
    }

    [Theory]
    [InlineData(0)]
    [InlineData(16)]
    [InlineData(31)]
    [InlineData(33)]
    [InlineData(64)]
    public void WrongSecretLength_Throws(int length) {
        var secret = new byte[length];
        Assert.Throws<ArgumentException>(() => Crypto.MailboxId(secret));
        Assert.Throws<ArgumentException>(() => Crypto.SealKey(secret));
        Assert.Throws<ArgumentException>(() => MailboxCrypto.Tag(secret));
        Assert.Throws<ArgumentException>(() => MailboxCrypto.OwnerHash(secret));
    }

    [Theory]
    [InlineData(31, 32)]
    [InlineData(32, 31)]
    [InlineData(0, 32)]
    [InlineData(33, 33)]
    public void Constructor_RejectsBadPepperOrSaltLength(int pepperLength, int saltLength) {
        Assert.Throws<ArgumentException>(() => new MailboxCrypto(new byte[pepperLength], new byte[saltLength]));
    }
}
