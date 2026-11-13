using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace GoldfishSend.Core.Crypto;

/// <summary>
/// The encrypted gateway (docs/protocol.md, "Encrypted transport and server identity"): a hybrid ML-KEM-768 + P-256 KEM,
/// HKDF-SHA-256 and AES-256-GCM. The hybrid holds as long as either ML-KEM-768 or P-256 does.
/// </summary>
public static class GatewayCrypto {
    public const int Version = 1;
    public const int SecretSize = 96;
    public const int MlKemSeedSize = 64;
    public const int P256ScalarSize = 32;
    public const int MlKemPublicSize = 1184;
    public const int MlKemCiphertextSize = 1088;
    public const int P256PointSize = 65;
    public const int BlobSize = 1 + MlKemPublicSize + P256PointSize; // 1250
    public const int EncSize = MlKemCiphertextSize + P256PointSize; // 1153
    public const int FingerprintSize = 32;
    public const int KeyIdSize = 8;
    public const int HeaderSize = 1 + KeyIdSize; // 9
    public const int TagSize = 16;
    public const int RequestOverhead = HeaderSize + EncSize + TagSize; // 1178
    public const int ResponseNonceSize = 32;
    public const int ResponseOverhead = ResponseNonceSize + TagSize; // 48

    private static readonly byte[] FingerprintLabel = "gf/server-key/v1"u8.ToArray();
    private static readonly byte[] TranscriptLabel = "gf/gw/v1"u8.ToArray();
    private static readonly byte[] RequestInfo = "gf/gw/v1 req"u8.ToArray();
    private static readonly byte[] ResponseInfo = "gf/gw/v1 resp"u8.ToArray();
    private static readonly byte[] ResponseKeyInfo = "gf/gw/v1 resp key"u8.ToArray();
    private static readonly byte[] ResponseAad = "gf/gw/v1 resp"u8.ToArray();
    private static readonly byte[] ZeroNonce = new byte[12];

    private static readonly byte[] P256Order = Convert.FromHexString("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");

    public static byte[] Fingerprint(ReadOnlySpan<byte> blob) {
        var input = new byte[FingerprintLabel.Length + blob.Length];
        FingerprintLabel.CopyTo(input, 0);
        blob.CopyTo(input.AsSpan(FingerprintLabel.Length));
        return SHA256.HashData(input);
    }

    /// <summary>RFC 4648 base32 (no padding) in groups of 4, the form users compare.</summary>
    public static string DisplayFingerprint(ReadOnlySpan<byte> fingerprint) {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var chars = new StringBuilder();
        int buffer = 0, bits = 0;
        foreach (var b in fingerprint) {
            buffer = (buffer << 8) | b;
            bits += 8;
            while (bits >= 5) {
                chars.Append(alphabet[(buffer >> (bits - 5)) & 31]);
                bits -= 5;
            }
        }
        if (bits > 0) {
            chars.Append(alphabet[(buffer << (5 - bits)) & 31]);
        }
        var grouped = new StringBuilder();
        for (var i = 0; i < chars.Length; i += 4) {
            if (i > 0) {
                grouped.Append(' ');
            }
            grouped.Append(chars.ToString(i, Math.Min(4, chars.Length - i)));
        }
        return grouped.ToString();
    }

    /// <summary>A new random <c>ServerKey</c> secret: a fresh ML-KEM seed and a valid P-256 scalar.</summary>
    public static byte[] GenerateSecret() {
        var secret = new byte[SecretSize];
        RandomNumberGenerator.Fill(secret.AsSpan(0, MlKemSeedSize));
        using var ec = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        ec.ExportParameters(true).D!.CopyTo(secret, MlKemSeedSize);
        return secret;
    }

    internal static bool IsValidScalar(ReadOnlySpan<byte> scalar) {
        if (scalar.Length != P256ScalarSize || scalar.IndexOfAnyExcept((byte)0) < 0) {
            return false;
        }
        return scalar.SequenceCompareTo(P256Order) < 0;
    }

    /// <summary>
    /// The key schedule shared by both sides: <c>th = SHA-256("gf/gw/v1" ‖ fp ‖ enc)</c>,
    /// <c>prk = HKDF-Extract(th, ssM ‖ ssX)</c>, then the request key and the response secret.
    /// </summary>
    internal static (byte[] ReqKey, byte[] RespSecret) Schedule(
        ReadOnlySpan<byte> fingerprint, ReadOnlySpan<byte> enc, ReadOnlySpan<byte> ssM, ReadOnlySpan<byte> ssX) {
        var transcript = new byte[TranscriptLabel.Length + FingerprintSize + EncSize];
        TranscriptLabel.CopyTo(transcript, 0);
        fingerprint.CopyTo(transcript.AsSpan(TranscriptLabel.Length));
        enc.CopyTo(transcript.AsSpan(TranscriptLabel.Length + FingerprintSize));
        var th = SHA256.HashData(transcript);

        var ikm = new byte[ssM.Length + ssX.Length];
        ssM.CopyTo(ikm);
        ssX.CopyTo(ikm.AsSpan(ssM.Length));
        var prk = HKDF.Extract(HashAlgorithmName.SHA256, ikm, th);
        CryptographicOperations.ZeroMemory(ikm);
        var reqKey = HKDF.Expand(HashAlgorithmName.SHA256, prk, 32, RequestInfo);
        var respSecret = HKDF.Expand(HashAlgorithmName.SHA256, prk, 32, ResponseInfo);
        CryptographicOperations.ZeroMemory(prk);
        return (reqKey, respSecret);
    }

    /// <summary>Encrypts an inner response: <c>respNonce ‖ AES-256-GCM(respKey, 0, "gf/gw/v1 resp", inner)</c>.</summary>
    public static byte[] SealResponse(ReadOnlySpan<byte> respSecret, ReadOnlySpan<byte> innerResponse, ReadOnlySpan<byte> respNonce = default) {
        var output = new byte[ResponseNonceSize + innerResponse.Length + TagSize];
        var nonce = output.AsSpan(0, ResponseNonceSize);
        if (respNonce.IsEmpty) {
            RandomNumberGenerator.Fill(nonce);
        } else {
            respNonce.CopyTo(nonce);
        }
        var key = ResponseKey(respSecret, nonce);
        using (var gcm = new AesGcm(key, TagSize)) {
            gcm.Encrypt(ZeroNonce, innerResponse, output.AsSpan(ResponseNonceSize, innerResponse.Length), output.AsSpan(^TagSize), ResponseAad);
        }
        CryptographicOperations.ZeroMemory(key);
        return output;
    }

    /// <summary>The client side of <see cref="SealResponse"/>. Returns null if it doesn't authenticate.</summary>
    public static byte[]? OpenResponse(ReadOnlySpan<byte> respSecret, ReadOnlySpan<byte> outerResponse) {
        if (outerResponse.Length < ResponseOverhead) {
            return null;
        }
        var key = ResponseKey(respSecret, outerResponse[..ResponseNonceSize]);
        var ciphertext = outerResponse[ResponseNonceSize..^TagSize];
        var plaintext = new byte[ciphertext.Length];
        try {
            using var gcm = new AesGcm(key, TagSize);
            gcm.Decrypt(ZeroNonce, ciphertext, outerResponse[^TagSize..], plaintext, ResponseAad);
            return plaintext;
        } catch (CryptographicException) {
            return null;
        } finally {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private static byte[] ResponseKey(ReadOnlySpan<byte> respSecret, ReadOnlySpan<byte> respNonce) {
        var rprk = new byte[32];
        HKDF.Extract(HashAlgorithmName.SHA256, respSecret, respNonce, rprk);
        var key = HKDF.Expand(HashAlgorithmName.SHA256, rprk, 32, ResponseKeyInfo);
        CryptographicOperations.ZeroMemory(rprk);
        return key;
    }

    internal static byte[] Aad(ReadOnlySpan<byte> keyId) {
        var header = new byte[HeaderSize];
        header[0] = Version;
        keyId.CopyTo(header.AsSpan(1));
        return header;
    }

    internal static byte[] EncodePoint(ECParameters parameters) {
        var point = new byte[P256PointSize];
        point[0] = 0x04;
        parameters.Q.X!.CopyTo(point, 1);
        parameters.Q.Y!.CopyTo(point, 33);
        return point;
    }

    internal static MLKemPublicKeyParameters ImportMlKemPublic(ReadOnlySpan<byte> encoded) {
        return MLKemPublicKeyParameters.FromEncoding(MLKemParameters.ml_kem_768, encoded.ToArray());
    }

    internal static (byte[] Ciphertext, byte[] Secret) MlKemEncapsulate(MLKemPublicKeyParameters publicKey) {
        var encapsulator = new MLKemEncapsulator(MLKemParameters.ml_kem_768);
        encapsulator.Init(new ParametersWithRandom(publicKey, new SecureRandom()));
        var ciphertext = new byte[encapsulator.EncapsulationLength];
        var secret = new byte[encapsulator.SecretLength];
        encapsulator.Encapsulate(ciphertext, 0, ciphertext.Length, secret, 0, secret.Length);
        return (ciphertext, secret);
    }

    internal static byte[] MlKemDecapsulate(MLKemPrivateKeyParameters privateKey, ReadOnlySpan<byte> ciphertext) {
        var decapsulator = new MLKemDecapsulator(MLKemParameters.ml_kem_768);
        decapsulator.Init(privateKey);
        var secret = new byte[decapsulator.SecretLength];
        var buffer = ciphertext.ToArray();
        decapsulator.Decapsulate(buffer, 0, buffer.Length, secret, 0, secret.Length);
        return secret;
    }

    public static string Base64UrlFingerprint(ReadOnlySpan<byte> fingerprint) => Base64Url.EncodeToString(fingerprint);
}

/// <summary>The server's identity key (<c>Goldfish:Keys:ServerKey</c>). It never expires.</summary>
public sealed class ServerKey {
    private readonly MLKemPrivateKeyParameters _mlKem;
    private readonly ECParameters _ec;

    /// <summary><c>0x01 ‖ ekMLKEM768 ‖ pkP256</c>, served by <c>GET /v1/key</c>.</summary>
    public byte[] Blob { get; }
    public byte[] Fingerprint { get; }
    public byte[] KeyId { get; }
    public string FingerprintBase64Url => GatewayCrypto.Base64UrlFingerprint(Fingerprint);
    public string FingerprintDisplay => GatewayCrypto.DisplayFingerprint(Fingerprint);

    public ServerKey(ReadOnlySpan<byte> secret) {
        if (secret.Length != GatewayCrypto.SecretSize) {
            throw new ArgumentException("The server key must be 96 bytes.", nameof(secret));
        }
        var scalar = secret[GatewayCrypto.MlKemSeedSize..];
        if (!GatewayCrypto.IsValidScalar(scalar)) {
            throw new ArgumentException("The server key's P-256 scalar is out of range.", nameof(secret));
        }
        _mlKem = MLKemPrivateKeyParameters.FromSeed(MLKemParameters.ml_kem_768, secret[..GatewayCrypto.MlKemSeedSize].ToArray());
        using var ec = ECDiffieHellman.Create(new ECParameters {
            Curve = ECCurve.NamedCurves.nistP256,
            D = scalar.ToArray(),
        });
        _ec = ec.ExportParameters(true);

        Blob = new byte[GatewayCrypto.BlobSize];
        Blob[0] = GatewayCrypto.Version;
        _mlKem.GetPublicKeyEncoded().CopyTo(Blob, 1);
        GatewayCrypto.EncodePoint(_ec).CopyTo(Blob, 1 + GatewayCrypto.MlKemPublicSize);
        Fingerprint = GatewayCrypto.Fingerprint(Blob);
        KeyId = Fingerprint[..GatewayCrypto.KeyIdSize];
    }

    public enum OpenStatus { Ok, Malformed, UnknownKey }

    /// <summary>
    /// Opens <c>header ‖ enc ‖ ct</c>. On success returns the inner request and the response secret. Every failure other
    /// than a foreign key id is reported as <see cref="OpenStatus.Malformed"/>, without detail.
    /// </summary>
    public OpenStatus TryOpenRequest(ReadOnlySpan<byte> outer, out byte[] innerRequest, out byte[] respSecret, out byte[] enc) {
        innerRequest = [];
        respSecret = [];
        enc = [];
        if (outer.Length < GatewayCrypto.RequestOverhead || outer[0] != GatewayCrypto.Version) {
            return OpenStatus.Malformed;
        }
        if (!outer.Slice(1, GatewayCrypto.KeyIdSize).SequenceEqual(KeyId)) {
            return OpenStatus.UnknownKey;
        }
        var encSpan = outer.Slice(GatewayCrypto.HeaderSize, GatewayCrypto.EncSize);
        var ctM = encSpan[..GatewayCrypto.MlKemCiphertextSize];
        var ctX = encSpan[GatewayCrypto.MlKemCiphertextSize..];
        var ciphertext = outer[(GatewayCrypto.HeaderSize + GatewayCrypto.EncSize)..];

        byte[] ssM;
        byte[] ssX;
        try {
            // ML-KEM decapsulation never fails (implicit rejection); a bad ciphertext just yields a wrong secret.
            ssM = GatewayCrypto.MlKemDecapsulate(_mlKem, ctM);
            using var ephemeral = WebPushCrypto.ImportPublicKey(ctX);
            using var ours = ECDiffieHellman.Create(_ec);
            ssX = ours.DeriveRawSecretAgreement(ephemeral.PublicKey);
        } catch (Exception e) when (e is CryptographicException or ArgumentException) {
            return OpenStatus.Malformed;
        }

        var (reqKey, secret) = GatewayCrypto.Schedule(Fingerprint, encSpan, ssM, ssX);
        CryptographicOperations.ZeroMemory(ssM);
        CryptographicOperations.ZeroMemory(ssX);
        var plaintext = new byte[ciphertext.Length - GatewayCrypto.TagSize];
        try {
            using var gcm = new AesGcm(reqKey, GatewayCrypto.TagSize);
            gcm.Decrypt(new byte[12], ciphertext[..^GatewayCrypto.TagSize], ciphertext[^GatewayCrypto.TagSize..], plaintext,
                outer[..GatewayCrypto.HeaderSize]);
        } catch (CryptographicException) {
            CryptographicOperations.ZeroMemory(secret);
            return OpenStatus.Malformed;
        } finally {
            CryptographicOperations.ZeroMemory(reqKey);
        }
        innerRequest = plaintext;
        respSecret = secret;
        enc = encSpan.ToArray();
        return OpenStatus.Ok;
    }

    public static ServerKey FromBase64Url(string value) {
        byte[] bytes;
        try {
            bytes = Base64Url.DecodeFromChars(value.Trim());
        } catch (FormatException) {
            throw new InvalidOperationException(InvalidMessage);
        }
        if (bytes.Length != GatewayCrypto.SecretSize) {
            throw new InvalidOperationException(InvalidMessage);
        }
        try {
            return new ServerKey(bytes);
        } catch (ArgumentException) {
            throw new InvalidOperationException(InvalidMessage);
        } finally {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private const string InvalidMessage =
        "Goldfish:Keys:ServerKey must be 96 bytes of base64url (ML-KEM-768 seed ‖ P-256 scalar). Generate one with: GoldfishSend.Api keygen";
}

/// <summary>A server's public key as a client sees it: parsed and checked from a <c>GET /v1/key</c> blob.</summary>
public sealed class ServerPublicKey {
    private readonly MLKemPublicKeyParameters _mlKem;
    private readonly byte[] _point;

    public byte[] Fingerprint { get; }
    public byte[] KeyId { get; }

    private ServerPublicKey(MLKemPublicKeyParameters mlKem, byte[] point, byte[] fingerprint) {
        _mlKem = mlKem;
        _point = point;
        Fingerprint = fingerprint;
        KeyId = fingerprint[..GatewayCrypto.KeyIdSize];
    }

    /// <summary>Parses a blob. If <paramref name="expectedFingerprint"/> is given, the blob must hash to it.</summary>
    public static ServerPublicKey? TryParse(ReadOnlySpan<byte> blob, ReadOnlySpan<byte> expectedFingerprint = default) {
        if (blob.Length != GatewayCrypto.BlobSize || blob[0] != GatewayCrypto.Version) {
            return null;
        }
        var fingerprint = GatewayCrypto.Fingerprint(blob);
        if (!expectedFingerprint.IsEmpty && !CryptographicOperations.FixedTimeEquals(fingerprint, expectedFingerprint)) {
            return null;
        }
        var point = blob[(1 + GatewayCrypto.MlKemPublicSize)..].ToArray();
        if (!WebPushCrypto.IsValidPublicKey(point)) {
            return null;
        }
        try {
            var mlKem = GatewayCrypto.ImportMlKemPublic(blob.Slice(1, GatewayCrypto.MlKemPublicSize));
            return new ServerPublicKey(mlKem, point, fingerprint);
        } catch (Exception e) when (e is ArgumentException or InvalidOperationException) {
            return null;
        }
    }

    /// <summary>The client side: encrypts a padded inner request. Returns the outer body and the response secret.</summary>
    public (byte[] Outer, byte[] RespSecret) Seal(ReadOnlySpan<byte> innerRequest) {
        var (ctM, ssM) = GatewayCrypto.MlKemEncapsulate(_mlKem);
        using var ephemeral = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        using var server = WebPushCrypto.ImportPublicKey(_point);
        var ssX = ephemeral.DeriveRawSecretAgreement(server.PublicKey);
        var ctX = WebPushCrypto.ExportPublicKey(ephemeral);

        var outer = new byte[GatewayCrypto.RequestOverhead + innerRequest.Length];
        var header = GatewayCrypto.Aad(KeyId);
        header.CopyTo(outer, 0);
        ctM.CopyTo(outer, GatewayCrypto.HeaderSize);
        ctX.CopyTo(outer, GatewayCrypto.HeaderSize + GatewayCrypto.MlKemCiphertextSize);
        var enc = outer.AsSpan(GatewayCrypto.HeaderSize, GatewayCrypto.EncSize);

        var (reqKey, respSecret) = GatewayCrypto.Schedule(Fingerprint, enc, ssM, ssX);
        CryptographicOperations.ZeroMemory(ssM);
        CryptographicOperations.ZeroMemory(ssX);
        var body = outer.AsSpan(GatewayCrypto.HeaderSize + GatewayCrypto.EncSize);
        using (var gcm = new AesGcm(reqKey, GatewayCrypto.TagSize)) {
            gcm.Encrypt(new byte[12], innerRequest, body[..innerRequest.Length], body[innerRequest.Length..], header);
        }
        CryptographicOperations.ZeroMemory(reqKey);
        return (outer, respSecret);
    }
}
