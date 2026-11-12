using System.Buffers.Text;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.Json;

namespace GoldfishSend.Core.Crypto;

/// <summary>RFC 8292 VAPID: an ES256-signed JWT that identifies this application server to push services.</summary>
public sealed class VapidSigner : IDisposable {
    private static readonly TimeSpan TokenLifetime = TimeSpan.FromHours(12);
    private static readonly TimeSpan RenewBefore = TimeSpan.FromHours(1);
    private const int MaxCachedAudiences = 4096;

    private readonly ECDsa _key;
    private readonly string _subject;
    private readonly ConcurrentDictionary<string, (string Header, DateTimeOffset Expires)> _cache = new();

    public byte[] PublicKey { get; }
    public string PublicKeyBase64Url { get; }

    public VapidSigner(ReadOnlySpan<byte> privateKey, string subject) {
        if (privateKey.Length != 32) {
            throw new ArgumentException("VAPID private key must be a 32-byte P-256 scalar.", nameof(privateKey));
        }
        if (!subject.StartsWith("mailto:", StringComparison.Ordinal) && !subject.StartsWith("https://", StringComparison.Ordinal)) {
            throw new ArgumentException("VAPID subject must be a mailto: or https: URI.", nameof(subject));
        }

        _key = ECDsa.Create(new ECParameters {
            Curve = ECCurve.NamedCurves.nistP256,
            D = privateKey.ToArray(),
        });
        _subject = subject;

        var q = _key.ExportParameters(false).Q;
        PublicKey = new byte[65];
        PublicKey[0] = 0x04;
        q.X!.CopyTo(PublicKey, 1);
        q.Y!.CopyTo(PublicKey, 33);
        PublicKeyBase64Url = Base64Url.EncodeToString(PublicKey);
    }

    public static byte[] GeneratePrivateKey() {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return key.ExportParameters(true).D!;
    }

    /// <summary>Returns the value of the <c>Authorization</c> header for a push to <paramref name="endpoint"/>.</summary>
    public string GetAuthorizationHeader(Uri endpoint, DateTimeOffset now) {
        var audience = endpoint.GetLeftPart(UriPartial.Authority);
        if (_cache.TryGetValue(audience, out var cached) && cached.Expires - now > RenewBefore) {
            return cached.Header;
        }

        var expires = now + TokenLifetime;
        var header = $"vapid t={CreateJwt(audience, expires)}, k={PublicKeyBase64Url}";
        if (_cache.Count >= MaxCachedAudiences) {
            _cache.Clear();
        }
        _cache[audience] = (header, expires);
        return header;
    }

    internal string CreateJwt(string audience, DateTimeOffset expires) {
        var headerPart = Base64Url.EncodeToString("{\"typ\":\"JWT\",\"alg\":\"ES256\"}"u8);

        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer)) {
            writer.WriteStartObject();
            writer.WriteString("aud", audience);
            writer.WriteNumber("exp", expires.ToUnixTimeSeconds());
            writer.WriteString("sub", _subject);
            writer.WriteEndObject();
        }
        var payloadPart = Base64Url.EncodeToString(buffer.ToArray());

        var signingInput = System.Text.Encoding.ASCII.GetBytes($"{headerPart}.{payloadPart}");
        // .NET emits IEEE P1363 (r ‖ s), which is exactly what JWS ES256 requires.
        var signature = _key.SignData(signingInput, HashAlgorithmName.SHA256);
        return $"{headerPart}.{payloadPart}.{Base64Url.EncodeToString(signature)}";
    }

    public void Dispose() {
        _key.Dispose();
    }
}
