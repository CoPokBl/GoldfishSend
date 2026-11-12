using System.Buffers.Binary;
using System.Text;
using GoldfishSend.Core.Crypto;

namespace GoldfishSend.Core.Protocol;

/// <summary>A device's UnifiedPush subscription. It only ever exists in plaintext in memory.</summary>
public sealed record EndpointRecord(string Url, byte[] P256dh, byte[] Auth) {
    public const int MaxUrlBytes = 2048;

    /// <summary>Format: u16 BE url length ‖ url (UTF-8) ‖ p256dh (65) ‖ auth (16).</summary>
    public byte[] Serialize() {
        if (P256dh.Length != WebPushCrypto.PublicKeySize || Auth.Length != WebPushCrypto.AuthSecretSize) {
            throw new ArgumentException("p256dh must be 65 bytes and auth 16 bytes.");
        }
        var url = Encoding.UTF8.GetBytes(Url);
        if (url.Length > MaxUrlBytes) {
            throw new ArgumentException("Endpoint URL too long.");
        }
        var output = new byte[2 + url.Length + WebPushCrypto.PublicKeySize + WebPushCrypto.AuthSecretSize];
        BinaryPrimitives.WriteUInt16BigEndian(output, (ushort)url.Length);
        url.CopyTo(output, 2);
        P256dh.CopyTo(output, 2 + url.Length);
        Auth.CopyTo(output, 2 + url.Length + WebPushCrypto.PublicKeySize);
        return output;
    }

    public static EndpointRecord Deserialize(ReadOnlySpan<byte> data) {
        if (data.Length < 2) {
            throw new FormatException("Truncated endpoint record.");
        }
        int urlLength = BinaryPrimitives.ReadUInt16BigEndian(data);
        var expected = 2 + urlLength + WebPushCrypto.PublicKeySize + WebPushCrypto.AuthSecretSize;
        if (urlLength > MaxUrlBytes || data.Length != expected) {
            throw new FormatException("Malformed endpoint record.");
        }
        var url = Encoding.UTF8.GetString(data.Slice(2, urlLength));
        var p256dh = data.Slice(2 + urlLength, WebPushCrypto.PublicKeySize).ToArray();
        var auth = data.Slice(2 + urlLength + WebPushCrypto.PublicKeySize, WebPushCrypto.AuthSecretSize).ToArray();
        return new EndpointRecord(url, p256dh, auth);
    }

    // Keep secrets out of logs if a record is ever formatted.
    public override string ToString() => "EndpointRecord { <redacted> }";
}
