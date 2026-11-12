using GoldfishSend.Core.Crypto;

namespace GoldfishSend.Core.Protocol;

public enum PushType : byte {
    Message = 0x01,
    Verification = 0x02,
}

/// <summary>The plaintext inside the Web Push layer: version ‖ type ‖ mailboxTag(8) ‖ body.</summary>
public static class PushEnvelope {
    public const byte Version = 0x01;
    public const int HeaderSize = 2 + MailboxCrypto.TagSize; // 10
    public const int MaxBodySize = WebPushCrypto.MaxPlaintextSize - HeaderSize; // 3983
    public const int VerificationCodeSize = 16;

    public static byte[] Build(PushType type, ReadOnlySpan<byte> tag, ReadOnlySpan<byte> body) {
        if (tag.Length != MailboxCrypto.TagSize) {
            throw new ArgumentException("Tag must be 8 bytes.", nameof(tag));
        }
        if (body.Length > MaxBodySize) {
            throw new ArgumentException($"Body exceeds {MaxBodySize} bytes.", nameof(body));
        }
        var output = new byte[HeaderSize + body.Length];
        output[0] = Version;
        output[1] = (byte)type;
        tag.CopyTo(output.AsSpan(2));
        body.CopyTo(output.AsSpan(HeaderSize));
        return output;
    }

    public static bool TryParse(ReadOnlySpan<byte> data, out PushType type, out byte[] tag, out byte[] body) {
        type = default;
        tag = [];
        body = [];
        if (data.Length < HeaderSize || data[0] != Version) {
            return false;
        }
        type = (PushType)data[1];
        if (type is not (PushType.Message or PushType.Verification)) {
            return false;
        }
        tag = data.Slice(2, MailboxCrypto.TagSize).ToArray();
        body = data[HeaderSize..].ToArray();
        return true;
    }
}
