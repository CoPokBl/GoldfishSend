namespace GoldfishSend.Core.Protocol;

public static class ProtocolLimits {
    public const int ProtocolVersion = 2;
    public const int MaxMessageBytes = PushEnvelope.MaxBodySize;
    public const int MaxInviteBytes = 4096;
    public const int IdempotencyKeySize = 16;
    public const int MessageIdSize = 16;
    public const int InviteIdSize = 16;
}
