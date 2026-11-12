using System.Text.Json.Serialization;

namespace GoldfishSend.Api;

public sealed record PowSolutionDto(string? Challenge, string? Nonce);

public sealed record CreateMailboxRequest(
    PowSolutionDto? Pow, string? SendSecret, string? OwnerHash, string? Endpoint, string? P256dh, string? Auth);

public sealed record MailboxCredentialDto(string? SendSecret, string? OwnerSecret);

public sealed record VerifyRequest(MailboxCredentialDto[]? Items, string? Code);

public sealed record RotateRequest(MailboxCredentialDto[]? Items, string? Endpoint, string? P256dh, string? Auth);

public sealed record BatchRequest(MailboxCredentialDto[]? Items);

public sealed record StatusResponse(string Status);

public sealed record ExpiresResponse(string ExpiresAt);

public sealed record IdResponse(string Id);

public sealed record ErrorResponse(string Error, string? Scope = null);

public sealed record PowChallengeResponse(string Challenge, int Difficulty, long ExpiresAt);

public sealed record InfoResponse(
    int Protocol, string VapidPublicKey, int MaxMessageBytes, int MaxInviteBytes, int DefaultTtlSeconds, int MaxTtlSeconds,
    int PowDifficulty);

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    UnmappedMemberHandling = JsonUnmappedMemberHandling.Skip)]
[JsonSerializable(typeof(CreateMailboxRequest))]
[JsonSerializable(typeof(VerifyRequest))]
[JsonSerializable(typeof(RotateRequest))]
[JsonSerializable(typeof(BatchRequest))]
[JsonSerializable(typeof(StatusResponse))]
[JsonSerializable(typeof(ExpiresResponse))]
[JsonSerializable(typeof(IdResponse))]
[JsonSerializable(typeof(ErrorResponse))]
[JsonSerializable(typeof(PowChallengeResponse))]
[JsonSerializable(typeof(InfoResponse))]
public sealed partial class ApiJsonContext : JsonSerializerContext;
