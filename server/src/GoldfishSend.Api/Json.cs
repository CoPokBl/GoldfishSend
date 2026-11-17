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

/// <param name="EndpointGone">The server can't reach at least one of these mailboxes' push endpoint: re-register push and rotate.</param>
public sealed record ExpiresResponse(string ExpiresAt, bool EndpointGone);

public sealed record IdResponse(string Id);

/// <summary>One entry of a batch send response: <c>202</c> with <c>id</c>, or an error exactly as a single send would return it.</summary>
public sealed record BatchItemResult(int Status, string? Id = null, string? Error = null, string? Scope = null, int? RetryAfter = null);

public sealed record BatchSendResponse(BatchItemResult[] Results);

public sealed record ErrorResponse(string Error, string? Scope = null);

/// <param name="Scheme">Always <c>gf/pow/v2</c>: Argon2id with these parameters (docs/protocol.md).</param>
/// <param name="Purpose"><c>create</c> or <c>send</c>: what the challenge can pay for.</param>
/// <param name="TtlSeconds">How long it stays valid from now, so clients can refresh it without trusting their clock.</param>
public sealed record PowChallengeResponse(
    string Scheme, string Purpose, string Challenge, int Difficulty, int MemoryKiB, int Iterations, int TtlSeconds, long ExpiresAt);

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
[JsonSerializable(typeof(BatchSendResponse))]
[JsonSerializable(typeof(ErrorResponse))]
[JsonSerializable(typeof(PowChallengeResponse))]
[JsonSerializable(typeof(InfoResponse))]
public sealed partial class ApiJsonContext : JsonSerializerContext;
