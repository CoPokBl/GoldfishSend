using GoldfishSend.Infrastructure.Redis;

namespace GoldfishSend.Infrastructure.Services;

/// <param name="Scope">For <c>rate_limited</c>: which limit was hit (<c>ip</c>, <c>network</c>, <c>mailbox</c>, <c>global</c>).</param>
public sealed record ServiceError(int Status, string Code, TimeSpan? RetryAfter = null, string? Scope = null) {
    public static readonly ServiceError InvalidRequest = new(400, "invalid_request");
    public static readonly ServiceError InvalidEndpoint = new(400, "invalid_endpoint");
    public static readonly ServiceError PowInvalid = new(403, "pow_invalid");
    public static readonly ServiceError VerificationFailed = new(403, "verification_failed");
    public static readonly ServiceError NotFound = new(404, "not_found");
    public static readonly ServiceError MailboxExists = new(409, "mailbox_exists");
    public static readonly ServiceError TooLarge = new(413, "too_large");
    public static readonly ServiceError UnsupportedMediaType = new(415, "unsupported_media_type");
    public static readonly ServiceError EndpointUnreachable = new(502, "endpoint_unreachable");
    /// <summary>This mailbox holds its maximum number of undelivered messages.</summary>
    public static readonly ServiceError MailboxFull = new(507, "mailbox_full", TimeSpan.FromHours(1), "mailbox");
    /// <summary>The server-wide held-message quota is reached, and this mailbox would add to the backlog.</summary>
    public static readonly ServiceError StorageFull = new(507, "mailbox_full", TimeSpan.FromHours(1), "global");
    public static readonly ServiceError Unavailable = new(503, "unavailable");
    /// <summary>Every PoW verification slot is busy. The challenge is still valid: retry the same solution.</summary>
    public static readonly ServiceError PowBusy = new(503, "unavailable", TimeSpan.FromSeconds(1));

    public static ServiceError? FromPow(PowRedemption redemption) => redemption switch {
        PowRedemption.Ok => null,
        PowRedemption.Busy => PowBusy,
        _ => PowInvalid,
    };

    public static ServiceError RateLimited(RateLimitDecision decision) => new(429, "rate_limited", decision.RetryAfter, decision.Scope);
}

public readonly struct ServiceResult<T> {
    public T? Value { get; }
    public ServiceError? Error { get; }
    public bool Ok => Error is null;

    private ServiceResult(T? value, ServiceError? error) {
        Value = value;
        Error = error;
    }

    public static implicit operator ServiceResult<T>(T value) => new(value, null);
    public static implicit operator ServiceResult<T>(ServiceError error) => new(default, error);
}
