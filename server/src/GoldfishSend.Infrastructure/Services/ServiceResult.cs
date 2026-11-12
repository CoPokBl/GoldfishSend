namespace GoldfishSend.Infrastructure.Services;

public sealed record ServiceError(int Status, string Code, TimeSpan? RetryAfter = null) {
    public static readonly ServiceError InvalidRequest = new(400, "invalid_request");
    public static readonly ServiceError InvalidEndpoint = new(400, "invalid_endpoint");
    public static readonly ServiceError PowInvalid = new(403, "pow_invalid");
    public static readonly ServiceError VerificationFailed = new(403, "verification_failed");
    public static readonly ServiceError NotFound = new(404, "not_found");
    public static readonly ServiceError MailboxExists = new(409, "mailbox_exists");
    public static readonly ServiceError TooLarge = new(413, "too_large");
    public static readonly ServiceError UnsupportedMediaType = new(415, "unsupported_media_type");
    public static readonly ServiceError EndpointUnreachable = new(502, "endpoint_unreachable");
    public static readonly ServiceError MailboxFull = new(507, "mailbox_full", TimeSpan.FromHours(1));
    public static readonly ServiceError Unavailable = new(503, "unavailable");

    public static ServiceError RateLimited(TimeSpan retryAfter) => new(429, "rate_limited", retryAfter);
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
