using System.Globalization;
using GoldfishSend.Core.Crypto;
using GoldfishSend.Core.Options;
using GoldfishSend.Core.Protocol;
using GoldfishSend.Infrastructure.MySql;
using GoldfishSend.Infrastructure.Redis;
using GoldfishSend.Infrastructure.Services;
using Microsoft.AspNetCore.Mvc;
using StackExchange.Redis;
using static GoldfishSend.Api.Endpoints.HttpHelpers;

namespace GoldfishSend.Api.Endpoints;

public static class ApiEndpoints {
    public const string SendTokenHeader = "GF-Send-Token";
    public const string IdempotencyHeader = "GF-Idempotency-Key";
    public const string TtlHeader = "GF-TTL";
    public const string PowHeader = "GF-PoW";

    public static void MapGoldfishApi(this WebApplication app) {
        var v1 = app.MapGroup("/v1");

        v1.MapGet("/info", GetInfo);
        v1.MapPost("/pow/challenge", IssueChallenge);

        v1.MapPost("/mailboxes", CreateMailbox);
        v1.MapPost("/mailboxes/verify", VerifyMailboxes);
        v1.MapPut("/mailboxes/endpoint", RotateEndpoint);
        v1.MapPost("/mailboxes/refresh", RefreshMailboxes);
        v1.MapPost("/mailboxes/delete", DeleteMailboxes);

        v1.MapPost("/messages", SendMessage);
        v1.MapPost("/messages/batch", SendBatch);

        v1.MapPost("/invites", CreateInvite);
        v1.MapGet("/invites/{id}", TakeInvite);

        app.MapGoldfishHealth();
    }

    /// <summary>Liveness and readiness. Every role maps these. The reverse proxy must not expose them publicly.</summary>
    public static void MapGoldfishHealth(this WebApplication app) {
        app.MapGet("/healthz", () => Results.Text("ok"));
        app.MapGet("/readyz", Ready);
    }

    private static async Task<IResult> GetInfo(GoldfishOptions options, VapidSigner vapid, PowService pow) {
        return Results.Json(new InfoResponse(
            ProtocolLimits.ProtocolVersion,
            vapid.PublicKeyBase64Url,
            ProtocolLimits.MaxMessageBytes,
            ProtocolLimits.MaxInviteBytes,
            options.Messages.DefaultTtlSeconds,
            options.Messages.MaxTtlSeconds,
            await pow.CurrentDifficultyAsync()), ApiJsonContext.Default.InfoResponse);
    }

    private static async Task<IResult> IssueChallenge(HttpContext context, PowService pow, RateLimiter limiter) {
        var client = Subject(context);
        foreach (var (policy, subject) in new[] { (RatePolicies.PowPerIp, client.Host), (RatePolicies.PowPerNetwork, client.Network) }) {
            var limit = await limiter.CheckAsync(policy, subject);
            if (!limit.Allowed) {
                return Error(ServiceError.RateLimited(limit));
            }
        }
        var challenge = await pow.IssueAsync();
        return Results.Json(
            new PowChallengeResponse(B64(challenge.Challenge), challenge.Difficulty, challenge.ExpiresAt.ToUnixTimeSeconds()),
            ApiJsonContext.Default.PowChallengeResponse);
    }

    private static async Task<IResult> CreateMailbox(
        HttpContext context, [FromBody] CreateMailboxRequest request, MailboxService mailboxes, CancellationToken ct) {
        var challenge = B64(request.Pow?.Challenge, ProofOfWork.ChallengeSize);
        var nonce = B64(request.Pow?.Nonce, ProofOfWork.NonceSize);
        var sendSecret = B64(request.SendSecret, MailboxCrypto.SecretSize);
        var ownerHash = B64(request.OwnerHash, 32);
        var endpoint = ParseEndpoint(request.Endpoint, request.P256dh, request.Auth);
        if (challenge is null || nonce is null || sendSecret is null || ownerHash is null || endpoint is null) {
            return Error(ServiceError.InvalidRequest);
        }

        var result = await mailboxes.CreateAsync(challenge, nonce, sendSecret, ownerHash, endpoint, Subject(context), ct);
        return result.Ok
            ? Results.Json(new StatusResponse("pending_verification"), ApiJsonContext.Default.StatusResponse, statusCode: 202)
            : Error(result.Error!);
    }

    private static async Task<IResult> VerifyMailboxes(
        HttpContext context, [FromBody] VerifyRequest request, MailboxService mailboxes, CancellationToken ct) {
        var items = ParseItems(request.Items);
        var code = B64(request.Code, PushEnvelope.VerificationCodeSize);
        if (items is null || code is null) {
            return Error(ServiceError.InvalidRequest);
        }
        var result = await mailboxes.VerifyAsync(items, code, Subject(context), ct);
        return result.Ok ? Expires(result.Value!) : Error(result.Error!);
    }

    private static async Task<IResult> RotateEndpoint(
        HttpContext context, [FromBody] RotateRequest request, MailboxService mailboxes, CancellationToken ct) {
        var items = ParseItems(request.Items);
        var endpoint = ParseEndpoint(request.Endpoint, request.P256dh, request.Auth);
        if (items is null || endpoint is null) {
            return Error(ServiceError.InvalidRequest);
        }
        var result = await mailboxes.RotateAsync(items, endpoint, Subject(context), ct);
        return result.Ok
            ? Results.Json(new StatusResponse("pending_verification"), ApiJsonContext.Default.StatusResponse, statusCode: 202)
            : Error(result.Error!);
    }

    private static async Task<IResult> RefreshMailboxes(
        HttpContext context, [FromBody] BatchRequest request, MailboxService mailboxes, CancellationToken ct) {
        var items = ParseItems(request.Items);
        if (items is null) {
            return Error(ServiceError.InvalidRequest);
        }
        var result = await mailboxes.RefreshAsync(items, Subject(context), ct);
        return result.Ok ? Expires(result.Value!) : Error(result.Error!);
    }

    private static async Task<IResult> DeleteMailboxes(
        HttpContext context, [FromBody] BatchRequest request, MailboxService mailboxes, CancellationToken ct) {
        var items = ParseItems(request.Items);
        if (items is null) {
            return Error(ServiceError.InvalidRequest);
        }
        var result = await mailboxes.DeleteAsync(items, Subject(context), ct);
        return result.Ok ? Results.NoContent() : Error(result.Error!);
    }

    private static async Task<IResult> SendMessage(HttpContext context, MessageService messages, CancellationToken ct) {
        var request = context.Request;
        if (!IsOctetStream(request)) {
            return Error(ServiceError.UnsupportedMediaType);
        }
        var sendSecret = B64(request.Headers[SendTokenHeader].ToString(), MailboxCrypto.SecretSize);
        if (sendSecret is null) {
            return Error(ServiceError.InvalidRequest);
        }

        byte[]? idempotencyKey = null;
        if (request.Headers.ContainsKey(IdempotencyHeader)) {
            idempotencyKey = B64(request.Headers[IdempotencyHeader].ToString(), ProtocolLimits.IdempotencyKeySize);
            if (idempotencyKey is null) {
                return Error(ServiceError.InvalidRequest);
            }
        }

        var body = await ReadBodyAsync(request, ProtocolLimits.MaxMessageBytes, ct);
        if (body is null) {
            return Error(ServiceError.TooLarge);
        }

        var result = await messages.AcceptAsync(
            sendSecret, body, IntHeader(request, TtlHeader), idempotencyKey, ParsePow(request), Subject(context), ct);
        return result.Ok
            ? Results.Json(new IdResponse(B64(result.Value!)), ApiJsonContext.Default.IdResponse, statusCode: 202)
            : Error(result.Error!);
    }

    private static async Task<IResult> SendBatch(HttpContext context, MessageService messages, CancellationToken ct) {
        var request = context.Request;
        if (!IsOctetStream(request)) {
            return Error(ServiceError.UnsupportedMediaType);
        }
        var body = await ReadBodyAsync(request, GatewayCodec.MaxRequestBody, ct);
        if (body is null) {
            return Error(ServiceError.TooLarge);
        }
        var items = MessageBatch.TryParse(body);
        if (items is null) {
            return Error(ServiceError.InvalidRequest);
        }

        var result = await messages.AcceptBatchAsync(items, ParsePow(request), Subject(context), ct);
        if (!result.Ok) {
            return Error(result.Error!);
        }
        var results = new BatchItemResult[result.Value!.Count];
        for (var i = 0; i < results.Length; i++) {
            var item = result.Value[i];
            results[i] = item.Ok
                ? new BatchItemResult(202, Id: B64(item.Value!))
                : new BatchItemResult(item.Error!.Status, Error: item.Error.Code, Scope: item.Error.Scope,
                    RetryAfter: item.Error.RetryAfter is { } retry ? Math.Max(1, (int)Math.Ceiling(retry.TotalSeconds)) : null);
        }
        return Results.Json(new BatchSendResponse(results), ApiJsonContext.Default.BatchSendResponse);
    }

    private static async Task<IResult> CreateInvite(HttpContext context, InviteService invites, CancellationToken ct) {
        if (!IsOctetStream(context.Request)) {
            return Error(ServiceError.UnsupportedMediaType);
        }
        var body = await ReadBodyAsync(context.Request, ProtocolLimits.MaxInviteBytes, ct);
        if (body is null) {
            return Error(ServiceError.TooLarge);
        }
        var result = await invites.CreateAsync(body, IntHeader(context.Request, TtlHeader), Subject(context));
        return result.Ok
            ? Results.Json(new IdResponse(B64(result.Value!)), ApiJsonContext.Default.IdResponse, statusCode: 201)
            : Error(result.Error!);
    }

    private static async Task<IResult> TakeInvite(HttpContext context, string id, InviteService invites) {
        var inviteId = B64(id, ProtocolLimits.InviteIdSize);
        if (inviteId is null) {
            return Error(ServiceError.NotFound);
        }
        var result = await invites.TakeAsync(inviteId, Subject(context));
        return result.Ok ? Results.Bytes(result.Value!, "application/octet-stream") : Error(result.Error!);
    }

    private static async Task<IResult> Ready(Db db, IConnectionMultiplexer redis, CancellationToken ct) {
        try {
            await using var conn = await db.OpenAsync(ct);
            await using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT 1";
            await cmd.ExecuteScalarAsync(ct);
            await redis.GetDatabase().PingAsync();
            return Results.Text("ready");
        } catch (Exception) {
            return Results.Text("not ready", statusCode: 503);
        }
    }

    private static IResult Expires(MailboxStatus status) {
        return Results.Json(
            new ExpiresResponse(status.ExpiresAt.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture), status.EndpointGone),
            ApiJsonContext.Default.ExpiresResponse);
    }

    private static NewEndpoint? ParseEndpoint(string? url, string? p256dh, string? auth) {
        var key = B64(p256dh, WebPushCrypto.PublicKeySize);
        var secret = B64(auth, WebPushCrypto.AuthSecretSize);
        if (string.IsNullOrEmpty(url) || key is null || secret is null) {
            return null;
        }
        return new NewEndpoint(url, key, secret);
    }

    private static List<MailboxCredential>? ParseItems(MailboxCredentialDto[]? items) {
        if (items is null || items.Length == 0 || items.Length > 100) {
            return null;
        }
        var result = new List<MailboxCredential>(items.Length);
        foreach (var item in items) {
            if (item is null) {
                return null;
            }
            var send = B64(item.SendSecret, MailboxCrypto.SecretSize);
            var owner = B64(item.OwnerSecret, MailboxCrypto.SecretSize);
            if (send is null || owner is null) {
                return null;
            }
            result.Add(new MailboxCredential(send, owner));
        }
        return result;
    }

    private static PowToken? ParsePow(HttpRequest request) {
        var raw = request.Headers[PowHeader].ToString();
        var dot = raw.IndexOf('.');
        if (dot <= 0) {
            return null;
        }
        var challenge = B64(raw[..dot], ProofOfWork.ChallengeSize);
        var nonce = B64(raw[(dot + 1)..], ProofOfWork.NonceSize);
        return challenge is null || nonce is null ? null : new PowToken(challenge, nonce);
    }
}
