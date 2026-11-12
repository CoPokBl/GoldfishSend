using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using GoldfishSend.Core.Crypto;
using GoldfishSend.Core.Net;
using GoldfishSend.Core.Options;
using GoldfishSend.Core.Protocol;
using Microsoft.Extensions.Logging;

namespace GoldfishSend.Infrastructure.Push;

public enum PushStatus {
    /// <summary>The push server accepted the message (2xx). The message has left our hands.</summary>
    Delivered,
    /// <summary>The subscription no longer exists (404, 410), or the destination is forbidden.</summary>
    Gone,
    /// <summary>A temporary failure: timeout, connection error, 429, 5xx, or 401/403 (usually VAPID or clock trouble, retried slowly).</summary>
    Transient,
    /// <summary>The push server rejected this particular message (400, 413, other 4xx), so retrying won't help.</summary>
    Rejected,
}

public readonly record struct PushResult(PushStatus Status, TimeSpan? RetryAfter = null);

/// <summary>Thrown from the connect callback when every resolved address for a host is forbidden.</summary>
public sealed class ForbiddenDestinationException : Exception {
    public ForbiddenDestinationException() : base("Destination resolves only to forbidden addresses.") { }
}

/// <summary>
/// Sends Web Push requests to untrusted, client-supplied URLs without giving attackers a way into internal networks:
/// <list type="bullet">
/// <item>DNS is resolved inside the connect callback, and every address is checked by <see cref="IpRangeFilter"/> at
/// connect time. That defeats DNS rebinding (there's no gap between the check and the connection).</item>
/// <item>No redirects, proxies, cookies or decompression. Strict timeouts, and capped response reads.</item>
/// <item>Per-host pacing, connection caps and a circuit breaker, so we can't be used to flood a push server.</item>
/// <item>Nothing identifying (URLs, tokens) is ever logged. Logs only see an opaque host fingerprint.</item>
/// </list>
/// The handler is built directly instead of through IHttpClientFactory, which also keeps the framework's
/// per-request URL logging out of the pipeline.
/// </summary>
public sealed class PushClient : IDisposable {
    private const int MaxResponseDrainBytes = 4096;

    private readonly HttpClient _http;
    private readonly IpRangeFilter _ipFilter;
    private readonly EndpointValidator _validator;
    private readonly VapidSigner _vapid;
    private readonly HostGuards _guards;
    private readonly ILogger<PushClient> _logger;
    private readonly TimeSpan _requestTimeout;

    public PushClient(
        GoldfishOptions options, IpRangeFilter ipFilter, EndpointValidator validator, VapidSigner vapid, HostGuards guards,
        ILogger<PushClient> logger) {
        _ipFilter = ipFilter;
        _validator = validator;
        _vapid = vapid;
        _guards = guards;
        _logger = logger;

        var push = options.Push;
        _requestTimeout = TimeSpan.FromSeconds(push.RequestTimeoutSeconds);
        var handler = new SocketsHttpHandler {
            AllowAutoRedirect = false,
            UseProxy = false,
            UseCookies = false,
            AutomaticDecompression = DecompressionMethods.None,
            ConnectTimeout = TimeSpan.FromSeconds(push.ConnectTimeoutSeconds),
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            PooledConnectionIdleTimeout = TimeSpan.FromMinutes(1),
            MaxConnectionsPerServer = push.MaxConnectionsPerHost,
            MaxResponseHeadersLength = 16,
            MaxResponseDrainSize = MaxResponseDrainBytes,
            ResponseDrainTimeout = TimeSpan.FromSeconds(2),
            SslOptions = new SslClientAuthenticationOptions {
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                CertificateRevocationCheckMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck,
            },
            ConnectCallback = ConnectAsync,
        };
        _http = new HttpClient(handler, disposeHandler: true) {
            Timeout = TimeSpan.FromSeconds(push.RequestTimeoutSeconds),
            // Never upgrade to HTTP/3: QUIC bypasses ConnectCallback and with it the SSRF filter.
            DefaultRequestVersion = HttpVersion.Version11,
            DefaultVersionPolicy = HttpVersionPolicy.RequestVersionOrLower,
        };
        _http.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("GoldfishSend", "1"));
    }

    public async Task<PushResult> SendAsync(EndpointRecord endpoint, byte[] plaintext, int ttlSeconds, CancellationToken ct) {
        // Re-validate on every send. Stored records were validated at registration, but rules may have tightened since.
        if (!_validator.TryValidate(endpoint.Url, out var uri)) {
            return new PushResult(PushStatus.Gone);
        }
        var host = uri.IdnHost.ToLowerInvariant();

        var gate = await _guards.TryEnterAsync(host);
        if (gate.Lease is not { } lease) {
            return new PushResult(PushStatus.Transient, gate.RetryAfter);
        }

        var success = false;
        // One deadline covers connect, headers and body. HttpClient.Timeout alone doesn't bound reading a
        // response body, so a hostile endpoint could otherwise tarpit a delivery slot forever.
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(_requestTimeout);
        try {
            var body = WebPushCrypto.Encrypt(plaintext, endpoint.P256dh, endpoint.Auth);
            using var request = new HttpRequestMessage(HttpMethod.Post, uri) {
                Content = new ByteArrayContent(body),
                Version = HttpVersion.Version11,
                VersionPolicy = HttpVersionPolicy.RequestVersionOrLower,
            };
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
            request.Content.Headers.ContentEncoding.Add("aes128gcm");
            request.Headers.TryAddWithoutValidation("TTL", Math.Max(0, ttlSeconds).ToString(CultureInfo.InvariantCulture));
            request.Headers.TryAddWithoutValidation("Urgency", "high");
            request.Headers.TryAddWithoutValidation("Authorization", _vapid.GetAuthorizationHeader(uri, DateTimeOffset.UtcNow));

            // The body is never read. Disposing the response lets the handler drain at most
            // MaxResponseDrainSize bytes within ResponseDrainTimeout, or else drop the connection.
            using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token);

            var result = Classify(response);
            success = result.Status is PushStatus.Delivered or PushStatus.Gone or PushStatus.Rejected;
            if (result.Status != PushStatus.Delivered) {
                _logger.LogInformation("Push to host {Host} returned {Status} ({Code})",
                    HostGuards.Fingerprint(host), result.Status, (int)response.StatusCode);
            }
            return result;
        } catch (HttpRequestException ex) when (ex.InnerException is ForbiddenDestinationException) {
            success = true; // The host answered DNS "correctly". This isn't host flakiness.
            _logger.LogWarning("Push host {Host} resolved to a forbidden address", HostGuards.Fingerprint(host));
            return new PushResult(PushStatus.Gone);
        } catch (Exception ex) when (ex is HttpRequestException or IOException or SocketException
                                         || (ex is TaskCanceledException && !ct.IsCancellationRequested)) {
            _logger.LogInformation("Push to host {Host} failed: {Error}", HostGuards.Fingerprint(host), ex.GetType().Name);
            return new PushResult(PushStatus.Transient);
        } finally {
            await lease.ExitAsync(success);
        }
    }

    internal static PushResult Classify(HttpResponseMessage response) {
        var code = (int)response.StatusCode;
        return code switch {
            >= 200 and < 300 => new PushResult(PushStatus.Delivered),
            404 or 410 => new PushResult(PushStatus.Gone),
            // Usually our VAPID key or clock. Never treat it as a dead subscription; retry slowly.
            401 or 403 => new PushResult(PushStatus.Transient, TimeSpan.FromHours(1)),
            429 or 408 or 425 => new PushResult(PushStatus.Transient, ParseRetryAfter(response)),
            >= 500 => new PushResult(PushStatus.Transient, ParseRetryAfter(response)),
            _ => new PushResult(PushStatus.Rejected),
        };
    }

    private static TimeSpan? ParseRetryAfter(HttpResponseMessage response) {
        var header = response.Headers.RetryAfter;
        TimeSpan? value = header?.Delta ?? (header?.Date is { } date ? date - DateTimeOffset.UtcNow : null);
        if (value is not { } v || v <= TimeSpan.Zero) {
            return null;
        }
        return v > TimeSpan.FromHours(6) ? TimeSpan.FromHours(6) : v;
    }

    private async ValueTask<Stream> ConnectAsync(SocketsHttpConnectionContext context, CancellationToken ct) {
        var endpoint = context.DnsEndPoint;
        IPAddress[] addresses = IPAddress.TryParse(endpoint.Host, out var literal)
            ? [literal]
            : await Dns.GetHostAddressesAsync(endpoint.Host, ct);

        var allowed = addresses.Where(_ipFilter.IsAllowed).ToArray();
        if (allowed.Length == 0) {
            throw new ForbiddenDestinationException();
        }

        Exception? last = null;
        foreach (var address in allowed) {
            var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            try {
                await socket.ConnectAsync(new IPEndPoint(address, endpoint.Port), ct);
                // Belt and braces: check the address the kernel actually connected to.
                if (socket.RemoteEndPoint is not IPEndPoint remote || !_ipFilter.IsAllowed(remote.Address)) {
                    throw new ForbiddenDestinationException();
                }
                return new NetworkStream(socket, ownsSocket: true);
            } catch (SocketException ex) {
                socket.Dispose();
                last = ex;
            } catch {
                socket.Dispose();
                throw;
            }
        }
        throw last ?? new SocketException((int)SocketError.HostUnreachable);
    }

    public void Dispose() {
        _http.Dispose();
    }
}
