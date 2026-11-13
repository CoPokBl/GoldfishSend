using System.Net;
using System.Text;
using System.Text.Json;
using GoldfishSend.Api;
using GoldfishSend.Core.Crypto;
using GoldfishSend.Core.Options;
using GoldfishSend.Core.Protocol;
using GoldfishSend.Infrastructure.Redis;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using StackExchange.Redis;
using static GoldfishSend.Tests.Integration.GoldfishFixture;

namespace GoldfishSend.Tests.Integration;

[Collection(GoldfishCollection.Name)]
public sealed class GatewayTests {
    private readonly GoldfishFixture _f;

    public GatewayTests(GoldfishFixture fixture) {
        _f = fixture;
    }

    private Task<ServerPublicKey> KeyAsync() => _f.Gateway.KeyAsync(_f.RawClient.BaseAddress!, default);

    private static long Now => DateTimeOffset.UtcNow.ToUnixTimeSeconds();

    private static InnerRequest Get(string path, long? timestamp = null) => new("GET", timestamp ?? Now, path, [], []);

    private async Task<(HttpResponseMessage Outer, byte[] RespSecret, byte[] OuterRequest)> PostRawAsync(InnerRequest inner) {
        var (outer, respSecret) = (await KeyAsync()).Seal(GatewayCodec.EncodeRequest(inner));
        return (await _f.RawClient.PostAsync("/v1/gw", Octets(outer)), respSecret, outer);
    }

    private static async Task<InnerResponse> OpenAsync(HttpResponseMessage outer, byte[] respSecret) {
        Assert.Equal(HttpStatusCode.OK, outer.StatusCode);
        Assert.Equal("application/octet-stream", outer.Content.Headers.ContentType?.MediaType);
        var sealedBody = await outer.Content.ReadAsByteArrayAsync();
        var plaintext = GatewayCrypto.OpenResponse(respSecret, sealedBody);
        Assert.NotNull(plaintext);
        Assert.True(GatewayCodec.TryDecodeResponse(plaintext, out var inner));
        return inner;
    }

    private static string Error(InnerResponse response) =>
        JsonDocument.Parse(response.Body).RootElement.GetProperty("error").GetString()!;

    private static async Task<string> OuterError(HttpResponseMessage response) =>
        JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement.GetProperty("error").GetString()!;

    [IntegrationFact]
    public async Task PlaintextApi_IsUnreachable() {
        Assert.Equal(HttpStatusCode.NotFound, (await _f.RawClient.GetAsync("/v1/info")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await _f.RawClient.PostAsync("/v1/messages", Octets([1]))).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await _f.RawClient.GetAsync("/V1/INFO")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await _f.RawClient.GetAsync("/v1")).StatusCode);
        Assert.Equal(HttpStatusCode.MethodNotAllowed, (await _f.RawClient.GetAsync("/v1/gw")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await _f.RawClient.GetAsync("/healthz")).StatusCode);
        // Through the gateway the same endpoint works.
        Assert.Equal(HttpStatusCode.OK, (await _f.Client.GetAsync("/v1/info")).StatusCode);
    }

    [IntegrationFact]
    public async Task Key_IsTheConfiguredKey() {
        var response = await _f.RawClient.GetAsync("/v1/key");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("application/octet-stream", response.Content.Headers.ContentType?.MediaType);
        var blob = await response.Content.ReadAsByteArrayAsync();
        var expected = new ServerKey(_f.ServerSecret);
        Assert.Equal(expected.Blob, blob);
        Assert.NotNull(ServerPublicKey.TryParse(blob, expected.Fingerprint));
    }

    [IntegrationFact]
    public async Task Tampering_IsRejectedWithoutDetail() {
        var (outer, _) = (await KeyAsync()).Seal(GatewayCodec.EncodeRequest(Get("/v1/info")));
        foreach (var index in new[] { 0, 500, 1100, 1170, outer.Length - 1 }) {
            var copy = outer.ToArray();
            copy[index] ^= 0x04;
            var response = await _f.RawClient.PostAsync("/v1/gw", Octets(copy));
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Equal("bad_request", await OuterError(response));
        }
        var keyId = outer.ToArray();
        keyId[3] ^= 0x01;
        var unknown = await _f.RawClient.PostAsync("/v1/gw", Octets(keyId));
        Assert.Equal((HttpStatusCode)421, unknown.StatusCode);
        Assert.Equal("unknown_key", await OuterError(unknown));

        Assert.Equal(HttpStatusCode.BadRequest, (await _f.RawClient.PostAsync("/v1/gw", Octets(outer[..100]))).StatusCode);
        var text = new ByteArrayContent(outer);
        text.Headers.ContentType = new("text/plain");
        Assert.Equal(HttpStatusCode.BadRequest, (await _f.RawClient.PostAsync("/v1/gw", text)).StatusCode);
    }

    [IntegrationFact]
    public async Task Replay_GetsAnEncrypted409() {
        var (first, respSecret, outer) = await PostRawAsync(Get("/v1/info"));
        Assert.Equal(200, (await OpenAsync(first, respSecret)).Status);
        var replay = await _f.RawClient.PostAsync("/v1/gw", Octets(outer));
        var inner = await OpenAsync(replay, respSecret);
        Assert.Equal(409, inner.Status);
        Assert.Equal("replay", Error(inner));
    }

    [IntegrationFact]
    public async Task ClockSkew_GetsAnEncrypted400WithTheServerTime() {
        foreach (var skew in new[] { -601L, 601L, -100_000L }) {
            var (response, respSecret, _) = await PostRawAsync(Get("/v1/info", Now + skew));
            var inner = await OpenAsync(response, respSecret);
            Assert.Equal(400, inner.Status);
            var json = JsonDocument.Parse(inner.Body).RootElement;
            Assert.Equal("clock_skew", json.GetProperty("error").GetString());
            Assert.InRange(json.GetProperty("serverTime").GetInt64(), Now - 5, Now + 5);
        }
        // Inside the window it's accepted.
        var (ok, okSecret, _) = await PostRawAsync(Get("/v1/info", Now - 590));
        Assert.Equal(200, (await OpenAsync(ok, okSecret)).Status);

        // A skewed client sees the (authenticated) clock_skew answer as a 400; the app then corrects its clock offset.
        _f.Gateway.ClockOffsetSeconds = -5000;
        try {
            var skewed = await _f.Client.GetAsync("/v1/info");
            Assert.Equal(HttpStatusCode.BadRequest, skewed.StatusCode);
        } finally {
            _f.Gateway.ClockOffsetSeconds = 0;
        }
    }

    [IntegrationFact]
    public async Task Sizes_ArePaddedToBuckets() {
        // GET /v1/info: a 512 B inner request, and a 512 B inner response.
        var (response, respSecret, outer) = await PostRawAsync(Get("/v1/info"));
        Assert.Equal(GatewayCrypto.RequestOverhead + 512, outer.Length);
        var body = await response.Content.ReadAsByteArrayAsync();
        Assert.Equal(GatewayCrypto.ResponseOverhead + 512, body.Length);
        Assert.NotNull(GatewayCrypto.OpenResponse(respSecret, body));

        // Messages: the framing (~150 B with the send token) pushes a full 3983 B message into the 8192 bucket, while
        // anything up to ~3.9 KB stays in 4096.
        InnerRequest Message(int size) => new("POST", Now, "/v1/messages",
            [new("content-type", "application/octet-stream"), new("gf-send-token", B64(new byte[32]))], new byte[size]);
        Assert.Equal(8192, GatewayCodec.EncodeRequest(Message(ProtocolLimits.MaxMessageBytes)).Length);
        Assert.Equal(4096, GatewayCodec.EncodeRequest(Message(3900)).Length);
    }

    [IntegrationFact]
    public async Task Oversize_IsRejected() {
        var key = await KeyAsync();
        // Inner bigger than the largest bucket.
        var (tooBigInner, _) = key.Seal(new byte[GatewayCodec.MaxInnerRequest + 1]);
        var r1 = await _f.RawClient.PostAsync("/v1/gw", Octets(tooBigInner));
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, r1.StatusCode);
        // Outer bigger than 20 KiB.
        var r2 = await _f.RawClient.PostAsync("/v1/gw", Octets(new byte[GatewayMiddleware.MaxOuterBody + 1]));
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, r2.StatusCode);
        // An inner body over 16 KiB decrypts fine, but is refused (encrypted).
        var (r3, secret, _) = await PostRawAsync(new InnerRequest("POST", Now, "/v1/invites",
            [new("content-type", "application/octet-stream")], new byte[16 * 1024 + 1]));
        var inner = await OpenAsync(r3, secret);
        Assert.Equal(400, inner.Status);
        Assert.Equal("bad_request", Error(inner));
    }

    [IntegrationFact]
    public async Task RateLimitAnswers_KeepRetryAfterInside_AndNothingOutside() {
        // Burn the per-mailbox send budget (default policy), then look at the 429.
        var mailbox = await _f.CreateActiveMailboxAsync();
        HttpResponseMessage? limited = null;
        for (var i = 0; i < 200 && limited is null; i++) {
            var response = await _f.SendAsync(mailbox.SendSecret, [(byte)i]);
            if (response.StatusCode == HttpStatusCode.TooManyRequests || (int)response.StatusCode == 507) {
                limited = response;
            }
        }
        Assert.NotNull(limited);
        Assert.True(limited.Headers.RetryAfter is not null, "Retry-After must survive the gateway");

        // The raw outer answer to the same kind of request carries no Retry-After and is a plain 200.
        var (outer, respSecret, _) = await PostRawAsync(new InnerRequest("POST", Now, "/v1/messages",
            [new("content-type", "application/octet-stream"), new("gf-send-token", B64(mailbox.SendSecret))], [1]));
        Assert.Equal(HttpStatusCode.OK, outer.StatusCode);
        Assert.False(outer.Headers.Contains("Retry-After"));
        var inner = await OpenAsync(outer, respSecret);
        Assert.Contains(inner.Status, new[] { 429, 507 });
        Assert.Contains(inner.Headers, h => h.Key == "retry-after");
    }

    /// <summary>Starts a node that pretends every connection comes from a trusted proxy at 10.9.9.9.</summary>
    private static WebApplicationFactory<Program> BehindProxy(Dictionary<string, string> overrides) {
        var previous = overrides.ToDictionary(kv => kv.Key, kv => Environment.GetEnvironmentVariable(kv.Key));
        foreach (var (k, v) in overrides) {
            Environment.SetEnvironmentVariable(k, v);
        }
        try {
            var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(b => {
                b.UseEnvironment("Development");
                b.ConfigureServices(s => s.AddSingleton<IStartupFilter, ProxyAddressFilter>());
            });
            _ = factory.Services; // Build now, while the overrides are set.
            return factory;
        } finally {
            foreach (var (k, v) in previous) {
                Environment.SetEnvironmentVariable(k, v);
            }
        }
    }

    private sealed class ProxyAddressFilter : IStartupFilter {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app => {
            app.Use((context, nextMiddleware) => {
                context.Connection.RemoteIpAddress = IPAddress.Parse("10.9.9.9");
                return nextMiddleware(context);
            });
            next(app);
        };
    }

    [IntegrationFact]
    public async Task RateLimits_StillUseTheOuterClientAddress() {
        await using var factory = BehindProxy(new() {
            ["Goldfish__Network__TrustedProxies__0"] = "10.9.9.9",
            ["Goldfish__Roles"] = "api",
            ["Goldfish__RateLimits__pow-ip__Limit"] = "1",
            ["Goldfish__RateLimits__pow-ip__Burst"] = "1",
            ["Goldfish__RateLimits__pow-ip__PeriodSeconds"] = "3600",
            ["Goldfish__RateLimits__pow-net__Burst"] = "100000",
        });
        using var client = GatewayHandler.Client(factory);

        async Task<HttpStatusCode> Challenge(string forwardedFor, string? innerSpoof = null) {
            using var request = new HttpRequestMessage(HttpMethod.Post, "/v1/pow/challenge");
            // The handler seals request headers into the inner request (a spoof attempt here), and adds the outer
            // X-Forwarded-For the way the trusted proxy would.
            if (innerSpoof is not null) {
                request.Headers.TryAddWithoutValidation("X-Forwarded-For", innerSpoof);
            }
            request.Options.Set(GatewayHandler.OuterForwardedFor, forwardedFor);
            return (await client.SendAsync(request)).StatusCode;
        }

        Assert.Equal(HttpStatusCode.OK, await Challenge("203.0.113.5"));
        Assert.Equal(HttpStatusCode.TooManyRequests, await Challenge("203.0.113.5"));
        // A different client behind the same proxy has its own bucket.
        Assert.Equal(HttpStatusCode.OK, await Challenge("198.51.100.7"));
        // An X-Forwarded-For inside the encrypted request is ignored: the limited client stays limited.
        Assert.Equal(HttpStatusCode.TooManyRequests, await Challenge("203.0.113.5", innerSpoof: "192.0.2.99"));
    }

    [IntegrationFact]
    public async Task FloodGuard_LimitsDecryptionWorkPerClient() {
        await using var factory = BehindProxy(new() {
            ["Goldfish__Network__TrustedProxies__0"] = "10.9.9.9",
            ["Goldfish__Roles"] = "api",
            ["Goldfish__Network__GatewayRequestsPerSecond"] = "0.01",
            ["Goldfish__Network__GatewayBurst"] = "2",
        });
        using var raw = factory.CreateClient();

        async Task<HttpResponseMessage> Junk(string forwardedFor) {
            using var request = new HttpRequestMessage(HttpMethod.Post, "/v1/gw") { Content = Octets(new byte[1300]) };
            request.Headers.TryAddWithoutValidation("X-Forwarded-For", forwardedFor);
            return await raw.SendAsync(request);
        }

        Assert.Equal(HttpStatusCode.BadRequest, (await Junk("203.0.113.5")).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await Junk("203.0.113.5")).StatusCode);
        var limited = await Junk("203.0.113.5");
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
        Assert.Equal("1", limited.Headers.GetValues("Retry-After").Single());
        Assert.Equal(HttpStatusCode.BadRequest, (await Junk("198.51.100.7")).StatusCode);
        // The public key stays reachable.
        Assert.Equal(HttpStatusCode.OK, (await raw.GetAsync("/v1/key")).StatusCode);
    }

    [IntegrationFact]
    public async Task TwoNodes_ShareTheKey_AndTheReplayCache() {
        await using var second = new WebApplicationFactory<Program>().WithWebHostBuilder(b => b.UseEnvironment("Development"));
        using var secondRaw = second.CreateClient();
        Assert.Equal(await (await _f.RawClient.GetAsync("/v1/key")).Content.ReadAsByteArrayAsync(),
            await (await secondRaw.GetAsync("/v1/key")).Content.ReadAsByteArrayAsync());

        // Sealed for node 1's key, answered by node 2; then replayed to node 1.
        var (outer, respSecret) = (await KeyAsync()).Seal(GatewayCodec.EncodeRequest(Get("/v1/info")));
        Assert.Equal(200, (await OpenAsync(await secondRaw.PostAsync("/v1/gw", Octets(outer)), respSecret)).Status);
        Assert.Equal(409, (await OpenAsync(await _f.RawClient.PostAsync("/v1/gw", Octets(outer)), respSecret)).Status);
    }

    // The middleware on its own, with a stand-in for the rest of the pipeline, to see exactly what crosses it.

    private async Task<(InnerResponse Response, HttpContext Context)> RunMiddleware(InnerRequest inner, RequestDelegate next) {
        var serverKey = new ServerKey(_f.ServerSecret);
        var replay = _f.Services.GetRequiredService<GatewayReplayGuard>();
        var middleware = new GatewayMiddleware(next, serverKey, replay, new GatewayFloodGuard(new GoldfishOptions()),
            NullLogger<GatewayMiddleware>.Instance);
        var (outer, respSecret) = ServerPublicKey.TryParse(serverKey.Blob)!.Seal(GatewayCodec.EncodeRequest(inner));

        var context = new DefaultHttpContext();
        context.Request.Method = "POST";
        context.Request.Path = "/v1/gw";
        context.Request.ContentType = "application/octet-stream";
        context.Request.Headers["Authorization"] = "outer";
        context.Request.Body = new MemoryStream(outer);
        context.Connection.RemoteIpAddress = IPAddress.Parse("192.0.2.1");
        var responseBody = new MemoryStream();
        context.Response.Body = responseBody;
        await middleware.InvokeAsync(context);

        Assert.Equal(200, context.Response.StatusCode);
        var plaintext = GatewayCrypto.OpenResponse(respSecret, responseBody.ToArray());
        Assert.NotNull(plaintext);
        Assert.True(GatewayCodec.TryDecodeResponse(plaintext, out var response));
        return (response, context);
    }

    [IntegrationFact]
    public async Task HeaderAllowlist_AppliesInBothDirections() {
        IHeaderDictionary? seenHeaders = null;
        string? seenMethod = null, seenPath = null, seenQuery = null, seenBody = null;
        IPAddress? seenIp = null;
        var (response, context) = await RunMiddleware(
            new InnerRequest("PUT", Now, "/v1/mailboxes/endpoint?a=1", [
                new("content-type", "application/json"),
                new("gf-send-token", "token"),
                new("authorization", "inner"),
                new("x-forwarded-for", "192.0.2.99"),
                new("cookie", "c=1"),
            ], "{\"x\":1}"u8.ToArray()),
            async ctx => {
                seenHeaders = ctx.Request.Headers;
                seenMethod = ctx.Request.Method;
                seenPath = ctx.Request.Path;
                seenQuery = ctx.Request.QueryString.Value;
                seenIp = ctx.Connection.RemoteIpAddress;
                seenBody = await new StreamReader(ctx.Request.Body).ReadToEndAsync();
                ctx.Response.StatusCode = 429;
                ctx.Response.Headers.RetryAfter = "30";
                ctx.Response.Headers["GF-Extra"] = "yes";
                ctx.Response.Headers["Set-Cookie"] = "leak=1";
                ctx.Response.Headers["X-Debug"] = "leak";
                ctx.Response.ContentType = "application/json";
                await ctx.Response.WriteAsync("{\"error\":\"rate_limited\"}");
            });

        Assert.Equal("PUT", seenMethod);
        Assert.Equal("/v1/mailboxes/endpoint", seenPath);
        Assert.Equal("?a=1", seenQuery);
        Assert.Equal("{\"x\":1}", seenBody);
        Assert.Equal(IPAddress.Parse("192.0.2.1"), seenIp);
        Assert.Equal("application/json", seenHeaders!.ContentType.ToString());
        Assert.Equal("token", seenHeaders["GF-Send-Token"].ToString());
        Assert.False(seenHeaders.ContainsKey("Authorization"));
        Assert.False(seenHeaders.ContainsKey("X-Forwarded-For"));
        Assert.False(seenHeaders.ContainsKey("Cookie"));

        Assert.Equal(429, response.Status);
        Assert.Equal("{\"error\":\"rate_limited\"}", Encoding.UTF8.GetString(response.Body));
        Assert.Equal(["content-type", "gf-extra", "retry-after"], response.Headers.Select(h => h.Key).Order());

        // Outside: only the opaque answer.
        var outer = context.Response.Headers;
        Assert.Equal("application/octet-stream", outer.ContentType.ToString());
        Assert.False(outer.ContainsKey("Retry-After"));
        Assert.False(outer.ContainsKey("GF-Extra"));
        Assert.False(outer.ContainsKey("Set-Cookie"));
        Assert.False(outer.ContainsKey("X-Debug"));
    }

    [IntegrationFact]
    public async Task EndpointException_IsAnEncrypted500() {
        var (response, context) = await RunMiddleware(Get("/v1/info"), async ctx => {
            ctx.Response.Headers["X-Partial"] = "1";
            await ctx.Response.WriteAsync("partial output");
            throw new InvalidOperationException("secret detail");
        });
        Assert.Equal(500, response.Status);
        var body = Encoding.UTF8.GetString(response.Body);
        Assert.Equal("{\"error\":\"internal\"}", body);
        Assert.DoesNotContain("secret", body);
        Assert.False(context.Response.Headers.ContainsKey("X-Partial"));
    }

    [IntegrationFact]
    public async Task ReplayGuard_IsInTheEphemeralRedis() {
        await PostRawAsync(Get("/v1/info"));
        await using var mux = await ConnectionMultiplexer.ConnectAsync(_f.Redis);
        var persistent = mux.GetServers()[0].Keys(0, "gf:gwr:*").ToList();
        var ephemeral = mux.GetServers()[0].Keys(1, "gf:gwr:*").ToList();
        Assert.Empty(persistent);
        Assert.NotEmpty(ephemeral);
        var ttl = await mux.GetDatabase(1).KeyTimeToLiveAsync(ephemeral[0]);
        Assert.InRange(ttl!.Value.TotalSeconds, 1, 1200);
    }
}
