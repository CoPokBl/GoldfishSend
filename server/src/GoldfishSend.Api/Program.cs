using System.Buffers.Text;
using System.Net;
using System.Security.Cryptography;
using GoldfishSend.Api;
using GoldfishSend.Api.Endpoints;
using GoldfishSend.Core.Crypto;
using GoldfishSend.Core.Options;
using GoldfishSend.Infrastructure;
using GoldfishSend.Infrastructure.MySql;
using Microsoft.AspNetCore.HttpOverrides;

if (args is ["keygen", ..]) {
    PrintKeys();
    return;
}

var builder = WebApplication.CreateSlimBuilder(args);

if (args is ["fingerprint", ..]) {
    var configured = builder.Configuration["Goldfish:Keys:ServerKey"] ?? "";
    var identity = ServerKey.FromBase64Url(configured);
    Console.WriteLine(identity.FingerprintBase64Url);
    Console.Error.WriteLine($"Server key fingerprint: {identity.FingerprintDisplay}");
    return;
}

var options = builder.Configuration.GetSection(GoldfishOptions.Section).Get<GoldfishOptions>() ?? new GoldfishOptions();
if (options.Push.DangerouslyAllowInsecureLoopback && !builder.Environment.IsDevelopment()) {
    throw new InvalidOperationException("Goldfish:Push:DangerouslyAllowInsecureLoopback is only allowed in the Development environment.");
}

var mySql = builder.Configuration.GetConnectionString("MySql")
    ?? throw new InvalidOperationException("ConnectionStrings:MySql is required.");
var redis = builder.Configuration.GetConnectionString("Redis")
    ?? throw new InvalidOperationException("ConnectionStrings:Redis is required.");

builder.WebHost.ConfigureKestrel(kestrel => {
    kestrel.AddServerHeader = false;
    // The gateway's outer body: a 16 KiB inner body plus padding and ~1.2 KB of KEM ciphertext.
    kestrel.Limits.MaxRequestBodySize = GatewayMiddleware.MaxOuterBody;
    kestrel.Limits.MaxRequestHeadersTotalSize = 16 * 1024;
    kestrel.Limits.MaxRequestHeaderCount = 50;
    kestrel.Limits.MaxRequestLineSize = 4 * 1024;
    kestrel.Limits.KeepAliveTimeout = TimeSpan.FromSeconds(60);
    kestrel.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(10);
    kestrel.Limits.MaxConcurrentConnections = 10_000;
    if (!string.IsNullOrWhiteSpace(options.Network.OnionCircuitEndpoint) && options.HasRole("api")) {
        var onion = IPEndPoint.TryParse(options.Network.OnionCircuitEndpoint.Trim(), out var endpoint) && endpoint.Port > 0
            ? endpoint
            : throw new InvalidOperationException(
                $"Goldfish:Network:OnionCircuitEndpoint must be ip:port, not '{options.Network.OnionCircuitEndpoint}'");
        // Listening in code replaces the configured URLs, so the usual listeners are added back first.
        foreach (var listen in ConfiguredEndpoints(builder.Configuration)) {
            kestrel.Listen(listen);
        }
        kestrel.Listen(onion, listen => listen.Use(OnionCircuits.Middleware(
            listen.ApplicationServices.GetRequiredService<ILoggerFactory>().CreateLogger("GoldfishSend.Onion"))));
    }
});

builder.Services.ConfigureHttpJsonOptions(json => {
    json.SerializerOptions.TypeInfoResolverChain.Insert(0, ApiJsonContext.Default);
});
// Unreadable request bodies are a client error in every environment. Development would otherwise throw, and the gateway
// would turn that into a 500.
builder.Services.Configure<Microsoft.AspNetCore.Routing.RouteHandlerOptions>(handlers => handlers.ThrowOnBadRequest = false);

// Trusted reverse proxies (Caddy, Traefik, a cloud load balancer). Blank entries are ignored, so compose files can leave
// optional slots empty. Anything else that doesn't parse is a hard startup error, never a silent "trust nobody".
var trustedProxyNetworks = options.Network.TrustedProxies
    .Where(p => !string.IsNullOrWhiteSpace(p))
    .Select(p => p.Trim())
    .Select(p => System.Net.IPNetwork.TryParse(p.Contains('/') ? p : p + (p.Contains(':') ? "/128" : "/32"), out var n)
        ? n
        : throw new InvalidOperationException($"Goldfish:Network:TrustedProxies contains an invalid IP or CIDR: '{p}'"))
    .ToArray();

builder.Services.Configure<ForwardedHeadersOptions>(forwarded => {
    forwarded.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    forwarded.ForwardLimit = Math.Clamp(options.Network.ForwardLimit, 1, 5);
    forwarded.KnownProxies.Clear();
    forwarded.KnownIPNetworks.Clear();
    foreach (var network in trustedProxyNetworks) {
        forwarded.KnownIPNetworks.Add(network);
    }
});

builder.Services.AddRequestTimeouts(timeouts => {
    timeouts.DefaultPolicy = new Microsoft.AspNetCore.Http.Timeouts.RequestTimeoutPolicy { Timeout = TimeSpan.FromSeconds(30) };
});

builder.Services.AddGoldfish(options, mySql, redis, builder.Configuration.GetConnectionString("RedisEphemeral"));

// The server's identity and gateway key. API nodes need it; worker-only nodes never touch client requests.
ServerKey? serverKey = null;
if (options.HasRole("api")) {
    serverKey = ServerKey.FromBase64Url(options.Keys.ServerKey);
    builder.Services.AddSingleton(serverKey);
    builder.Services.AddSingleton<GatewayFloodGuard>();
}

var app = builder.Build();

var startupLog = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("GoldfishSend.Startup");
if (options.HasRole("api") && trustedProxyNetworks.Length == 0 && !app.Environment.IsDevelopment()) {
    startupLog.LogWarning("No Goldfish:Network:TrustedProxies configured. Behind a reverse proxy, every client will share one rate-limit bucket.");
}
if (!app.Services.GetRequiredService<GoldfishSend.Infrastructure.Redis.EphemeralRedis>().IsSeparate && !app.Environment.IsDevelopment()) {
    startupLog.LogWarning("ConnectionStrings:RedisEphemeral is not set. Rate-limit state shares the persistent Redis, whose AOF then records client activity.");
}

if (serverKey is not null) {
    // Public: operators publish it, and clients pin it.
    startupLog.LogInformation("Server key fingerprint: {Fingerprint} ({FingerprintBase64Url})", serverKey.FingerprintDisplay, serverKey.FingerprintBase64Url);
}

await app.Services.GetRequiredService<Migrator>().MigrateAsync();
await app.Services.GetRequiredService<EpochKeyring>().RotateAsync();

app.UseForwardedHeaders();

// If the reverse proxy ever reports a client address inside our own proxy network, the container runtime is collapsing
// clients into one address (typically IPv6 traffic arriving through the bridge gateway). Then every client shares one
// rate-limit bucket. It's logged at most every 10 minutes and never includes the address.
var proxyNetworks = trustedProxyNetworks;
var lastCollapseWarning = 0L;
var lastUntrustedProxyWarning = 0L;
app.Use(async (context, next) => {
    var remote = context.Connection.RemoteIpAddress;
    // A proxy on a private network sent X-Forwarded-For, but it isn't trusted, so its header was ignored and every client
    // looks like the proxy. This is the usual Traefik setup mistake (its network isn't in TrustedProxies, or it's behind
    // a load balancer and ForwardLimit/TrustedProxies don't cover that hop). Only the proxy's own private address is logged.
    if (remote is not null && context.Request.Headers.ContainsKey("X-Forwarded-For") && IsPrivate(remote)) {
        var now = Environment.TickCount64;
        var last = Interlocked.Read(ref lastUntrustedProxyWarning);
        if (now - last > 600_000 && Interlocked.CompareExchange(ref lastUntrustedProxyWarning, now, last) == last) {
            startupLog.LogWarning(
                "Ignoring X-Forwarded-For from untrusted proxy {Proxy}. Add its network to Goldfish:Network:TrustedProxies " +
                "(and raise Goldfish:Network:ForwardLimit if there is another proxy in front of it), or every client shares one rate limit.",
                remote.IsIPv4MappedToIPv6 ? remote.MapToIPv4() : remote);
        }
    }
    if (remote is not null && proxyNetworks.Length > 0) {
        var ip = remote.IsIPv4MappedToIPv6 ? remote.MapToIPv4() : remote;
        if (proxyNetworks.Any(n => n.Contains(ip))) {
            var now = Environment.TickCount64;
            var last = Interlocked.Read(ref lastCollapseWarning);
            if (now - last > 600_000 && Interlocked.CompareExchange(ref lastCollapseWarning, now, last) == last) {
                startupLog.LogWarning(
                    "A client address arrived from inside the trusted proxy network. The container runtime is probably " +
                    "rewriting client addresses (for example IPv6 through the bridge gateway), so clients share rate limits. " +
                    "Enable IPv6 on the public network or publish IPv4 only (see server/README.md).");
            }
        }
    }
    await next();
});
app.Use(async (context, next) => {
    var headers = context.Response.Headers;
    headers.CacheControl = "no-store";
    headers.XContentTypeOptions = "nosniff";
    headers["Referrer-Policy"] = "no-referrer";
    headers.ContentSecurityPolicy = "default-src 'none'; frame-ancestors 'none'";
    await next();
});
app.UseRequestTimeouts();

if (options.HasRole("api")) {
    // The gateway rewrites each request into its decrypted inner request, so routing must come after it.
    app.UseMiddleware<GatewayMiddleware>();
}
app.UseRouting();

if (options.HasRole("api")) {
    app.MapGoldfishApi();
} else {
    app.MapGoldfishHealth();
}

app.Run();

static bool IsPrivate(IPAddress address) {
    var ip = address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
    if (IPAddress.IsLoopback(ip)) {
        return true;
    }
    if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) {
        var b = ip.GetAddressBytes();
        return b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168) || (b[0] == 100 && b[1] >= 64 && b[1] <= 127);
    }
    return ip.IsIPv6UniqueLocal || ip.IsIPv6LinkLocal;
}

// The listeners ASP.NET Core would have made from ASPNETCORE_URLS or ASPNETCORE_HTTP_PORTS (8080 in the container image).
static List<IPEndPoint> ConfiguredEndpoints(IConfiguration configuration) {
    var endpoints = new List<IPEndPoint>();
    var urls = configuration["urls"];
    if (!string.IsNullOrWhiteSpace(urls)) {
        foreach (var url in urls.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)) {
            var uri = new Uri(url.Replace("://*", "://0.0.0.0", StringComparison.Ordinal).Replace("://+", "://0.0.0.0", StringComparison.Ordinal));
            if (uri.Scheme != "http") {
                throw new InvalidOperationException($"With Goldfish:Network:OnionCircuitEndpoint, only http:// URLs can be listened on, not '{url}'");
            }
            var host = uri.Host.Trim('[', ']');
            endpoints.Add(new IPEndPoint(
                host is "0.0.0.0" or "::" ? IPAddress.IPv6Any : host == "localhost" ? IPAddress.Loopback : IPAddress.Parse(host), uri.Port));
        }
        return endpoints;
    }
    var ports = configuration["http_ports"];
    foreach (var port in (string.IsNullOrWhiteSpace(ports) ? "8080" : ports).Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)) {
        endpoints.Add(new IPEndPoint(IPAddress.IPv6Any, int.Parse(port, System.Globalization.CultureInfo.InvariantCulture)));
    }
    return endpoints;
}

static void PrintKeys() {
    string Key() => Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32));
    var vapid = VapidSigner.GeneratePrivateKey();
    using var signer = new VapidSigner(vapid, "mailto:admin@example.invalid");
    var serverSecret = GatewayCrypto.GenerateSecret();
    var identity = new ServerKey(serverSecret);
    Console.WriteLine($$"""
        {
          "Goldfish": {
            "Keys": {
              "Pepper": "{{Key()}}",
              "SealSalt": "{{Key()}}",
              "EpochKek": "{{Key()}}",
              "VapidPrivateKey": "{{Base64Url.EncodeToString(vapid)}}",
              "ServerKey": "{{Base64Url.EncodeToString(serverSecret)}}",
              "VapidSubject": "mailto:you@your-domain"
            }
          }
        }
        """);
    Console.Error.WriteLine($"VAPID public key: {signer.PublicKeyBase64Url}");
    Console.Error.WriteLine($"Server key fingerprint: {identity.FingerprintDisplay}");
    Console.Error.WriteLine($"  for -Pgf.defaultServerKey: {identity.FingerprintBase64Url}");
    Console.Error.WriteLine("Store these as secrets (env vars Goldfish__Keys__Pepper etc. or a mounted file). Losing Pepper/SealSalt orphans all mailboxes.");
}

public partial class Program;
