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
    kestrel.Limits.MaxRequestBodySize = 16 * 1024;
    kestrel.Limits.MaxRequestHeadersTotalSize = 16 * 1024;
    kestrel.Limits.MaxRequestHeaderCount = 50;
    kestrel.Limits.MaxRequestLineSize = 4 * 1024;
    kestrel.Limits.KeepAliveTimeout = TimeSpan.FromSeconds(60);
    kestrel.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(10);
    kestrel.Limits.MaxConcurrentConnections = 10_000;
});

builder.Services.ConfigureHttpJsonOptions(json => {
    json.SerializerOptions.TypeInfoResolverChain.Insert(0, ApiJsonContext.Default);
});

builder.Services.Configure<ForwardedHeadersOptions>(forwarded => {
    forwarded.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    forwarded.ForwardLimit = 1;
    forwarded.KnownProxies.Clear();
    forwarded.KnownIPNetworks.Clear();
    foreach (var proxy in options.Network.TrustedProxies) {
        if (proxy.Contains('/')) {
            forwarded.KnownIPNetworks.Add(System.Net.IPNetwork.Parse(proxy));
        } else {
            forwarded.KnownProxies.Add(IPAddress.Parse(proxy));
        }
    }
});

builder.Services.AddRequestTimeouts(timeouts => {
    timeouts.DefaultPolicy = new Microsoft.AspNetCore.Http.Timeouts.RequestTimeoutPolicy { Timeout = TimeSpan.FromSeconds(30) };
});

builder.Services.AddGoldfish(options, mySql, redis, builder.Configuration.GetConnectionString("RedisEphemeral"));

var app = builder.Build();

var startupLog = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("GoldfishSend.Startup");
if (options.HasRole("api") && options.Network.TrustedProxies.Length == 0 && !app.Environment.IsDevelopment()) {
    startupLog.LogWarning("No Goldfish:Network:TrustedProxies configured. Behind a reverse proxy, every client will share one rate-limit bucket.");
}
if (!app.Services.GetRequiredService<GoldfishSend.Infrastructure.Redis.EphemeralRedis>().IsSeparate && !app.Environment.IsDevelopment()) {
    startupLog.LogWarning("ConnectionStrings:RedisEphemeral is not set. Rate-limit state shares the persistent Redis, whose AOF then records client activity.");
}

await app.Services.GetRequiredService<Migrator>().MigrateAsync();
await app.Services.GetRequiredService<EpochKeyring>().RotateAsync();

app.UseForwardedHeaders();

// If the reverse proxy ever reports a client address inside our own proxy network, the container runtime is collapsing
// clients into one address (typically IPv6 traffic arriving through the bridge gateway). Then every client shares one
// rate-limit bucket. It's logged at most every 10 minutes and never includes the address.
var proxyNetworks = options.Network.TrustedProxies
    .Select(p => System.Net.IPNetwork.Parse(p.Contains('/') ? p : p + (p.Contains(':') ? "/128" : "/32")))
    .ToArray();
var lastCollapseWarning = 0L;
app.Use(async (context, next) => {
    var remote = context.Connection.RemoteIpAddress;
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
    app.MapGoldfishApi();
} else {
    app.MapGoldfishHealth();
}

app.Run();

static void PrintKeys() {
    string Key() => Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32));
    var vapid = VapidSigner.GeneratePrivateKey();
    using var signer = new VapidSigner(vapid, "mailto:admin@example.invalid");
    Console.WriteLine($$"""
        {
          "Goldfish": {
            "Keys": {
              "Pepper": "{{Key()}}",
              "SealSalt": "{{Key()}}",
              "EpochKek": "{{Key()}}",
              "VapidPrivateKey": "{{Base64Url.EncodeToString(vapid)}}",
              "VapidSubject": "mailto:you@your-domain"
            }
          }
        }
        """);
    Console.Error.WriteLine($"VAPID public key: {signer.PublicKeyBase64Url}");
    Console.Error.WriteLine("Store these as secrets (env vars Goldfish__Keys__Pepper etc. or a mounted file). Losing Pepper/SealSalt orphans all mailboxes.");
}

public partial class Program;
