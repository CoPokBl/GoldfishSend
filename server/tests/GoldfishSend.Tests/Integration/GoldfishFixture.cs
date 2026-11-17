using System.Buffers.Text;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using GoldfishSend.Core.Crypto;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using MySqlConnector;
using StackExchange.Redis;

namespace GoldfishSend.Tests.Integration;

/// <summary>
/// Runs only when GF_TEST_MYSQL and GF_TEST_REDIS point at disposable instances. The fixture wipes them.
/// Example: <c>GF_TEST_MYSQL="Server=127.0.0.1;Port=33306;User=root;Password=test;Database=goldfish"</c>
/// and <c>GF_TEST_REDIS="127.0.0.1:36379"</c>.
/// </summary>
public sealed class IntegrationFactAttribute : FactAttribute {
    public IntegrationFactAttribute() {
        if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("GF_TEST_MYSQL"))
            || string.IsNullOrEmpty(Environment.GetEnvironmentVariable("GF_TEST_REDIS"))) {
            Skip = "Set GF_TEST_MYSQL and GF_TEST_REDIS to run integration tests.";
        }
    }
}

public sealed class IntegrationTheoryAttribute : TheoryAttribute {
    public IntegrationTheoryAttribute() {
        if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("GF_TEST_MYSQL"))
            || string.IsNullOrEmpty(Environment.GetEnvironmentVariable("GF_TEST_REDIS"))) {
            Skip = "Set GF_TEST_MYSQL and GF_TEST_REDIS to run integration tests.";
        }
    }
}

[CollectionDefinition(Name)]
public sealed class GoldfishCollection : ICollectionFixture<GoldfishFixture> {
    public const string Name = "goldfish";
}

public sealed class GoldfishFixture : IAsyncLifetime {
    private WebApplicationFactory<Program>? _factory;

    public FakePushServer Push { get; } = new();
    /// <summary>Talks to the API through the encrypted gateway, like the app.</summary>
    public HttpClient Client { get; private set; } = null!;
    /// <summary>Plain HTTP, no gateway: for the outer protocol itself.</summary>
    public HttpClient RawClient { get; private set; } = null!;
    public GatewayHandler Gateway { get; private set; } = null!;
    public WebApplicationFactory<Program> Factory => _factory!;
    public byte[] ServerSecret { get; } = GatewayCrypto.GenerateSecret();
    public string MySql { get; } = Environment.GetEnvironmentVariable("GF_TEST_MYSQL") ?? "";
    public string Redis { get; } = Environment.GetEnvironmentVariable("GF_TEST_REDIS") ?? "";
    public IServiceProvider Services => _factory!.Services;

    public async Task InitializeAsync() {
        if (MySql.Length == 0 || Redis.Length == 0) {
            return;
        }

        await using (var conn = new MySqlConnection(MySql)) {
            await conn.OpenAsync();
            await using var cmd = conn.CreateCommand();
            cmd.CommandText = "DROP TABLE IF EXISTS pending_messages, mailboxes, epoch_keys, schema_migrations";
            await cmd.ExecuteNonQueryAsync();
        }
        await using (var mux = await ConnectionMultiplexer.ConnectAsync(Redis + ",allowAdmin=true")) {
            await mux.GetServers()[0].FlushAllDatabasesAsync();
        }

        await Push.StartAsync();

        string Key() => Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32));
        var settings = new Dictionary<string, string> {
            ["ConnectionStrings__MySql"] = MySql,
            ["ConnectionStrings__Redis"] = Redis,
            // A separate logical database stands in for the non-persistent ephemeral Redis.
            ["ConnectionStrings__RedisEphemeral"] = Redis + ",defaultDatabase=1",
            ["Goldfish__Keys__Pepper"] = Key(),
            ["Goldfish__Keys__SealSalt"] = Key(),
            ["Goldfish__Keys__EpochKek"] = Key(),
            ["Goldfish__Keys__VapidPrivateKey"] = Base64Url.EncodeToString(VapidSigner.GeneratePrivateKey()),
            ["Goldfish__Keys__VapidSubject"] = "mailto:test@example.com",
            ["Goldfish__Keys__ServerKey"] = Base64Url.EncodeToString(ServerSecret),
            // TestServer connections have no address, so every test shares one gateway flood bucket.
            ["Goldfish__Network__GatewayRequestsPerSecond"] = "100000",
            ["Goldfish__Network__GatewayBurst"] = "100000",
            ["Goldfish__Push__DangerouslyAllowInsecureLoopback"] = "true",
            // Tiny Argon2 parameters keep test PoW to a few milliseconds. Production defaults are in PowOptions.
            ["Goldfish__Pow__BaseDifficulty"] = "3",
            ["Goldfish__Pow__MemoryKiB"] = "64",
            // Every test client shares 127.0.0.1, so the per-network difficulty would climb across tests.
            ["Goldfish__Pow__NetworkLoadThreshold"] = "0",
            ["Goldfish__Messages__MaxHeldPerMailbox"] = "3",
            // Small enough that the tarpit test can prove one slow host can't take every slot.
            ["Goldfish__Messages__DeliveryParallelism"] = "8",
            ["Goldfish__Push__ResponseHeadersTimeoutSeconds"] = "2",
            ["Goldfish__RateLimits__send-net__Limit"] = "100000",
            ["Goldfish__RateLimits__send-net__Burst"] = "100000",
            ["Goldfish__RateLimits__owner-net__Limit"] = "100000",
            ["Goldfish__RateLimits__owner-net__Burst"] = "100000",
            ["Goldfish__RateLimits__create-global__Limit"] = "100000",
            ["Goldfish__RateLimits__create-global__Burst"] = "100000",
            ["Goldfish__RateLimits__newhost-global__Limit"] = "100000",
            ["Goldfish__RateLimits__newhost-global__Burst"] = "100000",
            ["Goldfish__RateLimits__push-mailbox__Limit"] = "1000",
            ["Goldfish__RateLimits__push-mailbox__Burst"] = "1000",
            ["Goldfish__RateLimits__create-net__Limit"] = "100000",
            ["Goldfish__RateLimits__pow-net__Limit"] = "100000",
            ["Goldfish__RateLimits__push-host__Limit"] = "100000",
            ["Goldfish__RateLimits__push-host__Burst"] = "100000",
            // Everything comes from 127.0.0.1, so loosen per-IP limits. Per-mailbox limits keep their defaults so they can be tested.
            ["Goldfish__RateLimits__send-ip__Limit"] = "100000",
            ["Goldfish__RateLimits__send-ip__PeriodSeconds"] = "60",
            ["Goldfish__RateLimits__send-ip__Burst"] = "100000",
            ["Goldfish__RateLimits__create-ip__Limit"] = "100000",
            ["Goldfish__RateLimits__create-ip__PeriodSeconds"] = "60",
            ["Goldfish__RateLimits__create-ip__Burst"] = "100000",
            ["Goldfish__RateLimits__owner-ip__Limit"] = "100000",
            ["Goldfish__RateLimits__owner-ip__PeriodSeconds"] = "60",
            ["Goldfish__RateLimits__owner-ip__Burst"] = "100000",
            ["Goldfish__RateLimits__pow-ip__Limit"] = "100000",
            ["Goldfish__RateLimits__pow-ip__PeriodSeconds"] = "60",
            ["Goldfish__RateLimits__pow-ip__Burst"] = "100000",
        };
        // Program reads configuration before Build(), so pass settings through the environment.
        foreach (var (key, value) in settings) {
            Environment.SetEnvironmentVariable(key, value);
        }

        _factory = new WebApplicationFactory<Program>().WithWebHostBuilder(b => b.UseEnvironment("Development"));
        Client = GatewayHandler.Client(_factory, out var gateway);
        Gateway = gateway;
        RawClient = _factory.CreateClient();
    }

    public async Task DisposeAsync() {
        Client?.Dispose();
        RawClient?.Dispose();
        if (_factory is not null) {
            await _factory.DisposeAsync();
        }
        await Push.DisposeAsync();
    }

    /// <summary>
    /// Starts another node against the same MySQL and Redis, with configuration overrides (Program reads the environment
    /// when the host is built, which happens here).
    /// </summary>
    public static (WebApplicationFactory<Program> Factory, HttpClient Client) Node(Dictionary<string, string> overrides) {
        var previous = overrides.ToDictionary(kv => kv.Key, kv => Environment.GetEnvironmentVariable(kv.Key));
        foreach (var (k, v) in overrides) {
            Environment.SetEnvironmentVariable(k, v);
        }
        try {
            var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(b => b.UseEnvironment("Development"));
            return (factory, GatewayHandler.Client(factory));
        } finally {
            foreach (var (k, v) in previous) {
                Environment.SetEnvironmentVariable(k, v);
            }
        }
    }

    /// <summary>
    /// Starts a node that pretends every connection comes from a trusted proxy at 10.9.9.9, so tests can pick each
    /// request's client address with <see cref="GatewayHandler.ForwardedFor"/> (or a raw <c>X-Forwarded-For</c>).
    /// Use made-up addresses: rate-limit buckets are shared with every other node.
    /// </summary>
    public static WebApplicationFactory<Program> NodeBehindProxy(Dictionary<string, string> overrides) {
        overrides = new Dictionary<string, string>(overrides) { ["Goldfish__Network__TrustedProxies__0"] = "10.9.9.9" };
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

    /// <summary>A gateway client of a <see cref="NodeBehindProxy"/> node whose requests come from <paramref name="address"/>.</summary>
    public static HttpClient ClientFrom(WebApplicationFactory<Program> factory, string address) {
        var client = GatewayHandler.Client(factory, out var handler);
        handler.ForwardedFor = address;
        return client;
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

    // Client helpers that mirror what the Android app does. They use the fixture node unless given another client.

    public async Task<(byte[] Challenge, byte[] Nonce)> SolvePowAsync(HttpClient? client = null) {
        var response = await (client ?? Client).PostAsync("/v1/pow/challenge", null);
        response.EnsureSuccessStatusCode();
        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        var challenge = Base64Url.DecodeFromChars(json.GetProperty("challenge").GetString());
        return (challenge, ProofOfWork.Solve(challenge, PowOf(json)));
    }

    /// <summary>The parameters of a <c>/v1/pow/challenge</c> response.</summary>
    public static PowParameters PowOf(JsonElement issued) {
        Assert.Equal(ProofOfWork.Scheme, issued.GetProperty("scheme").GetString());
        return new PowParameters(issued.GetProperty("difficulty").GetInt32(), issued.GetProperty("memoryKiB").GetInt32(),
            issued.GetProperty("iterations").GetInt32());
    }

    public sealed record Mailbox(byte[] SendSecret, byte[] OwnerSecret, FakeDevice Device) {
        public object Credential => new { sendSecret = B64(SendSecret), ownerSecret = B64(OwnerSecret) };
        public byte[] Tag => MailboxCrypto.Tag(SendSecret);
    }

    public async Task<HttpResponseMessage> RequestMailboxAsync(
        byte[] sendSecret, byte[] ownerSecret, FakeDevice device, string? url = null, HttpClient? client = null) {
        var (challenge, nonce) = await SolvePowAsync(client);
        return await (client ?? Client).PostAsJsonAsync("/v1/mailboxes", new {
            pow = new { challenge = B64(challenge), nonce = B64(nonce) },
            sendSecret = B64(sendSecret),
            ownerHash = B64(MailboxCrypto.OwnerHash(ownerSecret)),
            endpoint = url ?? device.Url,
            p256dh = B64(device.P256dh),
            auth = B64(device.Auth),
        });
    }

    /// <summary>Creates and verifies a mailbox, consuming the verification push.</summary>
    public async Task<Mailbox> CreateActiveMailboxAsync(FakeDevice? device = null, HttpClient? client = null) {
        device ??= Push.NewDevice();
        var mailbox = new Mailbox(RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(32), device);
        var response = await RequestMailboxAsync(mailbox.SendSecret, mailbox.OwnerSecret, device, client: client);
        Assert.Equal(202, (int)response.StatusCode);

        var (type, tag, code) = await device.NextAsync();
        Assert.Equal(GoldfishSend.Core.Protocol.PushType.Verification, type);
        Assert.Equal(mailbox.Tag, tag);

        var verify = await VerifyAsync([mailbox], code);
        Assert.Equal(200, (int)verify.StatusCode);
        return mailbox;
    }

    /// <summary>The verification code is the first 16 bytes of the (padded) verification push body.</summary>
    public Task<HttpResponseMessage> VerifyAsync(IEnumerable<Mailbox> mailboxes, byte[] code) {
        if (code.Length > 16) {
            code = code[..16];
        }
        return Client.PostAsJsonAsync("/v1/mailboxes/verify", new {
            items = mailboxes.Select(m => m.Credential).ToArray(),
            code = B64(code),
        });
    }

    public async Task<HttpResponseMessage> SendAsync(
        byte[] sendSecret, byte[] body, byte[]? idempotencyKey = null, int? ttl = null, HttpClient? client = null) {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/v1/messages") {
            Content = Octets(body),
        };
        request.Headers.Add("GF-Send-Token", B64(sendSecret));
        if (idempotencyKey is not null) {
            request.Headers.Add("GF-Idempotency-Key", B64(idempotencyKey));
        }
        if (ttl is not null) {
            request.Headers.Add("GF-TTL", ttl.Value.ToString());
        }
        return await (client ?? Client).SendAsync(request);
    }

    public async Task<long> ScalarAsync(string sql, object? param = null) {
        await using var conn = new MySqlConnection(MySql);
        await conn.OpenAsync();
        return await Dapper.SqlMapper.ExecuteScalarAsync<long>(conn, sql, param);
    }

    public static string B64(byte[] value) => Base64Url.EncodeToString(value);

    public static ByteArrayContent Octets(byte[] body) {
        var content = new ByteArrayContent(body);
        content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
        return content;
    }

    public static async Task EventuallyAsync(Func<Task<bool>> condition, TimeSpan? timeout = null, string? because = null) {
        var deadline = DateTime.UtcNow + (timeout ?? TimeSpan.FromSeconds(10));
        while (DateTime.UtcNow < deadline) {
            if (await condition()) {
                return;
            }
            await Task.Delay(100);
        }
        Assert.Fail(because ?? "Condition was not met in time.");
    }
}
