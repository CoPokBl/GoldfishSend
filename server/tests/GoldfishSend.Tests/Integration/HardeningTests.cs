using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using GoldfishSend.Infrastructure.Delivery;
using GoldfishSend.Infrastructure.Redis;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using StackExchange.Redis;
using static GoldfishSend.Tests.Integration.GoldfishFixture;

namespace GoldfishSend.Tests.Integration;

/// <summary>Regression tests for the server security audit (H1–H3, M3, M5, M6, L5, L9).</summary>
[Collection(GoldfishCollection.Name)]
public sealed class HardeningTests {
    private readonly GoldfishFixture _f;

    public HardeningTests(GoldfishFixture fixture) {
        _f = fixture;
    }

    /// <summary>Starts another node with configuration overrides (environment variables are only read at host build).</summary>
    private static (WebApplicationFactory<Program> Factory, HttpClient Client) Node(Dictionary<string, string> overrides) {
        var previous = overrides.ToDictionary(kv => kv.Key, kv => Environment.GetEnvironmentVariable(kv.Key));
        foreach (var (k, v) in overrides) {
            Environment.SetEnvironmentVariable(k, v);
        }
        try {
            var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(b => b.UseEnvironment("Development"));
            var client = GatewayHandler.Client(factory);
            return (factory, client);
        } finally {
            foreach (var (k, v) in previous) {
                Environment.SetEnvironmentVariable(k, v);
            }
        }
    }

    private static async Task<HttpResponseMessage> SendVia(HttpClient client, byte[] sendSecret, byte[] body) {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/v1/messages") { Content = Octets(body) };
        request.Headers.Add("GF-Send-Token", B64(sendSecret));
        return await client.SendAsync(request);
    }

    [IntegrationFact]
    public async Task VerificationPush_IsPaddedAndCarriesTheCodeFirst() {
        var device = _f.Push.NewDevice();
        var mailbox = new Mailbox(RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(32), device);
        Assert.Equal(HttpStatusCode.Accepted, (await _f.RequestMailboxAsync(mailbox.SendSecret, mailbox.OwnerSecret, device)).StatusCode);
        var (_, _, body) = await device.NextAsync();
        // Same size as a typical message, so push providers can't count mailbox creations by size.
        Assert.Equal(1024, body.Length);
        Assert.Equal(HttpStatusCode.OK, (await _f.VerifyAsync([mailbox], body[..16])).StatusCode);
    }

    [IntegrationFact]
    public async Task OneSubscribersFailures_DoNotPauseTheSharedHost() {
        var attacker = await _f.CreateActiveMailboxAsync();
        var victim = await _f.CreateActiveMailboxAsync(); // Same host (127.0.0.1) as the attacker.
        attacker.Device.Status = 503;
        // The fixture caps held messages at 3 per mailbox. This API-only node lifts that, so the attacker can drive a
        // high failure volume from its one endpoint (the fixture's workers deliver).
        var (factory, client) = Node(new() { ["Goldfish__Messages__MaxHeldPerMailbox"] = "1000", ["Goldfish__Roles"] = "api" });
        await using var _ = factory;
        for (var i = 0; i < 25; i++) {
            var r = await SendVia(client, attacker.SendSecret, [(byte)i]);
            Assert.True(r.StatusCode == HttpStatusCode.Accepted, $"send {i}: {(int)r.StatusCode} {await r.Content.ReadAsStringAsync()}");
        }
        await EventuallyAsync(() => Task.FromResult(attacker.Device.Attempts >= 20), TimeSpan.FromSeconds(15));

        attacker.Device.Status = 429;
        for (var i = 0; i < 5; i++) {
            await SendVia(client, attacker.SendSecret, [(byte)(100 + i)]);
        }

        var sw = Stopwatch.StartNew();
        await _f.SendAsync(victim.SendSecret, [42]);
        var (_, _, body) = await victim.Device.NextAsync(TimeSpan.FromSeconds(5));
        Assert.Equal([42], body);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(5));
        attacker.Device.Status = 201;
    }

    [IntegrationFact]
    public async Task TarpitHost_CannotStarveOtherHosts() {
        // Eight mailboxes on a tarpit host ("localhost"), each with a message stuck in a slow push. With 8 delivery slots,
        // the old code let them take every slot. Now only a few may be in flight per host.
        var tarpits = new List<Mailbox>();
        for (var i = 0; i < 8; i++) {
            tarpits.Add(await _f.CreateActiveMailboxAsync(_f.Push.NewDevice(alternateHost: true)));
        }
        foreach (var t in tarpits) {
            t.Device.DelayMs = 30_000;
        }
        foreach (var t in tarpits) {
            Assert.Equal(HttpStatusCode.Accepted, (await _f.SendAsync(t.SendSecret, [1])).StatusCode);
        }
        await Task.Delay(300);

        var healthy = await _f.CreateActiveMailboxAsync();
        await _f.SendAsync(healthy.SendSecret, [7]);
        var (_, _, body) = await healthy.Device.NextAsync(TimeSpan.FromSeconds(6));
        Assert.Equal([7], body);

        foreach (var t in tarpits) {
            t.Device.DelayMs = 0;
        }
    }

    [IntegrationFact]
    public async Task Idempotency_LivesOnlyInTheEphemeralRedis() {
        var mailbox = await _f.CreateActiveMailboxAsync();
        var key = RandomNumberGenerator.GetBytes(16);
        var first = await (await _f.SendAsync(mailbox.SendSecret, [9], key)).Content.ReadFromJsonAsync<JsonElement>();
        var second = await (await _f.SendAsync(mailbox.SendSecret, [9], key)).Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(first.GetProperty("id").GetString(), second.GetProperty("id").GetString());
        await mailbox.Device.NextAsync();

        await using var mux = await ConnectionMultiplexer.ConnectAsync(_f.Redis + ",allowAdmin=true");
        var server = mux.GetServers()[0];
        Assert.Empty(server.Keys(database: 0, pattern: "gf:idem:*"));   // the persistent (AOF) Redis
        Assert.NotEmpty(server.Keys(database: 1, pattern: "gf:idem:*")); // the ephemeral Redis
    }

    [IntegrationFact]
    public async Task FullQueue_SpillsToMySql_AndStillDelivers() {
        var queue = (MessageQueue)_f.Services.GetService(typeof(MessageQueue))!;
        var job = new DeliveryJob(RandomNumberGenerator.GetBytes(16), RandomNumberGenerator.GetBytes(32), 0, [1], DateTime.UtcNow.AddHours(1), 0);
        Assert.False(await queue.TryEnqueueAsync(job, maxLength: 0));

        // API-only: the fixture's workers deliver. A worker node disposed mid-read would leave entries unacknowledged.
        var (factory, client) = Node(new() { ["Goldfish__Messages__MaxStreamLength"] = "0", ["Goldfish__Roles"] = "api" });
        await using (factory) {
            var mailbox = await _f.CreateActiveMailboxAsync();
            Assert.Equal(HttpStatusCode.Accepted, (await SendVia(client, mailbox.SendSecret, [5, 5])).StatusCode);
            var (_, _, body) = await mailbox.Device.NextAsync(TimeSpan.FromSeconds(10));
            Assert.Equal([5, 5], body);
        }
    }

    [IntegrationFact]
    public async Task Refresh_ReportsEndpointGone_AndADeliveryRecoversIt() {
        var mailbox = await _f.CreateActiveMailboxAsync();
        mailbox.Device.Status = 410;
        await _f.SendAsync(mailbox.SendSecret, [1]);
        await EventuallyAsync(async () => await _f.ScalarAsync(
            "SELECT COUNT(*) FROM pending_messages p JOIN mailboxes m ON m.id = p.mailbox_id WHERE m.state = 2") >= 1);

        var refresh = await _f.Client.PostAsJsonAsync("/v1/mailboxes/refresh", new { items = new[] { mailbox.Credential } });
        var json = await refresh.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(json.GetProperty("endpointGone").GetBoolean());

        // The endpoint comes back. The next message gets through, the mailbox is active again, and held messages flush.
        mailbox.Device.Status = 201;
        await _f.SendAsync(mailbox.SendSecret, [2]);
        var received = new HashSet<byte>();
        for (var i = 0; i < 2; i++) {
            received.Add((await mailbox.Device.NextAsync(TimeSpan.FromSeconds(10))).Body[0]);
        }
        Assert.Equal(new HashSet<byte> { 1, 2 }, received);
        var after = await (await _f.Client.PostAsJsonAsync("/v1/mailboxes/refresh", new { items = new[] { mailbox.Credential } }))
            .Content.ReadFromJsonAsync<JsonElement>();
        Assert.False(after.GetProperty("endpointGone").GetBoolean());
    }

    [IntegrationFact]
    public async Task GlobalHeldQuota_RefusesOnlyMailboxesThatWouldAddToTheBacklog() {
        var gone = await _f.CreateActiveMailboxAsync();
        gone.Device.Status = 410;
        await _f.SendAsync(gone.SendSecret, [1]);
        await EventuallyAsync(async () => await _f.ScalarAsync("SELECT COUNT(*) FROM pending_messages") >= 1);
        var healthy = await _f.CreateActiveMailboxAsync();

        var (factory, client) = Node(new() { ["Goldfish__Messages__MaxHeldTotal"] = "1", ["Goldfish__Roles"] = "api" });
        await using (factory) {
            var refused = await SendVia(client, gone.SendSecret, [2]);
            Assert.Equal(507, (int)refused.StatusCode);
            var error = await refused.Content.ReadFromJsonAsync<JsonElement>();
            Assert.Equal("mailbox_full", error.GetProperty("error").GetString());
            Assert.Equal("global", error.GetProperty("scope").GetString());

            Assert.Equal(HttpStatusCode.Accepted, (await SendVia(client, healthy.SendSecret, [3])).StatusCode);
        }
    }

    [IntegrationFact]
    public async Task Redirects_AreRetriedNotDropped() {
        var mailbox = await _f.CreateActiveMailboxAsync();
        mailbox.Device.Status = 302;
        var sent = await (await _f.SendAsync(mailbox.SendSecret, [8])).Content.ReadFromJsonAsync<JsonElement>();
        var id = System.Buffers.Text.Base64Url.DecodeFromChars(sent.GetProperty("id").GetString());
        await EventuallyAsync(async () => await _f.ScalarAsync("SELECT COUNT(*) FROM pending_messages WHERE id = @id", new { id }) == 1,
            because: "a 3xx must hold the message for retry, not drop it");
        Assert.Equal(1, await _f.ScalarAsync(
            "SELECT COUNT(*) FROM mailboxes m JOIN pending_messages p ON p.mailbox_id = m.id WHERE p.id = @id AND m.state = 1", new { id }));
        mailbox.Device.Status = 201;
    }
}
