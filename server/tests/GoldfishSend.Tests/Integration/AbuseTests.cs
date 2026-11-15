using System.Buffers.Text;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using GoldfishSend.Core.Crypto;
using GoldfishSend.Core.Net;
using GoldfishSend.Core.Options;
using GoldfishSend.Core.Protocol;
using GoldfishSend.Infrastructure.MySql;
using GoldfishSend.Infrastructure.Push;
using GoldfishSend.Infrastructure.Redis;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using static GoldfishSend.Tests.Integration.GoldfishFixture;

namespace GoldfishSend.Tests.Integration;

/// <summary>
/// M4's abuse suite (PLAN.md §4.2, §7, §8): the promised defences that the other integration tests don't already cover.
/// Rate-limit buckets are shared by every node, so limits are tightened on separate nodes and exercised from made-up
/// client addresses (198.18.0.0/15, 2001:db8::/32), never from the address the other tests share. Burst-1 policies keep
/// the outcomes exact despite the limiter rounding stored times to whole seconds.
/// </summary>
[Collection(GoldfishCollection.Name)]
public sealed class AbuseTests {
    private readonly GoldfishFixture _f;

    public AbuseTests(GoldfishFixture fixture) {
        _f = fixture;
    }

    private static Dictionary<string, string> Policy(string name, int limit, int periodSeconds, int burst) => new() {
        [$"Goldfish__RateLimits__{name}__Limit"] = limit.ToString(),
        [$"Goldfish__RateLimits__{name}__PeriodSeconds"] = periodSeconds.ToString(),
        [$"Goldfish__RateLimits__{name}__Burst"] = burst.ToString(),
    };

    private static Dictionary<string, string> ApiNode(params Dictionary<string, string>[] parts) {
        var settings = new Dictionary<string, string> { ["Goldfish__Roles"] = "api" };
        foreach (var part in parts) {
            foreach (var (k, v) in part) {
                settings[k] = v;
            }
        }
        return settings;
    }

    private static async Task<(int Status, string? Error, string? Scope)> ErrorOf(HttpResponseMessage response) {
        var status = (int)response.StatusCode;
        if (status < 400) {
            return (status, null, null);
        }
        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        return (status, json.GetProperty("error").GetString(),
            json.TryGetProperty("scope", out var scope) ? scope.GetString() : null);
    }

    private async Task<HttpResponseMessage> CreateAsync(HttpClient client, FakeDevice? device = null) {
        device ??= _f.Push.NewDevice();
        return await _f.RequestMailboxAsync(RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(32), device, client: client);
    }

    [IntegrationFact]
    public async Task MailboxCreation_ChecksThePowFirst_ThenLimitsEachAddress() {
        await using var node = NodeBehindProxy(ApiNode(Policy("create-ip", 1, 3600, 1)));
        using var client = ClientFrom(node, "198.18.10.1");
        var device = _f.Push.NewDevice();

        object Body(byte[] challenge, byte[] nonce) => new {
            pow = new { challenge = B64(challenge), nonce = B64(nonce) },
            sendSecret = B64(RandomNumberGenerator.GetBytes(32)),
            ownerHash = B64(RandomNumberGenerator.GetBytes(32)),
            endpoint = device.Url, p256dh = B64(device.P256dh), auth = B64(device.Auth),
        };

        // A wrong solution and an unknown challenge are refused, and neither touches the address budget.
        var issued = await (await client.PostAsync("/v1/pow/challenge", null)).Content.ReadFromJsonAsync<JsonElement>();
        var challenge = Base64Url.DecodeFromChars(issued.GetProperty("challenge").GetString());
        var difficulty = issued.GetProperty("difficulty").GetInt32();
        byte[] wrong;
        do {
            wrong = RandomNumberGenerator.GetBytes(ProofOfWork.NonceSize);
        } while (ProofOfWork.Verify(challenge, wrong, difficulty));
        foreach (var body in new[] {
                     Body(challenge, wrong),
                     Body(RandomNumberGenerator.GetBytes(ProofOfWork.ChallengeSize), new byte[ProofOfWork.NonceSize]),
                 }) {
            var refused = await ErrorOf(await client.PostAsJsonAsync("/v1/mailboxes", body));
            Assert.Equal((403, "pow_invalid", null), refused);
        }
        // The challenge was consumed by the wrong answer: even the right one is now refused.
        var right = ProofOfWork.Solve(challenge, difficulty);
        Assert.Equal(403, (int)(await client.PostAsJsonAsync("/v1/mailboxes", Body(challenge, right))).StatusCode);
        Assert.False(device.TryNext(out _), "no verification push without a valid proof of work");

        Assert.Equal(HttpStatusCode.Accepted, (await CreateAsync(client)).StatusCode);
        Assert.Equal((429, "rate_limited", "ip"), await ErrorOf(await CreateAsync(client)));
        using var other = ClientFrom(node, "198.18.11.1");
        Assert.Equal(HttpStatusCode.Accepted, (await CreateAsync(other)).StatusCode);
    }

    [IntegrationFact]
    public async Task PowDifficulty_RisesWithServerWideCreationLoad() {
        await using var node = NodeBehindProxy(ApiNode(new Dictionary<string, string> {
            ["Goldfish__Pow__LoadThresholdPerMinute"] = "1",
            ["Goldfish__Pow__MaxExtraDifficulty"] = "1",
        }));
        using var client = ClientFrom(node, "198.18.12.1");
        // Four creations in the last two minutes, from anyone, are two a minute: over this node's threshold of one.
        for (var i = 0; i < 4; i++) {
            await _f.CreateActiveMailboxAsync();
        }
        var baseDifficulty = _f.Services.GetRequiredService<GoldfishOptions>().Pow.BaseDifficulty;
        var info = await client.GetFromJsonAsync<JsonElement>("/v1/info");
        Assert.Equal(baseDifficulty + 1, info.GetProperty("powDifficulty").GetInt32());
        var challenge = await (await client.PostAsync("/v1/pow/challenge", null)).Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(baseDifficulty + 1, challenge.GetProperty("difficulty").GetInt32());
    }

    [IntegrationFact]
    public async Task AddressBuckets_GroupIpv6By64_AndNetworkBucketsGroupBy24And48() {
        async Task<(int, string?, string?)> Challenge(HttpClient c) => await ErrorOf(await c.PostAsync("/v1/pow/challenge", null));
        var ok = (200, (string?)null, (string?)null);

        await using (var node = NodeBehindProxy(ApiNode(Policy("pow-ip", 1, 3600, 1)))) {
            using var a = ClientFrom(node, "2001:db8:a:1::1");
            using var sameSlash64 = ClientFrom(node, "2001:db8:a:1:ffff:ffff:ffff:ffff");
            using var nextSlash64 = ClientFrom(node, "2001:db8:a:2::1");
            Assert.Equal(ok, await Challenge(a));
            Assert.Equal((429, "rate_limited", "ip"), await Challenge(sameSlash64));
            Assert.Equal(ok, await Challenge(nextSlash64));
        }

        await using (var node = NodeBehindProxy(ApiNode(Policy("pow-net", 1, 3600, 1)))) {
            foreach (var (first, sameNetwork, otherNetwork) in new[] {
                         ("198.18.13.1", "198.18.13.200", "198.18.14.1"),
                         ("2001:db8:b::1", "2001:db8:b:ffff::1", "2001:db8:c::1"),
                     }) {
                using var a = ClientFrom(node, first);
                using var b = ClientFrom(node, sameNetwork);
                using var c = ClientFrom(node, otherNetwork);
                Assert.Equal(ok, await Challenge(a));
                Assert.Equal((429, "rate_limited", "network"), await Challenge(b));
                Assert.Equal(ok, await Challenge(c));
            }
        }
    }

    [IntegrationFact]
    public async Task OwnerOperations_ChargeTheAddressOnlyForFailedOwnership() {
        var mailbox = await _f.CreateActiveMailboxAsync();
        var impostor = mailbox with { OwnerSecret = RandomNumberGenerator.GetBytes(32) };
        await using var node = NodeBehindProxy(ApiNode(Policy("owner-ip", 1, 3600, 1)));
        using var owner = ClientFrom(node, "198.18.15.1");
        using var guesser = ClientFrom(node, "198.18.16.1");

        Task<HttpResponseMessage> Refresh(HttpClient c, Mailbox m) => c.PostAsJsonAsync("/v1/mailboxes/refresh", new { items = new[] { m.Credential } });

        // A real owner is never charged, however often it refreshes.
        for (var i = 0; i < 3; i++) {
            Assert.Equal(HttpStatusCode.OK, (await Refresh(owner, mailbox)).StatusCode);
        }
        // A failed ownership check is charged, so guessing stops quickly, and that address is then refused outright.
        Assert.Equal((404, "not_found", null), await ErrorOf(await Refresh(guesser, impostor)));
        Assert.Equal((429, "rate_limited", "ip"), await ErrorOf(await Refresh(guesser, impostor)));
        Assert.Equal((429, "rate_limited", "ip"), await ErrorOf(await Refresh(guesser, mailbox)));
        Assert.Equal(HttpStatusCode.OK, (await Refresh(owner, mailbox)).StatusCode);
    }

    [IntegrationFact]
    public async Task EndpointRotation_IsBudgetedPerMailbox() {
        var mailbox = await _f.CreateActiveMailboxAsync();
        var other = await _f.CreateActiveMailboxAsync();
        var (factory, client) = Node(ApiNode(Policy("rotate-mailbox", 1, 86400, 1)));
        await using var node = factory;

        Task<HttpResponseMessage> Rotate(Mailbox m, FakeDevice device) => client.PutAsJsonAsync("/v1/mailboxes/endpoint", new {
            items = new[] { m.Credential }, endpoint = device.Url, p256dh = B64(device.P256dh), auth = B64(device.Auth),
        });

        Assert.Equal(HttpStatusCode.Accepted, (await Rotate(mailbox, _f.Push.NewDevice())).StatusCode);
        // Each rotation pushes to a new URL of the client's choosing, so a mailbox gets only a few.
        var target = _f.Push.NewDevice();
        Assert.Equal((429, "rate_limited", "mailbox"), await ErrorOf(await Rotate(mailbox, target)));
        Assert.Equal(0, Volatile.Read(ref target.Attempts));
        Assert.Equal(HttpStatusCode.Accepted, (await Rotate(other, _f.Push.NewDevice())).StatusCode);
    }

    [IntegrationFact]
    public async Task Invites_AreLimitedPerAddress_ForUploadsAndFetches() {
        await using var node = NodeBehindProxy(ApiNode(Policy("invite-create-ip", 1, 3600, 1), Policy("invite-fetch-ip", 1, 3600, 1)));
        using var a = ClientFrom(node, "198.18.17.1");
        using var b = ClientFrom(node, "198.18.18.1");
        var blob = RandomNumberGenerator.GetBytes(500);

        Assert.Equal(HttpStatusCode.Created, (await a.PostAsync("/v1/invites", Octets(blob))).StatusCode);
        Assert.Equal((429, "rate_limited", "ip"), await ErrorOf(await a.PostAsync("/v1/invites", Octets(blob))));
        var created = await b.PostAsync("/v1/invites", Octets(blob));
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var id = (await created.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetString();

        // Guessing invite ids is limited: after one miss, this address can't fetch even a real invite.
        Assert.Equal(HttpStatusCode.NotFound, (await a.GetAsync($"/v1/invites/{B64(RandomNumberGenerator.GetBytes(ProtocolLimits.InviteIdSize))}")).StatusCode);
        Assert.Equal((429, "rate_limited", "ip"), await ErrorOf(await a.GetAsync($"/v1/invites/{id}")));
        var fetched = await b.GetAsync($"/v1/invites/{id}");
        Assert.Equal(HttpStatusCode.OK, fetched.StatusCode);
        Assert.Equal(blob, await fetched.Content.ReadAsByteArrayAsync());
    }

    [IntegrationFact]
    public async Task CircuitBreaker_PausesAHostFailingForSeveralSubscribers_ThenCloses() {
        await using var push = new FakePushServer();
        await push.StartAsync("127.0.0.6");
        var (factory, client) = Node(ApiNode(new Dictionary<string, string> {
            ["Goldfish__Push__CircuitBreakerMinVolume"] = "3",
            ["Goldfish__Push__CircuitBreakerMinEndpoints"] = "3",
            ["Goldfish__Push__CircuitBreakerOpenSeconds"] = "3",
        }));
        await using var node = factory;

        // Three subscribers on one push service, and the service is failing for all of them.
        for (var i = 0; i < 3; i++) {
            var failing = push.NewDevice();
            failing.Status = 503;
            Assert.Equal((502, "endpoint_unreachable", null), await ErrorOf(await CreateAsync(client, failing)));
        }

        // The circuit is open: the next push to that host isn't even attempted, and the client is told to come back.
        var healthy = push.NewDevice();
        var paused = await CreateAsync(client, healthy);
        Assert.Equal((503, "unavailable", null), await ErrorOf(paused));
        Assert.NotNull(paused.Headers.RetryAfter);
        Assert.Equal(0, Volatile.Read(ref healthy.Attempts));
        // Other push services are unaffected.
        Assert.Equal(HttpStatusCode.Accepted, (await CreateAsync(client)).StatusCode);

        // Once the open period is over, the host gets traffic again.
        await EventuallyAsync(async () => (await CreateAsync(client, healthy)).StatusCode == HttpStatusCode.Accepted,
            TimeSpan.FromSeconds(15), "the circuit should close after its open period");
        Assert.Equal(PushType.Verification, (await healthy.NextAsync()).Type);
    }

    [IntegrationFact]
    public async Task VerificationPushesToNewHosts_HaveAServerWideBudget() {
        await using var first = new FakePushServer();
        await first.StartAsync("127.0.0.7");
        await using var second = new FakePushServer();
        await second.StartAsync("127.0.0.8");
        // A period under an hour keys the bucket daily, apart from the fixture's hourly one.
        var (factory, client) = Node(ApiNode(Policy("newhost-global", 1, 600, 1)));
        await using var node = factory;

        Assert.Equal(HttpStatusCode.Accepted, (await CreateAsync(client, first.NewDevice())).StatusCode);
        var refusedDevice = second.NewDevice();
        Assert.Equal((429, "rate_limited", "global"), await ErrorOf(await CreateAsync(client, refusedDevice)));
        Assert.Equal(0, Volatile.Read(ref refusedDevice.Attempts));
        // Hosts that already took a verification push aren't charged: real push services keep working.
        Assert.Equal(HttpStatusCode.Accepted, (await CreateAsync(client, first.NewDevice())).StatusCode);
        Assert.Equal(HttpStatusCode.Accepted, (await CreateAsync(client)).StatusCode);
    }

    [IntegrationFact]
    public async Task GlobalSendCeiling_RefusesBeyondTheServerWideRate() {
        var mailbox = await _f.CreateActiveMailboxAsync();
        // This bucket is shared with the fixture node (2000/s, burst 4000, so 2 s of slack). A 5 s interval refuses the
        // second send, and the wait at the end lets the bucket drain again before other tests send.
        var (factory, client) = Node(ApiNode(Policy("send-global", 1, 5, 1)));
        try {
            Assert.Equal(HttpStatusCode.Accepted, (await _f.SendAsync(mailbox.SendSecret, [1], client: client)).StatusCode);
            Assert.Equal((429, "rate_limited", "global"), await ErrorOf(await _f.SendAsync(mailbox.SendSecret, [2], client: client)));
        } finally {
            await factory.DisposeAsync();
            await Task.Delay(TimeSpan.FromSeconds(6));
        }
    }

    [IntegrationFact]
    public async Task UnverifiedMailboxes_ArePurgedAfterTheirDeadline() {
        var device = _f.Push.NewDevice();
        var pending = new Mailbox(RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(32), device);
        Assert.Equal(HttpStatusCode.Accepted, (await _f.RequestMailboxAsync(pending.SendSecret, pending.OwnerSecret, device)).StatusCode);
        var (_, _, code) = await device.NextAsync();
        var active = await _f.CreateActiveMailboxAsync();

        var crypto = _f.Services.GetRequiredService<MailboxCrypto>();
        var ids = new[] { crypto.MailboxId(pending.SendSecret), crypto.MailboxId(active.SendSecret) };
        await _f.ScalarAsync("UPDATE mailboxes SET verify_expires_at = UTC_TIMESTAMP() - INTERVAL 1 MINUTE WHERE id IN @ids", new { ids });
        await _f.Services.GetRequiredService<MailboxRepository>().PurgeAsync();

        Assert.Equal(0, await _f.ScalarAsync("SELECT COUNT(*) FROM mailboxes WHERE id = @id", new { id = ids[0] }));
        Assert.Equal(1, await _f.ScalarAsync("SELECT COUNT(*) FROM mailboxes WHERE id = @id", new { id = ids[1] }));
        Assert.Equal(HttpStatusCode.NotFound, (await _f.VerifyAsync([pending], code)).StatusCode);
    }

    [IntegrationFact]
    public async Task PushClient_ChecksResolvedAddressesAtConnectTime() {
        // A name that passes validation but resolves to a forbidden address: what DNS rebinding produces. Here the
        // validator allows "localhost", but the connect-time filter doesn't allow loopback.
        var options = new GoldfishOptions();
        options.Push.DangerouslyAllowInsecureLoopback = true;
        var validator = new EndpointValidator(options.Push, new IpRangeFilter(dangerouslyAllowLoopback: true));
        var guards = ActivatorUtilities.CreateInstance<HostGuards>(_f.Services, options);
        using var client = new PushClient(options, new IpRangeFilter(), validator,
            _f.Services.GetRequiredService<VapidSigner>(), guards, NullLogger<PushClient>.Instance);

        var device = _f.Push.NewDevice(alternateHost: true);
        Assert.StartsWith("http://localhost:", device.Url);
        var envelope = PushEnvelope.Build(PushType.Message, new byte[MailboxCrypto.TagSize], [1]);
        var result = await client.SendAsync(new EndpointRecord(device.Url, device.P256dh, device.Auth), envelope, 60, CancellationToken.None);

        // Retried later rather than treated as a dead subscription, and nothing reached the address.
        Assert.Equal(PushStatus.Transient, result.Status);
        Assert.Equal(TimeSpan.FromMinutes(10), result.RetryAfter);
        Assert.Equal(0, Volatile.Read(ref device.Attempts));
    }
}
