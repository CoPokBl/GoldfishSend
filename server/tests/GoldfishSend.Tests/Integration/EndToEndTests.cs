using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using GoldfishSend.Core.Protocol;
using static GoldfishSend.Tests.Integration.GoldfishFixture;

namespace GoldfishSend.Tests.Integration;

[Collection(GoldfishCollection.Name)]
public sealed class EndToEndTests {
    private readonly GoldfishFixture _f;

    public EndToEndTests(GoldfishFixture fixture) {
        _f = fixture;
    }

    [IntegrationFact]
    public async Task Info_PublishesVapidKeyAndLimits() {
        var json = await _f.Client.GetFromJsonAsync<JsonElement>("/v1/info");
        Assert.Equal(2, json.GetProperty("protocol").GetInt32());
        Assert.Equal(3983, json.GetProperty("maxMessageBytes").GetInt32());
        Assert.Equal(87, json.GetProperty("vapidPublicKey").GetString()!.Length); // 65 bytes, base64url
    }

    [IntegrationFact]
    public async Task Message_IsDeliveredEncrypted_ThenForgotten() {
        var mailbox = await _f.CreateActiveMailboxAsync();
        var body = RandomNumberGenerator.GetBytes(ProtocolLimits.MaxMessageBytes);

        var response = await _f.SendAsync(mailbox.SendSecret, body);
        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);

        var (type, tag, received) = await mailbox.Device.NextAsync();
        Assert.Equal(PushType.Message, type);
        Assert.Equal(mailbox.Tag, tag);
        Assert.Equal(body, received);

        // Nothing is retained after delivery: no held row and no stream entry.
        var id = System.Buffers.Text.Base64Url.DecodeFromChars(
            (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetString());
        Assert.Equal(0, await _f.ScalarAsync("SELECT COUNT(*) FROM pending_messages WHERE id = @id", new { id }));
        // Other tests (and extra nodes they start) may have entries in flight, so look for this message specifically.
        await using var mux = await StackExchange.Redis.ConnectionMultiplexer.ConnectAsync(_f.Redis);
        var stream = mux.GetDatabase(0);
        await EventuallyAsync(async () => {
            var entries = await stream.StreamRangeAsync("gf:q");
            return !entries.Any(e => e.Values.Any(v => v.Name == "id" && ((byte[])v.Value!).AsSpan().SequenceEqual(id)));
        }, because: "stream entry should be deleted after delivery");
    }

    [IntegrationFact]
    public async Task Database_HoldsNoPlaintextIdentifiers() {
        var mailbox = await _f.CreateActiveMailboxAsync();
        await using var conn = new MySqlConnector.MySqlConnection(_f.MySql);
        await conn.OpenAsync();
        var rows = await Dapper.SqlMapper.QueryAsync<byte[]>(conn, "SELECT sealed_endpoint FROM mailboxes");
        var url = System.Text.Encoding.UTF8.GetBytes(mailbox.Device.Url);
        foreach (var sealedEndpoint in rows) {
            Assert.Equal(-1, sealedEndpoint.AsSpan().IndexOf(url));
            Assert.Equal(-1, sealedEndpoint.AsSpan().IndexOf(mailbox.Device.Auth));
        }
        var ids = await Dapper.SqlMapper.QueryAsync<byte[]>(conn, "SELECT id FROM mailboxes");
        Assert.DoesNotContain(ids, id => id.AsSpan().SequenceEqual(mailbox.SendSecret));
    }

    [IntegrationFact]
    public async Task Idempotency_DuplicateSendDeliversOnce() {
        var mailbox = await _f.CreateActiveMailboxAsync();
        var key = RandomNumberGenerator.GetBytes(16);

        var first = await (await _f.SendAsync(mailbox.SendSecret, [1, 2, 3], key)).Content.ReadFromJsonAsync<JsonElement>();
        var second = await (await _f.SendAsync(mailbox.SendSecret, [1, 2, 3], key)).Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(first.GetProperty("id").GetString(), second.GetProperty("id").GetString());

        await mailbox.Device.NextAsync();
        await Task.Delay(500);
        Assert.False(mailbox.Device.TryNext(out _));
    }

    [IntegrationFact]
    public async Task TransientFailure_IsHeldDurably_AndRetried() {
        var mailbox = await _f.CreateActiveMailboxAsync();
        mailbox.Device.Status = 503;

        var sent = await (await _f.SendAsync(mailbox.SendSecret, [42])).Content.ReadFromJsonAsync<JsonElement>();
        var id = System.Buffers.Text.Base64Url.DecodeFromChars(sent.GetProperty("id").GetString());
        const string held = "SELECT COUNT(*) FROM pending_messages WHERE id = @id";
        await EventuallyAsync(async () => await _f.ScalarAsync(held, new { id }) == 1,
            because: "a failed delivery must move to MySQL");

        mailbox.Device.Status = 201;
        // The first retry is scheduled 10s later, give or take 20% jitter.
        var (_, _, body) = await mailbox.Device.NextAsync(TimeSpan.FromSeconds(20));
        Assert.Equal([42], body);
        await EventuallyAsync(async () => await _f.ScalarAsync(held, new { id }) == 0, because: "delivered messages are forgotten");
    }

    [IntegrationFact]
    public async Task GoneEndpoint_HoldsMessages_UntilRotationThenFlushes() {
        var mailbox = await _f.CreateActiveMailboxAsync();
        mailbox.Device.Status = 410;

        await _f.SendAsync(mailbox.SendSecret, [7, 7, 7]);
        await EventuallyAsync(async () =>
            await _f.ScalarAsync("SELECT COUNT(*) FROM pending_messages WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE state = 2)") == 1,
            because: "410 marks the endpoint gone and holds the message");

        // The app re-registers with a new distributor endpoint.
        var newDevice = _f.Push.NewDevice();
        var rotate = await _f.Client.PutAsJsonAsync("/v1/mailboxes/endpoint", new {
            items = new[] { mailbox.Credential },
            endpoint = newDevice.Url,
            p256dh = B64(newDevice.P256dh),
            auth = B64(newDevice.Auth),
        });
        Assert.Equal(HttpStatusCode.Accepted, rotate.StatusCode);

        var (type, tag, code) = await newDevice.NextAsync();
        Assert.Equal(PushType.Verification, type);
        Assert.Equal(mailbox.Tag, tag);
        Assert.Equal(HttpStatusCode.OK, (await _f.VerifyAsync([mailbox], code)).StatusCode);

        var (_, _, body) = await newDevice.NextAsync();
        Assert.Equal([7, 7, 7], body);
    }

    [IntegrationFact]
    public async Task Verification_RejectsWrongCode_AndCapsAttempts() {
        var device = _f.Push.NewDevice();
        var mailbox = new Mailbox(RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(32), device);
        Assert.Equal(HttpStatusCode.Accepted, (await _f.RequestMailboxAsync(mailbox.SendSecret, mailbox.OwnerSecret, device)).StatusCode);
        var (_, _, code) = await device.NextAsync();

        for (var i = 0; i < 5; i++) {
            Assert.Equal(HttpStatusCode.Forbidden, (await _f.VerifyAsync([mailbox], RandomNumberGenerator.GetBytes(16))).StatusCode);
        }
        // The real code no longer works once the attempts are used up.
        Assert.Equal(HttpStatusCode.Forbidden, (await _f.VerifyAsync([mailbox], code)).StatusCode);
        // An unverified mailbox can't receive.
        Assert.Equal(HttpStatusCode.NotFound, (await _f.SendAsync(mailbox.SendSecret, [1])).StatusCode);
    }

    [IntegrationFact]
    public async Task OwnerOperations_RequireOwnerSecret() {
        var mailbox = await _f.CreateActiveMailboxAsync();
        var impostor = mailbox with { OwnerSecret = RandomNumberGenerator.GetBytes(32) };

        var denied = await _f.Client.PostAsJsonAsync("/v1/mailboxes/delete", new { items = new[] { impostor.Credential } });
        Assert.Equal(HttpStatusCode.NotFound, denied.StatusCode);

        var deleted = await _f.Client.PostAsJsonAsync("/v1/mailboxes/delete", new { items = new[] { mailbox.Credential } });
        Assert.Equal(HttpStatusCode.NoContent, deleted.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await _f.SendAsync(mailbox.SendSecret, [1])).StatusCode);
    }

    [IntegrationFact]
    public async Task Refresh_ExtendsExpiry() {
        var mailbox = await _f.CreateActiveMailboxAsync();
        var response = await _f.Client.PostAsJsonAsync("/v1/mailboxes/refresh", new { items = new[] { mailbox.Credential } });
        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        var expires = DateOnly.Parse(json.GetProperty("expiresAt").GetString()!);
        Assert.True(expires >= DateOnly.FromDateTime(DateTime.UtcNow).AddDays(89));
    }

    [IntegrationFact]
    public async Task Pow_IsSingleUse() {
        var (challenge, nonce) = await _f.SolvePowAsync();
        object Body(FakeDevice d) => new {
            pow = new { challenge = B64(challenge), nonce = B64(nonce) },
            sendSecret = B64(RandomNumberGenerator.GetBytes(32)),
            ownerHash = B64(RandomNumberGenerator.GetBytes(32)),
            endpoint = d.Url,
            p256dh = B64(d.P256dh),
            auth = B64(d.Auth),
        };
        var device = _f.Push.NewDevice();
        Assert.Equal(HttpStatusCode.Accepted, (await _f.Client.PostAsJsonAsync("/v1/mailboxes", Body(device))).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await _f.Client.PostAsJsonAsync("/v1/mailboxes", Body(device))).StatusCode);
    }

    [IntegrationFact]
    public async Task Ssrf_PrivateAndMetadataTargetsAreRefused() {
        var device = _f.Push.NewDevice();
        foreach (var url in new[] { "http://169.254.169.254/latest/meta-data", "http://10.0.0.1/push", "http://[fd00::1]/push", "ftp://example.com/x" }) {
            var response = await _f.RequestMailboxAsync(RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(32), device, url);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }
    }

    [IntegrationFact]
    public async Task UnreachableEndpoint_IsRejectedAtRegistration() {
        var device = _f.Push.NewDevice();
        device.Status = 404;
        var response = await _f.RequestMailboxAsync(RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(32), device);
        Assert.Equal(HttpStatusCode.BadGateway, response.StatusCode);
    }

    [IntegrationFact]
    public async Task NonRateLimitErrors_CarryNoScope() {
        var response = await _f.SendAsync(RandomNumberGenerator.GetBytes(32), [1]);
        var error = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("not_found", error.GetProperty("error").GetString());
        Assert.False(error.TryGetProperty("scope", out _));
    }

    [IntegrationFact]
    public async Task Send_ValidatesInput() {
        var mailbox = await _f.CreateActiveMailboxAsync();
        Assert.Equal(HttpStatusCode.NotFound, (await _f.SendAsync(RandomNumberGenerator.GetBytes(32), [1])).StatusCode);
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge,
            (await _f.SendAsync(mailbox.SendSecret, new byte[ProtocolLimits.MaxMessageBytes + 1])).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await _f.SendAsync(new byte[5], [1])).StatusCode);
    }

    [IntegrationFact]
    public async Task PerMailboxRateLimit_ProtectsRecipient() {
        var mailbox = await _f.CreateActiveMailboxAsync();
        HttpResponseMessage? limited = null;
        for (var i = 0; i < 40 && limited is null; i++) {
            var response = await _f.SendAsync(mailbox.SendSecret, [(byte)i]);
            if (response.StatusCode == HttpStatusCode.TooManyRequests) {
                limited = response;
            }
        }
        Assert.NotNull(limited);
        Assert.NotNull(limited!.Headers.RetryAfter);
        var error = await limited.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("rate_limited", error.GetProperty("error").GetString());
        // "mailbox" tells the client a proof of work won't help, so it backs off instead.
        Assert.Equal("mailbox", error.GetProperty("scope").GetString());
    }

    [IntegrationFact]
    public async Task Invite_CanBeFetchedExactlyOnce() {
        var blob = RandomNumberGenerator.GetBytes(2000);
        var created = await _f.Client.PostAsync("/v1/invites", Octets(blob));
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var id = (await created.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetString();

        var first = await _f.Client.GetAsync($"/v1/invites/{id}");
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(blob, await first.Content.ReadAsByteArrayAsync());
        Assert.Equal(HttpStatusCode.NotFound, (await _f.Client.GetAsync($"/v1/invites/{id}")).StatusCode);
    }

    [IntegrationFact]
    public async Task RawEndpoints_RequireOctetStream() {
        // A cross-site <form> or fetch() "simple request" can't send this type without a CORS preflight.
        var plain = new StringContent("hello");
        Assert.Equal(HttpStatusCode.UnsupportedMediaType, (await _f.Client.PostAsync("/v1/invites", plain)).StatusCode);
        Assert.Equal(HttpStatusCode.UnsupportedMediaType, (await _f.Client.PostAsync("/v1/messages", new StringContent("x"))).StatusCode);
    }

    [IntegrationFact]
    public async Task HeldMessages_AreCappedPerMailbox() {
        var mailbox = await _f.CreateActiveMailboxAsync();
        mailbox.Device.Status = 410;
        await _f.SendAsync(mailbox.SendSecret, [1]);
        await EventuallyAsync(async () => await _f.ScalarAsync("SELECT COUNT(*) FROM mailboxes WHERE state = 2") >= 1);

        HttpResponseMessage? full = null;
        for (var i = 0; i < 10 && full is null; i++) {
            var response = await _f.SendAsync(mailbox.SendSecret, [(byte)i]);
            if ((int)response.StatusCode == 507) {
                full = response;
            }
            await Task.Delay(200); // Let the stream worker move each message to the held table.
        }
        Assert.NotNull(full);
    }

    [IntegrationFact]
    public async Task Rotation_IsRefusedForMailboxesStillPendingCreation() {
        var device = _f.Push.NewDevice();
        var mailbox = new Mailbox(RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(32), device);
        await _f.RequestMailboxAsync(mailbox.SendSecret, mailbox.OwnerSecret, device);
        await device.NextAsync();

        var other = _f.Push.NewDevice();
        var rotate = await _f.Client.PutAsJsonAsync("/v1/mailboxes/endpoint", new {
            items = new[] { mailbox.Credential },
            endpoint = other.Url,
            p256dh = B64(other.P256dh),
            auth = B64(other.Auth),
        });
        Assert.Equal(HttpStatusCode.NotFound, rotate.StatusCode);
        Assert.False(other.TryNext(out _), "no push may be sent to the new URL");
    }

    [IntegrationFact]
    public async Task NullBatchItem_IsABadRequestNotAServerError() {
        var response = await _f.Client.PostAsync("/v1/mailboxes/refresh",
            new StringContent("{\"items\":[null]}", System.Text.Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [IntegrationFact]
    public async Task Responses_CarryPrivacyHeaders() {
        // The outer responses are what proxies and caches see: the key, a gateway answer and a gateway error.
        var key = await _f.RawClient.GetAsync("/v1/key");
        var (outer, _) = (await _f.Gateway.KeyAsync(_f.RawClient.BaseAddress!, default))
            .Seal(GatewayCodec.EncodeRequest(new InnerRequest("GET", DateTimeOffset.UtcNow.ToUnixTimeSeconds(), "/v1/info", [], [])));
        var sealedInfo = await _f.RawClient.PostAsync("/v1/gw", Octets(outer));
        var error = await _f.RawClient.PostAsync("/v1/gw", Octets(new byte[2000]));
        foreach (var response in new[] { key, sealedInfo, error }) {
            Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
            Assert.False(response.Headers.Contains("Server"));
            Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
        }
        Assert.Equal(HttpStatusCode.OK, sealedInfo.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, error.StatusCode);
    }
}
