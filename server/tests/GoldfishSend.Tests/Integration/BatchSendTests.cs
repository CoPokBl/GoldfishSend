using System.Buffers.Binary;
using System.Buffers.Text;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using GoldfishSend.Core.Crypto;
using GoldfishSend.Core.Protocol;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using static GoldfishSend.Tests.Integration.GoldfishFixture;

namespace GoldfishSend.Tests.Integration;

/// <summary><c>POST /v1/messages/batch</c> (docs/groups.md, "Server: batch send"), through the encrypted gateway.</summary>
[Collection(GoldfishCollection.Name)]
public sealed class BatchSendTests {
    private readonly GoldfishFixture _f;

    public BatchSendTests(GoldfishFixture fixture) {
        _f = fixture;
    }

    private static BatchItem Item(byte[] sendSecret, byte[] blob, byte[]? idempotencyKey = null, int? ttl = null) =>
        new(sendSecret, idempotencyKey ?? RandomNumberGenerator.GetBytes(16), ttl, blob);

    private static async Task<HttpResponseMessage> PostBatch(HttpClient client, byte[] body, string? pow = null, string contentType = "application/octet-stream") {
        var content = new ByteArrayContent(body);
        content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(contentType);
        using var request = new HttpRequestMessage(HttpMethod.Post, "/v1/messages/batch") { Content = content };
        if (pow is not null) {
            request.Headers.Add("GF-PoW", pow);
        }
        return await client.SendAsync(request);
    }

    private static async Task<JsonElement[]> Results(HttpResponseMessage response) {
        Assert.True(response.StatusCode == HttpStatusCode.OK, $"{(int)response.StatusCode} {await response.Content.ReadAsStringAsync()}");
        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        return json.GetProperty("results").EnumerateArray().ToArray();
    }

    private static (WebApplicationFactory<Program> Factory, HttpClient Client) Node(Dictionary<string, string> overrides) {
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

    [IntegrationFact]
    public async Task Batch_DeliversEveryItem_ToEveryDevice() {
        var mailboxes = new List<Mailbox>();
        for (var i = 0; i < 4; i++) {
            mailboxes.Add(await _f.CreateActiveMailboxAsync());
        }
        var items = mailboxes.Select((m, i) => Item(m.SendSecret, [(byte)i, 0xAA], ttl: 600)).ToArray();

        var results = await Results(await PostBatch(_f.Client, MessageBatch.Encode(items)));

        Assert.Equal(4, results.Length);
        for (var i = 0; i < 4; i++) {
            Assert.Equal(202, results[i].GetProperty("status").GetInt32());
            Assert.Equal(16, Base64Url.DecodeFromChars(results[i].GetProperty("id").GetString()).Length);
            var (type, tag, body) = await mailboxes[i].Device.NextAsync();
            Assert.Equal(PushType.Message, type);
            Assert.Equal(mailboxes[i].Tag, tag);
            Assert.Equal(new byte[] { (byte)i, 0xAA }, body);
        }
    }

    [IntegrationFact]
    public async Task Batch_ReportsEachItemLikeASingleSend() {
        var gone = await _f.CreateActiveMailboxAsync();
        gone.Device.Status = 410;
        var heldBefore = await _f.ScalarAsync("SELECT COUNT(*) FROM pending_messages");
        for (byte i = 0; i < 3; i++) { // MaxHeldPerMailbox is 3 in the fixture.
            Assert.Equal(HttpStatusCode.Accepted, (await _f.SendAsync(gone.SendSecret, [i])).StatusCode);
        }
        await EventuallyAsync(async () => await _f.ScalarAsync("SELECT COUNT(*) FROM pending_messages") >= heldBefore + 3);
        var healthy = await _f.CreateActiveMailboxAsync();

        var results = await Results(await PostBatch(_f.Client, MessageBatch.Encode([
            Item(RandomNumberGenerator.GetBytes(32), [1]),
            Item(gone.SendSecret, [2]),
            Item(healthy.SendSecret, [3]),
        ])));

        Assert.Equal(404, results[0].GetProperty("status").GetInt32());
        Assert.Equal("not_found", results[0].GetProperty("error").GetString());
        Assert.Equal(507, results[1].GetProperty("status").GetInt32());
        Assert.Equal("mailbox_full", results[1].GetProperty("error").GetString());
        Assert.Equal("mailbox", results[1].GetProperty("scope").GetString());
        Assert.Equal(3600, results[1].GetProperty("retryAfter").GetInt32());
        Assert.Equal(202, results[2].GetProperty("status").GetInt32());
        Assert.False(results[2].TryGetProperty("error", out _));
        Assert.Equal(new byte[] { 3 }, (await healthy.Device.NextAsync()).Body);
    }

    [IntegrationFact]
    public async Task Batch_AppliesThePerMailboxLimitPerItem() {
        var limited = await _f.CreateActiveMailboxAsync();
        var other = await _f.CreateActiveMailboxAsync();
        var (factory, client) = Node(new() {
            ["Goldfish__Roles"] = "api",
            ["Goldfish__RateLimits__send-mailbox__Limit"] = "1",
            ["Goldfish__RateLimits__send-mailbox__Burst"] = "1",
            ["Goldfish__RateLimits__send-mailbox__PeriodSeconds"] = "3600",
        });
        await using (factory) {
            var results = await Results(await PostBatch(client, MessageBatch.Encode([
                Item(limited.SendSecret, [1]),
                Item(limited.SendSecret, [2]),
                Item(other.SendSecret, [3]),
            ])));
            Assert.Equal(202, results[0].GetProperty("status").GetInt32());
            Assert.Equal(429, results[1].GetProperty("status").GetInt32());
            Assert.Equal("rate_limited", results[1].GetProperty("error").GetString());
            Assert.Equal("mailbox", results[1].GetProperty("scope").GetString());
            Assert.True(results[1].GetProperty("retryAfter").GetInt32() > 0);
            Assert.Equal(202, results[2].GetProperty("status").GetInt32());
        }
    }

    [IntegrationFact]
    public async Task Batch_IsIdempotent_PerItem() {
        var mailbox = await _f.CreateActiveMailboxAsync();
        var k1 = RandomNumberGenerator.GetBytes(16);
        var k2 = RandomNumberGenerator.GetBytes(16);
        var body = MessageBatch.Encode([
            Item(mailbox.SendSecret, [1], k1),
            Item(mailbox.SendSecret, [2], k2),
            Item(mailbox.SendSecret, [1], k1), // The same key inside one batch.
        ]);

        var first = await Results(await PostBatch(_f.Client, body));
        var ids = first.Select(r => r.GetProperty("id").GetString()).ToArray();
        Assert.Equal(ids[0], ids[2]);
        Assert.NotEqual(ids[0], ids[1]);

        // Retrying the whole batch (as a client does after a lost response) returns the same ids.
        var again = await Results(await PostBatch(_f.Client, body));
        Assert.Equal(ids, again.Select(r => r.GetProperty("id").GetString()).ToArray());

        var received = new List<byte> { (await mailbox.Device.NextAsync()).Body[0], (await mailbox.Device.NextAsync()).Body[0] };
        Assert.Equal(new byte[] { 1, 2 }, received.Order().ToArray());
        await Task.Delay(500);
        Assert.False(mailbox.Device.TryNext(out _), "A duplicate idempotency key was delivered twice.");
    }

    [IntegrationFact]
    public async Task Batch_RejectsMalformedBodies() {
        var secret = RandomNumberGenerator.GetBytes(32);
        var one = MessageBatch.Encode([Item(secret, [1, 2, 3])]);
        var full = MessageBatch.Encode(Enumerable.Range(0, 32).Select(_ => Item(secret, [1])).ToArray());
        var count33 = (byte[])full.Clone();
        count33[0] = 33;
        var lenZero = (byte[])one.Clone();
        BinaryPrimitives.WriteUInt16BigEndian(lenZero.AsSpan(53), 0);
        var tooLong = new byte[1 + 32 + 16 + 4 + 2 + ProtocolLimits.MaxMessageBytes + 1];
        tooLong[0] = 1;
        BinaryPrimitives.WriteUInt16BigEndian(tooLong.AsSpan(53), (ushort)(ProtocolLimits.MaxMessageBytes + 1));

        foreach (var body in new[] { new byte[] { 0 }, count33, one[..^1], (byte[])[.. one, 0], lenZero[..55], tooLong }) {
            var response = await PostBatch(_f.Client, body);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Equal("invalid_request", (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("error").GetString());
        }
        Assert.Equal(HttpStatusCode.UnsupportedMediaType, (await PostBatch(_f.Client, one, contentType: "application/json")).StatusCode);
    }

    [IntegrationFact]
    public async Task Batch_ChargesClientBucketsOncePerEightItems_AndPowPaysForAll() {
        var mailbox = await _f.CreateActiveMailboxAsync();
        // send-ip holds exactly 5 tokens and refills one per hour.
        var (factory, client) = Node(new() {
            ["Goldfish__Roles"] = "api",
            ["Goldfish__RateLimits__send-ip__Limit"] = "1",
            ["Goldfish__RateLimits__send-ip__Burst"] = "5",
            ["Goldfish__RateLimits__send-ip__PeriodSeconds"] = "3600",
        });
        await using (factory) {
            // 32 items (to mailboxes that don't exist, so only the client charge matters) cost 4 tokens.
            var unknown = Enumerable.Range(0, 32).Select(_ => Item(RandomNumberGenerator.GetBytes(32), [1])).ToArray();
            var results = await Results(await PostBatch(client, MessageBatch.Encode(unknown)));
            Assert.Equal(32, results.Length);
            Assert.All(results, r => Assert.Equal(404, r.GetProperty("status").GetInt32()));

            // About one token is left (earlier tests may have used a sliver of it), so a 9-item batch, which costs 2,
            // doesn't fit. A flat cost of 1 per batch would have left 4 tokens; a cost per item would have refused the first.
            var batch = MessageBatch.Encode(Enumerable.Range(0, 9).Select(i => Item(mailbox.SendSecret, [(byte)i])).ToArray());
            var limited = await PostBatch(client, batch);
            Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
            Assert.Equal("ip", (await limited.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("scope").GetString());
            Assert.True(limited.Headers.Contains("Retry-After"));

            // A solved proof of work pays for the whole batch, once.
            var challengeResponse = await client.PostAsync("/v1/pow/challenge", null);
            var challengeJson = await challengeResponse.Content.ReadFromJsonAsync<JsonElement>();
            var challenge = Base64Url.DecodeFromChars(challengeJson.GetProperty("challenge").GetString());
            var nonce = ProofOfWork.Solve(challenge, challengeJson.GetProperty("difficulty").GetInt32());
            var pow = $"{B64(challenge)}.{B64(nonce)}";
            var paid = await Results(await PostBatch(client, batch, pow));
            Assert.All(paid, r => Assert.Equal(202, r.GetProperty("status").GetInt32()));
            Assert.Equal(HttpStatusCode.TooManyRequests, (await PostBatch(client, batch, pow)).StatusCode);
        }
    }

    [IntegrationFact]
    public async Task Batch_IsNotReachableInPlaintext() {
        var response = await _f.RawClient.PostAsync("/v1/messages/batch", Octets(MessageBatch.Encode([Item(RandomNumberGenerator.GetBytes(32), [1])])));
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }
}
