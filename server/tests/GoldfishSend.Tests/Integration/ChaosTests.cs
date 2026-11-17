using System.Buffers.Text;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using GoldfishSend.Core.Crypto;
using GoldfishSend.Core.Protocol;
using GoldfishSend.Infrastructure.Delivery;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using StackExchange.Redis;
using static GoldfishSend.Tests.Integration.GoldfishFixture;

namespace GoldfishSend.Tests.Integration;

/// <summary>
/// With the push server failing and the delivery worker killed, nothing is lost within
/// its TTL, and nothing is delivered after it. Each test uses push servers on loopback addresses of their own, so their
/// failures (circuit breaker, slow lane) stay out of the other tests.
/// Slow by design (the second waits out the real reclaim and lease timeouts), so they carry a trait:
/// <c>dotnet test --filter Category=Chaos</c>.
/// </summary>
[Collection(GoldfishCollection.Name)]
[Trait("Category", "Chaos")]
public sealed class ChaosTests {
    private readonly GoldfishFixture _f;

    public ChaosTests(GoldfishFixture fixture) {
        _f = fixture;
    }

    private sealed record Sent(Mailbox Mailbox, byte[] Body, byte[] Key, string Id) {
        public string Hex => Convert.ToHexString(Body);
    }

    private async Task<List<Mailbox>> MailboxesAsync(FakePushServer server, int count) {
        var result = new List<Mailbox>();
        for (var i = 0; i < count; i++) {
            result.Add(await _f.CreateActiveMailboxAsync(server.NewDevice()));
        }
        return result;
    }

    private static async Task<Sent> SendAsync(HttpClient client, Mailbox mailbox, byte[]? body = null, byte[]? key = null, int? ttl = null) {
        body ??= RandomNumberGenerator.GetBytes(16);
        key ??= RandomNumberGenerator.GetBytes(16);
        using var request = new HttpRequestMessage(HttpMethod.Post, "/v1/messages") { Content = Octets(body) };
        request.Headers.Add("GF-Send-Token", B64(mailbox.SendSecret));
        request.Headers.Add("GF-Idempotency-Key", B64(key));
        if (ttl is not null) {
            request.Headers.Add("GF-TTL", ttl.Value.ToString());
        }
        var response = await client.SendAsync(request);
        Assert.True(response.StatusCode == HttpStatusCode.Accepted, $"send: {(int)response.StatusCode} {await response.Content.ReadAsStringAsync()}");
        var id = (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetString()!;
        return new Sent(mailbox, body, key, id);
    }

    /// <summary>Counts every message push the devices have received so far, duplicates included.</summary>
    private static void Drain(IEnumerable<Mailbox> mailboxes, Dictionary<string, int> seen) {
        foreach (var mailbox in mailboxes) {
            while (mailbox.Device.TryNext(out var envelope)) {
                Assert.True(PushEnvelope.TryParse(envelope, out var type, out _, out var body), "Malformed envelope");
                Assert.Equal(PushType.Message, type);
                var hex = Convert.ToHexString(body);
                seen[hex] = seen.GetValueOrDefault(hex) + 1;
            }
        }
    }

    private async Task WaitForAllAsync(List<Mailbox> mailboxes, List<Sent> sent, Dictionary<string, int> seen, TimeSpan timeout) {
        await EventuallyAsync(() => {
            Drain(mailboxes, seen);
            return Task.FromResult(sent.All(s => seen.ContainsKey(s.Hex)));
        }, timeout, $"lost {sent.Count(s => !seen.ContainsKey(s.Hex))} of {sent.Count} messages");
        // Give late duplicates a moment to show up.
        await Task.Delay(1000);
        Drain(mailboxes, seen);
    }

    private byte[][] MailboxIds(IEnumerable<Mailbox> mailboxes) {
        var crypto = _f.Services.GetRequiredService<MailboxCrypto>();
        return mailboxes.Select(m => crypto.MailboxId(m.SendSecret)).ToArray();
    }

    private Task<long> HeldAsync(IEnumerable<Mailbox> mailboxes) {
        return _f.ScalarAsync("SELECT COUNT(*) FROM pending_messages WHERE mailbox_id IN @ids", new { ids = MailboxIds(mailboxes) });
    }

    private static int Attempts(FakeDevice device) => Volatile.Read(ref device.Attempts);

    [IntegrationFact]
    public async Task PushServerOutage_LosesNothingWithinTtl_AndDeliversNothingAfterIt() {
        await using var refusing = new FakePushServer();
        await refusing.StartAsync("127.0.0.2");
        await using var flaky = new FakePushServer();
        await flaky.StartAsync("127.0.0.3");
        await using var dead = new FakePushServer();
        await dead.StartAsync("127.0.0.5");

        var refused = await MailboxesAsync(refusing, 3);
        var failing = await MailboxesAsync(flaky, 2);
        var slow = await MailboxesAsync(flaky, 2);
        var expiring = (await MailboxesAsync(dead, 1))[0];
        var all = refused.Concat(failing).Concat(slow).ToList();

        // Sends go through an API node that holds plenty per mailbox and accepts short TTLs. The fixture's workers deliver.
        var (factory, api) = Node(new() {
            ["Goldfish__Roles"] = "api",
            ["Goldfish__Messages__MinTtlSeconds"] = "1",
            ["Goldfish__Messages__MaxHeldPerMailbox"] = "1000",
        });
        await using var apiNode = factory;

        // This message's push server is down for longer than its 15 s TTL: the first retry (after 8–12 s) fails too,
        // and the next would come after expiry.
        expiring.Device.Status = 503;
        await SendAsync(api, expiring, ttl: 15);

        // Phase 1: one push server refuses connections, another answers 503.
        await refusing.StopAsync();
        foreach (var m in failing) {
            m.Device.Status = 503;
        }
        var sent = new List<Sent>();
        foreach (var m in refused.Concat(failing)) {
            for (var i = 0; i < 3; i++) {
                sent.Add(await SendAsync(api, m));
            }
        }
        // Every 5xx device has answered each message (after its verification push), and all 15 are held.
        await EventuallyAsync(async () => failing.All(m => Attempts(m.Device) >= 4) && await HeldAsync(refused.Concat(failing)) == 15,
            TimeSpan.FromSeconds(20), "refused and 5xx pushes must be held in MySQL");
        // Senders that missed the answer retry with the same idempotency key and get the same message, no second copy.
        // The fixture node holds at most 3 per mailbox, so these mailboxes are full there: a retry must still succeed.
        foreach (var s in sent.Where((_, i) => i % 2 == 0).ToList()) {
            Assert.Equal(s.Id, (await SendAsync(_f.Client, s.Mailbox, s.Body, s.Key)).Id);
        }
        await refusing.RestartAsync();
        foreach (var m in failing) {
            m.Device.Status = 201;
        }

        // Phase 2: a push server that accepts connections but never answers in time.
        foreach (var m in slow) {
            m.Device.DelayMs = 30_000;
        }
        foreach (var m in slow) {
            for (var i = 0; i < 2; i++) {
                sent.Add(await SendAsync(api, m));
            }
        }
        await EventuallyAsync(async () => await HeldAsync(slow) == 4 && slow.All(m => Attempts(m.Device) >= 3),
            TimeSpan.FromSeconds(30), "timed-out pushes must be held in MySQL");
        foreach (var m in slow) {
            m.Device.DelayMs = 0;
        }

        // Recovery, with new traffic arriving meanwhile.
        foreach (var m in all) {
            sent.Add(await SendAsync(api, m));
        }
        var seen = new Dictionary<string, int>();
        await WaitForAllAsync(all, sent, seen, TimeSpan.FromSeconds(90));

        // The expiring message was given up once its TTL couldn't be met, and its push server coming back changes nothing.
        await EventuallyAsync(async () => Attempts(expiring.Device) >= 3 && await HeldAsync([expiring]) == 0,
            TimeSpan.FromSeconds(30), "the expired message should have been retried once and then dropped");
        expiring.Device.Status = 201;
        await Task.Delay(TimeSpan.FromSeconds(2));
        Assert.False(expiring.Device.TryNext(out _), "a message was delivered after its TTL");

        // Nothing was lost, nothing was pushed twice, and nothing is left behind.
        Assert.Equal(sent.Count, seen.Count);
        Assert.All(sent, s => Assert.Equal(1, seen[s.Hex]));
        Assert.Equal(0, await HeldAsync(all));
    }

    [IntegrationFact]
    public async Task WorkerKilledMidFlight_AFreshNodeDeliversEverything() {
        await using var push = new FakePushServer();
        await push.StartAsync("127.0.0.4");
        var slow = await MailboxesAsync(push, 3);
        var failing = await MailboxesAsync(push, 2);
        var all = slow.Concat(failing).ToList();

        // Only the nodes started here may deliver, so the killed one is sure to hold work when it dies.
        var resumeFixtureWorkers = await PauseFixtureWorkersAsync();
        WebApplicationFactory<Program>? fresh = null;
        WebApplicationFactory<Program>? shortTtlNode = null;
        try {
            // A 2 s push deadline makes the job timeout 17 s: a dead node's stream entries are reclaimed after 68 s, and
            // its retry leases run out after 85 s. Those are the real recovery paths, so the test waits them out.
            var worker = new Dictionary<string, string> {
                ["Goldfish__Roles"] = "worker",
                ["Goldfish__Push__RequestTimeoutSeconds"] = "2",
            };
            var (doomed, doomedClient) = Node(new(worker) { ["Goldfish__Messages__DeliveryParallelism"] = "2" });
            doomedClient.Dispose();

            foreach (var m in slow) {
                m.Device.DelayMs = 1000;
            }
            foreach (var m in failing) {
                m.Device.Status = 503;
                m.Device.DelayMs = 1000;
            }

            var sent = new List<Sent>();
            foreach (var m in failing) {
                for (var i = 0; i < 2; i++) {
                    sent.Add(await SendAsync(_f.Client, m));
                }
            }
            foreach (var m in slow) {
                for (var i = 0; i < 10; i++) {
                    sent.Add(await SendAsync(_f.Client, m));
                }
            }

            // Each failing device has had its verification push and two failed first attempts. The next request is a
            // retry from MySQL: the node has leased the row and the push is in flight. Kill the node now.
            await EventuallyAsync(() => Task.FromResult(failing.Sum(m => Attempts(m.Device)) > failing.Count * 3),
                TimeSpan.FromSeconds(30), "a held message should have been retried");
            await doomed.DisposeAsync();

            // The dead node held unacknowledged stream entries and leased retry rows.
            var ourIds = sent.Select(s => s.Id).ToHashSet();
            Assert.True(await PendingStreamEntriesAsync(ourIds) > 0, "the killed worker should have held unacknowledged stream entries");
            Assert.True(await _f.ScalarAsync(
                "SELECT COUNT(*) FROM pending_messages WHERE mailbox_id IN @ids AND next_attempt_at > UTC_TIMESTAMP() + INTERVAL 45 SECOND",
                new { ids = MailboxIds(failing) }) > 0, "the killed worker should have held a retry lease");

            // While no worker runs, more messages arrive, one with a TTL that runs out before anyone can deliver it.
            foreach (var m in slow) {
                sent.Add(await SendAsync(_f.Client, m));
            }
            var shortTtl = Node(new() { ["Goldfish__Roles"] = "api", ["Goldfish__Messages__MinTtlSeconds"] = "1" });
            shortTtlNode = shortTtl.Factory;
            var expired = await SendAsync(shortTtl.Client, slow[0], ttl: 2);
            // Senders that never saw an answer retry with the same idempotency key, and get the same message.
            foreach (var s in sent.Where((_, i) => i % 3 == 0).ToList()) {
                Assert.Equal(s.Id, (await SendAsync(_f.Client, s.Mailbox, s.Body, s.Key)).Id);
            }

            foreach (var m in all) {
                m.Device.Status = 201;
                m.Device.DelayMs = 0;
            }
            await Task.Delay(TimeSpan.FromSeconds(3));

            // A fresh node joins the same MySQL and Redis.
            var (freshFactory, freshClient) = Node(worker);
            fresh = freshFactory;
            freshClient.Dispose();

            var seen = new Dictionary<string, int>();
            await WaitForAllAsync(all, sent, seen, TimeSpan.FromSeconds(150));

            Assert.False(seen.ContainsKey(expired.Hex), "a message was delivered after its TTL");
            Assert.Equal(sent.Count, seen.Count);
            // Delivery is at-least-once: only a push that was in flight when the node died may be repeated, and the
            // killed node had at most two per worker loop.
            var duplicates = seen.Values.Sum(n => n - 1);
            Assert.True(duplicates <= 4, $"{duplicates} duplicate pushes");
            await EventuallyAsync(async () => await HeldAsync(all) == 0, because: "delivered messages are forgotten");
            Assert.Equal(0, await PendingStreamEntriesAsync(ourIds));
        } finally {
            if (fresh is not null) {
                await fresh.DisposeAsync();
            }
            if (shortTtlNode is not null) {
                await shortTtlNode.DisposeAsync();
            }
            await resumeFixtureWorkers();
        }
    }

    /// <summary>Stops the fixture node's delivery workers. The returned callback starts them again.</summary>
    private async Task<Func<Task>> PauseFixtureWorkersAsync() {
        var workers = _f.Services.GetServices<IHostedService>().Where(s => s is StreamDeliveryWorker or RetryWorker).ToList();
        Assert.Equal(2, workers.Count);
        foreach (var worker in workers) {
            await worker.StopAsync(CancellationToken.None);
        }
        return async () => {
            foreach (var worker in workers) {
                await worker.StartAsync(CancellationToken.None);
            }
        };
    }

    /// <summary>How many of these messages sit in the stream, read by a consumer but not acknowledged.</summary>
    private async Task<int> PendingStreamEntriesAsync(HashSet<string> messageIds) {
        await using var mux = await ConnectionMultiplexer.ConnectAsync(_f.Redis);
        var db = mux.GetDatabase();
        var pending = await db.StreamPendingMessagesAsync("gf:q", "delivery", 1000, RedisValue.Null);
        var count = 0;
        foreach (var entry in pending) {
            var range = await db.StreamRangeAsync("gf:q", entry.MessageId, entry.MessageId);
            var id = range.SelectMany(e => e.Values).Where(v => v.Name == "id").Select(v => (byte[])v.Value!).FirstOrDefault();
            if (id is not null && messageIds.Contains(Base64Url.EncodeToString(id))) {
                count++;
            }
        }
        return count;
    }
}
