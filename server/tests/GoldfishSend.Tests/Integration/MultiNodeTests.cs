using System.Net;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;

namespace GoldfishSend.Tests.Integration;

[Collection(GoldfishCollection.Name)]
public sealed class MultiNodeTests {
    private readonly GoldfishFixture _f;

    public MultiNodeTests(GoldfishFixture fixture) {
        _f = fixture;
    }

    /// <summary>
    /// A second, independent node joins the same MySQL and Redis: it has its own consumer, workers and caches. Messages
    /// accepted by either node are delivered exactly once, with no loss and no duplicates.
    /// </summary>
    [IntegrationFact]
    public async Task TwoNodes_ShareTheQueue_AndDeliverEachMessageExactlyOnce() {
        await using var second = new WebApplicationFactory<Program>().WithWebHostBuilder(b => b.UseEnvironment("Development"));
        using var secondClient = GatewayHandler.Client(second);
        Assert.Equal(HttpStatusCode.OK, (await secondClient.GetAsync("/readyz")).StatusCode);

        var mailbox = await _f.CreateActiveMailboxAsync();
        const int count = 20; // within the per-mailbox burst
        for (var i = 0; i < count; i++) {
            var client = i % 2 == 0 ? _f.Client : secondClient;
            using var request = new HttpRequestMessage(HttpMethod.Post, "/v1/messages") { Content = GoldfishFixture.Octets([(byte)i]) };
            request.Headers.Add("GF-Send-Token", GoldfishFixture.B64(mailbox.SendSecret));
            Assert.Equal(HttpStatusCode.Accepted, (await client.SendAsync(request)).StatusCode);
        }

        var seen = new List<byte>();
        for (var i = 0; i < count; i++) {
            var (_, _, body) = await mailbox.Device.NextAsync();
            seen.Add(body[0]);
        }
        await Task.Delay(1000);
        Assert.False(mailbox.Device.TryNext(out _), "a message was delivered twice");
        Assert.Equal(Enumerable.Range(0, count).Select(i => (byte)i).Order(), seen.Order());
    }
}
