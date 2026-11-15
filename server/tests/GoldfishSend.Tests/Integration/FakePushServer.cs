using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Threading.Channels;
using GoldfishSend.Core.Crypto;
using GoldfishSend.Core.Protocol;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace GoldfishSend.Tests.Integration;

/// <summary>A phone plus its push distributor. It holds the Web Push keys and decrypts what it receives, exactly as a UA would.</summary>
public sealed class FakeDevice : IDisposable {
    public string Name { get; } = Convert.ToHexString(RandomNumberGenerator.GetBytes(8));
    public ECDiffieHellman Key { get; } = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
    public byte[] Auth { get; } = RandomNumberGenerator.GetBytes(16);
    public byte[] P256dh => WebPushCrypto.ExportPublicKey(Key);
    public string Url { get; set; } = "";

    /// <summary>Decrypted push envelopes.</summary>
    public Channel<byte[]> Received { get; } = Channel.CreateUnbounded<byte[]>();

    /// <summary>The HTTP status the push server answers with. 201 means accepted.</summary>
    public volatile int Status = 201;

    /// <summary>A delay before answering, to simulate a tarpit. 0 answers immediately.</summary>
    public volatile int DelayMs;

    public int Attempts;

    public async Task<(PushType Type, byte[] Tag, byte[] Body)> NextAsync(TimeSpan? timeout = null) {
        using var cts = new CancellationTokenSource(timeout ?? TimeSpan.FromSeconds(10));
        var data = await Received.Reader.ReadAsync(cts.Token);
        Assert.True(PushEnvelope.TryParse(data, out var type, out var tag, out var body), "Malformed envelope");
        return (type, tag, body);
    }

    public bool TryNext(out byte[] envelope) => Received.Reader.TryRead(out envelope!);

    public void Dispose() => Key.Dispose();
}

public sealed class FakePushServer : IAsyncDisposable {
    private readonly ConcurrentDictionary<string, FakeDevice> _devices = new();
    private WebApplication? _app;

    public string BaseUrl { get; private set; } = "";

    /// <param name="address">
    /// Another loopback address (127.0.0.2, ...) makes this server a push host of its own, so its circuit breaker, pacing
    /// and slow-lane state can't leak into tests that use the shared server on 127.0.0.1.
    /// </param>
    public Task StartAsync(string address = "127.0.0.1") => ListenAsync($"http://{address}:0");

    /// <summary>Stops listening, so pushes fail with "connection refused". Devices are kept.</summary>
    public async Task StopAsync() {
        if (_app is not null) {
            await _app.DisposeAsync();
            _app = null;
        }
    }

    /// <summary>Listens again on the same address and port, so existing endpoints work again.</summary>
    public async Task RestartAsync() {
        await StopAsync();
        for (var attempt = 0; ; attempt++) {
            try {
                await ListenAsync(BaseUrl);
                return;
            } catch (IOException) when (attempt < 50) {
                // The port of a listener that just closed can be briefly unavailable.
                await Task.Delay(100);
            }
        }
    }

    private async Task ListenAsync(string url) {
        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseUrls(url);
        builder.Logging.ClearProviders();
        _app = builder.Build();
        _app.MapPost("/push/{name}", async (string name, HttpRequest request) => {
            if (!_devices.TryGetValue(name, out var device)) {
                return Results.StatusCode(404);
            }
            Interlocked.Increment(ref device.Attempts);
            if (device.DelayMs > 0) {
                // Like a real push server, it doesn't accept a request the sender gave up on (a timeout or a crash).
                try {
                    await Task.Delay(device.DelayMs, request.HttpContext.RequestAborted);
                } catch (OperationCanceledException) {
                    return Results.Empty;
                }
            }
            if (device.Status is < 200 or >= 300) {
                return Results.StatusCode(device.Status);
            }

            // Protocol checks a real push server (and the UnifiedPush connector) depend on.
            if (request.Headers.ContentEncoding.ToString() != "aes128gcm"
                || !request.Headers.Authorization.ToString().StartsWith("vapid t=", StringComparison.Ordinal)
                || !int.TryParse(request.Headers["TTL"].ToString(), out _)) {
                return Results.StatusCode(400);
            }

            using var ms = new MemoryStream();
            await request.Body.CopyToAsync(ms);
            if (ms.Length > 4096) {
                return Results.StatusCode(413);
            }
            var plaintext = WebPushCrypto.Decrypt(ms.ToArray(), device.Key, device.Auth);
            if (request.HttpContext.RequestAborted.IsCancellationRequested) {
                return Results.Empty;
            }
            await device.Received.Writer.WriteAsync(plaintext);
            return Results.StatusCode(201);
        });
        await _app.StartAsync();
        BaseUrl = _app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.First();
    }

    /// <param name="alternateHost">Use "localhost" instead of 127.0.0.1, so the device counts as a different push host.</param>
    public FakeDevice NewDevice(bool alternateHost = false) {
        var device = new FakeDevice();
        var baseUrl = alternateHost ? BaseUrl.Replace("127.0.0.1", "localhost", StringComparison.Ordinal) : BaseUrl;
        device.Url = $"{baseUrl}/push/{device.Name}";
        _devices[device.Name] = device;
        return device;
    }

    public async ValueTask DisposeAsync() {
        if (_app is not null) {
            await _app.DisposeAsync();
        }
        foreach (var device in _devices.Values) {
            device.Dispose();
        }
    }
}
