using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using GoldfishSend.Core.Crypto;
using GoldfishSend.Core.Protocol;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace LoadTest;

/// <summary>One push subscription: what a phone's UnifiedPush distributor holds for a mailbox.</summary>
public sealed class Device {
    public string Id { get; } = Convert.ToHexString(RandomNumberGenerator.GetBytes(12));
    public ECDiffieHellman Key { get; } = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
    public byte[] Auth { get; } = RandomNumberGenerator.GetBytes(16);
    public byte[] P256dh => WebPushCrypto.ExportPublicKey(Key);
    public string Url { get; internal set; } = "";
    public TaskCompletionSource<byte[]> Verification { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
}

/// <summary>
/// A minimal push server on this machine. It decrypts each Web Push like a phone would, hands verification codes to the
/// waiting client, and matches message pushes to sends by a token at the start of each message body.
/// </summary>
public sealed class PushReceiver : IAsyncDisposable {
    public const int TokenSize = 16;

    private readonly WebApplication _app;
    private readonly ConcurrentDictionary<string, Device> _devices = new();
    private readonly ConcurrentDictionary<string, long> _inFlight = new();
    private readonly ConcurrentDictionary<string, byte> _delivered = new();
    private readonly Recorder _latency = new();
    private long _duplicates;
    private long _unknown;
    private long _malformed;
    private string _baseUrl = "";

    private PushReceiver(WebApplication app) {
        _app = app;
    }

    public long Pending => _inFlight.Count;
    public long Delivered => _delivered.Count;
    public long Duplicates => Interlocked.Read(ref _duplicates);
    public long Unknown => Interlocked.Read(ref _unknown) + Interlocked.Read(ref _malformed);
    public Recorder Latency => _latency;

    /// <param name="listen">The address to listen on, e.g. <c>127.0.0.1:0</c>.</param>
    /// <param name="publicHost">The host the server should push to, if not the listen address.</param>
    public static async Task<PushReceiver> StartAsync(string listen, string? publicHost) {
        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseUrls($"http://{listen}");
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(k => k.AddServerHeader = false);
        var app = builder.Build();
        var receiver = new PushReceiver(app);
        app.MapPost("/push/{id}", receiver.HandleAsync);
        await app.StartAsync();
        var address = new Uri(app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.First());
        receiver._baseUrl = $"http://{publicHost ?? address.Host}:{address.Port}";
        return receiver;
    }

    public Device NewDevice() {
        var device = new Device();
        device.Url = $"{_baseUrl}/push/{device.Id}";
        _devices[device.Id] = device;
        return device;
    }

    /// <summary>Call just before sending a message whose body starts with <paramref name="token"/>.</summary>
    public void Expect(byte[] token) => _inFlight[Convert.ToHexString(token)] = Stopwatch.GetTimestamp();

    /// <summary>The send wasn't accepted, so no push will come.</summary>
    public void Forget(byte[] token) => _inFlight.TryRemove(Convert.ToHexString(token), out _);

    public async Task<bool> WaitDrainedAsync(TimeSpan timeout) {
        var deadline = Stopwatch.GetTimestamp() + (long)(timeout.TotalSeconds * Stopwatch.Frequency);
        while (!_inFlight.IsEmpty && Stopwatch.GetTimestamp() < deadline) {
            await Task.Delay(100);
        }
        return _inFlight.IsEmpty;
    }

    private async Task<IResult> HandleAsync(string id, HttpRequest request) {
        if (!_devices.TryGetValue(id, out var device)) {
            return Results.StatusCode(404);
        }
        using var ms = new MemoryStream();
        await request.Body.CopyToAsync(ms);
        if (ms.Length > 4096) {
            return Results.StatusCode(413);
        }
        byte[] plaintext;
        try {
            plaintext = WebPushCrypto.Decrypt(ms.ToArray(), device.Key, device.Auth);
        } catch (CryptographicException) {
            Interlocked.Increment(ref _malformed);
            return Results.StatusCode(400);
        }
        if (!PushEnvelope.TryParse(plaintext, out var type, out _, out var body)) {
            Interlocked.Increment(ref _malformed);
            return Results.StatusCode(400);
        }
        if (type == PushType.Verification) {
            device.Verification.TrySetResult(body[..Math.Min(body.Length, PushEnvelope.VerificationCodeSize)]);
        } else if (body.Length >= TokenSize) {
            var token = Convert.ToHexString(body, 0, TokenSize);
            if (_inFlight.TryRemove(token, out var sentAt)) {
                _delivered[token] = 0;
                _latency.Add(Stopwatch.GetElapsedTime(sentAt).TotalMilliseconds);
            } else if (_delivered.ContainsKey(token)) {
                Interlocked.Increment(ref _duplicates);
            } else {
                Interlocked.Increment(ref _unknown);
            }
        }
        return Results.StatusCode(201);
    }

    public async ValueTask DisposeAsync() {
        await _app.DisposeAsync();
        foreach (var device in _devices.Values) {
            device.Key.Dispose();
        }
    }
}
