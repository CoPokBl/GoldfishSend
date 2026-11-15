using System.Buffers.Text;
using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using GoldfishSend.Core.Crypto;
using GoldfishSend.Core.Protocol;

namespace LoadTest;

public sealed record Mailbox(byte[] SendSecret, byte[] OwnerSecret, Device Device) {
    public object Credential => new { sendSecret = B64(SendSecret), ownerSecret = B64(OwnerSecret) };

    private static string B64(byte[] value) => Base64Url.EncodeToString(value);
}

/// <summary>Every verified mailbox, so clients can send to each other's like contacts do.</summary>
public sealed class MailboxPool {
    private readonly List<Mailbox> _items = [];

    public int Count {
        get {
            lock (_items) {
                return _items.Count;
            }
        }
    }

    public void Add(Mailbox mailbox) {
        lock (_items) {
            _items.Add(mailbox);
        }
    }

    public Mailbox Pick() {
        lock (_items) {
            return _items[Random.Shared.Next(_items.Count)];
        }
    }
}

/// <summary>
/// One simulated app: it creates and verifies its own mailboxes (proof of work, verification push), then loops over a
/// realistic mix of calls until the run ends, and finally deletes its mailboxes.
/// </summary>
public sealed class VirtualClient {
    private const string Json = "application/json";
    private const string Octets = "application/octet-stream";
    private static readonly int[] BodySizes = [256, 1024, 2048, 3072];

    private readonly GatewayClient _gateway;
    private readonly PushReceiver _receiver;
    private readonly Metrics _metrics;
    private readonly MailboxPool _pool;
    private readonly LoadTestOptions _options;
    private readonly List<Mailbox> _own = [];

    public VirtualClient(GatewayClient gateway, PushReceiver receiver, Metrics metrics, MailboxPool pool, LoadTestOptions options) {
        _gateway = gateway;
        _receiver = receiver;
        _metrics = metrics;
        _pool = pool;
        _options = options;
    }

    public async Task SetupAsync() {
        for (var i = 0; i < _options.MailboxesPerClient; i++) {
            if (await CreateMailboxAsync() is { } mailbox) {
                _own.Add(mailbox);
                _pool.Add(mailbox);
            }
        }
    }

    public async Task RunAsync(CancellationToken ct) {
        while (!ct.IsCancellationRequested) {
            var roll = Random.Shared.Next(100);
            if (roll < 60) {
                await SendAsync();
            } else if (roll < 75) {
                await SendBatchAsync();
            } else if (roll < 85) {
                await InviteAsync();
            } else if (roll < 95) {
                await RefreshAsync();
            } else {
                await CallAsync("info", () => _gateway.SendAsync("GET", "/v1/info"), 200);
            }
            if (_options.ThinkMs > 0) {
                // ±50% jitter, so clients don't move in lockstep.
                var delay = _options.ThinkMs / 2 + Random.Shared.Next(_options.ThinkMs + 1);
                await Task.Delay(delay, ct).ContinueWith(_ => { }, CancellationToken.None);
            }
        }
    }

    public async Task TeardownAsync() {
        foreach (var chunk in _own.Chunk(100)) {
            await CallAsync("delete_mailboxes", () => PostJsonAsync("/v1/mailboxes/delete", new { items = chunk.Select(m => m.Credential) }), 204);
        }
    }

    private async Task<Mailbox?> CreateMailboxAsync() {
        var issued = await CallAsync("pow_challenge", () => _gateway.SendAsync("POST", "/v1/pow/challenge"), 200);
        if (issued?.Status != 200) {
            return null;
        }
        var challengeJson = JsonDocument.Parse(issued.Body).RootElement;
        var challenge = Base64Url.DecodeFromChars(challengeJson.GetProperty("challenge").GetString());
        var nonce = ProofOfWork.Solve(challenge, challengeJson.GetProperty("difficulty").GetInt32());

        var device = _receiver.NewDevice();
        var mailbox = new Mailbox(RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(32), device);
        var created = await CallAsync("create_mailbox", () => PostJsonAsync("/v1/mailboxes", new {
            pow = new { challenge = Base64Url.EncodeToString(challenge), nonce = Base64Url.EncodeToString(nonce) },
            sendSecret = Base64Url.EncodeToString(mailbox.SendSecret),
            ownerHash = Base64Url.EncodeToString(MailboxCrypto.OwnerHash(mailbox.OwnerSecret)),
            endpoint = device.Url,
            p256dh = Base64Url.EncodeToString(device.P256dh),
            auth = Base64Url.EncodeToString(device.Auth),
        }), 202);
        if (created?.Status != 202) {
            return null;
        }

        byte[] code;
        try {
            code = await device.Verification.Task.WaitAsync(TimeSpan.FromSeconds(15));
        } catch (TimeoutException) {
            _metrics["verification_push"].Record(Outcome.Error, null, "no verification push");
            return null;
        }
        var verified = await CallAsync("verify_mailbox", () => PostJsonAsync("/v1/mailboxes/verify", new {
            items = new[] { mailbox.Credential },
            code = Base64Url.EncodeToString(code),
        }), 200);
        return verified?.Status == 200 ? mailbox : null;
    }

    /// <summary>A message body: the delivery token, then random bytes up to one of the client's padding buckets.</summary>
    private (byte[] Token, byte[] Body) NewMessage() {
        var size = Math.Min(BodySizes[Random.Shared.Next(BodySizes.Length)], _options.MaxMessageBytes);
        var body = RandomNumberGenerator.GetBytes(size);
        return (body[..PushReceiver.TokenSize], body);
    }

    private async Task SendAsync() {
        var target = _pool.Pick();
        var (token, body) = NewMessage();
        _receiver.Expect(token);
        var response = await CallAsync("send", () => _gateway.SendAsync("POST", "/v1/messages", body, Octets, [
            new("gf-send-token", Base64Url.EncodeToString(target.SendSecret)),
            new("gf-idempotency-key", Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(ProtocolLimits.IdempotencyKeySize))),
        ]), 202);
        if (response?.Status != 202) {
            _receiver.Forget(token);
        }
    }

    private async Task SendBatchAsync() {
        var count = Random.Shared.Next(4, 9);
        var items = new List<BatchItem>(count);
        var tokens = new List<byte[]>(count);
        for (var i = 0; i < count; i++) {
            var (token, body) = NewMessage();
            // A group fan-out carries the same size per member, and the batch must fit the gateway's 16 KiB body.
            body = body[..Math.Min(body.Length, 1024)];
            tokens.Add(token);
            items.Add(new BatchItem(_pool.Pick().SendSecret, RandomNumberGenerator.GetBytes(ProtocolLimits.IdempotencyKeySize), null, body));
            _receiver.Expect(token);
        }
        var response = await CallAsync("send_batch", () => _gateway.SendAsync("POST", "/v1/messages/batch", MessageBatch.Encode(items), Octets), 200);
        var accepted = new bool[count];
        if (response?.Status == 200) {
            var results = JsonDocument.Parse(response.Body).RootElement.GetProperty("results").EnumerateArray().ToArray();
            for (var i = 0; i < Math.Min(count, results.Length); i++) {
                var status = results[i].GetProperty("status").GetInt32();
                accepted[i] = status == 202;
                var outcome = Classify(status, 202);
                _metrics["send_batch_item"].Record(outcome, null, outcome == Outcome.Error ? $"HTTP {status}" : null);
            }
        }
        for (var i = 0; i < count; i++) {
            if (!accepted[i]) {
                _receiver.Forget(tokens[i]);
            }
        }
    }

    private async Task InviteAsync() {
        var blob = RandomNumberGenerator.GetBytes(Random.Shared.Next(500, 2001));
        var created = await CallAsync("invite_create", () => _gateway.SendAsync("POST", "/v1/invites", blob, Octets), 201);
        if (created?.Status != 201) {
            return;
        }
        var id = JsonDocument.Parse(created.Body).RootElement.GetProperty("id").GetString();
        var fetched = await CallAsync("invite_fetch", () => _gateway.SendAsync("GET", $"/v1/invites/{id}"), 200);
        if (fetched?.Status == 200 && !fetched.Body.AsSpan().SequenceEqual(blob)) {
            _metrics["invite_mismatch"].Record(Outcome.Error, null, "wrong invite body");
        }
    }

    private async Task RefreshAsync() {
        if (_own.Count == 0) {
            return;
        }
        await CallAsync("refresh_mailboxes", () => PostJsonAsync("/v1/mailboxes/refresh", new { items = _own.Select(m => m.Credential) }), 200);
    }

    private Task<ApiResponse> PostJsonAsync(string path, object body) {
        return _gateway.SendAsync("POST", path, JsonSerializer.SerializeToUtf8Bytes(body), Json);
    }

    private static Outcome Classify(int status, int expected) {
        if (status == expected) {
            return Outcome.Ok;
        }
        return status is 429 or 503 or 507 ? Outcome.Throttled : Outcome.Error;
    }

    /// <summary>Times one call and records its outcome. Returns null if it failed in transport.</summary>
    private async Task<ApiResponse?> CallAsync(string operation, Func<Task<ApiResponse>> call, int expected) {
        var started = Stopwatch.GetTimestamp();
        try {
            var response = await call();
            var outcome = Classify(response.Status, expected);
            _metrics[operation].Record(outcome, Stopwatch.GetElapsedTime(started).TotalMilliseconds,
                outcome == Outcome.Error ? $"HTTP {response.Status.ToString(CultureInfo.InvariantCulture)}" : null);
            return response;
        } catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or IOException or InvalidOperationException or JsonException) {
            _metrics[operation].Record(Outcome.Error, Stopwatch.GetElapsedTime(started).TotalMilliseconds, ex.GetType().Name);
            return null;
        }
    }
}
