using System.Diagnostics;
using System.Globalization;
using System.Text.Json;
using LoadTest;

if (args is ["--help" or "-h", ..]) {
    Console.WriteLine(LoadTestOptions.Usage);
    return 0;
}

LoadTestOptions options;
try {
    options = LoadTestOptions.Parse(args);
} catch (Exception ex) when (ex is ArgumentException or FormatException or UriFormatException or OverflowException) {
    Console.Error.WriteLine(ex.Message);
    Console.Error.WriteLine("Run with --help for the options.");
    return 2;
}

using var http = new HttpClient(new SocketsHttpHandler {
    MaxConnectionsPerServer = Math.Max(16, options.Clients * 2),
    PooledConnectionLifetime = TimeSpan.FromMinutes(2),
}) {
    BaseAddress = options.Url,
    Timeout = TimeSpan.FromSeconds(30),
};

Console.WriteLine($"GoldfishSend load test against {options.Url}{(options.Smoke ? " (smoke)" : "")}");
if (!await WaitReadyAsync(http, options.WaitReady)) {
    Console.Error.WriteLine($"The server didn't answer GET /v1/key within {options.WaitReady.TotalSeconds:0} s.");
    return 2;
}

GatewayClient gateway;
try {
    gateway = await GatewayClient.ConnectAsync(http, options.ServerKey, CancellationToken.None);
    var info = await gateway.SendAsync("GET", "/v1/info");
    if (info.Status != 200) {
        Console.Error.WriteLine($"GET /v1/info through the gateway answered {info.Status}.");
        return 2;
    }
    var json = JsonDocument.Parse(info.Body).RootElement;
    options.MaxMessageBytes = json.GetProperty("maxMessageBytes").GetInt32();
    Console.WriteLine($"Server key {gateway.Fingerprint}, PoW difficulty {json.GetProperty("powDifficulty").GetInt32()}");
} catch (Exception ex) when (ex is HttpRequestException or InvalidOperationException or JsonException or TaskCanceledException) {
    Console.Error.WriteLine($"Couldn't talk to the gateway: {ex.Message}");
    return 2;
}

await using var receiver = await PushReceiver.StartAsync(options.PushListen, options.PushHost);
var metrics = new Metrics();
var pool = new MailboxPool();
var clients = Enumerable.Range(0, options.Clients)
    .Select(_ => new VirtualClient(gateway, receiver, metrics, pool, options))
    .ToList();

Console.WriteLine($"Setting up {options.Clients} clients with {options.MailboxesPerClient} mailbox(es) each...");
var setup = Stopwatch.StartNew();
await Task.WhenAll(clients.Select(c => Task.Run(c.SetupAsync)));
Console.WriteLine($"  {pool.Count} mailboxes verified in {setup.Elapsed.TotalSeconds:0.0} s");
if (pool.Count == 0) {
    Console.Error.WriteLine("No mailbox could be created and verified. Is the server in Development with "
        + "Goldfish__Push__DangerouslyAllowInsecureLoopback=true, and can it reach the push receiver?");
    PrintOperations(metrics);
    return 2;
}

Console.WriteLine($"Running for {options.Duration.TotalSeconds:0} s...");
var startRequests = metrics.Requests;
var run = Stopwatch.StartNew();
using (var stop = new CancellationTokenSource(options.Duration)) {
    var progress = Task.Run(async () => {
        while (!stop.IsCancellationRequested) {
            await Task.Delay(TimeSpan.FromSeconds(10), stop.Token).ContinueWith(_ => { }, CancellationToken.None);
            if (!stop.IsCancellationRequested) {
                Console.WriteLine(string.Create(CultureInfo.InvariantCulture,
                    $"  {run.Elapsed.TotalSeconds,5:0} s  {metrics.Requests - startRequests,8} calls  {(metrics.Requests - startRequests) / run.Elapsed.TotalSeconds,7:0.0}/s  "
                    + $"{metrics.Errors} errors  {metrics.Throttled} throttled  {receiver.Delivered} pushed"));
            }
        }
    });
    await Task.WhenAll(clients.Select(c => Task.Run(() => c.RunAsync(stop.Token))));
    await progress;
}
var runSeconds = run.Elapsed.TotalSeconds;
var mainPhaseCalls = metrics.Requests - startRequests;

Console.WriteLine($"Waiting up to {options.Drain.TotalSeconds:0} s for outstanding pushes...");
await receiver.WaitDrainedAsync(options.Drain);
var missing = receiver.Pending;
await Task.WhenAll(clients.Select(c => c.TeardownAsync()));

// Report.
Console.WriteLine();
PrintOperations(metrics);
var all = metrics.AllLatencies().Summarize();
var total = metrics.Total;
var errorRate = total == 0 ? 1 : (double)metrics.Errors / total;
var throttledRate = total == 0 ? 0 : (double)metrics.Throttled / total;
var accepted = receiver.Delivered + missing;
var deliveredRatio = accepted == 0 ? 0 : (double)receiver.Delivered / accepted;
var push = receiver.Latency.Summarize();

Console.WriteLine();
Console.WriteLine(string.Create(CultureInfo.InvariantCulture,
    $"Throughput: {mainPhaseCalls / runSeconds:0.0} calls/s over {runSeconds:0.0} s ({mainPhaseCalls} calls; {metrics.Requests} including setup and teardown)"));
Console.WriteLine(string.Create(CultureInfo.InvariantCulture,
    $"All calls:  p50 {all.P50:0.0} ms  p95 {all.P95:0.0} ms  p99 {all.P99:0.0} ms  max {all.Max:0.0} ms  errors {metrics.Errors}  throttled {metrics.Throttled}"));
Console.WriteLine(string.Create(CultureInfo.InvariantCulture,
    $"Push delivery (send to push received): {receiver.Delivered}/{accepted} delivered, {missing} missing, {receiver.Duplicates} duplicate(s), "
    + $"{receiver.Unknown} unexpected; p50 {push.P50:0.0} ms  p95 {push.P95:0.0} ms  p99 {push.P99:0.0} ms"));

var checks = new List<(string Name, bool Ok, string Detail)> {
    ("error rate", errorRate <= options.MaxErrorRate, $"{errorRate:P2} (max {options.MaxErrorRate:P2})"),
    ("throttled rate", throttledRate <= options.MaxThrottledRate, $"{throttledRate:P2} (max {options.MaxThrottledRate:P2})"),
    ("p95 latency", all.P95 <= options.MaxP95Ms, string.Create(CultureInfo.InvariantCulture, $"{all.P95:0.0} ms (max {options.MaxP95Ms:0} ms)")),
    ("delivered", deliveredRatio >= options.MinDelivered, $"{deliveredRatio:P2} (min {options.MinDelivered:P2})"),
};
Console.WriteLine();
foreach (var (name, ok, detail) in checks) {
    Console.WriteLine($"{(ok ? "PASS" : "FAIL")}  {name}: {detail}");
}
var passed = checks.All(c => c.Ok);

if (options.JsonPath is not null) {
    var report = new {
        url = options.Url.ToString(),
        smoke = options.Smoke,
        clients = options.Clients,
        durationSeconds = runSeconds,
        mailboxes = pool.Count,
        callsPerSecond = mainPhaseCalls / runSeconds,
        totalCalls = metrics.Requests,
        outcomes = total,
        errors = metrics.Errors,
        throttled = metrics.Throttled,
        latencyMs = all,
        operations = metrics.Operations.ToDictionary(kv => kv.Key, kv => new {
            ok = kv.Value.Ok,
            throttled = kv.Value.Throttled,
            errors = kv.Value.Errors,
            errorKinds = kv.Value.ErrorKinds,
            latencyMs = kv.Value.Latency.Summarize(),
        }),
        push = new { delivered = receiver.Delivered, missing, duplicates = receiver.Duplicates, unexpected = receiver.Unknown, latencyMs = push },
        checks = checks.Select(c => new { name = c.Name, ok = c.Ok, detail = c.Detail }),
        passed,
    };
    await File.WriteAllTextAsync(options.JsonPath, JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
}

return passed ? 0 : 1;

static async Task<bool> WaitReadyAsync(HttpClient http, TimeSpan timeout) {
    var deadline = DateTime.UtcNow + timeout;
    while (true) {
        try {
            using var response = await http.GetAsync("/v1/key");
            if (response.IsSuccessStatusCode) {
                return true;
            }
        } catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException) {
            // Not up yet.
        }
        if (DateTime.UtcNow >= deadline) {
            return false;
        }
        await Task.Delay(500);
    }
}

static void PrintOperations(Metrics metrics) {
    Console.WriteLine($"{"operation",-20} {"calls",8} {"ok",8} {"throttled",9} {"errors",7} {"p50 ms",8} {"p95 ms",8} {"p99 ms",8} {"max ms",8}");
    foreach (var (name, op) in metrics.Operations) {
        var s = op.Latency.Summarize();
        var latency = s.Count == 0
            ? $"{"",8} {"",8} {"",8} {"",8}"
            : string.Create(CultureInfo.InvariantCulture, $"{s.P50,8:0.0} {s.P95,8:0.0} {s.P99,8:0.0} {s.Max,8:0.0}");
        Console.WriteLine($"{name,-20} {op.Total,8} {op.Ok,8} {op.Throttled,9} {op.Errors,7} {latency}");
        foreach (var (kind, count) in op.ErrorKinds) {
            Console.WriteLine($"{"",22}{count} × {kind}");
        }
    }
}
