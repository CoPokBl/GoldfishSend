using System.Globalization;

namespace LoadTest;

public sealed class LoadTestOptions {
    public Uri Url { get; set; } = new("http://127.0.0.1:5234");
    public int Clients { get; set; } = 32;
    public TimeSpan Duration { get; set; } = TimeSpan.FromSeconds(120);
    public int MailboxesPerClient { get; set; } = 2;
    public int ThinkMs { get; set; }
    public string PushListen { get; set; } = "127.0.0.1:0";
    public string? PushHost { get; set; }
    public string? ServerKey { get; set; }
    public TimeSpan WaitReady { get; set; } = TimeSpan.FromSeconds(60);
    public TimeSpan Drain { get; set; } = TimeSpan.FromSeconds(30);
    public double MaxErrorRate { get; set; } = 0.01;
    public double MaxThrottledRate { get; set; } = 0.05;
    public double MaxP95Ms { get; set; } = 500;
    public double MinDelivered { get; set; } = 0.99;
    public string? JsonPath { get; set; }
    public bool Smoke { get; set; }

    /// <summary>Learned from <c>/v1/info</c>.</summary>
    public int MaxMessageBytes { get; set; } = 3983;

    public const string Usage = """
        GoldfishSend load test: drives a running server through the encrypted gateway with simulated clients, and
        receives the server's pushes itself. The server must allow pushes to this machine over http (Development with
        Goldfish__Push__DangerouslyAllowInsecureLoopback=true) and have relaxed limits: see tools/LoadTest/server.env.

        Usage: LoadTest [--smoke] [options]

          --url URL                server base URL (default http://127.0.0.1:5234)
          --smoke                  short CI run: 8 clients, 45 s, 50 ms think time, p95 limit 1000 ms
          --clients N              concurrent simulated clients (default 32)
          --duration SECONDS       length of the main phase (default 120)
          --mailboxes N            mailboxes each client creates and verifies first (default 2)
          --think-ms MS            average pause between a client's calls, ±50% (default 0)
          --push-listen HOST:PORT  where the push receiver listens (default 127.0.0.1:0, a free port)
          --push-host HOST         host the server should push to, if not the listen address
          --server-key B64U        pin the server key fingerprint (default: trust what /v1/key returns)
          --wait-ready SECONDS     wait this long for the server to come up (default 60)
          --drain SECONDS          after the run, wait this long for outstanding pushes (default 30)
          --max-error-rate R       fail above this share of failed calls (default 0.01)
          --max-throttled-rate R   fail above this share of 429/503/507 answers (default 0.05)
          --max-p95-ms MS          fail if the p95 latency of all calls is above this (default 500)
          --min-delivered R        fail if fewer than this share of accepted messages were pushed back (default 0.99)
          --json PATH              also write the results as JSON

        Exit code: 0 all thresholds met, 1 a threshold was breached, 2 the test couldn't run.
        """;

    public static LoadTestOptions Parse(string[] args) {
        var options = new LoadTestOptions();
        if (args.Contains("--smoke")) {
            options.Smoke = true;
            options.Clients = 8;
            options.Duration = TimeSpan.FromSeconds(45);
            options.ThinkMs = 50;
            options.MaxP95Ms = 1000;
            options.Drain = TimeSpan.FromSeconds(20);
        }
        for (var i = 0; i < args.Length; i++) {
            var name = args[i];
            if (name == "--smoke") {
                continue;
            }
            if (i + 1 >= args.Length) {
                throw new ArgumentException($"Missing value for {name}.");
            }
            var value = args[++i];
            switch (name) {
                case "--url": options.Url = new Uri(value); break;
                case "--clients": options.Clients = Positive(name, Int(value)); break;
                case "--duration": options.Duration = TimeSpan.FromSeconds(Positive(name, Double(value))); break;
                case "--mailboxes": options.MailboxesPerClient = Positive(name, Int(value)); break;
                case "--think-ms": options.ThinkMs = Math.Max(0, Int(value)); break;
                case "--push-listen": options.PushListen = value; break;
                case "--push-host": options.PushHost = value; break;
                case "--server-key": options.ServerKey = value; break;
                case "--wait-ready": options.WaitReady = TimeSpan.FromSeconds(Double(value)); break;
                case "--drain": options.Drain = TimeSpan.FromSeconds(Double(value)); break;
                case "--max-error-rate": options.MaxErrorRate = Double(value); break;
                case "--max-throttled-rate": options.MaxThrottledRate = Double(value); break;
                case "--max-p95-ms": options.MaxP95Ms = Double(value); break;
                case "--min-delivered": options.MinDelivered = Double(value); break;
                case "--json": options.JsonPath = value; break;
                default: throw new ArgumentException($"Unknown option {name}.");
            }
        }
        return options;
    }

    private static int Int(string value) => int.Parse(value, CultureInfo.InvariantCulture);

    private static double Double(string value) => double.Parse(value, CultureInfo.InvariantCulture);

    private static T Positive<T>(string name, T value) where T : System.Numerics.INumber<T> {
        return value > T.Zero ? value : throw new ArgumentException($"{name} must be positive.");
    }
}
