using System.Collections.Concurrent;

namespace LoadTest;

public enum Outcome {
    Ok,
    /// <summary>The server said "not now" (429, 503 unavailable, 507): working as designed, but not what a load test wants.</summary>
    Throttled,
    /// <summary>A transport failure, a timeout, a 5xx or an unexpected status.</summary>
    Error,
}

/// <summary>Latency samples in milliseconds. A load test keeps at most a few hundred thousand, so exact percentiles are cheap.</summary>
public sealed class Recorder {
    private readonly List<double> _samples = [];

    public void Add(double ms) {
        lock (_samples) {
            _samples.Add(ms);
        }
    }

    public void AddRange(Recorder other) {
        double[] copy;
        lock (other._samples) {
            copy = [.. other._samples];
        }
        lock (_samples) {
            _samples.AddRange(copy);
        }
    }

    public int Count {
        get {
            lock (_samples) {
                return _samples.Count;
            }
        }
    }

    public Summary Summarize() {
        double[] sorted;
        lock (_samples) {
            sorted = [.. _samples];
        }
        Array.Sort(sorted);
        if (sorted.Length == 0) {
            return new Summary(0, 0, 0, 0, 0, 0);
        }
        double At(double p) => sorted[Math.Clamp((int)Math.Ceiling(p * sorted.Length) - 1, 0, sorted.Length - 1)];
        return new Summary(sorted.Length, sorted.Average(), At(0.50), At(0.95), At(0.99), sorted[^1]);
    }
}

public readonly record struct Summary(int Count, double Mean, double P50, double P95, double P99, double Max);

public sealed class OperationStats {
    private long _ok;
    private long _throttled;
    private long _errors;

    public Recorder Latency { get; } = new();
    public ConcurrentDictionary<string, long> ErrorKinds { get; } = new();
    public long Ok => Interlocked.Read(ref _ok);
    public long Throttled => Interlocked.Read(ref _throttled);
    public long Errors => Interlocked.Read(ref _errors);
    public long Total => Ok + Throttled + Errors;

    /// <param name="ms">Null for outcomes that aren't a request of their own (a batch item, a missing push).</param>
    public void Record(Outcome outcome, double? ms, string? errorKind) {
        if (ms is { } value) {
            Latency.Add(value);
        }
        switch (outcome) {
            case Outcome.Ok:
                Interlocked.Increment(ref _ok);
                break;
            case Outcome.Throttled:
                Interlocked.Increment(ref _throttled);
                break;
            default:
                Interlocked.Increment(ref _errors);
                ErrorKinds.AddOrUpdate(errorKind ?? "unknown", 1, (_, n) => n + 1);
                break;
        }
    }
}

public sealed class Metrics {
    private readonly ConcurrentDictionary<string, OperationStats> _operations = new();

    public IEnumerable<KeyValuePair<string, OperationStats>> Operations => _operations.OrderBy(kv => kv.Key, StringComparer.Ordinal);

    public OperationStats this[string name] => _operations.GetOrAdd(name, _ => new OperationStats());

    /// <summary>Every outcome, batch items included.</summary>
    public long Total => _operations.Values.Sum(o => o.Total);
    /// <summary>HTTP calls only.</summary>
    public long Requests => _operations.Values.Sum(o => (long)o.Latency.Count);
    public long Errors => _operations.Values.Sum(o => o.Errors);
    public long Throttled => _operations.Values.Sum(o => o.Throttled);

    public Recorder AllLatencies() {
        var all = new Recorder();
        foreach (var op in _operations.Values) {
            all.AddRange(op.Latency);
        }
        return all;
    }
}
