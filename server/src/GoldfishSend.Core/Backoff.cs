namespace GoldfishSend.Core;

public static class Backoff {
    private static readonly TimeSpan[] Schedule = [
        TimeSpan.FromSeconds(10),
        TimeSpan.FromSeconds(30),
        TimeSpan.FromMinutes(2),
        TimeSpan.FromMinutes(10),
        TimeSpan.FromMinutes(30),
        TimeSpan.FromHours(1),
    ];

    public static readonly TimeSpan Max = TimeSpan.FromHours(6);

    /// <summary>The delay before retry number <paramref name="attempt"/> (1-based), with ±20% jitter.</summary>
    public static TimeSpan Next(int attempt, TimeSpan? retryAfter = null) {
        var baseDelay = attempt <= 0
            ? Schedule[0]
            : attempt <= Schedule.Length ? Schedule[attempt - 1] : Max;
        var jitter = 0.8 + Random.Shared.NextDouble() * 0.4;
        var delay = TimeSpan.FromMilliseconds(baseDelay.TotalMilliseconds * jitter);
        if (retryAfter is { } ra && ra > delay) {
            delay = ra;
        }
        return delay > Max ? Max : delay;
    }
}
