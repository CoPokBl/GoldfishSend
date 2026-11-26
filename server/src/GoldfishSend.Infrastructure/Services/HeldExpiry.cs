namespace GoldfishSend.Infrastructure.Services;

/// <summary>
/// When an accepted message expires. It's stored at rest (the held-message table's <c>expires_at</c>, and its
/// <c>next_attempt_at</c> while parked) and bound into the job's AAD, so it's rounded to a coarse boundary: a seized
/// database then can't give each message's exact send time, or show which held copies (one sender's group fan-out) were
/// accepted in the same second.
/// </summary>
public static class HeldExpiry {
    /// <summary>The longest rounding step.</summary>
    public static readonly TimeSpan MaxStep = TimeSpan.FromHours(1);

    /// <summary>
    /// <c>now + ttl</c>, rounded down to a multiple of the step: an hour, or a quarter of the TTL when that's shorter (at
    /// least a second). Down, so a message never outlives the TTL its sender chose, and by at most a quarter of it. Always
    /// whole seconds, since MySQL DATETIME has whole-second precision and the expiry must round-trip exactly through the AAD.
    /// </summary>
    public static DateTime At(DateTime nowUtc, int ttlSeconds) {
        var ttl = Math.Max(1, ttlSeconds);
        var step = TimeSpan.FromSeconds(Math.Clamp(ttl / 4, 1, (int)MaxStep.TotalSeconds)).Ticks;
        var exact = nowUtc.AddSeconds(ttl).Ticks;
        return new DateTime(exact - exact % step, DateTimeKind.Utc);
    }

    /// <summary>"Due now" for a row written straight to the held table, without the exact second it was accepted.</summary>
    public static DateTime DueNow(DateTime nowUtc) {
        return new DateTime(nowUtc.Ticks - nowUtc.Ticks % TimeSpan.TicksPerMinute, DateTimeKind.Utc);
    }
}
