using GoldfishSend.Core;

namespace GoldfishSend.Tests.Core;

public sealed class BackoffTests {
    private const int Samples = 2000;

    private static void AssertWithinJitter(TimeSpan baseDelay, TimeSpan actual) {
        var low = baseDelay.TotalMilliseconds * 0.8;
        var high = Math.Min(baseDelay.TotalMilliseconds * 1.2, Backoff.Max.TotalMilliseconds);
        Assert.InRange(actual.TotalMilliseconds, low - 1, high + 1);
    }

    public static TheoryData<int, double> Steps => new() {
        { 1, 10 },
        { 2, 30 },
        { 3, 120 },
        { 4, 600 },
        { 5, 1800 },
        { 6, 3600 },
    };

    [Theory]
    [MemberData(nameof(Steps))]
    public void Next_IsWithinTwentyPercentOfSchedule(int attempt, double baseSeconds) {
        var baseDelay = TimeSpan.FromSeconds(baseSeconds);
        var min = TimeSpan.MaxValue;
        var max = TimeSpan.MinValue;
        for (var i = 0; i < Samples; i++) {
            var delay = Backoff.Next(attempt);
            AssertWithinJitter(baseDelay, delay);
            min = delay < min ? delay : min;
            max = delay > max ? delay : max;
        }
        // The jitter actually spreads values across most of the range.
        Assert.True(min.TotalMilliseconds < baseDelay.TotalMilliseconds * 0.9);
        Assert.True(max.TotalMilliseconds > baseDelay.TotalMilliseconds * 1.1);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    public void Next_NonPositiveAttempt_UsesFirstStep(int attempt) {
        for (var i = 0; i < 200; i++) {
            AssertWithinJitter(TimeSpan.FromSeconds(10), Backoff.Next(attempt));
        }
    }

    [Theory]
    [InlineData(7)]
    [InlineData(8)]
    [InlineData(100)]
    [InlineData(int.MaxValue)]
    public void Next_BeyondSchedule_IsCappedAtSixHours(int attempt) {
        for (var i = 0; i < Samples; i++) {
            var delay = Backoff.Next(attempt);
            Assert.True(delay <= TimeSpan.FromHours(6));
            Assert.True(delay >= TimeSpan.FromHours(6 * 0.8) - TimeSpan.FromMilliseconds(1));
        }
    }

    [Fact]
    public void Max_IsSixHours() {
        Assert.Equal(TimeSpan.FromHours(6), Backoff.Max);
    }

    [Fact]
    public void Next_RetryAfterLongerThanDelay_IsRespected() {
        var retryAfter = TimeSpan.FromMinutes(5);
        for (var i = 0; i < 200; i++) {
            Assert.Equal(retryAfter, Backoff.Next(1, retryAfter));
        }
    }

    [Fact]
    public void Next_RetryAfterShorterThanDelay_IsIgnored() {
        for (var i = 0; i < 200; i++) {
            AssertWithinJitter(TimeSpan.FromMinutes(10), Backoff.Next(4, TimeSpan.FromSeconds(1)));
        }
    }

    [Fact]
    public void Next_RetryAfterBeyondMax_IsCapped() {
        Assert.Equal(Backoff.Max, Backoff.Next(1, TimeSpan.FromDays(2)));
        Assert.Equal(Backoff.Max, Backoff.Next(1, TimeSpan.FromHours(6) + TimeSpan.FromTicks(1)));
    }

    [Fact]
    public void Next_NegativeOrZeroRetryAfter_IsIgnored() {
        AssertWithinJitter(TimeSpan.FromSeconds(10), Backoff.Next(1, TimeSpan.Zero));
        AssertWithinJitter(TimeSpan.FromSeconds(10), Backoff.Next(1, TimeSpan.FromSeconds(-30)));
    }

    [Fact]
    public void Next_IsMonotonicOnAverage() {
        double Mean(int attempt) => Enumerable.Range(0, 500).Average(_ => Backoff.Next(attempt).TotalMilliseconds);
        var previous = 0.0;
        for (var attempt = 1; attempt <= 7; attempt++) {
            var mean = Mean(attempt);
            Assert.True(mean > previous, $"attempt {attempt}: mean {mean} <= {previous}");
            previous = mean;
        }
    }
}
