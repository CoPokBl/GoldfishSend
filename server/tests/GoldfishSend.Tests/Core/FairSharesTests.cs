using GoldfishSend.Infrastructure.Redis;

namespace GoldfishSend.Tests.Core;

public sealed class FairSharesTests {
    [Fact]
    public void ASubject_HoldsAtMostItsLimit_OthersAreUnaffected() {
        var shares = new FairShares();
        var x = new[] { ("x", 2) };
        var y = new[] { ("y", 2) };
        Assert.True(shares.TryEnter(x));
        Assert.True(shares.TryEnter(x));
        Assert.False(shares.TryEnter(x));
        Assert.True(shares.TryEnter(y));
        shares.Exit(x);
        Assert.True(shares.TryEnter(x));
    }

    [Fact]
    public void AllKeysOrNone_SoAFullWiderTierBlocksWithoutLeakingANarrowShare() {
        var shares = new FairShares();
        // Two /48s in one /32 whose limit is 1.
        Assert.True(shares.TryEnter([("n1", 1), ("a", 1)]));
        Assert.False(shares.TryEnter([("n2", 1), ("a", 1)]));
        Assert.Equal(0, shares.Held("n2"));
        shares.Exit([("n1", 1), ("a", 1)]);
        Assert.True(shares.TryEnter([("n2", 1), ("a", 1)]));
    }

    [Fact]
    public void EntriesGoAwayWhenReleased() {
        var shares = new FairShares();
        var keys = new[] { ("n", 3), ("a", 6) };
        for (var i = 0; i < 3; i++) {
            Assert.True(shares.TryEnter(keys));
        }
        for (var i = 0; i < 3; i++) {
            shares.Exit(keys);
        }
        Assert.Equal(0, shares.Count);
    }

    [Fact]
    public void ConcurrentCallers_NeverExceedTheLimit() {
        var shares = new FairShares();
        var keys = new[] { ("n", 4) };
        var inside = 0;
        var most = 0;
        Parallel.For(0, 20_000, _ => {
            if (!shares.TryEnter(keys)) {
                return;
            }
            var now = Interlocked.Increment(ref inside);
            int seen;
            while ((seen = Volatile.Read(ref most)) < now && Interlocked.CompareExchange(ref most, now, seen) != seen) {
            }
            Interlocked.Decrement(ref inside);
            shares.Exit(keys);
        });
        Assert.InRange(most, 1, 4);
        Assert.Equal(0, shares.Count);
    }
}
