using GoldfishSend.Core.Crypto;
using GoldfishSend.Core.Options;

namespace GoldfishSend.Tests.Core;

public sealed class PowDifficultyTests {
    // Defaults: base 8, network threshold 5 per 5-minute window and /32 threshold 50 (up to +6 together), global 120
    // verified a minute (up to +2).
    private static readonly PowOptions Defaults = new();

    [Theory]
    [InlineData(0, 5, 6, 0)]
    [InlineData(5, 5, 6, 0)]
    [InlineData(6, 5, 6, 1)]
    [InlineData(9, 5, 6, 1)]
    [InlineData(10, 5, 6, 2)]
    [InlineData(19, 5, 6, 2)]
    [InlineData(20, 5, 6, 3)]
    [InlineData(159, 5, 6, 5)]
    [InlineData(160, 5, 6, 6)]
    [InlineData(1_000_000, 5, 6, 6)]
    [InlineData(100, 0, 6, 0)]
    [InlineData(100, 5, 0, 0)]
    public void ExtraBits_OneBitPerDoublingPastTheThreshold_Capped(double load, double threshold, int max, int expected) {
        Assert.Equal(expected, PowDifficulty.ExtraBits(load, threshold, max));
    }

    [Fact]
    public void NoLoad_IsTheBaseDifficulty() {
        Assert.Equal(8, PowDifficulty.For(Defaults, 0, 0, 0));
        // A household onboarding a few phones at once stays at base.
        Assert.Equal(8, PowDifficulty.For(Defaults, 5, 5, 0));
    }

    [Fact]
    public void NetworkLoad_RaisesThatNetworkUpToSixBits() {
        Assert.Equal(9, PowDifficulty.For(Defaults, 6, 6, 0));
        Assert.Equal(14, PowDifficulty.For(Defaults, 10_000, 10_000, 0));
    }

    [Fact]
    public void AllocationLoad_CatchesFloodsSpreadOverManyNetworks_ButIsTenTimesLooser() {
        // A /48 with one creation in a /32 that saw 50: an ISP's ordinary traffic, not raised.
        Assert.Equal(8, PowDifficulty.For(Defaults, 1, 50, 0));
        // One actor with 500 /48s in a /32, three creations each: each /48 is under its threshold, the /32 is not.
        Assert.Equal(8 + 5, PowDifficulty.For(Defaults, 3, 1500, 0));
        // The larger of the two counts, not the sum, and still capped at +6.
        Assert.Equal(8 + 6, PowDifficulty.For(Defaults, 10_000, 1_000_000, 0));
        Assert.Equal(PowDifficulty.For(Defaults, 40, 0, 0), PowDifficulty.For(Defaults, 40, 60, 0));
    }

    [Fact]
    public void GlobalLoad_AddsAtMostTwoBits() {
        // 5-minute window: 600 verified is 120 a minute (not over), 601 is just over, 1201 is past one doubling.
        Assert.Equal(8, PowDifficulty.For(Defaults, 0, 0, 600));
        Assert.Equal(9, PowDifficulty.For(Defaults, 0, 0, 601));
        Assert.Equal(10, PowDifficulty.For(Defaults, 0, 0, 1201));
        Assert.Equal(10, PowDifficulty.For(Defaults, 0, 0, 10_000_000));
    }

    [Fact]
    public void LoadFromOneNetwork_RaisesAnotherOnlyByTheGlobalCap() {
        // Network X floods (and everything it creates is verified, so it also counts globally). Network Y, in another
        // /32, is idle.
        foreach (var flood in new long[] { 10, 100, 1000, 100_000 }) {
            var x = PowDifficulty.For(Defaults, flood, flood, flood);
            var y = PowDifficulty.For(Defaults, 0, 0, flood);
            Assert.True(y <= Defaults.BaseDifficulty + Defaults.MaxGlobalExtraDifficulty, $"flood {flood}: y = {y}");
            Assert.True(x >= y);
        }
        Assert.Equal(8 + 6 + 2, PowDifficulty.For(Defaults, 100_000, 100_000, 100_000));
        Assert.Equal(8 + 2, PowDifficulty.For(Defaults, 0, 0, 100_000));
        Assert.Equal(16, PowDifficulty.Highest(Defaults));
    }

    [Fact]
    public void Total_NeverExceedsWhatClientsAccept() {
        var extreme = new PowOptions {
            BaseDifficulty = 20,
            MaxNetworkExtraDifficulty = 10,
            MaxGlobalExtraDifficulty = 10,
            NetworkLoadThreshold = 1,
            GlobalLoadThresholdPerMinute = 1,
        };
        Assert.Equal(ProofOfWork.MaxDifficulty, PowDifficulty.For(extreme, long.MaxValue / 2, 0, long.MaxValue / 2));
    }
}
