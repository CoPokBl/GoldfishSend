using GoldfishSend.Core.Options;

namespace GoldfishSend.Tests.Core;

public sealed class RatePoliciesTests {
    [Theory]
    [InlineData(RatePolicies.SendPerIp, "ip")]
    [InlineData(RatePolicies.CreatePerIp, "ip")]
    [InlineData(RatePolicies.PowPerIp, "ip")]
    [InlineData(RatePolicies.OwnerPerIp, "ip")]
    [InlineData(RatePolicies.InviteCreatePerIp, "ip")]
    [InlineData(RatePolicies.InviteFetchPerIp, "ip")]
    [InlineData(RatePolicies.SendPerNetwork, "network")]
    [InlineData(RatePolicies.CreatePerNetwork, "network")]
    [InlineData(RatePolicies.PowPerNetwork, "network")]
    [InlineData(RatePolicies.CreatePerAllocation, "network")]
    [InlineData(RatePolicies.PowPerAllocation, "network")]
    [InlineData(RatePolicies.OwnerPerNetwork, "network")]
    [InlineData(RatePolicies.InviteCreatePerNetwork, "network")]
    [InlineData(RatePolicies.InviteFetchPerNetwork, "network")]
    [InlineData(RatePolicies.SendPerAllocation, "network")]
    [InlineData(RatePolicies.OwnerPerAllocation, "network")]
    [InlineData(RatePolicies.InviteCreatePerAllocation, "network")]
    [InlineData(RatePolicies.NewHostPerNetwork, "network")]
    [InlineData(RatePolicies.NewHostPerAllocation, "network")]
    [InlineData(RatePolicies.SendPerMailbox, "mailbox")]
    [InlineData(RatePolicies.SendPerMailboxDaily, "mailbox")]
    [InlineData(RatePolicies.RotatePerMailbox, "mailbox")]
    [InlineData(RatePolicies.PushPerMailbox, "mailbox")]
    [InlineData(RatePolicies.SendGlobal, "global")]
    [InlineData(RatePolicies.SendLookupGlobal, "global")]
    [InlineData(RatePolicies.CreateGlobal, "global")]
    [InlineData(RatePolicies.NewHostGlobal, "global")]
    [InlineData(RatePolicies.InviteCreateGlobal, "global")]
    [InlineData(RatePolicies.PushPerHost, "global")]
    public void EveryPolicy_HasTheIntendedScope(string policy, string scope) {
        Assert.Equal(scope, RatePolicies.ScopeOf(policy));
    }

    [Fact]
    public void ScopeTable_CoversEveryDefaultPolicy() {
        // A newly added policy must be added to the theory above (and ScopeOf) deliberately.
        Assert.Equal(29, RatePolicies.Defaults.Count);
    }

    [Fact]
    public void PartialOverride_KeepsRemainingDefaults() {
        var options = new GoldfishOptions();
        options.RateLimits[RatePolicies.SendPerIp] = new RatePolicy { Limit = 120 };
        var resolved = RatePolicies.Resolve(options, RatePolicies.SendPerIp);
        Assert.Equal(120, resolved.Limit);
        Assert.Equal(60, resolved.PeriodSeconds);
        Assert.Equal(20, resolved.Burst);
    }

    [Theory]
    [InlineData(RatePolicies.SendPerMailboxDaily, true)]
    [InlineData(RatePolicies.RotatePerMailbox, true)]
    [InlineData(RatePolicies.CreatePerIp, true)]
    [InlineData(RatePolicies.SendPerIp, false)]
    [InlineData(RatePolicies.SendGlobal, false)]
    public void LongPeriodBuckets_UseTheStableKey(string policy, bool stable) {
        // Hourly-or-longer budgets must not reset when the daily HMAC key rotates at midnight.
        Assert.Equal(stable, RatePolicies.UsesStableKey(RatePolicies.Defaults[policy]));
    }

    [Fact]
    public void WideScopesAreMoreGenerousThanNarrowOnes() {
        foreach (var (narrow, wide) in new[] {
                     (RatePolicies.SendPerIp, RatePolicies.SendPerNetwork),
                     (RatePolicies.OwnerPerIp, RatePolicies.OwnerPerNetwork),
                     (RatePolicies.InviteFetchPerIp, RatePolicies.InviteFetchPerNetwork),
                     (RatePolicies.CreatePerIp, RatePolicies.CreatePerNetwork),
                     (RatePolicies.SendPerNetwork, RatePolicies.SendPerAllocation),
                     (RatePolicies.OwnerPerNetwork, RatePolicies.OwnerPerAllocation),
                     (RatePolicies.InviteCreatePerNetwork, RatePolicies.InviteCreatePerAllocation),
                     (RatePolicies.CreatePerNetwork, RatePolicies.CreatePerAllocation),
                     (RatePolicies.PowPerNetwork, RatePolicies.PowPerAllocation),
                     (RatePolicies.NewHostPerNetwork, RatePolicies.NewHostPerAllocation),
                 }) {
            var n = RatePolicies.Defaults[narrow];
            var w = RatePolicies.Defaults[wide];
            Assert.True(w.Limit / (double)w.PeriodSeconds > n.Limit / (double)n.PeriodSeconds, $"{wide} vs {narrow}");
        }
    }
}
