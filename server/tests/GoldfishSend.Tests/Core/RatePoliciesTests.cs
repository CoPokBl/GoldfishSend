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
    [InlineData(RatePolicies.CreatePerNetwork, "network")]
    [InlineData(RatePolicies.PowPerNetwork, "network")]
    [InlineData(RatePolicies.InviteCreatePerNetwork, "network")]
    [InlineData(RatePolicies.SendPerMailbox, "mailbox")]
    [InlineData(RatePolicies.SendPerMailboxDaily, "mailbox")]
    [InlineData(RatePolicies.RotatePerMailbox, "mailbox")]
    [InlineData(RatePolicies.SendGlobal, "global")]
    [InlineData(RatePolicies.InviteCreateGlobal, "global")]
    [InlineData(RatePolicies.PushPerHost, "global")]
    public void EveryPolicy_HasTheIntendedScope(string policy, string scope) {
        Assert.Equal(scope, RatePolicies.ScopeOf(policy));
    }

    [Fact]
    public void ScopeTable_CoversEveryDefaultPolicy() {
        // A newly added policy must be added to the theory above (and ScopeOf) deliberately.
        Assert.Equal(15, RatePolicies.Defaults.Count);
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
}
