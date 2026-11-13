namespace GoldfishSend.Core.Options;

public static class RatePolicies {
    public const string SendPerIp = "send-ip";
    public const string SendPerNetwork = "send-net";
    /// <summary>All sends that reach the database lookup, server-wide. It protects MySQL from floods of junk send tokens.</summary>
    public const string SendLookupGlobal = "send-lookup-global";
    public const string SendPerMailbox = "send-mailbox";
    public const string SendPerMailboxDaily = "send-mailbox-day";
    public const string SendGlobal = "send-global";
    public const string CreatePerIp = "create-ip";
    public const string CreatePerNetwork = "create-net";
    public const string CreateGlobal = "create-global";
    /// <summary>Verification pushes to push hosts no mailbox has used before, server-wide.</summary>
    public const string NewHostGlobal = "newhost-global";
    public const string PowPerIp = "pow-ip";
    public const string PowPerNetwork = "pow-net";
    public const string OwnerPerIp = "owner-ip";
    public const string OwnerPerNetwork = "owner-net";
    public const string RotatePerMailbox = "rotate-mailbox";
    public const string InviteCreatePerIp = "invite-create-ip";
    public const string InviteCreatePerNetwork = "invite-create-net";
    public const string InviteCreateGlobal = "invite-create-global";
    public const string InviteFetchPerIp = "invite-fetch-ip";
    public const string InviteFetchPerNetwork = "invite-fetch-net";
    /// <summary>Outbound pushes per push-service host, shared cluster-wide.</summary>
    public const string PushPerHost = "push-host";
    /// <summary>Outbound pushes per mailbox. It sits in front of the host budget, so a few mailboxes can't take a shared push service's whole budget.</summary>
    public const string PushPerMailbox = "push-mailbox";

    // "-ip" policies key on an IPv4 /32 or IPv6 /64. "-net" policies key on an IPv4 /24 or IPv6 /48, so one
    // allocation can't multiply its quota by rotating through the addresses it controls.
    public static readonly IReadOnlyDictionary<string, RatePolicy> Defaults = new Dictionary<string, RatePolicy> {
        [SendPerIp] = new(60, 60, 20),
        [SendPerNetwork] = new(600, 60, 200),
        [SendLookupGlobal] = new(3000, 1, 6000),
        [SendPerMailbox] = new(30, 60, 30),
        [SendPerMailboxDaily] = new(1000, 86400, 1000),
        [SendGlobal] = new(2000, 1, 4000),
        [CreatePerIp] = new(10, 3600, 10),
        [CreatePerNetwork] = new(100, 3600, 50),
        [CreateGlobal] = new(3000, 3600, 300),
        [NewHostGlobal] = new(120, 3600, 30),
        [PowPerIp] = new(30, 60, 30),
        [PowPerNetwork] = new(300, 60, 100),
        [OwnerPerIp] = new(30, 60, 30),
        [OwnerPerNetwork] = new(300, 60, 100),
        [RotatePerMailbox] = new(10, 86400, 5),
        [InviteCreatePerIp] = new(20, 3600, 10),
        [InviteCreatePerNetwork] = new(100, 3600, 30),
        [InviteCreateGlobal] = new(5, 1, 50),
        [InviteFetchPerIp] = new(60, 60, 20),
        [InviteFetchPerNetwork] = new(300, 60, 100),
        [PushPerHost] = new(200, 1, 200),
        [PushPerMailbox] = new(2, 1, 10),
    };

    public const string ScopeIp = "ip";
    public const string ScopeNetwork = "network";
    public const string ScopeMailbox = "mailbox";
    public const string ScopeGlobal = "global";

    /// <summary>
    /// Which kind of subject a policy limits. It's reported to clients as <c>scope</c> on <c>429</c>, so they can react:
    /// only an <c>ip</c>-scoped send limit can be paid off with a proof of work.
    /// </summary>
    public static string ScopeOf(string policy) => policy switch {
        SendPerIp or CreatePerIp or PowPerIp or OwnerPerIp or InviteCreatePerIp or InviteFetchPerIp => ScopeIp,
        SendPerNetwork or CreatePerNetwork or PowPerNetwork or OwnerPerNetwork or InviteCreatePerNetwork or InviteFetchPerNetwork => ScopeNetwork,
        SendPerMailbox or SendPerMailboxDaily or RotatePerMailbox or PushPerMailbox => ScopeMailbox,
        _ => ScopeGlobal,
    };

    /// <summary>
    /// Long-period buckets (an hour or more) are keyed with a stable cluster secret instead of the daily key, so the
    /// daily key rotation at UTC midnight can't reset them (which would double the budget).
    /// </summary>
    public static bool UsesStableKey(RatePolicy policy) => policy.PeriodSeconds >= 3600;

    /// <summary>
    /// The configured policy, with any field left at 0 taken from the default. A partial override
    /// (just <c>Limit</c>, say) can't silently switch a limit off.
    /// </summary>
    public static RatePolicy Resolve(GoldfishOptions options, string name) {
        var defaults = Defaults[name];
        if (!options.RateLimits.TryGetValue(name, out var configured)) {
            return defaults;
        }
        return new RatePolicy(
            configured.Limit > 0 ? configured.Limit : defaults.Limit,
            configured.PeriodSeconds > 0 ? configured.PeriodSeconds : defaults.PeriodSeconds,
            configured.Burst > 0 ? configured.Burst : defaults.Burst);
    }
}
