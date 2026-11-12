namespace GoldfishSend.Core.Options;

public static class RatePolicies {
    public const string SendPerIp = "send-ip";
    public const string SendPerMailbox = "send-mailbox";
    public const string SendPerMailboxDaily = "send-mailbox-day";
    public const string SendGlobal = "send-global";
    public const string CreatePerIp = "create-ip";
    public const string CreatePerNetwork = "create-net";
    public const string PowPerIp = "pow-ip";
    public const string PowPerNetwork = "pow-net";
    public const string OwnerPerIp = "owner-ip";
    public const string RotatePerMailbox = "rotate-mailbox";
    public const string InviteCreatePerIp = "invite-create-ip";
    public const string InviteCreatePerNetwork = "invite-create-net";
    public const string InviteCreateGlobal = "invite-create-global";
    public const string InviteFetchPerIp = "invite-fetch-ip";
    /// <summary>Outbound pushes per push-service host, shared cluster-wide.</summary>
    public const string PushPerHost = "push-host";

    // "-ip" policies key on an IPv4 /32 or IPv6 /64. "-net" policies key on an IPv4 /24 or IPv6 /48, so one
    // allocation can't multiply its quota by rotating through the addresses it controls.
    public static readonly IReadOnlyDictionary<string, RatePolicy> Defaults = new Dictionary<string, RatePolicy> {
        [SendPerIp] = new(60, 60, 20),
        [SendPerMailbox] = new(30, 60, 30),
        [SendPerMailboxDaily] = new(1000, 86400, 1000),
        [SendGlobal] = new(2000, 1, 4000),
        [CreatePerIp] = new(10, 3600, 10),
        [CreatePerNetwork] = new(100, 3600, 50),
        [PowPerIp] = new(30, 60, 30),
        [PowPerNetwork] = new(300, 60, 100),
        [OwnerPerIp] = new(30, 60, 30),
        [RotatePerMailbox] = new(10, 86400, 5),
        [InviteCreatePerIp] = new(20, 3600, 10),
        [InviteCreatePerNetwork] = new(100, 3600, 30),
        [InviteCreateGlobal] = new(5, 1, 50),
        [InviteFetchPerIp] = new(60, 60, 20),
        [PushPerHost] = new(50, 1, 50),
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
        CreatePerNetwork or PowPerNetwork or InviteCreatePerNetwork => ScopeNetwork,
        SendPerMailbox or SendPerMailboxDaily or RotatePerMailbox => ScopeMailbox,
        _ => ScopeGlobal,
    };

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
