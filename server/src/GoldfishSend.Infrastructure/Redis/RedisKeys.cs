namespace GoldfishSend.Infrastructure.Redis;

internal static class RedisKeys {
    public const string Queue = "gf:q";
    public const string QueueGroup = "delivery";
    public const string WakeQueue = "gf:wake:q";
    public const string WakeRetry = "gf:wake:retry";

    public static string RateLimit(string policy, string hashedKey) => $"gf:rl:{policy}:{hashedKey}";
    public static string RateLimitKey(string day) => $"gf:rlkey:{day}";
    public static string Pow(string challengeHex) => $"gf:pow:{challengeHex}";
    public static string PowLoad(long minute) => $"gf:pow:load:{minute}";
    public static string PowNetworkLoad(string hmacHex, long minute) => $"gf:pow:netload:{hmacHex}:{minute}";
    public static string Idempotency(string hmacHex) => $"gf:idem:{hmacHex}";
    public const string InviteIndex = "gf:inv:index";
    public static string MailboxInFlight(string hmacHex) => $"gf:mbxlease:{hmacHex}";
    public static string HostSeen(string hmacHex) => $"gf:hostseen:{hmacHex}";
    public static string Invite(string idHex) => $"gf:inv:{idHex}";
    public static string GatewayReplay(string hex) => $"gf:gwr:{hex}";
}
