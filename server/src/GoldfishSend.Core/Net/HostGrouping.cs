using System.Net;

namespace GoldfishSend.Core.Net;

public static class HostGrouping {
    /// <summary>
    /// Approximate registrable domain ("base domain") of a host, used to group wildcard subdomains
    /// (<c>a1.evil.example</c>, <c>a2.evil.example</c>…) into one slow-lane bucket. It's a heuristic without the Public
    /// Suffix List: the last two labels, or three when the second-to-last label looks like a second-level suffix
    /// (<c>example.co.uk</c>). IP literals are their own group.
    /// </summary>
    public static string BaseDomain(string host) {
        var h = host.Trim().TrimEnd('.').ToLowerInvariant();
        if (h.Length == 0 || IPAddress.TryParse(h.Trim('[', ']'), out _)) {
            return h;
        }
        var labels = h.Split('.');
        if (labels.Length <= 2) {
            return h;
        }
        var tld = labels[^1];
        var second = labels[^2];
        var take = tld.Length == 2 && second.Length <= 3 ? 3 : 2;
        return string.Join('.', labels[^take..]);
    }
}

public static class PushTtl {
    private static readonly int[] Buckets = [60, 600, 3600, 6 * 3600, 86400, 3 * 86400, 7 * 86400, 14 * 86400];

    /// <summary>
    /// Rounds a push TTL down to a few fixed values, so push services (and anyone watching them) can't read a message's
    /// exact age or the sender's chosen TTL from the header. Rounding down means a push never outlives the message.
    /// </summary>
    public static int Coarse(int seconds) {
        var result = Buckets[0];
        foreach (var b in Buckets) {
            if (b <= seconds) {
                result = b;
            }
        }
        return seconds <= 0 ? 0 : result;
    }
}
