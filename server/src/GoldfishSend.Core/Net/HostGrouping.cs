using System.Globalization;
using System.Net;

namespace GoldfishSend.Core.Net;

public static class HostGrouping {
    /// <summary>
    /// The registrable domain ("base domain") of a host by the Public Suffix List, both its ICANN and private sections:
    /// <c>a1.evil.example</c> and <c>a2.evil.example</c> share <c>evil.example</c>, while <c>alice.ts.net</c> and
    /// <c>bob.ts.net</c> (or <c>x.duckdns.org</c>) are separate, since their owners are. It groups the push hosts one
    /// party controls: wildcard tarpits share one slow-lane bucket and one new-host charge. Unknown TLDs count as one
    /// label of suffix. A host that is itself a public suffix, and an IP literal, is its own group.
    /// </summary>
    public static string BaseDomain(string host) {
        var h = host.Trim().TrimEnd('.').ToLowerInvariant();
        if (h.Length == 0 || IPAddress.TryParse(h.Trim('[', ']'), out _)) {
            return h;
        }
        var labels = h.Split('.');
        var suffix = PublicSuffixList.SuffixLabels(labels);
        return suffix >= labels.Length ? h : string.Join('.', labels[^(suffix + 1)..]);
    }

    /// <summary>True if <paramref name="host"/> is one of <paramref name="names"/> or a subdomain of one.</summary>
    public static bool IsWithin(string host, IEnumerable<string> names) {
        var h = host.Trim().TrimEnd('.').ToLowerInvariant();
        if (h.Length == 0) {
            return false;
        }
        foreach (var name in names) {
            var n = name.Trim().TrimEnd('.').ToLowerInvariant();
            if (n.Length > 0 && (h == n || h.EndsWith("." + n, StringComparison.Ordinal))) {
                return true;
            }
        }
        return false;
    }
}

/// <summary>
/// The rules of the embedded Public Suffix List snapshot (<c>Net/public_suffix_list.dat</c>), loaded once. Nothing is
/// downloaded: an old snapshot only means a newer shared suffix is grouped as one domain, like before it was listed.
/// </summary>
internal static class PublicSuffixList {
    private static readonly Lazy<Rules> Loaded = new(Load);

    private sealed record Rules(HashSet<string> Exact, HashSet<string> Wildcard, HashSet<string> Exception);

    /// <summary>How many trailing labels of <paramref name="labels"/> (lower case, ASCII) are the public suffix.</summary>
    public static int SuffixLabels(string[] labels) {
        var rules = Loaded.Value;
        var n = labels.Length;
        // An exception rule ("!city.kobe.jp") beats the wildcard it carves out of: its suffix is one label shorter.
        for (var i = 0; i < n; i++) {
            if (rules.Exception.Contains(string.Join('.', labels[i..]))) {
                return n - i - 1;
            }
        }
        // Otherwise the longest matching rule wins, and the implicit "*" rule makes any TLD a suffix.
        for (var i = 0; i < n; i++) {
            var candidate = string.Join('.', labels[i..]);
            if (rules.Exact.Contains(candidate) || (i + 1 < n && rules.Wildcard.Contains(string.Join('.', labels[(i + 1)..])))) {
                return n - i;
            }
        }
        return 1;
    }

    private static Rules Load() {
        var rules = new Rules(new(StringComparer.Ordinal), new(StringComparer.Ordinal), new(StringComparer.Ordinal));
        using var stream = typeof(PublicSuffixList).Assembly.GetManifestResourceStream("GoldfishSend.Core.public_suffix_list.dat")
            ?? throw new InvalidOperationException("The Public Suffix List resource is missing.");
        using var reader = new StreamReader(stream);
        var idn = new IdnMapping();
        while (reader.ReadLine() is { } line) {
            var rule = line.Trim();
            if (rule.Length == 0 || rule.StartsWith("//", StringComparison.Ordinal)) {
                continue;
            }
            var set = rules.Exact;
            if (rule.StartsWith("!", StringComparison.Ordinal)) {
                set = rules.Exception;
                rule = rule[1..];
            } else if (rule.StartsWith("*.", StringComparison.Ordinal)) {
                set = rules.Wildcard;
                rule = rule[2..];
            }
            try {
                // Hosts arrive in their ASCII (punycode) form, so the Unicode rules are matched in that form too.
                set.Add(idn.GetAscii(rule).ToLowerInvariant());
            } catch (ArgumentException) {
                // Not a valid name: skip the rule.
            }
        }
        return rules;
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
