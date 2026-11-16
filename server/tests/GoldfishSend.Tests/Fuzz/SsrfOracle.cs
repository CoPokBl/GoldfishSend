using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Numerics;

namespace GoldfishSend.Tests.Fuzz;

/// <summary>
/// Independent references for the SSRF defences: which addresses are globally reachable (the IANA IPv4 and IPv6
/// special-purpose address registries, written out as plain prefixes, not shared with <c>IpRangeFilter</c>), how a C
/// resolver reads numeric host names (glibc <c>inet_aton</c>), and which names can never be public push services.
/// </summary>
public static class SsrfOracle {
    private static readonly (string Prefix, bool Global)[] V4 = [
        ("0.0.0.0/8", false), ("10.0.0.0/8", false), ("100.64.0.0/10", false), ("127.0.0.0/8", false),
        ("169.254.0.0/16", false), ("172.16.0.0/12", false), ("192.0.0.0/24", false), ("192.0.0.9/32", true),
        ("192.0.0.10/32", true), ("192.0.2.0/24", false), ("192.88.99.0/24", false), ("192.168.0.0/16", false),
        ("198.18.0.0/15", false), ("198.51.100.0/24", false), ("203.0.113.0/24", false), ("224.0.0.0/4", false),
        ("240.0.0.0/4", false), ("255.255.255.255/32", false),
    ];

    // Within 2000::/3 (everything outside it is not global unicast). 6to4 and Teredo embed IPv4 and count as not global.
    private static readonly (string Prefix, bool Global)[] V6 = [
        ("2001::/23", false), ("2001::/32", false), ("2001:1::1/128", true), ("2001:1::2/128", true), ("2001:1::3/128", true),
        ("2001:2::/48", false), ("2001:3::/32", true), ("2001:4:112::/48", true), ("2001:10::/28", false), ("2001:20::/28", true),
        ("2001:30::/28", true), ("2001:db8::/32", false), ("2002::/16", false), ("3fff::/20", false), ("5f00::/16", false),
    ];

    /// <summary>Longest matching prefix wins; addresses matching nothing are global.</summary>
    public static bool IsGloballyReachable(IPAddress address) {
        var bytes = address.GetAddressBytes();
        if (address.AddressFamily == AddressFamily.InterNetwork) {
            return Lookup(V4, bytes);
        }
        if (address.ScopeId != 0) {
            return false;
        }
        if (bytes.AsSpan(0, 10).IndexOfAnyExcept((byte)0) < 0 && bytes[10] == 0xff && bytes[11] == 0xff) {
            return Lookup(V4, bytes[12..]);
        }
        return (bytes[0] & 0xe0) == 0x20 && Lookup(V6, bytes);
    }

    private static bool Lookup((string Prefix, bool Global)[] table, byte[] bytes) {
        var best = -1;
        var global = true;
        var value = new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
        var bits = bytes.Length * 8;
        foreach (var (prefix, isGlobal) in table) {
            var parts = prefix.Split('/');
            var network = new BigInteger(IPAddress.Parse(parts[0]).GetAddressBytes(), isUnsigned: true, isBigEndian: true);
            var length = int.Parse(parts[1], CultureInfo.InvariantCulture);
            if (value >> (bits - length) == network >> (bits - length) && length > best) {
                best = length;
                global = isGlobal;
            }
        }
        return global;
    }

    /// <summary>glibc's <c>inet_aton</c> (1 to 4 parts, each decimal, 0-octal or 0x-hex, the last one filling the rest), whole string.</summary>
    public static IPAddress? InetAton(string text) {
        var parts = text.Split('.');
        if (parts.Length is < 1 or > 4) {
            return null;
        }
        var values = new ulong[parts.Length];
        for (var i = 0; i < parts.Length; i++) {
            var p = parts[i];
            int radix = 10, start = 0;
            if (p.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) {
                (radix, start) = (16, 2);
            } else if (p.Length > 1 && p[0] == '0') {
                (radix, start) = (8, 1);
            }
            if (p.Length == 0) {
                return null;
            }
            ulong v = 0;
            for (var j = start; j < p.Length; j++) {
                var d = char.IsAsciiDigit(p[j]) ? p[j] - '0' : char.IsAsciiHexDigit(p[j]) ? char.ToLowerInvariant(p[j]) - 'a' + 10 : 99;
                if (d >= radix || v > 0xffffffffUL) {
                    return null;
                }
                v = v * (ulong)radix + (ulong)d;
            }
            values[i] = v;
        }
        var last = values[^1];
        var max = parts.Length switch { 1 => 0xffffffffUL, 2 => 0xffffffUL, 3 => 0xffffUL, _ => 0xffUL };
        if (last > max || values[..^1].Any(v => v > 0xff)) {
            return null;
        }
        var result = last;
        for (var i = 0; i < parts.Length - 1; i++) {
            result |= values[i] << (24 - 8 * i);
        }
        return new IPAddress([(byte)(result >> 24), (byte)(result >> 16), (byte)(result >> 8), (byte)result]);
    }

    /// <summary>WHATWG URL "ends in a number": a host whose last label is numeric is an IPv4 address (or invalid), never a name.</summary>
    public static bool EndsInNumber(string host) {
        var labels = host.Split('.').ToList();
        if (labels[^1].Length == 0 && labels.Count > 1) {
            labels.RemoveAt(labels.Count - 1);
        }
        var last = labels[^1];
        return last.Length > 0 && (last.All(char.IsAsciiDigit)
            || (last.StartsWith("0x", StringComparison.OrdinalIgnoreCase) && last[2..].All(char.IsAsciiHexDigit)));
    }

    /// <summary>Every address some parser could read <paramref name="host"/> as (without DNS).</summary>
    public static IReadOnlyList<IPAddress> NumericReadings(string host) {
        var bare = host.Trim('[', ']');
        var readings = new List<IPAddress>();
        foreach (var candidate in new[] { bare, bare.TrimEnd('.') }.Distinct()) {
            if (IPAddress.TryParse(candidate, out var parsed)) {
                readings.Add(parsed);
            }
            if (InetAton(candidate) is { } aton) {
                readings.Add(aton);
            }
        }
        return readings;
    }

    // RFC 6761, 6762, 7686, 8375, 9476 and ICANN's .internal: never public DNS. All of .arpa is infrastructure.
    private static readonly string[] SpecialUse = ["localhost", "local", "test", "invalid", "example", "onion", "alt", "internal", "arpa"];

    public static bool IsSpecialUseName(string host) {
        var h = host.TrimEnd('.').ToLowerInvariant();
        return SpecialUse.Any(s => h == s || h.EndsWith("." + s, StringComparison.Ordinal));
    }
}
