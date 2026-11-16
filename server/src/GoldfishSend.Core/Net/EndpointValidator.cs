using System.Net;
using GoldfishSend.Core.Options;
using GoldfishSend.Core.Protocol;

namespace GoldfishSend.Core.Net;

/// <summary>
/// Syntactic validation of client-supplied UnifiedPush endpoint URLs. Resolved addresses are checked
/// separately, at connect time (see the SSRF-safe push client), so DNS rebinding can't get around these checks.
/// </summary>
public sealed class EndpointValidator {
    private static readonly string[] ForbiddenSuffixes = [
        ".localhost", ".local", ".localdomain", ".internal", ".intranet", ".lan", ".home", ".corp",
        ".arpa", ".onion", ".test", ".invalid", ".example", ".alt",
    ];

    private readonly PushOptions _options;
    private readonly IpRangeFilter _ipFilter;

    public EndpointValidator(PushOptions options, IpRangeFilter ipFilter) {
        _options = options;
        _ipFilter = ipFilter;
    }

    public bool TryValidate(string? url, out Uri uri) {
        uri = null!;
        if (string.IsNullOrWhiteSpace(url) || url.Length > EndpointRecord.MaxUrlBytes
            || System.Text.Encoding.UTF8.GetByteCount(url) > EndpointRecord.MaxUrlBytes) {
            return false;
        }
        if (!Uri.TryCreate(url, UriKind.Absolute, out var parsed)) {
            return false;
        }

        var insecureAllowed = _options.DangerouslyAllowInsecureLoopback;
        if (parsed.Scheme != Uri.UriSchemeHttps && !(insecureAllowed && parsed.Scheme == Uri.UriSchemeHttp)) {
            return false;
        }
        if (!string.IsNullOrEmpty(parsed.UserInfo) || !string.IsNullOrEmpty(parsed.Fragment)) {
            return false;
        }

        if (!parsed.IsDefaultPort && !_options.AllowedPorts.Contains(parsed.Port) && !insecureAllowed) {
            return false;
        }

        var host = parsed.IdnHost.TrimEnd('.').ToLowerInvariant();
        if (host.Length == 0 || host.Length > 253) {
            return false;
        }

        switch (parsed.HostNameType) {
            case UriHostNameType.IPv4:
            case UriHostNameType.IPv6:
                if (!_options.AllowIpLiterals && !insecureAllowed) {
                    return false;
                }
                // Uri.Host drops an IPv6 zone id, but HttpClient connects with it ("%2525" is scope 2525).
                if (parsed.IdnHost.Contains('%')) {
                    return false;
                }
                if (!IPAddress.TryParse(parsed.Host.Trim('[', ']'), out var literal) || !_ipFilter.IsAllowed(literal)) {
                    return false;
                }
                break;
            case UriHostNameType.Dns:
                if (!IsAcceptableHostName(host, insecureAllowed)) {
                    return false;
                }
                break;
            default:
                return false;
        }

        uri = parsed;
        return true;
    }

    private bool IsAcceptableHostName(string host, bool insecureAllowed) {
        if (insecureAllowed && host == "localhost") {
            return true;
        }
        // Uri types "127.0.0.1." and "127。0。0。1" (IDNA maps U+3002 to a dot) as DNS names, but HttpClient and resolvers
        // read them as addresses. No real name ends in a numeric label, so these never get the more lenient name rules.
        if (EndsInNumber(host)) {
            return false;
        }
        // Single-label names (intranet hosts, "localhost") aren't public push services.
        if (!host.Contains('.') || host == "localhost") {
            return false;
        }
        foreach (var suffix in ForbiddenSuffixes) {
            if (host.EndsWith(suffix, StringComparison.Ordinal)) {
                return false;
            }
        }
        foreach (var blocked in _options.BlockedHosts) {
            var b = blocked.Trim().TrimEnd('.').ToLowerInvariant();
            if (b.Length == 0) {
                continue;
            }
            if (host == b || host.EndsWith("." + b, StringComparison.Ordinal)) {
                return false;
            }
        }
        return true;
    }

    /// <summary>WHATWG URL's "ends in a number": the last label is decimal digits, or 0x and hex digits.</summary>
    private static bool EndsInNumber(string host) {
        var last = host[(host.LastIndexOf('.') + 1)..];
        if (last.StartsWith("0x", StringComparison.Ordinal)) {
            return last[2..].All(char.IsAsciiHexDigit);
        }
        return last.Length > 0 && last.All(char.IsAsciiDigit);
    }
}
