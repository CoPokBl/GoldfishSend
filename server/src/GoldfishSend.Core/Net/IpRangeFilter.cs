using System.Net;
using System.Net.Sockets;

namespace GoldfishSend.Core.Net;

/// <summary>
/// Decides whether the server may open an outbound connection to an address. It allows only globally routable
/// unicast destinations, which blocks SSRF into private networks, cloud metadata services and transition-mechanism tricks.
/// </summary>
public sealed class IpRangeFilter {
    private static readonly IPNetwork GlobalUnicastV6 = IPNetwork.Parse("2000::/3");

    private static readonly IPNetwork[] DefaultBlockedV4 = [
        IPNetwork.Parse("0.0.0.0/8"),          // "this" network
        IPNetwork.Parse("10.0.0.0/8"),         // RFC 1918
        IPNetwork.Parse("100.64.0.0/10"),      // CGNAT
        IPNetwork.Parse("127.0.0.0/8"),        // loopback
        IPNetwork.Parse("169.254.0.0/16"),     // link-local, incl. cloud metadata 169.254.169.254
        IPNetwork.Parse("168.63.129.16/32"),   // Azure WireServer (host agent), reachable from every Azure VM
        IPNetwork.Parse("172.16.0.0/12"),      // RFC 1918
        IPNetwork.Parse("192.0.0.0/24"),       // IETF protocol assignments
        IPNetwork.Parse("192.0.2.0/24"),       // TEST-NET-1
        IPNetwork.Parse("192.88.99.0/24"),     // 6to4 relay anycast
        IPNetwork.Parse("192.168.0.0/16"),     // RFC 1918
        IPNetwork.Parse("198.18.0.0/15"),      // benchmarking
        IPNetwork.Parse("198.51.100.0/24"),    // TEST-NET-2
        IPNetwork.Parse("203.0.113.0/24"),     // TEST-NET-3
        IPNetwork.Parse("224.0.0.0/4"),        // multicast
        IPNetwork.Parse("240.0.0.0/4"),        // reserved + broadcast
    ];

    // Everything outside 2000::/3 is already rejected (loopback, ULA, link-local, multicast, NAT64, IPv4-compatible...).
    private static readonly IPNetwork[] DefaultBlockedV6 = [
        IPNetwork.Parse("2001::/23"),          // IETF protocol assignments, incl. Teredo 2001::/32
        IPNetwork.Parse("2001:db8::/32"),      // documentation
        IPNetwork.Parse("2002::/16"),          // 6to4 (embeds arbitrary IPv4)
        IPNetwork.Parse("3fff::/20"),          // documentation (RFC 9637)
    ];

    private readonly IPNetwork[] _blocked;
    private readonly bool _allowLoopback;

    public IpRangeFilter(IEnumerable<string>? extraBlocked = null, bool dangerouslyAllowLoopback = false) {
        var extra = (extraBlocked ?? []).Select(IPNetwork.Parse);
        _blocked = [.. DefaultBlockedV4, .. DefaultBlockedV6, .. extra];
        _allowLoopback = dangerouslyAllowLoopback;
    }

    public bool IsAllowed(IPAddress address) {
        if (address.IsIPv4MappedToIPv6) {
            address = address.MapToIPv4();
        }

        if (_allowLoopback && IPAddress.IsLoopback(address)) {
            return true;
        }

        switch (address.AddressFamily) {
            case AddressFamily.InterNetwork:
                break;
            case AddressFamily.InterNetworkV6:
                if (address.ScopeId != 0 || !GlobalUnicastV6.Contains(address)) {
                    return false;
                }
                break;
            default:
                return false;
        }

        foreach (var network in _blocked) {
            if (network.BaseAddress.AddressFamily == address.AddressFamily && network.Contains(address)) {
                return false;
            }
        }
        return true;
    }
}
