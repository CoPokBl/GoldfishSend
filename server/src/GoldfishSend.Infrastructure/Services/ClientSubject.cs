using System.Net;
using System.Net.Sockets;

namespace GoldfishSend.Infrastructure.Services;

/// <summary>
/// Rate-limiting subjects for a client address. They're only ever stored as daily-keyed HMACs, never as raw addresses.
/// <list type="bullet">
/// <item><see cref="Host"/>: one end user. IPv4 /32, or IPv6 /64 (a typical end-site allocation).</item>
/// <item><see cref="Network"/>: one provider allocation. IPv4 /24, or IPv6 /48. This stops a single /48
/// (65,536 /64s) from multiplying per-host quotas.</item>
/// <item><see cref="Allocation"/>: IPv6 /32 (a typical ISP or hosting allocation), or null for IPv4. Its limits are much
/// looser than the network ones, since one /32 can hold a whole ISP's customers. They only stop one actor that holds
/// thousands of /48s.</item>
/// </list>
/// </summary>
public sealed record ClientSubject(byte[] Host, byte[] Network, byte[]? Allocation = null) {
    public static ClientSubject From(IPAddress? address) {
        if (address is null) {
            return new ClientSubject([0], [0]);
        }
        if (address.IsIPv4MappedToIPv6) {
            address = address.MapToIPv4();
        }
        var bytes = address.GetAddressBytes();
        if (address.AddressFamily == AddressFamily.InterNetworkV6) {
            return new ClientSubject(Prefix(6, bytes, 8), Prefix(7, bytes, 6), Prefix(8, bytes, 4));
        }
        return new ClientSubject(Prefix(4, bytes, 4), Prefix(5, bytes, 3));
    }

    private static byte[] Prefix(byte kind, byte[] address, int length) {
        var result = new byte[length + 1];
        result[0] = kind;
        Array.Copy(address, 0, result, 1, length);
        return result;
    }
}
