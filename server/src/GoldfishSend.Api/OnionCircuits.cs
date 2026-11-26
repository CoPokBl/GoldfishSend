using System.Buffers;
using System.Globalization;
using System.Net;
using System.Text;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Connections.Features;

namespace GoldfishSend.Api;

/// <summary>
/// The optional onion listener with Tor circuit ids (<see cref="Core.Options.NetworkOptions.OnionCircuitEndpoint"/>).
/// Every onion client reaches the api from the Tor container's address, so the gateway flood guard can't tell them apart,
/// and one of them could use up the bucket they all share. With <c>HiddenServiceExportCircuitID haproxy</c>, Tor starts
/// each connection with a PROXY protocol v1 line whose source address carries the id of the circuit it arrived on. The
/// flood guard then gives each circuit its own bucket inside one shared onion bucket. A client can't choose the id (Tor
/// writes the line, not the client) and opening circuits to an onion service is slow, so one client can no longer stall
/// the others.
/// <para>
/// Only the flood guard uses the circuit. Everything else still sees one onion address, so rate limits stay shared and
/// a client can't gain budget by opening circuits.
/// </para>
/// </summary>
public static class OnionCircuits {
    private const string ItemKey = "goldfish.onion-circuit";
    /// <summary>The longest v1 header the protocol allows, CRLF included.</summary>
    private const int MaxHeader = 107;
    private static readonly TimeSpan HeaderTimeout = TimeSpan.FromSeconds(10);
    /// <summary>Tor's source addresses are <c>fc00:dead:beef:4dad::/96</c> plus the 32-bit global circuit id.</summary>
    private static readonly byte[] TorPrefix = [0xfc, 0x00, 0xde, 0xad, 0xbe, 0xef, 0x4d, 0xad, 0, 0, 0, 0];

    /// <summary>The circuit of this request's connection, or null when it didn't come in on the onion listener.</summary>
    public static ulong? From(HttpContext context) {
        return context.Features.Get<IConnectionItemsFeature>()?.Items.TryGetValue(ItemKey, out var value) == true
            ? value as ulong?
            : null;
    }

    /// <summary>Connection middleware for the onion listener: reads Tor's PROXY line, or drops the connection.</summary>
    public static Func<ConnectionDelegate, ConnectionDelegate> Middleware(ILogger log) => next => async connection => {
        ulong? circuit;
        using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(connection.ConnectionClosed)) {
            timeout.CancelAfter(HeaderTimeout);
            try {
                circuit = await ReadHeaderAsync(connection, timeout.Token);
            } catch (OperationCanceledException) {
                circuit = null;
            }
        }
        if (circuit is null) {
            log.LogWarning("Dropped an onion-listener connection without a valid Tor PROXY header.");
            connection.Abort();
            return;
        }
        connection.Items[ItemKey] = circuit;
        await next(connection);
    };

    private static async Task<ulong?> ReadHeaderAsync(ConnectionContext connection, CancellationToken ct) {
        var input = connection.Transport.Input;
        while (true) {
            var read = await input.ReadAsync(ct);
            var buffer = read.Buffer;
            var end = buffer.PositionOf((byte)'\n');
            if (end is { } newline) {
                var line = buffer.Slice(0, newline);
                var consumed = buffer.GetPosition(1, newline);
                if (line.Length + 1 > MaxHeader) {
                    input.AdvanceTo(buffer.Start, buffer.End);
                    return null;
                }
                var circuit = Parse(Encoding.ASCII.GetString(line.ToArray()));
                input.AdvanceTo(consumed);
                return circuit;
            }
            if (buffer.Length >= MaxHeader || read.IsCompleted) {
                input.AdvanceTo(buffer.Start, buffer.End);
                return null;
            }
            input.AdvanceTo(buffer.Start, buffer.End);
        }
    }

    /// <summary>
    /// <c>PROXY TCP6 fc00:dead:beef:4dad::&lt;id&gt; &lt;dst&gt; &lt;sport&gt; &lt;dport&gt;\r</c> (the line, without its
    /// final LF) to the circuit id. Anything else, including a source outside Tor's range, is null.
    /// </summary>
    public static ulong? Parse(string line) {
        var parts = line.TrimEnd('\r').Split(' ');
        if (parts.Length != 6 || parts[0] != "PROXY" || parts[1] != "TCP6"
            || !IPAddress.TryParse(parts[2], out var source) || source.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6
            || !ushort.TryParse(parts[4], NumberStyles.None, CultureInfo.InvariantCulture, out _)) {
            return null;
        }
        var bytes = source.GetAddressBytes();
        if (!bytes.AsSpan(0, TorPrefix.Length).SequenceEqual(TorPrefix)) {
            return null;
        }
        return System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(12));
    }
}
