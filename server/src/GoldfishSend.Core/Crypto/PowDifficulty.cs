using GoldfishSend.Core.Options;

namespace GoldfishSend.Core.Crypto;

/// <summary>
/// Adaptive difficulty. Most of the rise goes to the network causing the load, so a flood mainly slows the flooder. A
/// small, capped server-wide part covers floods spread over many networks.
/// </summary>
public static class PowDifficulty {
    /// <param name="networkCreations">Creations from the requester's network in the load window.</param>
    /// <param name="globalVerified">Verified creations server-wide in the load window.</param>
    public static int For(PowOptions options, long networkCreations, long globalVerified) {
        var window = Math.Max(1, options.LoadWindowMinutes);
        var network = ExtraBits(networkCreations, options.NetworkLoadThreshold, options.MaxNetworkExtraDifficulty);
        var global = ExtraBits((double)globalVerified / window, options.GlobalLoadThresholdPerMinute, options.MaxGlobalExtraDifficulty);
        return Math.Min(ProofOfWork.MaxDifficulty, options.BaseDifficulty + network + global);
    }

    /// <summary>One bit once <paramref name="load"/> passes the threshold, and one more each time it doubles, up to <paramref name="max"/>.</summary>
    public static int ExtraBits(double load, double threshold, int max) {
        if (threshold <= 0 || load <= threshold || max <= 0) {
            return 0;
        }
        return Math.Min(max, (int)Math.Floor(Math.Log2(load / threshold)) + 1);
    }
}
