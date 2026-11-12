using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;

namespace GoldfishSend.Core.Crypto;

/// <summary>Hashcash-style PoW: <c>SHA256("gf/pow/v1" ‖ challenge ‖ nonce)</c> needs <c>difficulty</c> leading zero bits.</summary>
public static class ProofOfWork {
    public const int ChallengeSize = 32;
    public const int NonceSize = 8;
    public const int MaxDifficulty = 40;

    private static readonly byte[] Label = "gf/pow/v1"u8.ToArray();

    public static bool Verify(ReadOnlySpan<byte> challenge, ReadOnlySpan<byte> nonce, int difficulty) {
        if (challenge.Length != ChallengeSize || nonce.Length != NonceSize || difficulty < 0 || difficulty > MaxDifficulty) {
            return false;
        }
        Span<byte> input = stackalloc byte[Label.Length + ChallengeSize + NonceSize];
        Label.CopyTo(input);
        challenge.CopyTo(input[Label.Length..]);
        nonce.CopyTo(input[(Label.Length + ChallengeSize)..]);
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(input, hash);
        return LeadingZeroBits(hash) >= difficulty;
    }

    public static int LeadingZeroBits(ReadOnlySpan<byte> hash) {
        var bits = 0;
        foreach (var b in hash) {
            if (b == 0) {
                bits += 8;
                continue;
            }
            return bits + BitOperations.LeadingZeroCount((uint)b) - 24;
        }
        return bits;
    }

    /// <summary>Reference solver. Clients have their own. This one exists for tests and tooling.</summary>
    public static byte[] Solve(ReadOnlySpan<byte> challenge, int difficulty) {
        var nonce = new byte[NonceSize];
        for (ulong n = 0; ; n++) {
            BinaryPrimitives.WriteUInt64BigEndian(nonce, n);
            if (Verify(challenge, nonce, difficulty)) {
                return nonce;
            }
        }
    }
}
