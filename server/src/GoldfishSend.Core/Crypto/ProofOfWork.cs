using System.Buffers.Binary;
using System.Numerics;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace GoldfishSend.Core.Crypto;

/// <summary>The parameters of one challenge. They travel with it, so the server can tune them and clients can check them.</summary>
public readonly record struct PowParameters(int Difficulty, int MemoryKiB, int Iterations) {
    /// <summary>Within the bounds clients accept (see <see cref="ProofOfWork"/>).</summary>
    public bool IsValid => Difficulty is >= 0 and <= ProofOfWork.MaxDifficulty
        && MemoryKiB is >= ProofOfWork.MinMemoryKiB and <= ProofOfWork.MaxMemoryKiB
        && Iterations is >= 1 and <= ProofOfWork.MaxIterations
        && ExpectedWorkKiB <= ProofOfWork.MaxWorkKiB;

    /// <summary>KiB of Argon2 memory a solver fills on average: <c>2^difficulty × m × t</c>.</summary>
    public long ExpectedWorkKiB => Difficulty is >= 0 and < 62 ? (1L << Difficulty) * MemoryKiB * Iterations : long.MaxValue;
}

/// <summary>
/// Memory-hard proof of work (<c>gf/pow/v2</c>): find a nonce such that
/// <c>Argon2id(password = "gf/pow/v2" ‖ challenge ‖ nonce, salt = challenge, m, t, p = 1, 32 bytes)</c> has at least
/// <c>difficulty</c> leading zero bits. Solving takes about <c>2^difficulty</c> Argon2 calls; verifying takes one.
/// </summary>
public static class ProofOfWork {
    public const string Scheme = "gf/pow/v2";
    public const int ChallengeSize = 32;
    public const int NonceSize = 8;
    public const int HashSize = 32;

    // The app refuses challenges outside these bounds (Pow.kt), so the server must never issue one.
    public const int MaxDifficulty = 20;
    public const int MinMemoryKiB = 8;
    public const int MaxMemoryKiB = 64 * 1024;
    public const int MaxIterations = 4;
    /// <summary>The default parameters at their worst (6 + 6 + 2 bits at 16 MiB, t = 1).</summary>
    public const long MaxWorkKiB = (1L << 14) * 16 * 1024;

    private static readonly byte[] Label = "gf/pow/v2"u8.ToArray();

    /// <summary>The Argon2id output for this nonce. Costs one full Argon2 call: <c>m</c> KiB of memory and the CPU to fill it <c>t</c> times.</summary>
    public static byte[] Hash(ReadOnlySpan<byte> challenge, ReadOnlySpan<byte> nonce, int memoryKiB, int iterations) {
        if (challenge.Length != ChallengeSize || nonce.Length != NonceSize) {
            throw new ArgumentException("bad challenge or nonce size");
        }
        var generator = new Argon2BytesGenerator();
        generator.Init(Parameters(challenge, memoryKiB, iterations));
        var output = new byte[HashSize];
        generator.GenerateBytes(Password(challenge, nonce), output);
        return output;
    }

    public static bool Verify(ReadOnlySpan<byte> challenge, ReadOnlySpan<byte> nonce, PowParameters parameters) {
        if (challenge.Length != ChallengeSize || nonce.Length != NonceSize || !parameters.IsValid) {
            return false;
        }
        return LeadingZeroBits(Hash(challenge, nonce, parameters.MemoryKiB, parameters.Iterations)) >= parameters.Difficulty;
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

    /// <summary>
    /// Reference solver: nonces 0, 1, 2, ... (big-endian) on one thread, reusing one Argon2 instance. Clients have their
    /// own; this one is for tests and tooling.
    /// </summary>
    public static byte[] Solve(ReadOnlySpan<byte> challenge, PowParameters parameters, CancellationToken ct = default) {
        if (challenge.Length != ChallengeSize || !parameters.IsValid) {
            throw new ArgumentException("bad challenge or parameters");
        }
        var generator = new Argon2BytesGenerator();
        generator.Init(Parameters(challenge, parameters.MemoryKiB, parameters.Iterations));
        var nonce = new byte[NonceSize];
        var password = Password(challenge, nonce);
        var output = new byte[HashSize];
        for (ulong n = 0; ; n++) {
            ct.ThrowIfCancellationRequested();
            BinaryPrimitives.WriteUInt64BigEndian(password.AsSpan(Label.Length + ChallengeSize), n);
            generator.GenerateBytes(password, output);
            if (LeadingZeroBits(output) >= parameters.Difficulty) {
                BinaryPrimitives.WriteUInt64BigEndian(nonce, n);
                return nonce;
            }
        }
    }

    private static Argon2Parameters Parameters(ReadOnlySpan<byte> challenge, int memoryKiB, int iterations) {
        return new Argon2Parameters.Builder(Argon2Parameters.Argon2id)
            .WithVersion(Argon2Parameters.Version13)
            .WithMemoryAsKB(memoryKiB)
            .WithIterations(iterations)
            .WithParallelism(1)
            .WithSalt(challenge.ToArray())
            .Build();
    }

    private static byte[] Password(ReadOnlySpan<byte> challenge, ReadOnlySpan<byte> nonce) {
        var password = new byte[Label.Length + ChallengeSize + NonceSize];
        Label.CopyTo(password, 0);
        challenge.CopyTo(password.AsSpan(Label.Length));
        nonce.CopyTo(password.AsSpan(Label.Length + ChallengeSize));
        return password;
    }
}
