using System.Buffers.Binary;
using System.Security.Cryptography;
using GoldfishSend.Core.Crypto;
using GoldfishSend.Core.Options;

namespace GoldfishSend.Tests.Core;

public sealed class ProofOfWorkTests {
    /// <summary>Small Argon2 parameters, so solving takes milliseconds.</summary>
    private static PowParameters Small(int difficulty) => new(difficulty, 64, 1);

    private static int ReferenceLeadingZeroBits(byte[] hash) {
        var bits = 0;
        foreach (var b in hash) {
            for (var i = 7; i >= 0; i--) {
                if ((b >> i & 1) != 0) {
                    return bits;
                }
                bits++;
            }
        }
        return bits;
    }

    private static byte[] Nonce(ulong n) {
        var nonce = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(nonce, n);
        return nonce;
    }

    [Theory]
    [InlineData("00", 8)]
    [InlineData("80", 0)]
    [InlineData("FF", 0)]
    [InlineData("40", 1)]
    [InlineData("01", 7)]
    [InlineData("0F", 4)]
    [InlineData("10", 3)]
    [InlineData("0080", 8)]
    [InlineData("0001", 15)]
    [InlineData("000000FF", 24)]
    [InlineData("00000001", 31)]
    [InlineData("0000000000", 40)]
    [InlineData("", 0)]
    public void LeadingZeroBits_Table(string hex, int expected) {
        Assert.Equal(expected, ProofOfWork.LeadingZeroBits(Convert.FromHexString(hex)));
    }

    [Fact]
    public void LeadingZeroBits_MatchesReferenceOnRandomInputs() {
        var rng = new Random(1234);
        for (var i = 0; i < 500; i++) {
            var hash = new byte[32];
            rng.NextBytes(hash);
            Array.Clear(hash, 0, rng.Next(0, 6));
            Assert.Equal(ReferenceLeadingZeroBits(hash), ProofOfWork.LeadingZeroBits(hash));
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(4)]
    [InlineData(7)]
    public void SolveThenVerify(int difficulty) {
        var challenge = RandomNumberGenerator.GetBytes(32);
        var nonce = ProofOfWork.Solve(challenge, Small(difficulty));
        Assert.Equal(8, nonce.Length);
        Assert.True(ProofOfWork.Verify(challenge, nonce, Small(difficulty)));
        Assert.True(ReferenceLeadingZeroBits(ProofOfWork.Hash(challenge, nonce, 64, 1)) >= difficulty);
    }

    [Fact]
    public void Solve_ReturnsTheFirstBigEndianCounterThatWorks() {
        var challenge = RandomNumberGenerator.GetBytes(32);
        Assert.Equal(new byte[8], ProofOfWork.Solve(challenge, Small(0)));
        var nonce = ProofOfWork.Solve(challenge, Small(5));
        var n = BinaryPrimitives.ReadUInt64BigEndian(nonce);
        for (ulong i = 0; i < n; i++) {
            Assert.False(ProofOfWork.Verify(challenge, Nonce(i), Small(5)));
        }
    }

    [Fact]
    public void Verify_AgreesWithTheHashForManyNonces() {
        var challenge = RandomNumberGenerator.GetBytes(32);
        for (ulong n = 0; n < 200; n++) {
            var zeros = ReferenceLeadingZeroBits(ProofOfWork.Hash(challenge, Nonce(n), 64, 1));
            Assert.True(ProofOfWork.Verify(challenge, Nonce(n), Small(Math.Min(zeros, ProofOfWork.MaxDifficulty))));
            if (zeros < ProofOfWork.MaxDifficulty) {
                Assert.False(ProofOfWork.Verify(challenge, Nonce(n), Small(zeros + 1)));
            }
        }
    }

    [Fact]
    public void Hash_DependsOnEveryInput() {
        var challenge = RandomNumberGenerator.GetBytes(32);
        var other = challenge.ToArray();
        other[31] ^= 1;
        var reference = ProofOfWork.Hash(challenge, Nonce(1), 64, 1);
        Assert.NotEqual(reference, ProofOfWork.Hash(other, Nonce(1), 64, 1));
        Assert.NotEqual(reference, ProofOfWork.Hash(challenge, Nonce(2), 64, 1));
        Assert.NotEqual(reference, ProofOfWork.Hash(challenge, Nonce(1), 72, 1));
        Assert.NotEqual(reference, ProofOfWork.Hash(challenge, Nonce(1), 64, 2));
        Assert.Equal(reference, ProofOfWork.Hash(challenge, Nonce(1), 64, 1));
    }

    [Theory]
    [InlineData(31, 8)]
    [InlineData(33, 8)]
    [InlineData(0, 8)]
    [InlineData(32, 7)]
    [InlineData(32, 9)]
    [InlineData(32, 0)]
    public void Verify_RejectsWrongLengths(int challengeLength, int nonceLength) {
        // Difficulty 0 would accept any well-formed input, so only lengths can cause rejection.
        Assert.False(ProofOfWork.Verify(new byte[challengeLength], new byte[nonceLength], Small(0)));
    }

    [Theory]
    [InlineData(-1, 64, 1)]
    [InlineData(25, 64, 1)]
    [InlineData(18, 16 * 1024, 1)]
    [InlineData(16, 64 * 1024, 1)]
    [InlineData(int.MaxValue, 64, 1)]
    [InlineData(0, 7, 1)]
    [InlineData(0, 64 * 1024 + 1, 1)]
    [InlineData(0, int.MaxValue, 1)]
    [InlineData(0, 64, 0)]
    [InlineData(0, 64, 5)]
    public void Verify_RejectsParametersOutsideWhatClientsAccept(int difficulty, int memoryKiB, int iterations) {
        var parameters = new PowParameters(difficulty, memoryKiB, iterations);
        Assert.False(parameters.IsValid);
        Assert.False(ProofOfWork.Verify(new byte[32], new byte[8], parameters));
    }

    [Fact]
    public void ProductionDefaults_AreValid_EvenAtFullLoad() {
        var options = new PowOptions();
        Assert.True(new PowParameters(
            options.BaseDifficulty + options.MaxNetworkExtraDifficulty + options.MaxGlobalExtraDifficulty,
            options.MemoryKiB, options.Iterations).IsValid);
        Assert.Equal((8, 16 * 1024, 1), (options.BaseDifficulty, options.MemoryKiB, options.Iterations));
        Assert.True(new PowParameters(options.SendDifficulty, options.MemoryKiB, options.Iterations).IsValidForSend);
        Assert.False(new PowParameters(12, options.MemoryKiB, options.Iterations).IsValidForSend);
        Assert.True(new PowParameters(16, options.MemoryKiB, options.Iterations).IsValid);
    }
}
