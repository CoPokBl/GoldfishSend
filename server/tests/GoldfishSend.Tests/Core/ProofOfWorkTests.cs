using System.Security.Cryptography;
using System.Text;
using GoldfishSend.Core.Crypto;

namespace GoldfishSend.Tests.Core;

public sealed class ProofOfWorkTests {
    private static byte[] Hash(byte[] challenge, byte[] nonce) {
        return SHA256.HashData(Encoding.UTF8.GetBytes("gf/pow/v1").Concat(challenge).Concat(nonce).ToArray());
    }

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
    public void LeadingZeroBits_All32ZeroBytes_Is256() {
        Assert.Equal(256, ProofOfWork.LeadingZeroBits(new byte[32]));
    }

    [Fact]
    public void LeadingZeroBits_OnlyLastBitSet_Is255() {
        var hash = new byte[32];
        hash[31] = 0x01;
        Assert.Equal(255, ProofOfWork.LeadingZeroBits(hash));
    }

    [Fact]
    public void LeadingZeroBits_MatchesReferenceOnRandomInputs() {
        var rng = new Random(1234);
        for (var i = 0; i < 500; i++) {
            var hash = new byte[32];
            rng.NextBytes(hash);
            var zeros = rng.Next(0, 6);
            Array.Clear(hash, 0, zeros);
            Assert.Equal(ReferenceLeadingZeroBits(hash), ProofOfWork.LeadingZeroBits(hash));
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(8)]
    [InlineData(10)]
    [InlineData(12)]
    [InlineData(14)]
    [InlineData(16)]
    public void SolveThenVerify(int difficulty) {
        var challenge = RandomNumberGenerator.GetBytes(32);
        var nonce = ProofOfWork.Solve(challenge, difficulty);
        Assert.Equal(8, nonce.Length);
        Assert.True(ProofOfWork.Verify(challenge, nonce, difficulty));
        // Independent check of the spec formula.
        Assert.True(ReferenceLeadingZeroBits(Hash(challenge, nonce)) >= difficulty);
    }

    [Fact]
    public void Solve_NonceIsBigEndianCounter() {
        var challenge = RandomNumberGenerator.GetBytes(32);
        // Difficulty 0: the very first candidate (0) is accepted.
        Assert.Equal(new byte[8], ProofOfWork.Solve(challenge, 0));
    }

    [Fact]
    public void Verify_AgreesWithReferenceForManyNonces() {
        var challenge = RandomNumberGenerator.GetBytes(32);
        for (ulong n = 0; n < 2000; n++) {
            var nonce = BitConverter.GetBytes(n);
            var zeros = ReferenceLeadingZeroBits(Hash(challenge, nonce));
            Assert.True(ProofOfWork.Verify(challenge, nonce, Math.Min(zeros, ProofOfWork.MaxDifficulty)));
            if (zeros < ProofOfWork.MaxDifficulty) {
                Assert.False(ProofOfWork.Verify(challenge, nonce, zeros + 1));
            }
        }
    }

    [Fact]
    public void Verify_RejectsWrongNonce() {
        var challenge = RandomNumberGenerator.GetBytes(32);
        const int difficulty = 12;
        // Find a nonce that doesn't meet the difficulty, by the reference formula.
        var rng = new Random(42);
        var nonce = new byte[8];
        do {
            rng.NextBytes(nonce);
        } while (ReferenceLeadingZeroBits(Hash(challenge, nonce)) >= difficulty);
        Assert.False(ProofOfWork.Verify(challenge, nonce, difficulty));
    }

    [Fact]
    public void Verify_SolutionIsBoundToChallenge() {
        var challenge = RandomNumberGenerator.GetBytes(32);
        var nonce = ProofOfWork.Solve(challenge, 16);
        var other = challenge.ToArray();
        other[0] ^= 1;
        var stillValid = ReferenceLeadingZeroBits(Hash(other, nonce)) >= 16;
        Assert.Equal(stillValid, ProofOfWork.Verify(other, nonce, 16));
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
        Assert.False(ProofOfWork.Verify(new byte[challengeLength], new byte[nonceLength], 0));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(41)]
    [InlineData(256)]
    [InlineData(int.MinValue)]
    [InlineData(int.MaxValue)]
    public void Verify_RejectsOutOfRangeDifficulty(int difficulty) {
        Assert.False(ProofOfWork.Verify(new byte[32], new byte[8], difficulty));
    }

    [Fact]
    public void Verify_DifficultyZeroAcceptsAnything_AndMaxIsInRange() {
        var challenge = RandomNumberGenerator.GetBytes(32);
        Assert.True(ProofOfWork.Verify(challenge, RandomNumberGenerator.GetBytes(8), 0));
        Assert.Equal(40, ProofOfWork.MaxDifficulty);
    }
}
