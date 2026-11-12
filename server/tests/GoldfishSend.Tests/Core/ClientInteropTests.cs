using GoldfishSend.Core.Crypto;

namespace GoldfishSend.Tests.Core;

/// <summary>
/// The same vectors appear in android/app/src/test/.../ProtocolTest.kt. If either implementation drifts from
/// docs/protocol.md, one side fails.
/// </summary>
public sealed class ClientInteropTests {
    private static readonly byte[] Secret = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();

    [Fact]
    public void MailboxTag_MatchesAndroidVector() {
        Assert.Equal("3bfa8321742bc8e8", Convert.ToHexStringLower(MailboxCrypto.Tag(Secret)));
    }

    [Fact]
    public void OwnerHash_MatchesAndroidVector() {
        Assert.Equal("630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd",
            Convert.ToHexStringLower(MailboxCrypto.OwnerHash(Secret)));
    }

    [Fact]
    public void Pow_FirstSolutionMatchesAndroidVector() {
        var challenge = Enumerable.Repeat((byte)7, 32).ToArray();
        var nonce = ProofOfWork.Solve(challenge, 12);
        Assert.Equal("000000000000079d", Convert.ToHexStringLower(nonce)); // 1949, big-endian
    }
}
