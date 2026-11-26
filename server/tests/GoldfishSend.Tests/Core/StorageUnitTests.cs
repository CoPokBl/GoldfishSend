using GoldfishSend.Core.Options;
using GoldfishSend.Infrastructure.MySql;
using GoldfishSend.Infrastructure.Redis;
using Microsoft.Extensions.Logging.Abstractions;
using MySqlConnector;

namespace GoldfishSend.Tests.Core;

public sealed class RedisPersistenceTests {
    private const string Info = "# Persistence\r\nloading:0\r\naof_enabled:1\r\naof_rewrite_in_progress:0\r\naof_rewrites:3\r\n";

    [Theory]
    [InlineData("aof_enabled", "1")]
    [InlineData("aof_rewrites", "3")]
    [InlineData("loading", "0")]
    [InlineData("aof_rewrite", null)]
    [InlineData("enabled", null)]
    [InlineData("missing", null)]
    public void Field_ReadsWholeNamesOnly(string name, string? expected) {
        Assert.Equal(expected, RedisPersistence.Field(Info, name));
    }

    [Fact]
    public void Field_OfNoInfo_IsNull() {
        Assert.Null(RedisPersistence.Field(null, "aof_enabled"));
    }
}

public sealed class EpochKeyStoreCheckTests {
    // Connects only when asked something, and neither test gets that far.
    private static readonly RedisPersistence Unused = new("127.0.0.1:1", null);

    private static EpochKeyring Keyring(EpochKeyStore store, EphemeralRedis redis) {
        // Neither path below touches MySQL, so the data source never connects.
        var db = new Db(new MySqlDataSourceBuilder("Server=127.0.0.1;Port=1").Build());
        return new EpochKeyring(db, redis, new byte[32], new GoldfishOptions { EpochKeyStore = store }, NullLogger<EpochKeyring>.Instance);
    }

    [Fact]
    public async Task Ephemeral_WithoutASeparateRedis_IsAProblem() {
        var problem = await Keyring(EpochKeyStore.Ephemeral, new EphemeralRedis(null!, isSeparate: false)).StoreProblemAsync(Unused);
        Assert.NotNull(problem);
        Assert.Contains("RedisEphemeral", problem);
    }

    [Fact]
    public async Task MySql_NeedsNoEphemeralRedis() {
        Assert.Null(await Keyring(EpochKeyStore.MySql, new EphemeralRedis(null!, isSeparate: false)).StoreProblemAsync(Unused));
    }
}
