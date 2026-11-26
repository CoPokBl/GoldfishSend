using System.Security.Cryptography;
using Dapper;
using GoldfishSend.Core.Crypto;
using GoldfishSend.Core.Options;
using GoldfishSend.Infrastructure.Delivery;
using GoldfishSend.Infrastructure.MySql;
using GoldfishSend.Infrastructure.Redis;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using MySqlConnector;
using StackExchange.Redis;
using static GoldfishSend.Tests.Integration.GoldfishFixture;

namespace GoldfishSend.Tests.Integration;

/// <summary>What the server keeps, for how long, and that held messages aren't stranded.</summary>
[Collection(GoldfishCollection.Name)]
public sealed class StorageTests {
    private readonly GoldfishFixture _f;

    public StorageTests(GoldfishFixture fixture) {
        _f = fixture;
    }

    private T Get<T>() where T : notnull => _f.Services.GetRequiredService<T>();

    [IntegrationFact]
    public async Task LeakedLeases_LapseEvenWhileTheMailboxKeepsBeingTried() {
        var options = Get<GoldfishOptions>();
        var mailboxId = RandomNumberGenerator.GetBytes(32);
        var ttl = TimeSpan.FromMilliseconds(800);

        // Another node takes every slot for this mailbox and dies without releasing them.
        var deadNode = new MailboxLeases(Get<EphemeralRedis>(), Get<ClusterSecret>(), options);
        for (var i = 0; i < options.Push.MaxInFlightPerMailbox; i++) {
            Assert.NotNull(await deadNode.TryAcquireAsync(mailboxId, ttl));
        }

        // Deliveries keep coming back every few hundred milliseconds. Refused attempts mustn't keep the leaks alive.
        var leases = Get<MailboxLeases>();
        var started = DateTime.UtcNow;
        Assert.Null(await leases.TryAcquireAsync(mailboxId, ttl));
        MailboxLeases.Lease? lease = null;
        while (lease is null && DateTime.UtcNow - started < TimeSpan.FromSeconds(5)) {
            await Task.Delay(50);
            lease = await leases.TryAcquireAsync(mailboxId, ttl);
        }
        Assert.NotNull(lease);
        Assert.True(DateTime.UtcNow - started >= ttl - TimeSpan.FromMilliseconds(100));
        await lease.ReleaseAsync();
    }

    [IntegrationFact]
    public async Task ReleasedLeases_FreeTheirSlotsAtOnce() {
        var options = Get<GoldfishOptions>();
        var mailboxId = RandomNumberGenerator.GetBytes(32);
        var leases = Get<MailboxLeases>();
        var held = new List<MailboxLeases.Lease>();
        for (var i = 0; i < options.Push.MaxInFlightPerMailbox; i++) {
            held.Add((await leases.TryAcquireAsync(mailboxId, TimeSpan.FromMinutes(1)))!);
        }
        Assert.Null(await leases.TryAcquireAsync(mailboxId, TimeSpan.FromMinutes(1)));
        await held[0].ReleaseAsync();
        var again = await leases.TryAcquireAsync(mailboxId, TimeSpan.FromMinutes(1));
        Assert.NotNull(again);
        foreach (var lease in held.Skip(1).Append(again)) {
            await lease.ReleaseAsync();
        }
    }

    private async Task<DateTime?> NextAttemptAsync(byte[] id) {
        await using var conn = new MySqlConnection(_f.MySql);
        return await conn.ExecuteScalarAsync<DateTime?>("SELECT next_attempt_at FROM pending_messages WHERE id = @id", new { id });
    }

    /// <summary>Due now, or already attempted and dropped by a retry worker.</summary>
    private static bool DueNowOrGone(DateTime? nextAttempt) => nextAttempt is null || nextAttempt <= DateTime.UtcNow.AddSeconds(5);

    /// <summary>A held row nobody can open: if a retry worker gets to it, it drops it.</summary>
    private async Task<byte[]> ParkAsync(byte[] mailboxId) {
        var id = RandomNumberGenerator.GetBytes(16);
        var expires = DateTime.UtcNow.AddHours(1);
        await Get<PendingMessageRepository>().UpsertAsync(
            id, mailboxId, EpochKeyring.CurrentEpoch, RandomNumberGenerator.GetBytes(64), 0, expires, expires);
        return id;
    }

    [IntegrationFact]
    public async Task Hold_IsWokenWhenTheMailboxMovedOnDuringTheAttempt() {
        var mailbox = await _f.CreateActiveMailboxAsync();
        var mailboxId = Get<MailboxCrypto>().MailboxId(mailbox.SendSecret);
        var repo = Get<MailboxRepository>();
        var pending = Get<PendingMessageRepository>();
        var tried = (await repo.GetAsync(mailboxId))!.SealedEndpoint;

        // The endpoint answered 410 and is still the mailbox's: stay parked.
        await repo.MarkEndpointGoneAsync(mailboxId, tried);
        var stays = await ParkAsync(mailboxId);
        Assert.False(await pending.RecheckHeldAsync(stays, mailboxId, tried));
        Assert.True(await NextAttemptAsync(stays) > DateTime.UtcNow.AddMinutes(30));
        await pending.DeleteAsync(stays);

        // A rotation replaced the endpoint while the old one was being tried (or before the 410 was recorded).
        var rotated = await ParkAsync(mailboxId);
        Assert.True(await pending.RecheckHeldAsync(rotated, mailboxId, RandomNumberGenerator.GetBytes(tried.Length)));
        Assert.True(DueNowOrGone(await NextAttemptAsync(rotated)));

        // The mailbox recovered (verification, or another message got through) after this attempt read it.
        await repo.MarkRecoveredAsync(mailboxId, tried);
        var recovered = await ParkAsync(mailboxId);
        Assert.True(await pending.RecheckHeldAsync(recovered, mailboxId, tried));

        // The mailbox was deleted: due now, so the next attempt drops it instead of keeping it until it expires.
        var orphan = await ParkAsync(RandomNumberGenerator.GetBytes(32));
        Assert.True(await pending.RecheckHeldAsync(orphan, RandomNumberGenerator.GetBytes(32), tried));
    }

    [IntegrationFact]
    public async Task Wakeups_SkipRowsAWorkerIsAttempting() {
        var mailboxId = RandomNumberGenerator.GetBytes(32);
        var pending = Get<PendingMessageRepository>();
        var id = await ParkAsync(mailboxId);
        await using var conn = new MySqlConnection(_f.MySql);
        // As ClaimDueAsync leaves it: due again only when the lease runs out.
        await conn.ExecuteAsync("""
            UPDATE pending_messages SET next_attempt_at = DATE_ADD(UTC_TIMESTAMP(), INTERVAL 10 MINUTE),
                claimed_until = DATE_ADD(UTC_TIMESTAMP(), INTERVAL 10 MINUTE)
            WHERE id = @id
            """, new { id });

        await pending.WakeMailboxAsync(mailboxId);
        await pending.PokeOldestAsync([mailboxId]);
        Assert.True(await NextAttemptAsync(id) > DateTime.UtcNow.AddMinutes(5));

        // Once the attempt is over, the claim is gone and wake-ups work again.
        var parkUntil = DateTime.UtcNow.AddHours(1);
        await pending.RescheduleAsync(id, 1, parkUntil);
        Assert.Null(await conn.ExecuteScalarAsync<DateTime?>("SELECT claimed_until FROM pending_messages WHERE id = @id", new { id }));
        await pending.WakeMailboxAsync(mailboxId);
        Assert.True(DueNowOrGone(await NextAttemptAsync(id)));
        await pending.DeleteAsync(id);
    }

    [IntegrationFact]
    public async Task EphemeralStore_DeletesEpochKeysLeftInMySql() {
        await using var conn = new MySqlConnection(_f.MySql);
        var before = (await conn.QueryAsync<(int Epoch, byte[] WrappedKey)>("SELECT epoch, wrapped_key FROM epoch_keys")).AsList();
        Assert.NotEmpty(before);
        var ephemeral = new EpochKeyring(Get<Db>(), Get<EphemeralRedis>(), RandomNumberGenerator.GetBytes(32),
            new GoldfishOptions { EpochKeyStore = EpochKeyStore.Ephemeral }, NullLogger<EpochKeyring>.Instance);
        try {
            await ephemeral.RotateAsync();
            Assert.Equal(0, await _f.ScalarAsync("SELECT COUNT(*) FROM epoch_keys"));
        } finally {
            // Put the fixture's keys back for the other tests, and drop the ones this keyring made.
            foreach (var (epoch, wrapped) in before) {
                await conn.ExecuteAsync("INSERT IGNORE INTO epoch_keys (epoch, wrapped_key) VALUES (@epoch, @wrapped)", new { epoch, wrapped });
            }
            var db = Get<EphemeralRedis>().Db;
            await db.KeyDeleteAsync([(RedisKey)$"gf:epoch:{EpochKeyring.CurrentEpoch}", (RedisKey)$"gf:epoch:{EpochKeyring.CurrentEpoch + 1}"]);
        }
    }

    [IntegrationFact]
    public async Task EphemeralStore_OnARedisWithAnAof_IsAProblem() {
        var ephemeral = Get<EphemeralRedis>();
        var keyring = new EpochKeyring(Get<Db>(), ephemeral, RandomNumberGenerator.GetBytes(32),
            new GoldfishOptions { EpochKeyStore = EpochKeyStore.Ephemeral }, NullLogger<EpochKeyring>.Instance);
        // The fixture's "ephemeral" Redis is a database of the main one, so this depends on how the test Redis runs.
        var persistence = Get<RedisPersistence>();
        var aof = await persistence.AofEnabledAsync(ephemeral: true);
        Assert.NotNull(aof);
        var problem = await keyring.StoreProblemAsync(persistence);
        Assert.Equal(aof == true, problem is not null);
    }

    [IntegrationFact]
    public async Task Maintenance_CompactsTheAof_OnlyWhenThereIsOne() {
        var redis = Get<IConnectionMultiplexer>();
        var db = redis.GetDatabase();
        var worker = ActivatorUtilities.CreateInstance<MaintenanceWorker>(_f.Services);
        var persistence = Get<RedisPersistence>();
        var aof = await persistence.AofEnabledAsync();
        Assert.NotNull(aof);
        async Task<long> Rewrites() => long.Parse(RedisPersistence.Field(await persistence.InfoAsync(), "aof_rewrites") ?? "0");

        await EventuallyAsync(async () => RedisPersistence.Field(await persistence.InfoAsync(), "aof_rewrite_in_progress") == "0");
        var before = await Rewrites();
        // The fixture's own worker may have compacted moments ago; this test wants a fresh turn.
        await db.KeyDeleteAsync("gf:lock:aof-rewrite");
        await worker.CompactAofAsync();

        if (aof == true) {
            await EventuallyAsync(async () => await Rewrites() > before, because: "the AOF should have been rewritten");
            // At most once per interval across the cluster.
            Assert.True(await db.KeyExistsAsync("gf:lock:aof-rewrite"));
        } else {
            // Without an AOF, BGREWRITEAOF would write the dataset to disk.
            await Task.Delay(500);
            Assert.Equal(before, await Rewrites());
        }
    }
}
