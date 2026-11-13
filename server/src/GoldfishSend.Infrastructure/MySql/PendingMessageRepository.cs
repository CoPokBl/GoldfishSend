using Dapper;
using MySqlConnector;

namespace GoldfishSend.Infrastructure.MySql;

public sealed class PendingMessageRow {
    public byte[] Id { get; init; } = [];
    public byte[] MailboxId { get; init; } = [];
    public int KeyEpoch { get; init; }
    public byte[] Payload { get; init; } = [];
    public int Attempts { get; init; }
    public DateTime ExpiresAt { get; init; }
}

public sealed class PendingMessageRepository {
    private readonly Db _db;

    public PendingMessageRepository(Db db) {
        _db = db;
    }

    /// <summary>Idempotent. Re-inserting an id (a redelivered stream entry, for example) updates the schedule.</summary>
    public async Task UpsertAsync(
        byte[] id, byte[] mailboxId, int keyEpoch, byte[] blob, int attempts, DateTime nextAttemptAt, DateTime expiresAt,
        CancellationToken ct = default) {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(new CommandDefinition("""
            INSERT INTO pending_messages (id, mailbox_id, key_epoch, payload, attempts, next_attempt_at, expires_at)
            VALUES (@id, @mailboxId, @keyEpoch, @blob, @attempts, @nextAttemptAt, @expiresAt)
            ON DUPLICATE KEY UPDATE attempts = VALUES(attempts), next_attempt_at = VALUES(next_attempt_at)
            """,
            new { id, mailboxId, keyEpoch, blob, attempts, nextAttemptAt, expiresAt }, cancellationToken: ct));
    }

    /// <summary>
    /// Claims up to <paramref name="limit"/> due messages by pushing their <c>next_attempt_at</c> forward by a lease.
    /// <c>SKIP LOCKED</c> lets several workers claim disjoint sets at the same time. If a worker crashes,
    /// its claimed rows simply come due again once the lease runs out.
    /// </summary>
    public async Task<IReadOnlyList<PendingMessageRow>> ClaimDueAsync(int limit, TimeSpan lease, CancellationToken ct = default) {
        await using var conn = await _db.OpenAsync(ct);
        await using var tx = await conn.BeginTransactionAsync(ct);
        var rows = (await conn.QueryAsync<PendingMessageRow>(new CommandDefinition("""
            SELECT id AS Id, mailbox_id AS MailboxId, key_epoch AS KeyEpoch, payload AS Payload, attempts AS Attempts, expires_at AS ExpiresAt
            FROM pending_messages
            WHERE next_attempt_at <= UTC_TIMESTAMP()
            ORDER BY next_attempt_at
            LIMIT @limit
            FOR UPDATE SKIP LOCKED
            """, new { limit }, tx, cancellationToken: ct))).AsList();

        if (rows.Count > 0) {
            await conn.ExecuteAsync(new CommandDefinition(
                "UPDATE pending_messages SET next_attempt_at = DATE_ADD(UTC_TIMESTAMP(), INTERVAL @secs SECOND) WHERE id IN @ids",
                new { secs = (int)lease.TotalSeconds, ids = rows.Select(r => r.Id).ToArray() }, tx, cancellationToken: ct));
        }
        await tx.CommitAsync(ct);
        return rows;
    }

    public async Task DeleteAsync(byte[] id, CancellationToken ct = default) {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(new CommandDefinition("DELETE FROM pending_messages WHERE id = @id", new { id }, cancellationToken: ct));
    }

    public async Task RescheduleAsync(byte[] id, int attempts, DateTime nextAttemptAt, CancellationToken ct = default) {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(new CommandDefinition(
            "UPDATE pending_messages SET attempts = @attempts, next_attempt_at = @nextAttemptAt WHERE id = @id",
            new { id, attempts, nextAttemptAt }, cancellationToken: ct));
    }

    /// <summary>Makes every held message of a mailbox due now (after its endpoint recovered).</summary>
    public async Task WakeMailboxAsync(byte[] mailboxId, CancellationToken ct = default) {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(new CommandDefinition(
            "UPDATE pending_messages SET next_attempt_at = UTC_TIMESTAMP() WHERE mailbox_id = @mailboxId",
            new { mailboxId }, cancellationToken: ct));
    }

    /// <summary>Makes the oldest held message of each mailbox due now: one probe of its endpoint, not a burst.</summary>
    public async Task PokeOldestAsync(IReadOnlyList<byte[]> mailboxIds, CancellationToken ct = default) {
        if (mailboxIds.Count == 0) {
            return;
        }
        await using var conn = await _db.OpenAsync(ct);
        foreach (var mailboxId in mailboxIds) {
            await conn.ExecuteAsync(new CommandDefinition("""
                UPDATE pending_messages SET next_attempt_at = UTC_TIMESTAMP()
                WHERE mailbox_id = @mailboxId AND expires_at > UTC_TIMESTAMP()
                ORDER BY expires_at LIMIT 1
                """, new { mailboxId }, cancellationToken: ct));
        }
    }

    public async Task<int> DeleteExpiredAsync(CancellationToken ct = default) {
        await using var conn = await _db.OpenAsync(ct);
        var total = 0;
        int removed;
        do {
            removed = await conn.ExecuteAsync(new CommandDefinition(
                "DELETE FROM pending_messages WHERE expires_at < UTC_TIMESTAMP() LIMIT 1000", cancellationToken: ct));
            total += removed;
        } while (removed == 1000);
        return total;
    }

    public async Task<long> CountAsync(CancellationToken ct = default) {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.ExecuteScalarAsync<long>(new CommandDefinition("SELECT COUNT(*) FROM pending_messages", cancellationToken: ct));
    }
}
