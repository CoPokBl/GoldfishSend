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
    /// Claims up to <paramref name="limit"/> due messages by pushing their <c>next_attempt_at</c> forward by a lease, and
    /// recording the lease in <c>claimed_until</c> so wake-ups leave them alone (<see cref="Unclaimed"/>).
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
                """
                UPDATE pending_messages
                SET next_attempt_at = DATE_ADD(UTC_TIMESTAMP(), INTERVAL @secs SECOND), claimed_until = DATE_ADD(UTC_TIMESTAMP(), INTERVAL @secs SECOND)
                WHERE id IN @ids
                """,
                new { secs = (int)lease.TotalSeconds, ids = rows.Select(r => r.Id).ToArray() }, tx, cancellationToken: ct));
        }
        await tx.CommitAsync(ct);
        return rows;
    }

    public async Task DeleteAsync(byte[] id, CancellationToken ct = default) {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(new CommandDefinition("DELETE FROM pending_messages WHERE id = @id", new { id }, cancellationToken: ct));
    }

    /// <summary>Ends the claim: the attempt is over and the row waits for <paramref name="nextAttemptAt"/>.</summary>
    public async Task RescheduleAsync(byte[] id, int attempts, DateTime nextAttemptAt, CancellationToken ct = default) {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(new CommandDefinition(
            "UPDATE pending_messages SET attempts = @attempts, next_attempt_at = @nextAttemptAt, claimed_until = NULL WHERE id = @id",
            new { id, attempts, nextAttemptAt }, cancellationToken: ct));
    }

    /// <summary>
    /// The condition every wake-up adds: a row a retry worker is attempting right now is left alone. Making it due would
    /// let another worker push it at the same time; if this attempt fails, <see cref="RecheckHeldAsync"/> or the retry
    /// schedule takes over.
    /// </summary>
    public const string Unclaimed = "(claimed_until IS NULL OR claimed_until < UTC_TIMESTAMP())";

    /// <summary>Makes every held message of a mailbox due now (after its endpoint recovered).</summary>
    public async Task WakeMailboxAsync(byte[] mailboxId, CancellationToken ct = default) {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(new CommandDefinition(
            $"UPDATE pending_messages SET next_attempt_at = UTC_TIMESTAMP() WHERE mailbox_id = @mailboxId AND {Unclaimed}",
            new { mailboxId }, cancellationToken: ct));
    }

    /// <summary>Makes the oldest held message of each mailbox due now: one probe of its endpoint, not a burst.</summary>
    public async Task PokeOldestAsync(IReadOnlyList<byte[]> mailboxIds, CancellationToken ct = default) {
        if (mailboxIds.Count == 0) {
            return;
        }
        await using var conn = await _db.OpenAsync(ct);
        foreach (var mailboxId in mailboxIds) {
            await conn.ExecuteAsync(new CommandDefinition($"""
                UPDATE pending_messages SET next_attempt_at = UTC_TIMESTAMP()
                WHERE mailbox_id = @mailboxId AND expires_at > UTC_TIMESTAMP() AND {Unclaimed}
                ORDER BY expires_at LIMIT 1
                """, new { mailboxId }, cancellationToken: ct));
        }
    }

    /// <summary>
    /// Run straight after parking a message until its expiry. Verification, rotation and recovery wake the mailbox's
    /// held messages, but only the rows there when they commit, so a park racing one of them would sleep until the
    /// message expires. This looks at the mailbox again, with a locking read that waits for such a change to commit,
    /// and makes the message due now unless the mailbox still can't receive at the endpoint the attempt used. A mailbox
    /// deleted meanwhile also counts: the next attempt then drops the message instead of keeping it until expiry.
    /// </summary>
    /// <returns><c>true</c> if the message was made due again.</returns>
    public async Task<bool> RecheckHeldAsync(byte[] id, byte[] mailboxId, byte[] heldEndpoint, CancellationToken ct = default) {
        await using var conn = await _db.OpenAsync(ct);
        // Its own statement, holding no other lock afterwards, so it can't deadlock with a transaction that takes the
        // mailbox and its messages in the other order (deletion does).
        var mailbox = await conn.QuerySingleOrDefaultAsync<MailboxRow>(new CommandDefinition(
            "SELECT id AS Id, state AS State, sealed_endpoint AS SealedEndpoint FROM mailboxes WHERE id = @mailboxId FOR SHARE",
            new { mailboxId }, cancellationToken: ct));
        if (mailbox is not null && mailbox.State != MailboxState.Active && mailbox.SealedEndpoint.AsSpan().SequenceEqual(heldEndpoint)) {
            return false;
        }
        await conn.ExecuteAsync(new CommandDefinition(
            "UPDATE pending_messages SET next_attempt_at = UTC_TIMESTAMP() WHERE id = @id", new { id }, cancellationToken: ct));
        return true;
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
