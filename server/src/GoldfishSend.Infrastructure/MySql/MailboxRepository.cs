using Dapper;
using MySqlConnector;

namespace GoldfishSend.Infrastructure.MySql;

public enum MailboxState : byte {
    PendingVerification = 0,
    Active = 1,
    EndpointGone = 2,
}

public sealed class MailboxRow {
    public byte[] Id { get; init; } = [];
    public byte[] OwnerHash { get; init; } = [];
    public byte[] SealedEndpoint { get; init; } = [];
    public byte[]? PendingEndpoint { get; init; }
    public MailboxState State { get; init; }
    public byte[]? VerifyHash { get; init; }
    public int VerifyAttempts { get; init; }
    public DateTime? VerifyExpiresAt { get; init; }
    public DateTime ExpiresAt { get; init; }
}

public sealed class MailboxRepository {
    private const string Columns = """
        id AS Id, owner_hash AS OwnerHash, sealed_endpoint AS SealedEndpoint, pending_endpoint AS PendingEndpoint,
        state AS State, verify_hash AS VerifyHash, verify_attempts AS VerifyAttempts,
        verify_expires_at AS VerifyExpiresAt, expires_at AS ExpiresAt
        """;

    private readonly Db _db;

    public MailboxRepository(Db db) {
        _db = db;
    }

    /// <returns><c>false</c> if a mailbox with this id already exists.</returns>
    public async Task<bool> InsertPendingAsync(
        byte[] id, byte[] ownerHash, byte[] sealedEndpoint, byte[] verifyHash, DateTime verifyExpiresAt, DateOnly expiresAt,
        CancellationToken ct = default) {
        await using var conn = await _db.OpenAsync(ct);
        try {
            await conn.ExecuteAsync(new CommandDefinition("""
                INSERT INTO mailboxes (id, owner_hash, sealed_endpoint, state, verify_hash, verify_attempts, verify_expires_at, expires_at)
                VALUES (@id, @ownerHash, @sealedEndpoint, @state, @verifyHash, 0, @verifyExpiresAt, @expiresAt)
                """,
                new {
                    id,
                    ownerHash,
                    sealedEndpoint,
                    state = (byte)MailboxState.PendingVerification,
                    verifyHash,
                    verifyExpiresAt,
                    expiresAt = expiresAt.ToDateTime(TimeOnly.MinValue),
                },
                cancellationToken: ct));
            return true;
        } catch (MySqlException ex) when (Db.IsDuplicateKey(ex)) {
            return false;
        }
    }

    public async Task<MailboxRow?> GetAsync(byte[] id, CancellationToken ct = default) {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.QuerySingleOrDefaultAsync<MailboxRow>(new CommandDefinition(
            $"SELECT {Columns} FROM mailboxes WHERE id = @id", new { id }, cancellationToken: ct));
    }

    public async Task DeleteAsync(byte[] id, CancellationToken ct = default) {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(new CommandDefinition("DELETE FROM mailboxes WHERE id = @id", new { id }, cancellationToken: ct));
    }

    /// <summary>Deletes the mailbox and every message held for it.</summary>
    public async Task DeleteWithMessagesAsync(byte[] id, CancellationToken ct = default) {
        await using var conn = await _db.OpenAsync(ct);
        await using var tx = await conn.BeginTransactionAsync(ct);
        await conn.ExecuteAsync(new CommandDefinition("DELETE FROM pending_messages WHERE mailbox_id = @id", new { id }, tx, cancellationToken: ct));
        await conn.ExecuteAsync(new CommandDefinition("DELETE FROM mailboxes WHERE id = @id", new { id }, tx, cancellationToken: ct));
        await tx.CommitAsync(ct);
    }

    /// <summary>Stages a new endpoint for verification. Only active or endpoint-gone mailboxes can rotate.</summary>
    /// <returns><c>false</c> if the mailbox can't rotate (gone, or still pending creation).</returns>
    public async Task<bool> BeginRotationAsync(
        byte[] id, byte[] pendingEndpoint, byte[] verifyHash, DateTime verifyExpiresAt, CancellationToken ct = default) {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.ExecuteAsync(new CommandDefinition("""
            UPDATE mailboxes
            SET pending_endpoint = @pendingEndpoint, verify_hash = @verifyHash, verify_attempts = 0, verify_expires_at = @verifyExpiresAt
            WHERE id = @id AND state <> @pendingState
            """,
            new { id, pendingEndpoint, verifyHash, verifyExpiresAt, pendingState = (byte)MailboxState.PendingVerification },
            cancellationToken: ct)) == 1;
    }

    public async Task CancelRotationAsync(byte[] id, CancellationToken ct = default) {
        await using var conn = await _db.OpenAsync(ct);
        // Never touch a mailbox still pending creation: clearing its deadline would exempt it from purging.
        await conn.ExecuteAsync(new CommandDefinition("""
            UPDATE mailboxes SET pending_endpoint = NULL, verify_hash = NULL, verify_attempts = 0, verify_expires_at = NULL
            WHERE id = @id AND state <> @pendingState
            """, new { id, pendingState = (byte)MailboxState.PendingVerification }, cancellationToken: ct));
    }

    /// <summary>Atomically spends one verification attempt, but only while the mailbox is under <paramref name="max"/>.</summary>
    /// <returns><c>false</c> if it had no attempt left (or nothing to verify).</returns>
    public async Task<bool> ConsumeVerifyAttemptAsync(byte[] id, int max, CancellationToken ct = default) {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.ExecuteAsync(new CommandDefinition("""
            UPDATE mailboxes SET verify_attempts = verify_attempts + 1
            WHERE id = @id AND verify_hash IS NOT NULL AND verify_attempts < @max AND verify_expires_at >= UTC_TIMESTAMP()
            """, new { id, max }, cancellationToken: ct)) == 1;
    }

    /// <summary>
    /// Completes verification in one transaction. Any pending endpoint is promoted, the mailbox becomes active,
    /// its expiry is refreshed, and its held messages are scheduled for immediate delivery.
    /// The update is conditional on the code hash that was verified still being the stored one, so a
    /// rotation that commits in between can't be promoted unverified.
    /// </summary>
    public async Task<bool> CompleteVerificationAsync(
        byte[] id, byte[] verifyHash, int maxAttempts, DateOnly expiresAt, CancellationToken ct = default) {
        await using var conn = await _db.OpenAsync(ct);
        await using var tx = await conn.BeginTransactionAsync(ct);
        var updated = await conn.ExecuteAsync(new CommandDefinition("""
            UPDATE mailboxes
            SET sealed_endpoint = COALESCE(pending_endpoint, sealed_endpoint),
                pending_endpoint = NULL, verify_hash = NULL, verify_attempts = 0, verify_expires_at = NULL,
                state = @active, expires_at = GREATEST(expires_at, @expiresAt), reprobe_at = NULL, reprobe_count = 0
            WHERE id = @id AND verify_hash = @verifyHash AND verify_expires_at >= UTC_TIMESTAMP() AND verify_attempts <= @maxAttempts
            """,
            new { id, verifyHash, maxAttempts, active = (byte)MailboxState.Active, expiresAt = expiresAt.ToDateTime(TimeOnly.MinValue) },
            tx, cancellationToken: ct));
        if (updated != 1) {
            await tx.RollbackAsync(ct);
            return false;
        }
        // Rows parked by an attempt that's still running miss this, but that attempt rechecks the mailbox after parking.
        await conn.ExecuteAsync(new CommandDefinition(
            $"UPDATE pending_messages SET next_attempt_at = UTC_TIMESTAMP() WHERE mailbox_id = @id AND {PendingMessageRepository.Unclaimed}",
            new { id }, tx, cancellationToken: ct));
        await tx.CommitAsync(ct);
        return true;
    }

    /// <summary>
    /// Marks the endpoint dead, but only if <paramref name="failedEndpoint"/> is still the active one. A late
    /// 404/410 from an endpoint that has since been replaced must not take down its successor.
    /// </summary>
    public async Task MarkEndpointGoneAsync(byte[] id, byte[] failedEndpoint, CancellationToken ct = default) {
        await using var conn = await _db.OpenAsync(ct);
        // The first re-probe is an hour later (see DueReprobesAsync for the backoff).
        await conn.ExecuteAsync(new CommandDefinition("""
            UPDATE mailboxes SET state = @gone, reprobe_at = DATE_ADD(UTC_TIMESTAMP(), INTERVAL 1 HOUR), reprobe_count = 0
            WHERE id = @id AND state = @active AND sealed_endpoint = @failedEndpoint
            """,
            new { id, failedEndpoint, gone = (byte)MailboxState.EndpointGone, active = (byte)MailboxState.Active }, cancellationToken: ct));
    }

    /// <summary>A "gone" endpoint accepted a push again, so the mailbox is active again (if the endpoint hasn't changed meanwhile).</summary>
    /// <returns><c>true</c> if this call changed the state.</returns>
    public async Task<bool> MarkRecoveredAsync(byte[] id, byte[] workingEndpoint, CancellationToken ct = default) {
        await using var conn = await _db.OpenAsync(ct);
        var n = await conn.ExecuteAsync(new CommandDefinition("""
            UPDATE mailboxes SET state = @active, reprobe_at = NULL, reprobe_count = 0
            WHERE id = @id AND state = @gone AND sealed_endpoint = @workingEndpoint
            """,
            new { id, workingEndpoint, gone = (byte)MailboxState.EndpointGone, active = (byte)MailboxState.Active }, cancellationToken: ct));
        return n == 1;
    }

    /// <summary>
    /// Mailboxes whose "gone" endpoint is due a re-probe. Their next probe is pushed out with exponential backoff:
    /// 1 h, 2 h, 4 h … capped at 24 h.
    /// </summary>
    public async Task<IReadOnlyList<byte[]>> ClaimDueReprobesAsync(int limit, CancellationToken ct = default) {
        await using var conn = await _db.OpenAsync(ct);
        await using var tx = await conn.BeginTransactionAsync(ct);
        var ids = (await conn.QueryAsync<byte[]>(new CommandDefinition("""
            SELECT id FROM mailboxes WHERE state = @gone AND reprobe_at <= UTC_TIMESTAMP()
            ORDER BY reprobe_at LIMIT @limit FOR UPDATE SKIP LOCKED
            """, new { limit, gone = (byte)MailboxState.EndpointGone }, tx, cancellationToken: ct))).AsList();
        if (ids.Count > 0) {
            await conn.ExecuteAsync(new CommandDefinition("""
                UPDATE mailboxes
                SET reprobe_count = LEAST(reprobe_count + 1, 10),
                    reprobe_at = DATE_ADD(UTC_TIMESTAMP(), INTERVAL CAST(LEAST(24, POW(2, LEAST(reprobe_count + 1, 10))) AS UNSIGNED) HOUR)
                WHERE id IN @ids
                """, new { ids }, tx, cancellationToken: ct));
        }
        await tx.CommitAsync(ct);
        return ids;
    }

    /// <summary>The number of messages held for a mailbox, counting at most <paramref name="cap"/>.</summary>
    public async Task<int> CountHeldAsync(byte[] id, int cap, CancellationToken ct = default) {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.ExecuteScalarAsync<int>(new CommandDefinition(
            "SELECT COUNT(*) FROM (SELECT 1 FROM pending_messages WHERE mailbox_id = @id LIMIT @cap) held",
            new { id, cap }, cancellationToken: ct));
    }

    public async Task RefreshAsync(byte[] id, DateOnly expiresAt, CancellationToken ct = default) {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(new CommandDefinition(
            "UPDATE mailboxes SET expires_at = GREATEST(expires_at, @expiresAt) WHERE id = @id",
            new { id, expiresAt = expiresAt.ToDateTime(TimeOnly.MinValue) }, cancellationToken: ct));
    }

    /// <summary>Removes expired and never-verified mailboxes and abandons stale endpoint rotations.</summary>
    public async Task<int> PurgeAsync(CancellationToken ct = default) {
        await using var conn = await _db.OpenAsync(ct);
        var removed = 0;
        // Small batches keep lock times short.
        while (true) {
            var ids = (await conn.QueryAsync<byte[]>(new CommandDefinition("""
                SELECT id FROM mailboxes
                WHERE expires_at < UTC_DATE()
                   OR (state = @pendingState AND verify_expires_at < UTC_TIMESTAMP())
                LIMIT 500
                """, new { pendingState = (byte)MailboxState.PendingVerification }, cancellationToken: ct))).AsList();
            if (ids.Count == 0) {
                break;
            }
            await using (var tx = await conn.BeginTransactionAsync(ct)) {
                // Re-check the predicate: a mailbox verified or refreshed since the SELECT must survive.
                var deleted = (await conn.QueryAsync<byte[]>(new CommandDefinition("""
                    SELECT id FROM mailboxes
                    WHERE id IN @ids
                      AND (expires_at < UTC_DATE() OR (state = @pendingState AND verify_expires_at < UTC_TIMESTAMP()))
                    FOR UPDATE
                    """, new { ids, pendingState = (byte)MailboxState.PendingVerification }, tx, cancellationToken: ct))).AsList();
                if (deleted.Count > 0) {
                    await conn.ExecuteAsync(new CommandDefinition("DELETE FROM pending_messages WHERE mailbox_id IN @deleted", new { deleted }, tx, cancellationToken: ct));
                    await conn.ExecuteAsync(new CommandDefinition("DELETE FROM mailboxes WHERE id IN @deleted", new { deleted }, tx, cancellationToken: ct));
                }
                await tx.CommitAsync(ct);
                removed += deleted.Count;
            }
            if (ids.Count < 500) {
                break;
            }
        }

        await conn.ExecuteAsync(new CommandDefinition("""
            UPDATE mailboxes SET pending_endpoint = NULL, verify_hash = NULL, verify_attempts = 0, verify_expires_at = NULL
            WHERE state <> @pendingState AND verify_expires_at < UTC_TIMESTAMP()
            """, new { pendingState = (byte)MailboxState.PendingVerification }, cancellationToken: ct));
        return removed;
    }
}
