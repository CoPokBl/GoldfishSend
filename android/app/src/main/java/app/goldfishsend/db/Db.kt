package app.goldfishsend.db

import android.content.Context
import android.database.Cursor
import app.goldfishsend.proto.Hash
import app.goldfishsend.proto.utf8
import app.goldfishsend.proto.wipe
import java.io.File
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import net.zetetic.database.sqlcipher.SQLiteDatabase

/**
 * SQLCipher database (whole-DB AES-256 with per-page HMAC). The raw 256-bit key is derived from MK,
 * so no PBKDF2 runs at open. secure_delete zeroes freed pages, and cipher_memory_security wipes buffers.
 */
class Db private constructor(private val sql: SQLiteDatabase) {
    private val _changes = MutableStateFlow(0L)

    /** Bumped after every write so the UI can re-query. */
    val changes: StateFlow<Long> = _changes

    fun notifyChanged() {
        _changes.value = _changes.value + 1
    }

    fun exec(statement: String, vararg args: Any?) {
        sql.execSQL(statement, args)
    }

    fun insert(statement: String, vararg args: Any?): Long {
        val st = sql.compileStatement(statement)
        try {
            bind(st, args)
            return st.executeInsert()
        } finally {
            st.close()
        }
    }

    fun update(statement: String, vararg args: Any?): Int {
        val st = sql.compileStatement(statement)
        try {
            bind(st, args)
            return st.executeUpdateDelete()
        } finally {
            st.close()
        }
    }

    fun <T> query(statement: String, vararg args: Any?, map: (Cursor) -> T): List<T> {
        val c = sql.query(statement, args)
        try {
            val out = ArrayList<T>(c.count)
            while (c.moveToNext()) {
                out += map(c)
            }
            return out
        } finally {
            c.close()
        }
    }

    fun <T> queryOne(statement: String, vararg args: Any?, map: (Cursor) -> T): T? =
        query(statement, *args, map = map).firstOrNull()

    fun long(statement: String, vararg args: Any?): Long =
        queryOne(statement, *args) { it.getLong(0) } ?: 0L

    fun <T> tx(block: () -> T): T {
        sql.beginTransaction()
        try {
            val r = block()
            sql.setTransactionSuccessful()
            return r
        } finally {
            sql.endTransaction()
        }
    }

    fun close() {
        runCatching { sql.close() }
    }

    /** Re-encrypts the whole database under a key derived from [newMk] (SQLCipher PRAGMA rekey, atomic). */
    fun rekey(newMk: ByteArray) {
        val key = keyBlob(newMk)
        try {
            sql.changePassword(key)
        } finally {
            key.wipe()
        }
    }

    private fun bind(st: net.zetetic.database.sqlcipher.SQLiteStatement, args: Array<out Any?>) {
        args.forEachIndexed { i, a ->
            val idx = i + 1
            when (a) {
                null -> st.bindNull(idx)
                is ByteArray -> st.bindBlob(idx, a)
                is String -> st.bindString(idx, a)
                is Int -> st.bindLong(idx, a.toLong())
                is Long -> st.bindLong(idx, a)
                is Boolean -> st.bindLong(idx, if (a) 1 else 0)
                is Double -> st.bindDouble(idx, a)
                else -> error("unsupported bind type ${a::class}")
            }
        }
    }

    companion object {
        private const val NAME = "goldfish.db"

        /** The duress PIN's decoy profile: a separate database with its own key, identity and message root. */
        const val DECOY_NAME = "decoy.db"
        private var libLoaded = false

        fun file(context: Context, name: String = NAME): File = context.getDatabasePath(name)

        fun open(context: Context, mk: ByteArray, name: String = NAME): Db {
            if (!libLoaded) {
                System.loadLibrary("sqlcipher")
                libLoaded = true
            }
            val keyBytes = keyBlob(mk)
            val f = file(context, name)
            f.parentFile?.mkdirs()
            val sql = try {
                SQLiteDatabase.openOrCreateDatabase(f, keyBytes, null, null, null)
            } finally {
                keyBytes.wipe()
            }
            try {
                // Fails here (not later) if the key is wrong, so callers can try another key.
                sql.rawQuery("SELECT count(*) FROM sqlite_master", null).use { it.moveToFirst() }
            } catch (e: Exception) {
                runCatching { sql.close() }
                throw e
            }
            sql.rawExecSQL("PRAGMA cipher_memory_security = ON")
            sql.rawExecSQL("PRAGMA secure_delete = ON")
            // Explicit rather than the library default: a rollback journal that's deleted at the end of every transaction
            // (no long-lived WAL file holding old page copies), and temporary tables and indices kept in memory, never in
            // temp files.
            sql.rawQuery("PRAGMA journal_mode = DELETE", null).use { it.moveToFirst() }
            sql.rawExecSQL("PRAGMA temp_store = MEMORY")
            sql.rawExecSQL("PRAGMA foreign_keys = ON")
            val db = Db(sql)
            Schema.migrate(db, sql)
            return db
        }

        /**
         * The SQLCipher raw-key literal `x'<64 hex>'`, built directly in a byte array so the key never exists as an
         * immutable String. The caller wipes it.
         */
        fun keyBlob(mk: ByteArray): ByteArray {
            val raw = Hash.hmacSha256(mk, "gf/db-key/v1".utf8())
            val out = ByteArray(3 + raw.size * 2)
            out[0] = 'x'.code.toByte()
            out[1] = '\''.code.toByte()
            val digits = "0123456789abcdef"
            for (i in raw.indices) {
                val v = raw[i].toInt() and 0xff
                out[2 + 2 * i] = digits[v ushr 4].code.toByte()
                out[3 + 2 * i] = digits[v and 0xf].code.toByte()
            }
            out[out.size - 1] = '\''.code.toByte()
            raw.wipe()
            return out
        }

        /** Deletes the DB file and its journals. */
        fun deleteFiles(context: Context, name: String = NAME) {
            val f = file(context, name)
            for (suffix in listOf("", "-journal", "-wal", "-shm")) {
                File(f.path + suffix).delete()
            }
        }
    }
}

internal object Schema {
    const val VERSION = 9

    fun migrate(db: Db, sql: SQLiteDatabase) {
        val v = sql.version
        if (v >= VERSION) {
            return
        }
        db.tx {
            if (v < 1) {
                for (s in V1) {
                    db.exec(s)
                }
            }
            if (v < 2) {
                for (s in V2) {
                    db.exec(s)
                }
            }
            if (v < 3) {
                for (s in V3) {
                    db.exec(s)
                }
            }
            if (v < 4) {
                for (s in V4) {
                    db.exec(s)
                }
            }
            if (v < 5) {
                for (s in V5) {
                    db.exec(s)
                }
            }
            if (v < 6) {
                for (s in V6) {
                    db.exec(s)
                }
            }
            if (v < 7) {
                for (s in V7) {
                    db.exec(s)
                }
            }
            if (v < 8) {
                for (s in V8) {
                    db.exec(s)
                }
            }
            if (v < 9) {
                for (s in V9) {
                    db.exec(s)
                }
            }
            sql.version = VERSION
        }
    }

    /**
     * A UnifiedPush registration per mailbox, and owner requests sent one mailbox at a time, spread out. Mailboxes made
     * before shared one endpoint and can't be used any more (nothing was released: a fresh install is expected).
     */
    internal val V9 = listOf(
        "DELETE FROM kv WHERE k IN ('push_endpoint', 'rotation_needed', 'endpoint_gone_at')",
        // Our UnifiedPush instances. Every mailbox has its own, so its endpoint and Web Push keys are its own, and the
        // mailboxes of different contacts and groups carry nothing in common the server could link them by. `used`: a
        // mailbox was created on it (the server has seen its endpoint), so once that mailbox is gone the instance is
        // unregistered, never reused. Until then it's a spare, registered ahead for the next mailbox. `endpoint`: JSON
        // PushEndpointData, null until the distributor sends one. `gone_at`: when the server last said its endpoint was
        // gone (re-registered at most every 6 hours).
        """CREATE TABLE push_instances (
            name TEXT PRIMARY KEY,
            endpoint TEXT,
            used INTEGER NOT NULL DEFAULT 0,
            gone_at INTEGER,
            created_at INTEGER NOT NULL
        )""",
        "ALTER TABLE mailboxes ADD COLUMN push_instance TEXT",
        // When to refresh the mailbox on the server, and when to point it at its instance's new endpoint. Each is picked
        // at random, so the server never sees two of our mailboxes in one request or one burst ([app.goldfishsend.core.OwnerOps]).
        "ALTER TABLE mailboxes ADD COLUMN refresh_at INTEGER",
        "ALTER TABLE mailboxes ADD COLUMN rotate_at INTEGER",
        // When to delete it on the server, spread out the same way.
        "ALTER TABLE doomed_mailboxes ADD COLUMN delete_at INTEGER NOT NULL DEFAULT 0",
    )

    /** Held messages sealed like message bodies, tombstones for removed messages, and mailboxes still to delete. */
    internal val V8 = listOf(
        // Rebuilt: held blobs were sealed only by the DB key, so wipes and timers didn't reach them. Nothing was released.
        "DROP TABLE held_incoming",
        // Raw E2E blobs that arrived with a changed identity key [identity], waiting for the user to review it. Sealed like a
        // message body ([MessageVault], label "held/<id>"), with the chat's timer as their expiry, so erasing messages,
        // the reboot wipe and disappearing timers destroy them too.
        """CREATE TABLE held_incoming (
            id TEXT PRIMARY KEY,
            contact_id INTEGER NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
            identity BLOB NOT NULL,
            tag BLOB NOT NULL,
            blob BLOB NOT NULL,
            key BLOB NOT NULL,
            bucket INTEGER,
            received_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        )""",
        // Wire ids of incoming messages that were viewed once, deleted or expired, so a re-send of one (its sender never got
        // our receipt) doesn't bring it back. Ids only, kept until no re-send can still arrive.
        """CREATE TABLE gone_incoming (
            contact_id INTEGER NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
            wire_id TEXT NOT NULL,
            until INTEGER NOT NULL,
            PRIMARY KEY (contact_id, wire_id)
        )""",
        // Our mailboxes whose chat is gone (blocked contact, left group, server switch) but that the server may still hold.
        // Retried until the server confirms, so a blocked contact can't keep writing to one.
        """CREATE TABLE doomed_mailboxes (
            send_secret BLOB PRIMARY KEY,
            owner_secret BLOB NOT NULL,
            server TEXT NOT NULL,
            server_key TEXT,
            created_at INTEGER NOT NULL
        )""",
    )

    /** Group delivery by state and heads (docs/groups.md, "State"). Groups made before can't be read any more. */
    internal val V7 = listOf(
        "DELETE FROM contacts WHERE is_group = 1",
        // What we know of each peer's head and what we've sent them (JSON).
        "ALTER TABLE groups ADD COLUMN peers TEXT",
        // How often our head changed, and the last one counted (docs/groups.md, "Heads").
        "ALTER TABLE groups ADD COLUMN head_seq INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE groups ADD COLUMN head_key TEXT",
    )

    /** Groups v2 (one owner, membership facts). Groups made before can't be read any more, and nothing was released. */
    internal val V6 = listOf(
        "DELETE FROM contacts WHERE is_group = 1",
        "ALTER TABLE groups DROP COLUMN pending_op",
        "ALTER TABLE groups DROP COLUMN pending_hash",
        // Our stint: the `since` of our entry in the roster.
        "ALTER TABLE groups ADD COLUMN since INTEGER NOT NULL DEFAULT 0",
        // The facts held (docs/groups.md, "Fact"), one `fact sig` (b64u) per line.
        "ALTER TABLE groups ADD COLUMN facts TEXT",
    )

    /** Group chats (docs/groups.md). A group is a `contacts` row with is_group = 1, so chats, timers and wipes cover it. */
    internal val V5 = listOf(
        "ALTER TABLE contacts ADD COLUMN is_group INTEGER NOT NULL DEFAULT 0",
        // The hint key of a group inbox (each inbox has its own; a rotated one keeps its old key while draining).
        "ALTER TABLE mailboxes ADD COLUMN hint_key BLOB",
        // Group fan-out: the member (identity key, b64u) this row goes to.
        "ALTER TABLE outbox ADD COLUMN member_key TEXT",
        // Group messages: who sent it (identity key, b64u), and how many members an outgoing one went to.
        "ALTER TABLE messages ADD COLUMN sender_key TEXT",
        "ALTER TABLE messages ADD COLUMN recipients INTEGER NOT NULL DEFAULT 0",
        // A group's last-resort prekeys are reused by every member who starts a session, so they aren't deleted on use.
        "ALTER TABLE sig_kyber_prekey ADD COLUMN last_resort INTEGER NOT NULL DEFAULT 0",
        """CREATE TABLE groups (
            cid INTEGER PRIMARY KEY REFERENCES contacts(id) ON DELETE CASCADE,
            gid TEXT NOT NULL UNIQUE,
            state INTEGER NOT NULL,
            roster BLOB,
            roster_sig BLOB,
            my_card BLOB,
            my_card_sig BLOB,
            invited_by TEXT,
            pending_op TEXT,
            pending_hash TEXT,
            rotate_needed INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL
        )""",
        """CREATE TABLE group_cards (
            cid INTEGER NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
            member TEXT NOT NULL,
            card BLOB NOT NULL,
            sig BLOB NOT NULL,
            seq INTEGER NOT NULL,
            pending_server_key TEXT,
            unreachable INTEGER NOT NULL DEFAULT 0,
            -- No longer a member: kept only until what's queued to them (the roster that removed them) is delivered.
            gone INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (cid, member)
        )""",
        """CREATE TABLE group_rosters (
            cid INTEGER NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
            ver INTEGER NOT NULL,
            hash TEXT NOT NULL,
            roster BLOB NOT NULL,
            sig BLOB NOT NULL,
            PRIMARY KEY (cid, hash)
        )""",
        """CREATE TABLE group_held (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cid INTEGER NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
            hint_key BLOB NOT NULL,
            blob BLOB NOT NULL,
            received_at INTEGER NOT NULL
        )""",
        // Read receipts per member for our outgoing group messages.
        "CREATE TABLE group_receipts (message_id TEXT NOT NULL, member TEXT NOT NULL, PRIMARY KEY (message_id, member))",
    )

    /** Server identity pins (gateway v1). */
    internal val V4 = listOf(
        // The pinned identity fingerprint (b64u) of the contact's server. Null: trusted on first use.
        "ALTER TABLE contacts ADD COLUMN out_server_key TEXT",
        // A different fingerprint that server presented, waiting for review. Messages to this contact wait meanwhile.
        "ALTER TABLE contacts ADD COLUMN pending_server_key TEXT",
    )

    /** Time-bucketed message keys, and invite-to-prekey binding. */
    private val V3 = listOf(
        // The expiry bucket whose key wraps this message key (null = wrapped by the message root key).
        "ALTER TABLE message_keys ADD COLUMN bucket INTEGER",
        // The signed and Kyber prekey ids published in this mailbox's invite. A first PreKey hello is only accepted on the
        // mailbox whose invite issued exactly those ids.
        "ALTER TABLE mailboxes ADD COLUMN invite_spk_id INTEGER",
        "ALTER TABLE mailboxes ADD COLUMN invite_kyber_id INTEGER",
    )

    /** Identity-change review, hidden chats and mailbox rotation. */
    private val V2 = listOf(
        // A changed identity key seen from this contact, waiting for the user to review it (null = none).
        "ALTER TABLE contacts ADD COLUMN pending_identity BLOB",
        "ALTER TABLE contacts ADD COLUMN hidden INTEGER NOT NULL DEFAULT 0",
        // Rotation: when a mailbox was superseded, and when it may finally be deleted (after the contact has switched).
        "ALTER TABLE mailboxes ADD COLUMN replaced_at INTEGER",
        "ALTER TABLE mailboxes ADD COLUMN drain_until INTEGER",
        // Raw E2E blobs that arrived with an untrusted (changed) identity key. Processed after the user accepts the change.
        """CREATE TABLE held_incoming (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            contact_id INTEGER NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
            tag BLOB NOT NULL,
            blob BLOB NOT NULL,
            received_at INTEGER NOT NULL
        )""",
    )

    private val V1 = listOf(
        "CREATE TABLE kv (k TEXT PRIMARY KEY, v BLOB)",
        """CREATE TABLE contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            identity_key BLOB,
            verified INTEGER NOT NULL DEFAULT 0,
            timer_secs INTEGER NOT NULL DEFAULT 0,
            out_server TEXT,
            out_secret BLOB,
            received_any INTEGER NOT NULL DEFAULT 0,
            unreachable INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            last_activity INTEGER NOT NULL,
            unread INTEGER NOT NULL DEFAULT 0
        )""",
        """CREATE TABLE mailboxes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            contact_id INTEGER REFERENCES contacts(id) ON DELETE SET NULL,
            purpose INTEGER NOT NULL,
            send_secret BLOB NOT NULL,
            owner_secret BLOB NOT NULL,
            tag BLOB NOT NULL UNIQUE,
            state INTEGER NOT NULL,
            expires_at TEXT,
            created_at INTEGER NOT NULL,
            invite_used INTEGER NOT NULL DEFAULT 0,
            invite_expires_at INTEGER,
            orphaned INTEGER NOT NULL DEFAULT 0
        )""",
        "CREATE TABLE rotations (tag BLOB PRIMARY KEY, mailbox_ids TEXT NOT NULL, created_at INTEGER NOT NULL)",
        """CREATE TABLE messages (
            id TEXT PRIMARY KEY,
            contact_id INTEGER NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
            wire_id TEXT NOT NULL,
            outgoing INTEGER NOT NULL,
            kind INTEGER NOT NULL,
            ciphertext BLOB NOT NULL,
            ts INTEGER NOT NULL,
            received_at INTEGER,
            read_at INTEGER,
            exp_secs INTEGER NOT NULL DEFAULT 0,
            view_once INTEGER NOT NULL DEFAULT 0,
            expires_at INTEGER,
            status INTEGER NOT NULL,
            resend_count INTEGER NOT NULL DEFAULT 0,
            UNIQUE (contact_id, wire_id, outgoing)
        )""",
        "CREATE INDEX ix_messages_contact ON messages (contact_id, ts)",
        "CREATE INDEX ix_messages_expiry ON messages (expires_at)",
        "CREATE TABLE message_keys (message_id TEXT PRIMARY KEY, key BLOB NOT NULL)",
        """CREATE TABLE chunks (
            contact_id INTEGER NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
            wire_id TEXT NOT NULL,
            part INTEGER NOT NULL,
            parts INTEGER NOT NULL,
            body BLOB NOT NULL,
            created_at INTEGER NOT NULL,
            PRIMARY KEY (contact_id, wire_id, part)
        )""",
        """CREATE TABLE outbox (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            contact_id INTEGER NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
            message_id TEXT,
            kind INTEGER NOT NULL,
            content BLOB,
            blob BLOB,
            idem BLOB NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            next_at INTEGER NOT NULL,
            created_at INTEGER NOT NULL
        )""",
        "CREATE INDEX ix_outbox_contact ON outbox (contact_id, seq)",
        "CREATE TABLE sig_identity (address TEXT PRIMARY KEY, key BLOB NOT NULL)",
        "CREATE TABLE sig_session (address TEXT PRIMARY KEY, record BLOB NOT NULL)",
        "CREATE TABLE sig_prekey (id INTEGER PRIMARY KEY, record BLOB NOT NULL)",
        "CREATE TABLE sig_signed_prekey (id INTEGER PRIMARY KEY, record BLOB NOT NULL, created_at INTEGER NOT NULL)",
        "CREATE TABLE sig_kyber_prekey (id INTEGER PRIMARY KEY, record BLOB NOT NULL, created_at INTEGER NOT NULL)",
        "CREATE TABLE sig_sender_key (address TEXT NOT NULL, dist TEXT NOT NULL, record BLOB NOT NULL, PRIMARY KEY (address, dist))",
    )
}
