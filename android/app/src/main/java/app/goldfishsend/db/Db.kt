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
        private var libLoaded = false

        fun file(context: Context): File = context.getDatabasePath(NAME)

        fun open(context: Context, mk: ByteArray): Db {
            if (!libLoaded) {
                System.loadLibrary("sqlcipher")
                libLoaded = true
            }
            val raw = Hash.hmacSha256(mk, "gf/db-key/v1".utf8())
            val hex = raw.joinToString("") { "%02x".format(it) }
            val keyBytes = "x'$hex'".utf8()
            raw.wipe()
            val f = file(context)
            f.parentFile?.mkdirs()
            val sql = try {
                SQLiteDatabase.openOrCreateDatabase(f, keyBytes, null, null, null)
            } finally {
                keyBytes.wipe()
            }
            sql.rawExecSQL("PRAGMA cipher_memory_security = ON")
            sql.rawExecSQL("PRAGMA secure_delete = ON")
            sql.rawExecSQL("PRAGMA foreign_keys = ON")
            val db = Db(sql)
            Schema.migrate(db, sql)
            return db
        }

        /** Deletes the DB file and its journals. */
        fun deleteFiles(context: Context) {
            val f = file(context)
            for (suffix in listOf("", "-journal", "-wal", "-shm")) {
                File(f.path + suffix).delete()
            }
        }
    }
}

internal object Schema {
    private const val VERSION = 1

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
            sql.version = VERSION
        }
    }

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
