package app.goldfishsend.db

import app.goldfishsend.proto.Sanitize
import android.database.Cursor
import app.goldfishsend.crypto.MessageVault
import app.goldfishsend.proto.B64
import app.goldfishsend.proto.Rand

data class Contact(
    val id: Long,
    val name: String,
    val identityKey: ByteArray?,
    val verified: Boolean,
    val timerSecs: Long,
    val outServer: String?,
    val outSecret: ByteArray?,
    val receivedAny: Boolean,
    val unreachable: Boolean,
    val createdAt: Long,
    val lastActivity: Long,
    val unread: Int,
    /** A changed identity key that hasn't been reviewed yet. Sending is paused while it's set. */
    val pendingIdentity: ByteArray? = null,
    val hidden: Boolean = false,
    /** The pinned identity fingerprint (b64u) of [outServer], or null to trust it on first use. */
    val outServerKey: String? = null,
    /** A different fingerprint [outServer] presented. Messages to this contact wait until it's resolved. */
    val pendingServerKey: String? = null,
    /** A group chat (docs/groups.md): [name] is the group name, [timerSecs] the group timer. */
    val isGroup: Boolean = false,
    /** The key that wraps our blobs to [outSecret]'s mailbox ([app.goldfishsend.proto.BlobWrap]), from the contact. */
    val outWrapKey: ByteArray? = null,
) {
    val ready: Boolean
        get() = outServer != null && outSecret != null && outWrapKey != null
}

data class Mailbox(
    val id: Long,
    val contactId: Long?,
    val purpose: Int,
    val sendSecret: ByteArray,
    val ownerSecret: ByteArray,
    val tag: ByteArray,
    val state: Int,
    val expiresAt: String?,
    val createdAt: Long,
    val inviteUsed: Boolean,
    val inviteExpiresAt: Long?,
    /** Set when a newer mailbox replaced this one for the same contact (rotation). */
    val replacedAt: Long? = null,
    /** After this time, a replaced mailbox is deleted. It's set once the contact is seen using the new one. */
    val drainUntil: Long? = null,
    /** The signed prekey id published in this mailbox's invite. A first hello must use exactly this prekey. */
    val inviteSpkId: Int? = null,
    val inviteKyberId: Int? = null,
    /** A group inbox's hint key (docs/groups.md, "Blob"). Null for 1:1 mailboxes. */
    val hintKey: ByteArray? = null,
    /**
     * The key that wraps every blob sent to this mailbox ([app.goldfishsend.proto.BlobWrap]), handed out with its
     * sendSecret. A group inbox's blobs are wrapped under a key from its [hintKey] instead.
     */
    val wrapKey: ByteArray? = null,
) {
    companion object {
        const val PURPOSE_QR = 0
        const val PURPOSE_LINK = 1
        const val PURPOSE_CONTACT = 2
        const val PURPOSE_GROUP = 3

        const val STATE_CREATING = 0
        const val STATE_PENDING_VERIFY = 1
        const val STATE_ACTIVE = 2
    }
}

object MsgStatus {
    const val QUEUED = 0
    const val SENT = 1
    const val DELIVERED = 2
    const val READ = 3
    const val FAILED = 4
}

object MsgKind {
    const val TEXT = 0
    const val SYSTEM = 1
}

/** One of our mailboxes whose chat is gone, still to delete on [server] (pinned to [serverKey]). */
class DoomedMailbox(val sendSecret: ByteArray, val ownerSecret: ByteArray, val server: String, val serverKey: String?, val createdAt: Long)

data class Message(
    val id: String,
    val contactId: Long,
    val wireId: String,
    val outgoing: Boolean,
    val kind: Int,
    val body: String,
    val ts: Long,
    val receivedAt: Long?,
    val readAt: Long?,
    val expSecs: Long,
    val viewOnce: Boolean,
    val expiresAt: Long?,
    val status: Int,
    /** Groups: the sender of an incoming message (identity key, b64u). */
    val senderKey: String? = null,
    /** Groups: how many members an outgoing message was sent to. */
    val recipients: Int = 0,
)

data class ChatSummary(
    val contact: Contact,
    val lastBody: String?,
    val lastTs: Long?,
    val lastOutgoing: Boolean,
    val lastStatus: Int,
    /** Groups: who sent the last message (identity key, b64u). */
    val lastSender: String? = null,
)

object OutboxKind {
    const val CONTENT = 0
    const val HELLO = 1
}

data class OutboxItem(
    val seq: Long,
    val contactId: Long,
    val messageId: String?,
    val kind: Int,
    val content: ByteArray?,
    val blob: ByteArray?,
    val idem: ByteArray,
    val attempts: Int,
    val nextAt: Long,
    /** Group fan-out: the member this row goes to (identity key, b64u). Null for 1:1 rows. */
    val memberKey: String? = null,
)

/** Typed data access over [Db]. Message bodies are always stored through [MessageVault]. */
/** Incomplete chunked messages kept per contact (64 parts × 4 messages). */
const val MAX_CHUNKS_PER_CONTACT = 256L

/** kv: messages were deleted since the message root key was last rotated. */
const val KV_SHRED_PENDING = "shred_pending"

/** Messages held behind a changed safety number, per contact. */
const val MAX_HELD_PER_CONTACT = 200L

/** How long after sending an unreceipted message may be re-sent automatically. */
const val RESEND_WINDOW_MS = 7 * 86_400_000L

/**
 * How long the wire id of a removed incoming message is remembered. A re-send leaves within [RESEND_WINDOW_MS] of the
 * original and the server keeps it for at most 14 days, so none can arrive later than this (with a margin).
 */
const val GONE_KEEP_MS = RESEND_WINDOW_MS + 16 * 86_400_000L

class Repo(val db: Db, private val vault: MessageVault) {
    // --- kv ---

    fun kvGet(k: String): ByteArray? = db.queryOne("SELECT v FROM kv WHERE k = ?", k) { it.getBlob(0) }

    fun kvPut(k: String, v: ByteArray?) {
        if (v == null) {
            db.exec("DELETE FROM kv WHERE k = ?", k)
        } else {
            db.exec("INSERT OR REPLACE INTO kv (k, v) VALUES (?, ?)", k, v)
        }
    }

    fun kvString(k: String): String? = kvGet(k)?.toString(Charsets.UTF_8)

    fun kvPutString(k: String, v: String?) = kvPut(k, v?.toByteArray(Charsets.UTF_8))

    /** Every kv key that starts with [prefix]. */
    fun kvKeys(prefix: String): List<String> =
        db.query("SELECT k FROM kv WHERE substr(k, 1, ?) = ?", prefix.length, prefix) { it.getString(0) }

    var displayName: String?
        get() = kvString("display_name")?.takeIf { it.isNotBlank() }
        set(v) {
            kvPutString("display_name", v?.trim())
            db.notifyChanged()
        }

    // --- contacts ---

    private fun contact(c: Cursor) = Contact(
        id = c.getLong(0),
        name = c.getString(1),
        identityKey = if (c.isNull(2)) null else c.getBlob(2),
        verified = c.getInt(3) != 0,
        timerSecs = c.getLong(4),
        outServer = if (c.isNull(5)) null else c.getString(5),
        outSecret = if (c.isNull(6)) null else c.getBlob(6),
        receivedAny = c.getInt(7) != 0,
        unreachable = c.getInt(8) != 0,
        createdAt = c.getLong(9),
        lastActivity = c.getLong(10),
        unread = c.getInt(11),
        pendingIdentity = if (c.isNull(12)) null else c.getBlob(12),
        hidden = c.getInt(13) != 0,
        outServerKey = if (c.isNull(14)) null else c.getString(14),
        pendingServerKey = if (c.isNull(15)) null else c.getString(15),
        isGroup = c.getInt(16) != 0,
        outWrapKey = if (c.isNull(17)) null else c.getBlob(17),
    )

    private val contactCols =
        "id, name, identity_key, verified, timer_secs, out_server, out_secret, received_any, unreachable, created_at, last_activity, unread, " +
            "pending_identity, hidden, out_server_key, pending_server_key, is_group, out_wrap_key"

    fun contact(id: Long): Contact? = db.queryOne("SELECT $contactCols FROM contacts WHERE id = ?", id, map = ::contact)

    /** Every chat: people and groups. */
    fun contacts(): List<Contact> = db.query("SELECT $contactCols FROM contacts ORDER BY last_activity DESC", map = ::contact)

    /** People only (1:1 contacts), without group chats. */
    fun people(): List<Contact> = db.query("SELECT $contactCols FROM contacts WHERE is_group = 0 ORDER BY name COLLATE NOCASE", map = ::contact)

    /** The 1:1 contact with this identity key (b64u), if any. */
    fun personByIdentity(identityKey: ByteArray): Contact? =
        db.queryOne("SELECT $contactCols FROM contacts WHERE is_group = 0 AND identity_key = ?", identityKey, map = ::contact)

    /** A new group chat row (name and timer from its roster). */
    fun createGroupContact(name: String, timerSecs: Long): Long {
        val now = System.currentTimeMillis()
        return db.insert(
            "INSERT INTO contacts (name, verified, timer_secs, is_group, created_at, last_activity) VALUES (?, 1, ?, 1, ?, ?)",
            Sanitize.name(name) ?: "Group", timerSecs, now, now,
        )
    }

    fun createContact(
        name: String,
        verified: Boolean,
        timerSecs: Long,
        outServer: String?,
        outSecret: ByteArray?,
        outServerKey: String? = null,
        outWrapKey: ByteArray? = null,
    ): Long {
        val now = System.currentTimeMillis()
        return db.insert(
            "INSERT INTO contacts (name, verified, timer_secs, out_server, out_secret, out_server_key, out_wrap_key, created_at, last_activity) " +
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            Sanitize.name(name) ?: "Contact", verified, timerSecs, outServer, outSecret, outServerKey, outWrapKey, now, now,
        )
    }

    /**
     * Where to reach a contact, from their E2E-authenticated `hello` or `mailbox` message: the mailbox and its [wrapKey].
     * [serverKey] replaces the pin (and resolves a pending identity change). Without one, the pin is kept if the server
     * didn't change, or is learned on first use if it did.
     */
    fun updateContactOutbound(id: Long, server: String, secret: ByteArray, serverKey: String?, wrapKey: ByteArray) {
        val current = contact(id)
        val key = serverKey ?: current?.outServerKey?.takeIf { current.outServer == server }
        db.exec(
            "UPDATE contacts SET out_server = ?, out_secret = ?, out_server_key = ?, out_wrap_key = ?, pending_server_key = NULL, " +
                "unreachable = 0 WHERE id = ?",
            server, secret, key, wrapKey, id,
        )
    }

    /** Trust on first use: records [key] only if the contact still uses [server] and has no pin yet. */
    fun learnOutServerKey(id: Long, server: String, key: String) =
        db.exec("UPDATE contacts SET out_server_key = ? WHERE id = ? AND out_server = ? AND out_server_key IS NULL", key, id, server)

    fun setPendingServerKey(id: Long, key: String?) = db.exec("UPDATE contacts SET pending_server_key = ? WHERE id = ?", key, id)

    /** The user reviewed and trusted the new identity of this contact's server. */
    fun trustPendingServerKey(id: Long, key: String) =
        db.exec("UPDATE contacts SET out_server_key = ?, pending_server_key = NULL WHERE id = ? AND pending_server_key = ?", key, id, key)

    fun setContactIdentity(id: Long, key: ByteArray) = db.exec("UPDATE contacts SET identity_key = ? WHERE id = ?", key, id)

    fun renameContact(id: Long, name: String) {
        val clean = Sanitize.name(name) ?: return
        db.exec("UPDATE contacts SET name = ? WHERE id = ?", clean, id)
    }

    /** Every inbound mailbox of a contact, including replaced ones still draining. */
    fun mailboxesForContact(contactId: Long): List<Mailbox> =
        db.query("SELECT $mbCols FROM mailboxes WHERE contact_id = ?", contactId, map = ::mailbox)

    /** Unverifying always works. Verifying only if [key] is still the contact's identity key: the one the user compared. */
    fun setVerified(id: Long, v: Boolean, key: ByteArray?): Boolean = if (v) {
        key != null && db.update("UPDATE contacts SET verified = 1 WHERE id = ? AND identity_key = ?", id, key) == 1
    } else {
        db.update("UPDATE contacts SET verified = 0 WHERE id = ?", id) == 1
    }

    // --- identity changes ---

    fun setPendingIdentity(id: Long, key: ByteArray?) = db.exec("UPDATE contacts SET pending_identity = ? WHERE id = ?", key, id)

    /**
     * Accepts a reviewed identity change: the new key becomes the contact's key, and they're no longer verified. Only while
     * [key] is still the pending one (the one the user compared); false otherwise.
     */
    fun acceptPendingIdentity(id: Long, key: ByteArray): Boolean = db.update(
        "UPDATE contacts SET identity_key = ?, pending_identity = NULL, verified = 0 WHERE id = ? AND pending_identity = ?", key, id, key,
    ) == 1

    /** Drops a pending identity change the user rejected (only while it's still [key]). The held messages go with it. */
    fun rejectPendingIdentity(id: Long, key: ByteArray): Boolean = db.tx {
        val ok = db.update("UPDATE contacts SET pending_identity = NULL WHERE id = ? AND pending_identity = ?", id, key) == 1
        if (ok) {
            clearHeldIncoming(id)
        }
        ok
    }

    /**
     * Keeps a message that came with the changed identity [identity] until the user reviews it. It's sealed like a message
     * body and expires at [expiresAt] (its key bucket is destroyed then, even while locked).
     */
    fun holdIncoming(contactId: Long, identity: ByteArray, tag: ByteArray, blob: ByteArray, expiresAt: Long) {
        // Bounded: a flood from a hostile peer can't fill storage.
        if (db.long("SELECT COUNT(*) FROM held_incoming WHERE contact_id = ?", contactId) >= MAX_HELD_PER_CONTACT) {
            return
        }
        val id = B64.enc(Rand.bytes(16))
        val sealed = vault.seal("held/$id", blob, expiresAt)
        db.exec(
            "INSERT INTO held_incoming (id, contact_id, identity, tag, blob, key, bucket, received_at, expires_at) " +
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            id, contactId, identity, tag, sealed.ciphertext, sealed.wrappedKey, sealed.bucket, System.currentTimeMillis(), expiresAt,
        )
    }

    /**
     * The held messages (tag, blob) that came with [identity], oldest first. Whatever came with another key is left out, so
     * it's never replayed under this one. Expired ones, and ones whose key was destroyed, are left out too.
     */
    fun heldIncoming(contactId: Long, identity: ByteArray, now: Long): List<Pair<ByteArray, ByteArray>> = db.query(
        "SELECT id, tag, blob, key, bucket FROM held_incoming WHERE contact_id = ? AND identity = ? AND expires_at > ? " +
            "ORDER BY received_at, rowid",
        contactId, identity, now,
    ) { c ->
        runCatching {
            c.getBlob(1) to vault.open("held/" + c.getString(0), c.getBlob(3), c.getBlob(2), if (c.isNull(4)) null else c.getLong(4))
        }.getOrNull()
    }.filterNotNull()

    fun clearHeldIncoming(contactId: Long) = db.exec("DELETE FROM held_incoming WHERE contact_id = ?", contactId)

    // --- hidden chats ---

    fun setHidden(id: Long, hidden: Boolean) = db.exec("UPDATE contacts SET hidden = ? WHERE id = ?", hidden, id)

    fun hiddenContactIds(): List<Long> = db.query("SELECT id FROM contacts WHERE hidden = 1") { it.getLong(0) }

    fun setTimer(id: Long, secs: Long) = db.exec("UPDATE contacts SET timer_secs = ? WHERE id = ?", secs, id)

    fun setReceivedAny(id: Long) = db.exec("UPDATE contacts SET received_any = 1 WHERE id = ?", id)

    fun setUnreachable(id: Long, v: Boolean) = db.exec("UPDATE contacts SET unreachable = ? WHERE id = ?", v, id)

    fun touchContact(id: Long, incrementUnread: Boolean) {
        db.exec(
            "UPDATE contacts SET last_activity = ?, unread = unread + ? WHERE id = ?",
            System.currentTimeMillis(), if (incrementUnread) 1 else 0, id,
        )
    }

    fun clearUnread(id: Long) = db.exec("UPDATE contacts SET unread = 0 WHERE id = ?", id)

    fun unverifiedCount(): Long = db.long("SELECT COUNT(*) FROM contacts WHERE verified = 0 AND is_group = 0")

    /** Deletes the contact, all its messages (shredding keys first), session state and outbox rows. Group rows cascade. */
    fun deleteContact(id: Long) {
        db.tx {
            db.exec("DELETE FROM group_receipts WHERE message_id IN (SELECT id FROM messages WHERE contact_id = ?)", id)
            db.exec("DELETE FROM message_keys WHERE message_id IN (SELECT id FROM messages WHERE contact_id = ?)", id)
            db.exec("DELETE FROM messages WHERE contact_id = ?", id)
            db.exec("DELETE FROM chunks WHERE contact_id = ?", id)
            db.exec("DELETE FROM outbox WHERE contact_id = ?", id)
            db.exec("DELETE FROM sig_session WHERE address = ?", "c$id.1")
            db.exec("DELETE FROM sig_identity WHERE address = ?", "c$id.1")
            db.exec("DELETE FROM mailboxes WHERE contact_id = ?", id)
            // A group's remembered member names (Groups.nameKey / pendingNameKey).
            db.exec("DELETE FROM kv WHERE k LIKE ? OR k LIKE ?", "gname/$id/%", "gjoin/$id/%")
            db.exec("DELETE FROM contacts WHERE id = ?", id)
            deleted()
        }
        onMessagesDeleted?.invoke()
    }

    fun chatSummaries(now: Long): List<ChatSummary> {
        val contacts = contacts()
        return contacts.map { c ->
            val last = db.queryOne(
                "SELECT m.id, m.ciphertext, mk.key, m.ts, m.outgoing, m.status, m.view_once, m.kind, mk.bucket, m.sender_key FROM messages m " +
                    "JOIN message_keys mk ON mk.message_id = m.id " +
                    // System lines ("You created the group") aren't conversation: the preview is the last real message.
                    "WHERE m.contact_id = ? AND m.kind = ? AND (m.expires_at IS NULL OR m.expires_at > ?) ORDER BY m.ts DESC LIMIT 1",
                c.id, MsgKind.TEXT, now,
            ) { cur ->
                val body = if (cur.getInt(6) != 0) {
                    "View-once message"
                } else {
                    openBody(cur.getString(0), cur.getBlob(2), cur.getBlob(1), if (cur.isNull(8)) null else cur.getLong(8))
                }
                ChatSummary(c, body, cur.getLong(3), cur.getInt(4) != 0, cur.getInt(5), if (cur.isNull(9)) null else cur.getString(9))
            }
            last ?: ChatSummary(c, null, null, false, 0)
        }
    }

    // --- messages ---

    private fun openBody(id: String, key: ByteArray, ct: ByteArray, bucket: Long?): String = try {
        vault.open(id, key, ct, bucket).toString(Charsets.UTF_8)
    } catch (e: Exception) {
        ""
    }

    private val msgCols =
        "m.id, m.contact_id, m.wire_id, m.outgoing, m.kind, m.ciphertext, mk.key, m.ts, m.received_at, m.read_at, m.exp_secs, m.view_once, m.expires_at, m.status, mk.bucket, " +
            "m.sender_key, m.recipients"

    private fun message(c: Cursor, known: Map<String, String>? = null): Message {
        val id = c.getString(0)
        return Message(
            id = id,
            contactId = c.getLong(1),
            wireId = c.getString(2),
            outgoing = c.getInt(3) != 0,
            kind = c.getInt(4),
            body = known?.get(id) ?: openBody(id, c.getBlob(6), c.getBlob(5), if (c.isNull(14)) null else c.getLong(14)),
            ts = c.getLong(7),
            receivedAt = if (c.isNull(8)) null else c.getLong(8),
            readAt = if (c.isNull(9)) null else c.getLong(9),
            expSecs = c.getLong(10),
            viewOnce = c.getInt(11) != 0,
            expiresAt = if (c.isNull(12)) null else c.getLong(12),
            status = c.getInt(13),
            senderKey = if (c.isNull(15)) null else c.getString(15),
            recipients = c.getInt(16),
        )
    }

    /**
     * Expired messages are filtered at query time, so nothing expired is ever shown even if the sweeper is late.
     * [known] holds bodies the caller already decrypted (a message's body never changes), so re-querying an open chat
     * after a status change only decrypts new messages.
     */
    fun messages(contactId: Long, now: Long, limit: Int = 500, known: Map<String, String>? = null): List<Message> = db.query(
        "SELECT $msgCols FROM messages m JOIN message_keys mk ON mk.message_id = m.id " +
            "WHERE m.contact_id = ? AND (m.expires_at IS NULL OR m.expires_at > ?) ORDER BY m.ts DESC, m.rowid DESC LIMIT ?",
        contactId, now, limit,
    ) { message(it, known) }

    fun message(id: String): Message? = db.queryOne(
        "SELECT $msgCols FROM messages m JOIN message_keys mk ON mk.message_id = m.id WHERE m.id = ?", id,
    ) { message(it) }

    fun messageByWire(contactId: Long, wireId: String, outgoing: Boolean): Message? = db.queryOne(
        "SELECT $msgCols FROM messages m JOIN message_keys mk ON mk.message_id = m.id WHERE m.contact_id = ? AND m.wire_id = ? AND m.outgoing = ?",
        contactId, wireId, outgoing,
    ) { message(it) }

    /** Returns the local id, or null if the message already exists (dedupe). */
    fun insertMessage(
        contactId: Long,
        wireId: String,
        outgoing: Boolean,
        kind: Int,
        body: String,
        ts: Long,
        receivedAt: Long?,
        expSecs: Long,
        viewOnce: Boolean,
        expiresAt: Long?,
        status: Int,
        senderKey: String? = null,
        recipients: Int = 0,
    ): String? {
        if (db.long("SELECT COUNT(*) FROM messages WHERE contact_id = ? AND wire_id = ? AND outgoing = ?", contactId, wireId, outgoing) > 0) {
            return null
        }
        // A re-send of one that was viewed, deleted or expired here: it stays gone.
        if (!outgoing && db.long(
                "SELECT COUNT(*) FROM gone_incoming WHERE contact_id = ? AND wire_id = ? AND until > ?", contactId, wireId, System.currentTimeMillis(),
            ) > 0
        ) {
            return null
        }
        val id = B64.enc(Rand.bytes(16))
        db.tx {
            // Sealed inside the transaction, so a root rotation (which holds the database meanwhile) can't slip in between
            // sealing under the old root and storing the row.
            val sealed = vault.seal(id, body.toByteArray(Charsets.UTF_8), expiresAt)
            db.exec(
                "INSERT INTO messages (id, contact_id, wire_id, outgoing, kind, ciphertext, ts, received_at, exp_secs, view_once, expires_at, status, " +
                    "sender_key, recipients) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                id, contactId, wireId, outgoing, kind, sealed.ciphertext, ts, receivedAt, expSecs, viewOnce, expiresAt, status, senderKey, recipients,
            )
            db.exec("INSERT INTO message_keys (message_id, key, bucket) VALUES (?, ?, ?)", id, sealed.wrappedKey, sealed.bucket)
        }
        return id
    }

    fun setStatus(id: String, status: Int) = db.exec("UPDATE messages SET status = ? WHERE id = ?", status, id)

    /** Raises status for outgoing messages identified by wire ids (receipts never lower it). */
    fun raiseStatus(contactId: Long, wireIds: List<String>, status: Int) {
        for (w in wireIds) {
            db.exec(
                "UPDATE messages SET status = ? WHERE contact_id = ? AND wire_id = ? AND outgoing = 1 AND status < ? AND status != ?",
                status, contactId, w, status, MsgStatus.FAILED,
            )
        }
    }

    /** Marks incoming messages read, starting start-on-read timers. Returns the wire ids that were newly read. */
    fun markRead(contactId: Long, now: Long): List<String> {
        val unread = db.query(
            "SELECT id, wire_id, exp_secs FROM messages WHERE contact_id = ? AND outgoing = 0 AND read_at IS NULL AND kind = ?",
            contactId, MsgKind.TEXT,
        ) { Triple(it.getString(0), it.getString(1), it.getLong(2)) }
        if (unread.isEmpty()) {
            return emptyList()
        }
        db.tx {
            for ((id, _, exp) in unread) {
                val startsNow = exp > 0 && db.long("SELECT COUNT(*) FROM messages WHERE id = ? AND expires_at IS NULL", id) > 0
                db.exec(
                    "UPDATE messages SET read_at = ?, expires_at = CASE WHEN expires_at IS NULL AND ? > 0 THEN ? ELSE expires_at END WHERE id = ?",
                    now, exp, now + exp * 1000, id,
                )
                if (startsNow) {
                    // The timer just started: move the key into its expiry bucket so it's destroyed on time, even while locked.
                    rewrapForExpiry(id, now + exp * 1000)
                }
            }
            clearUnread(contactId)
        }
        return unread.map { it.second }
    }

    private fun rewrapForExpiry(id: String, expiresAt: Long) {
        val row = db.queryOne("SELECT key, bucket FROM message_keys WHERE message_id = ?", id) {
            it.getBlob(0) to (if (it.isNull(1)) null else it.getLong(1))
        } ?: return
        val (wk, bucket) = vault.rewrap(id, row.first, row.second, expiresAt) ?: return
        db.exec("UPDATE message_keys SET key = ?, bucket = ? WHERE message_id = ?", wk, bucket, id)
    }

    /** After bulk deletes, an idle VACUUM rewrites the file so freed pages don't linger (see MaintenanceWorker). */
    fun markNeedsVacuum() = kvPutString("needs_vacuum", "1")

    fun vacuumIfNeeded() {
        if (kvString("needs_vacuum") == "1") {
            kvPutString("needs_vacuum", null)
            db.exec("VACUUM")
        }
    }

    /**
     * Called after messages were deleted, so the message root key is rotated soon (core/Shredder). Until then, stale
     * copies of the deleted rows in flash would still open with it.
     */
    @Volatile
    var onMessagesDeleted: (() -> Unit)? = null

    /** Messages were deleted since the message root key was last rotated. Kept in the DB, so a rotation is never lost. */
    val shredPending: Boolean
        get() = kvString(KV_SHRED_PENDING) != null

    private fun deleted() {
        kvPutString(KV_SHRED_PENDING, "1")
    }

    /**
     * Remembers the wire ids of the incoming messages that [where] (a condition on `messages`) selects, so a re-send of one
     * doesn't bring it back. Called just before they're deleted.
     */
    private fun tombstone(where: String, vararg args: Any?) = db.exec(
        "INSERT OR REPLACE INTO gone_incoming (contact_id, wire_id, until) " +
            "SELECT contact_id, wire_id, ? FROM messages WHERE outgoing = 0 AND kind = ${MsgKind.TEXT} AND ($where)",
        System.currentTimeMillis() + GONE_KEEP_MS, *args,
    )

    fun deleteMessage(id: String) {
        db.tx {
            tombstone("id = ?", id)
            db.exec("DELETE FROM group_receipts WHERE message_id = ?", id)
            db.exec("DELETE FROM message_keys WHERE message_id = ?", id)
            db.exec("DELETE FROM outbox WHERE message_id = ?", id)
            db.exec("DELETE FROM messages WHERE id = ?", id)
            deleted()
        }
        onMessagesDeleted?.invoke()
    }

    /**
     * Rotates the message root key: everything still wrapped or sealed under it is re-wrapped under [next], [store]
     * saves the new root, and the vault switches to it, all in one transaction. Stale copies of deleted rows stay under
     * the old root, which the caller then destroys. On success the vault owns [next]; if this throws, nothing changed.
     */
    fun rotateMessageRoot(next: ByteArray, store: () -> Unit) {
        var undo: (() -> Unit)? = null
        try {
            db.tx {
                val keys = db.query("SELECT message_id, key FROM message_keys WHERE bucket IS NULL") { it.getString(0) to it.getBlob(1) }
                for ((id, wk) in keys) {
                    // A key that doesn't open is unreadable either way, so it's left as it is.
                    vault.rewrapUnder(next, id, wk)?.let { db.exec("UPDATE message_keys SET key = ? WHERE message_id = ?", it, id) }
                }
                val chunks = db.query("SELECT contact_id, wire_id, part, body FROM chunks") {
                    Triple(it.getLong(0), it.getString(1), it.getInt(2)) to it.getBlob(3)
                }
                for ((at, body) in chunks) {
                    val (cid, wire, part) = at
                    vault.resealUnder(next, "chunk/$cid/$wire/$part", body)?.let {
                        db.exec("UPDATE chunks SET body = ? WHERE contact_id = ? AND wire_id = ? AND part = ?", it, cid, wire, part)
                    }
                }
                // Held messages whose key couldn't go in an expiry bucket are wrapped by the root like a message key.
                val held = db.query("SELECT id, key FROM held_incoming WHERE bucket IS NULL") { it.getString(0) to it.getBlob(1) }
                for ((id, wk) in held) {
                    vault.rewrapUnder(next, "held/$id", wk)?.let { db.exec("UPDATE held_incoming SET key = ? WHERE id = ?", it, id) }
                }
                val outbox = db.query("SELECT seq, content FROM outbox WHERE content IS NOT NULL") { it.getLong(0) to it.getBlob(1) }
                for ((seq, content) in outbox) {
                    vault.resealUnder(next, "outbox", content)?.let { db.exec("UPDATE outbox SET content = ? WHERE seq = ?", it, seq) }
                }
                store()
                kvPutString(KV_SHRED_PENDING, null)
                undo = vault.replaceRoot(next)
            }
        } catch (e: Exception) {
            undo?.invoke()
            throw e
        }
    }

    fun deleteIncomingByWire(contactId: Long, wireIds: List<String>) {
        for (w in wireIds) {
            val id = db.queryOne("SELECT id FROM messages WHERE contact_id = ? AND wire_id = ? AND outgoing = 0", contactId, w) { it.getString(0) }
            if (id != null) {
                deleteMessage(id)
            }
        }
    }

    /** Crypto-shred every expired message. Returns the number removed. */
    fun deleteExpired(now: Long): Int {
        val ids = db.query("SELECT id FROM messages WHERE expires_at IS NOT NULL AND expires_at <= ?", now) { it.getString(0) }
        for (id in ids) {
            deleteMessage(id)
        }
        db.exec("DELETE FROM chunks WHERE created_at < ?", now - 7 * 24 * 3600_000L)
        // Held messages go on the chat's timer like any other.
        db.exec("DELETE FROM held_incoming WHERE expires_at <= ?", now)
        db.exec("DELETE FROM gone_incoming WHERE until <= ?", now)
        if (ids.size >= 20) {
            markNeedsVacuum()
        }
        return ids.size
    }

    fun nextExpiry(): Long? = db.queryOne(
        "SELECT MIN(e) FROM (SELECT MIN(expires_at) AS e FROM messages WHERE expires_at IS NOT NULL " +
            "UNION ALL SELECT MIN(expires_at) AS e FROM held_incoming)",
    ) {
        if (it.isNull(0)) null else it.getLong(0)
    }

    /** Deletes a chat's messages with their keys, and its message content that is still queued, partial or held. */
    fun clearConversation(contactId: Long) {
        db.tx {
            tombstone("contact_id = ?", contactId)
            // Messages held behind a changed safety number are this chat's messages too.
            db.exec("DELETE FROM held_incoming WHERE contact_id = ?", contactId)
            db.exec("DELETE FROM group_receipts WHERE message_id IN (SELECT id FROM messages WHERE contact_id = ?)", contactId)
            db.exec("DELETE FROM message_keys WHERE message_id IN (SELECT id FROM messages WHERE contact_id = ?)", contactId)
            // Unsent copies hold the plaintext sealed only under the message root key, which outlives the clear.
            db.exec("DELETE FROM outbox WHERE message_id IN (SELECT id FROM messages WHERE contact_id = ?)", contactId)
            db.exec("DELETE FROM chunks WHERE contact_id = ?", contactId)
            db.exec("DELETE FROM group_held WHERE cid = ?", contactId)
            db.exec("DELETE FROM messages WHERE contact_id = ?", contactId)
            deleted()
        }
        onMessagesDeleted?.invoke()
    }

    /**
     * Deletes every message and its key, and the messages held behind a changed safety number (a pending change stays
     * pending, with nothing left to deliver). The contacts and sessions stay.
     */
    fun wipeAllMessages() {
        db.tx {
            tombstone("1")
            db.exec("DELETE FROM held_incoming")
            db.exec("DELETE FROM group_receipts")
            db.exec("DELETE FROM message_keys")
            db.exec("DELETE FROM messages")
            db.exec("DELETE FROM chunks")
            // Undelivered group messages that arrived before their sender's roster are messages too.
            db.exec("DELETE FROM group_held")
            // Group membership traffic (rosters, cards) isn't a message: keep it so the groups stay consistent.
            db.exec("DELETE FROM outbox WHERE kind = ? AND (member_key IS NULL OR message_id IS NOT NULL)", OutboxKind.CONTENT)
            db.exec("UPDATE contacts SET unread = 0")
            db.exec("DELETE FROM kv WHERE k LIKE 'bk/%'")
            deleted()
        }
        markNeedsVacuum()
        onMessagesDeleted?.invoke()
    }

    /**
     * Outgoing text messages still awaiting a delivery receipt after [olderThan], and sent after [notBefore]. The window is
     * bounded so that the recipient's tombstones ([GONE_KEEP_MS]) outlast every re-send.
     */
    fun unreceipted(olderThan: Long, notBefore: Long, maxResends: Int): List<Message> = db.query(
        "SELECT $msgCols FROM messages m JOIN message_keys mk ON mk.message_id = m.id " +
            "WHERE m.outgoing = 1 AND m.kind = ? AND m.status = ? AND m.ts < ? AND m.ts > ? AND m.resend_count < ? " +
            "AND NOT EXISTS (SELECT 1 FROM outbox o WHERE o.message_id = m.id)",
        MsgKind.TEXT, MsgStatus.SENT, olderThan, notBefore, maxResends,
    ) { message(it) }

    fun incrementResend(id: String) = db.exec("UPDATE messages SET resend_count = resend_count + 1 WHERE id = ?", id)

    // --- chunks ---

    fun storeChunk(contactId: Long, wireId: String, part: Int, parts: Int, body: String) = db.tx {
        // Bounded per contact: a hostile peer can't fill storage with chunks that never complete.
        if (db.long("SELECT COUNT(*) FROM chunks WHERE contact_id = ?", contactId) >= MAX_CHUNKS_PER_CONTACT) {
            db.exec(
                "DELETE FROM chunks WHERE contact_id = ? AND created_at = (SELECT MIN(created_at) FROM chunks WHERE contact_id = ?)",
                contactId, contactId,
            )
        }
        // Sealed and stored in one transaction, like insertMessage, so a root rotation can't come in between.
        val sealed = vault.sealBlob("chunk/$contactId/$wireId/$part", body.toByteArray(Charsets.UTF_8))
        db.exec(
            "INSERT OR REPLACE INTO chunks (contact_id, wire_id, part, parts, body, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            contactId, wireId, part, parts, sealed, System.currentTimeMillis(),
        )
    }

    /** Returns the reassembled body when every part has arrived, deleting the chunks. Otherwise returns null. */
    fun assembleChunks(contactId: Long, wireId: String, parts: Int): String? {
        val rows = db.query("SELECT part, body FROM chunks WHERE contact_id = ? AND wire_id = ? ORDER BY part", contactId, wireId) {
            it.getInt(0) to it.getBlob(1)
        }
        if (rows.size != parts || rows.map { it.first } != (0 until parts).toList()) {
            return null
        }
        val sb = StringBuilder()
        for ((part, blob) in rows) {
            sb.append(vault.openBlob("chunk/$contactId/$wireId/$part", blob).toString(Charsets.UTF_8))
        }
        db.exec("DELETE FROM chunks WHERE contact_id = ? AND wire_id = ?", contactId, wireId)
        return sb.toString()
    }

    // --- mailboxes ---

    private fun mailbox(c: Cursor) = Mailbox(
        id = c.getLong(0),
        contactId = if (c.isNull(1)) null else c.getLong(1),
        purpose = c.getInt(2),
        sendSecret = c.getBlob(3),
        ownerSecret = c.getBlob(4),
        tag = c.getBlob(5),
        state = c.getInt(6),
        expiresAt = if (c.isNull(7)) null else c.getString(7),
        createdAt = c.getLong(8),
        inviteUsed = c.getInt(9) != 0,
        inviteExpiresAt = if (c.isNull(10)) null else c.getLong(10),
        replacedAt = if (c.isNull(11)) null else c.getLong(11),
        drainUntil = if (c.isNull(12)) null else c.getLong(12),
        inviteSpkId = if (c.isNull(13)) null else c.getInt(13),
        inviteKyberId = if (c.isNull(14)) null else c.getInt(14),
        hintKey = if (c.isNull(15)) null else c.getBlob(15),
        wrapKey = if (c.isNull(16)) null else c.getBlob(16),
    )

    private val mbCols =
        "id, contact_id, purpose, send_secret, owner_secret, tag, state, expires_at, created_at, invite_used, invite_expires_at, " +
            "replaced_at, drain_until, invite_spk_id, invite_kyber_id, hint_key, wrap_key"

    /** Binds a claimed mailbox to a group as its inbox, with its hint key. */
    fun bindGroupInbox(id: Long, groupCid: Long, hintKey: ByteArray) = db.exec(
        "UPDATE mailboxes SET contact_id = ?, invite_used = 1, purpose = ?, hint_key = ?, created_at = ? WHERE id = ?",
        groupCid, Mailbox.PURPOSE_GROUP, hintKey, System.currentTimeMillis(), id,
    )

    /** A group inbox replaced by a fresh one: it keeps receiving until in-flight messages (max TTL) have arrived, then goes. */
    fun retireGroupInbox(id: Long, now: Long, drainUntil: Long) =
        db.exec("UPDATE mailboxes SET replaced_at = ?, drain_until = ? WHERE id = ?", now, drainUntil, id)

    fun mailboxByTag(tag: ByteArray): Mailbox? = db.queryOne("SELECT $mbCols FROM mailboxes WHERE tag = ?", tag, map = ::mailbox)

    fun mailbox(id: Long): Mailbox? = db.queryOne("SELECT $mbCols FROM mailboxes WHERE id = ?", id, map = ::mailbox)

    /** The contact's current inbound mailbox (the newest one that hasn't been replaced). */
    fun mailboxForContact(contactId: Long): Mailbox? = db.queryOne(
        "SELECT $mbCols FROM mailboxes WHERE contact_id = ? AND replaced_at IS NULL ORDER BY id DESC LIMIT 1",
        contactId, map = ::mailbox,
    )

    // --- rotation ---

    fun markReplaced(id: Long, at: Long) = db.exec("UPDATE mailboxes SET replaced_at = ? WHERE id = ? AND replaced_at IS NULL", at, id)

    /** Once the contact uses the new mailbox, older ones only need to live until in-flight messages (max TTL) have arrived. */
    fun startDraining(contactId: Long, newerThanId: Long, until: Long) = db.exec(
        "UPDATE mailboxes SET drain_until = ? WHERE contact_id = ? AND replaced_at IS NOT NULL AND drain_until IS NULL AND id < ?",
        until, contactId, newerThanId,
    )

    fun drainedMailboxes(now: Long): List<Mailbox> =
        db.query("SELECT $mbCols FROM mailboxes WHERE drain_until IS NOT NULL AND drain_until < ?", now, map = ::mailbox)

    /** Contacts whose current mailbox is older than [before] and whose previous rotation has finished. */
    fun contactsDueForRotation(before: Long): List<Long> = db.query(
        """SELECT m.contact_id FROM mailboxes m JOIN contacts c ON c.id = m.contact_id
           WHERE m.replaced_at IS NULL AND m.state = ? AND m.created_at < ? AND c.out_secret IS NOT NULL
             AND NOT EXISTS (SELECT 1 FROM mailboxes o WHERE o.contact_id = m.contact_id AND o.replaced_at IS NOT NULL AND o.drain_until IS NULL)""",
        Mailbox.STATE_ACTIVE, before,
    ) { it.getLong(0) }

    fun allMailboxes(): List<Mailbox> = db.query("SELECT $mbCols FROM mailboxes", map = ::mailbox)

    fun activeMailboxes(): List<Mailbox> = db.query("SELECT $mbCols FROM mailboxes WHERE state = ?", Mailbox.STATE_ACTIVE, map = ::mailbox)

    /** Unbound, active, not-yet-advertised mailboxes, ready to back a new invite or contact. */
    fun pooledMailboxes(): List<Mailbox> = db.query(
        "SELECT $mbCols FROM mailboxes WHERE contact_id IS NULL AND invite_used = 0 AND state = ? ORDER BY id",
        Mailbox.STATE_ACTIVE, map = ::mailbox,
    )

    fun pendingCount(): Long = db.long(
        "SELECT COUNT(*) FROM mailboxes WHERE contact_id IS NULL AND invite_used = 0 AND state != ?", Mailbox.STATE_ACTIVE,
    )

    /** A new mailbox row, with a fresh wrap key: it goes out with the sendSecret, to whoever may send to it. */
    fun insertMailbox(purpose: Int, sendSecret: ByteArray, ownerSecret: ByteArray, tag: ByteArray): Long = db.insert(
        "INSERT INTO mailboxes (purpose, send_secret, owner_secret, tag, state, created_at, wrap_key) VALUES (?, ?, ?, ?, ?, ?, ?)",
        purpose, sendSecret, ownerSecret, tag, Mailbox.STATE_CREATING, System.currentTimeMillis(), app.goldfishsend.proto.BlobWrap.newKey(),
    )

    fun setMailboxState(id: Long, state: Int, expiresAt: String? = null) {
        if (expiresAt != null) {
            db.exec("UPDATE mailboxes SET state = ?, expires_at = ? WHERE id = ?", state, expiresAt, id)
        } else {
            db.exec("UPDATE mailboxes SET state = ? WHERE id = ?", state, id)
        }
    }

    fun setMailboxExpiry(id: Long, expiresAt: String) = db.exec("UPDATE mailboxes SET expires_at = ? WHERE id = ?", expiresAt, id)

    fun bindMailbox(id: Long, contactId: Long) =
        db.exec("UPDATE mailboxes SET contact_id = ?, invite_used = 1, created_at = ? WHERE id = ?", contactId, System.currentTimeMillis(), id)

    /**
     * Atomically claims a ready pool mailbox for [purpose], so two invites (or an invite and a new contact) can never
     * share one. Returns null if the pool is empty.
     */
    fun claimPoolMailbox(purpose: Int, provisionalExpiry: Long): Mailbox? = db.tx {
        var claimed: Mailbox? = null
        for (m in pooledMailboxes()) {
            if (claimMailbox(m.id, purpose, provisionalExpiry)) {
                claimed = mailbox(m.id)
                break
            }
        }
        claimed
    }

    /** Claims a specific unclaimed mailbox. False if someone else got it first. */
    fun claimMailbox(id: Long, purpose: Int, provisionalExpiry: Long): Boolean = db.update(
        "UPDATE mailboxes SET invite_used = 1, purpose = ?, invite_expires_at = ? WHERE id = ? AND invite_used = 0 AND contact_id IS NULL",
        purpose, provisionalExpiry, id,
    ) == 1

    /** Returns a claimed but never-advertised mailbox to the pool (the invite upload failed). */
    fun releasePoolMailbox(id: Long) = db.exec(
        "UPDATE mailboxes SET invite_used = 0, invite_expires_at = NULL, invite_spk_id = NULL, invite_kyber_id = NULL " +
            "WHERE id = ? AND contact_id IS NULL",
        id,
    )

    fun setInvitePrekeys(id: Long, spkId: Int, kyberId: Int) =
        db.exec("UPDATE mailboxes SET invite_spk_id = ?, invite_kyber_id = ? WHERE id = ?", spkId, kyberId, id)

    fun markInviteUsed(id: Long, expiresAt: Long) =
        db.exec("UPDATE mailboxes SET invite_used = 1, invite_expires_at = ? WHERE id = ?", expiresAt, id)

    fun deleteMailboxRow(id: Long) = db.exec("DELETE FROM mailboxes WHERE id = ?", id)

    // --- mailboxes still to delete on the server ---

    /**
     * Drops the rows of [boxes] and records them as doomed on [server] (our server, pinned to [serverKey]), in one
     * transaction: they're deleted there later, retried until it confirms ([DoomedMailbox]).
     */
    fun doomMailboxes(boxes: List<Mailbox>, server: String, serverKey: String?) = db.tx {
        val now = System.currentTimeMillis()
        for (b in boxes) {
            db.exec(
                "INSERT OR REPLACE INTO doomed_mailboxes (send_secret, owner_secret, server, server_key, created_at) VALUES (?, ?, ?, ?, ?)",
                b.sendSecret, b.ownerSecret, server, serverKey, now,
            )
            db.exec("DELETE FROM mailboxes WHERE id = ?", b.id)
        }
    }

    fun doomedMailboxes(): List<DoomedMailbox> = db.query(
        "SELECT send_secret, owner_secret, server, server_key, created_at FROM doomed_mailboxes ORDER BY created_at",
    ) { DoomedMailbox(it.getBlob(0), it.getBlob(1), it.getString(2), if (it.isNull(3)) null else it.getString(3), it.getLong(4)) }

    /** The server confirmed (or it can't hold the mailbox any more). */
    fun forgetDoomed(sendSecret: ByteArray) = db.exec("DELETE FROM doomed_mailboxes WHERE send_secret = ?", sendSecret)

    fun forgetDoomedBefore(t: Long) = db.exec("DELETE FROM doomed_mailboxes WHERE created_at < ?", t)

    /** Mailboxes advertised in an invite that expired without anyone using it. */
    fun abandonedInviteMailboxes(now: Long): List<Mailbox> = db.query(
        "SELECT $mbCols FROM mailboxes WHERE contact_id IS NULL AND invite_used = 1 AND invite_expires_at IS NOT NULL AND invite_expires_at < ?",
        now, map = ::mailbox,
    )

    fun staleCreating(before: Long): List<Mailbox> = db.query(
        "SELECT $mbCols FROM mailboxes WHERE state != ? AND created_at < ? AND contact_id IS NULL",
        Mailbox.STATE_ACTIVE, before, map = ::mailbox,
    )

    // --- rotations ---

    fun addRotation(tag: ByteArray, ids: List<Long>) = db.exec(
        "INSERT OR REPLACE INTO rotations (tag, mailbox_ids, created_at) VALUES (?, ?, ?)",
        tag, ids.joinToString(","), System.currentTimeMillis(),
    )

    fun rotation(tag: ByteArray): List<Long>? =
        db.queryOne("SELECT mailbox_ids FROM rotations WHERE tag = ?", tag) { c -> c.getString(0).split(',').filter { it.isNotEmpty() }.map { it.toLong() } }

    fun deleteRotation(tag: ByteArray) = db.exec("DELETE FROM rotations WHERE tag = ?", tag)

    fun clearRotations() = db.exec("DELETE FROM rotations")

    /** When the newest rotation still waiting for its verification push was sent, or null if none is waiting. */
    fun rotationsPendingSince(): Long? =
        db.queryOne("SELECT MAX(created_at) FROM rotations") { c -> if (c.isNull(0)) null else c.getLong(0) }

    // --- outbox ---

    fun enqueue(contactId: Long, messageId: String?, kind: Int, content: ByteArray?, memberKey: String? = null): Long {
        val now = System.currentTimeMillis()
        // Sealed and stored in one transaction, like insertMessage, so a root rotation can't come in between.
        return db.tx {
            val sealed = content?.let { vault.sealBlob("outbox", it) }
            db.insert(
                "INSERT INTO outbox (contact_id, message_id, kind, content, idem, next_at, created_at, member_key) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                contactId, messageId, kind, sealed, Rand.bytes(16), now, now, memberKey,
            )
        }
    }

    fun openOutboxContent(item: OutboxItem): ByteArray? = item.content?.let { vault.openBlob("outbox", it) }

    private fun outbox(c: Cursor) = OutboxItem(
        seq = c.getLong(0),
        contactId = c.getLong(1),
        messageId = if (c.isNull(2)) null else c.getString(2),
        kind = c.getInt(3),
        content = if (c.isNull(4)) null else c.getBlob(4),
        blob = if (c.isNull(5)) null else c.getBlob(5),
        idem = c.getBlob(6),
        attempts = c.getInt(7),
        nextAt = c.getLong(8),
        memberKey = if (c.isNull(9)) null else c.getString(9),
    )

    private val outboxCols = "seq, contact_id, message_id, kind, content, blob, idem, attempts, next_at, member_key"

    fun outboxAll(): List<OutboxItem> = db.query("SELECT $outboxCols FROM outbox ORDER BY contact_id, seq", map = ::outbox)

    fun outboxFor(contactId: Long): List<OutboxItem> =
        db.query("SELECT $outboxCols FROM outbox WHERE contact_id = ? ORDER BY seq", contactId, map = ::outbox)

    /** Drops every queued row to one group member (removed, left, or their inbox is gone). Returns the affected message ids. */
    fun outboxDropMember(contactId: Long, memberKey: String): List<String> {
        val ids = db.query(
            "SELECT DISTINCT message_id FROM outbox WHERE contact_id = ? AND member_key = ? AND message_id IS NOT NULL", contactId, memberKey,
        ) { it.getString(0) }
        db.exec("DELETE FROM outbox WHERE contact_id = ? AND member_key = ?", contactId, memberKey)
        return ids
    }

    fun outboxSetBlob(seq: Long, blob: ByteArray) = db.exec("UPDATE outbox SET blob = ?, content = NULL WHERE seq = ?", blob, seq)

    fun outboxBackoff(seq: Long, attempts: Int, nextAt: Long) =
        db.exec("UPDATE outbox SET attempts = ?, next_at = ? WHERE seq = ?", attempts, nextAt, seq)

    fun outboxDelete(seq: Long) = db.exec("DELETE FROM outbox WHERE seq = ?", seq)

    fun outboxRemaining(messageId: String): Long = db.long("SELECT COUNT(*) FROM outbox WHERE message_id = ?", messageId)

    /** Messages of a chat whose sending failed at least once and is waiting to be retried. */
    fun waitingMessageIds(contactId: Long): Set<String> = db.query(
        "SELECT DISTINCT message_id FROM outbox WHERE contact_id = ? AND message_id IS NOT NULL AND attempts > 0", contactId,
    ) { it.getString(0) }.toSet()

    fun outboxRetryNow(contactId: Long, now: Long) = db.exec("UPDATE outbox SET next_at = ? WHERE contact_id = ? AND next_at > ?", now, contactId, now)

    fun outboxEarliest(): Long? = db.queryOne("SELECT MIN(next_at) FROM outbox") { if (it.isNull(0)) null else it.getLong(0) }
}
