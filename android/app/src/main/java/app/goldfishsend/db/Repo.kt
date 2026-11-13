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
) {
    val ready: Boolean
        get() = outServer != null && outSecret != null
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
) {
    companion object {
        const val PURPOSE_QR = 0
        const val PURPOSE_LINK = 1
        const val PURPOSE_CONTACT = 2

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
)

data class ChatSummary(val contact: Contact, val lastBody: String?, val lastTs: Long?, val lastOutgoing: Boolean, val lastStatus: Int)

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
)

/** Typed data access over [Db]. Message bodies are always stored through [MessageVault]. */
/** Incomplete chunked messages kept per contact (64 parts × 4 messages). */
const val MAX_CHUNKS_PER_CONTACT = 256L

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
    )

    private val contactCols =
        "id, name, identity_key, verified, timer_secs, out_server, out_secret, received_any, unreachable, created_at, last_activity, unread, " +
            "pending_identity, hidden, out_server_key, pending_server_key"

    fun contact(id: Long): Contact? = db.queryOne("SELECT $contactCols FROM contacts WHERE id = ?", id, map = ::contact)

    fun contacts(): List<Contact> = db.query("SELECT $contactCols FROM contacts ORDER BY last_activity DESC", map = ::contact)

    fun createContact(
        name: String,
        verified: Boolean,
        timerSecs: Long,
        outServer: String?,
        outSecret: ByteArray?,
        outServerKey: String? = null,
    ): Long {
        val now = System.currentTimeMillis()
        return db.insert(
            "INSERT INTO contacts (name, verified, timer_secs, out_server, out_secret, out_server_key, created_at, last_activity) " +
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            Sanitize.name(name) ?: "Contact", verified, timerSecs, outServer, outSecret, outServerKey, now, now,
        )
    }

    /**
     * Where to reach a contact, from their E2E-authenticated `hello` or `mailbox` message. [serverKey] replaces the pin
     * (and resolves a pending identity change). Without one, the pin is kept if the server didn't change, or is
     * learned on first use if it did.
     */
    fun updateContactOutbound(id: Long, server: String, secret: ByteArray, serverKey: String?) {
        val current = contact(id)
        val key = serverKey ?: current?.outServerKey?.takeIf { current.outServer == server }
        db.exec(
            "UPDATE contacts SET out_server = ?, out_secret = ?, out_server_key = ?, pending_server_key = NULL, unreachable = 0 WHERE id = ?",
            server, secret, key, id,
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

    fun setVerified(id: Long, v: Boolean) = db.exec("UPDATE contacts SET verified = ? WHERE id = ?", v, id)

    // --- identity changes ---

    fun setPendingIdentity(id: Long, key: ByteArray?) = db.exec("UPDATE contacts SET pending_identity = ? WHERE id = ?", key, id)

    /** Accepts a reviewed identity change: the new key becomes the contact's key, and they're no longer verified. */
    fun acceptPendingIdentity(id: Long, key: ByteArray) =
        db.exec("UPDATE contacts SET identity_key = ?, pending_identity = NULL, verified = 0 WHERE id = ?", key, id)

    fun holdIncoming(contactId: Long, tag: ByteArray, blob: ByteArray) {
        // Bounded: a flood from a hostile peer can't fill storage.
        if (db.queryOne("SELECT COUNT(*) FROM held_incoming WHERE contact_id = ?", contactId) { it.getLong(0) }!! >= 200) {
            return
        }
        db.insert("INSERT INTO held_incoming (contact_id, tag, blob, received_at) VALUES (?, ?, ?, ?)", contactId, tag, blob, System.currentTimeMillis())
    }

    fun heldIncoming(contactId: Long): List<Pair<ByteArray, ByteArray>> =
        db.query("SELECT tag, blob FROM held_incoming WHERE contact_id = ? ORDER BY id", contactId) { it.getBlob(0) to it.getBlob(1) }

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

    fun unverifiedCount(): Long = db.long("SELECT COUNT(*) FROM contacts WHERE verified = 0")

    /** Deletes the contact, all its messages (shredding keys first), session state and outbox rows. */
    fun deleteContact(id: Long) {
        db.tx {
            db.exec("DELETE FROM message_keys WHERE message_id IN (SELECT id FROM messages WHERE contact_id = ?)", id)
            db.exec("DELETE FROM messages WHERE contact_id = ?", id)
            db.exec("DELETE FROM chunks WHERE contact_id = ?", id)
            db.exec("DELETE FROM outbox WHERE contact_id = ?", id)
            db.exec("DELETE FROM sig_session WHERE address = ?", "c$id.1")
            db.exec("DELETE FROM sig_identity WHERE address = ?", "c$id.1")
            db.exec("DELETE FROM mailboxes WHERE contact_id = ?", id)
            db.exec("DELETE FROM contacts WHERE id = ?", id)
        }
    }

    fun chatSummaries(now: Long): List<ChatSummary> {
        val contacts = contacts()
        return contacts.map { c ->
            val last = db.queryOne(
                "SELECT m.id, m.ciphertext, mk.key, m.ts, m.outgoing, m.status, m.view_once, m.kind, mk.bucket FROM messages m JOIN message_keys mk ON mk.message_id = m.id " +
                    "WHERE m.contact_id = ? AND (m.expires_at IS NULL OR m.expires_at > ?) ORDER BY m.ts DESC LIMIT 1",
                c.id, now,
            ) { cur ->
                val body = if (cur.getInt(6) != 0) {
                    "View-once message"
                } else {
                    openBody(cur.getString(0), cur.getBlob(2), cur.getBlob(1), if (cur.isNull(8)) null else cur.getLong(8))
                }
                ChatSummary(c, body, cur.getLong(3), cur.getInt(4) != 0, cur.getInt(5))
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
        "m.id, m.contact_id, m.wire_id, m.outgoing, m.kind, m.ciphertext, mk.key, m.ts, m.received_at, m.read_at, m.exp_secs, m.view_once, m.expires_at, m.status, mk.bucket"

    private fun message(c: Cursor) = Message(
        id = c.getString(0),
        contactId = c.getLong(1),
        wireId = c.getString(2),
        outgoing = c.getInt(3) != 0,
        kind = c.getInt(4),
        body = openBody(c.getString(0), c.getBlob(6), c.getBlob(5), if (c.isNull(14)) null else c.getLong(14)),
        ts = c.getLong(7),
        receivedAt = if (c.isNull(8)) null else c.getLong(8),
        readAt = if (c.isNull(9)) null else c.getLong(9),
        expSecs = c.getLong(10),
        viewOnce = c.getInt(11) != 0,
        expiresAt = if (c.isNull(12)) null else c.getLong(12),
        status = c.getInt(13),
    )

    /** Expired messages are filtered at query time, so nothing expired is ever shown even if the sweeper is late. */
    fun messages(contactId: Long, now: Long, limit: Int = 500): List<Message> = db.query(
        "SELECT $msgCols FROM messages m JOIN message_keys mk ON mk.message_id = m.id " +
            "WHERE m.contact_id = ? AND (m.expires_at IS NULL OR m.expires_at > ?) ORDER BY m.ts DESC, m.rowid DESC LIMIT ?",
        contactId, now, limit, map = ::message,
    )

    fun message(id: String): Message? = db.queryOne(
        "SELECT $msgCols FROM messages m JOIN message_keys mk ON mk.message_id = m.id WHERE m.id = ?", id, map = ::message,
    )

    fun messageByWire(contactId: Long, wireId: String, outgoing: Boolean): Message? = db.queryOne(
        "SELECT $msgCols FROM messages m JOIN message_keys mk ON mk.message_id = m.id WHERE m.contact_id = ? AND m.wire_id = ? AND m.outgoing = ?",
        contactId, wireId, outgoing, map = ::message,
    )

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
    ): String? {
        if (db.long("SELECT COUNT(*) FROM messages WHERE contact_id = ? AND wire_id = ? AND outgoing = ?", contactId, wireId, outgoing) > 0) {
            return null
        }
        val id = B64.enc(Rand.bytes(16))
        val sealed = vault.seal(id, body.toByteArray(Charsets.UTF_8), expiresAt)
        db.tx {
            db.exec(
                "INSERT INTO messages (id, contact_id, wire_id, outgoing, kind, ciphertext, ts, received_at, exp_secs, view_once, expires_at, status) " +
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                id, contactId, wireId, outgoing, kind, sealed.ciphertext, ts, receivedAt, expSecs, viewOnce, expiresAt, status,
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

    fun deleteMessage(id: String) {
        db.tx {
            db.exec("DELETE FROM message_keys WHERE message_id = ?", id)
            db.exec("DELETE FROM outbox WHERE message_id = ?", id)
            db.exec("DELETE FROM messages WHERE id = ?", id)
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
        if (ids.size >= 20) {
            markNeedsVacuum()
        }
        return ids.size
    }

    fun nextExpiry(): Long? = db.queryOne("SELECT MIN(expires_at) FROM messages WHERE expires_at IS NOT NULL") {
        if (it.isNull(0)) null else it.getLong(0)
    }

    fun clearConversation(contactId: Long) {
        db.tx {
            db.exec("DELETE FROM message_keys WHERE message_id IN (SELECT id FROM messages WHERE contact_id = ?)", contactId)
            db.exec("DELETE FROM messages WHERE contact_id = ?", contactId)
        }
    }

    /** Deletes every message and its key. The contacts and sessions stay. */
    fun wipeAllMessages() {
        db.tx {
            db.exec("DELETE FROM message_keys")
            db.exec("DELETE FROM messages")
            db.exec("DELETE FROM chunks")
            db.exec("DELETE FROM outbox WHERE kind = ?", OutboxKind.CONTENT)
            db.exec("UPDATE contacts SET unread = 0")
            db.exec("DELETE FROM kv WHERE k LIKE 'bk/%'")
        }
        markNeedsVacuum()
    }

    /** Outgoing text messages still awaiting a delivery receipt after [olderThan]. */
    fun unreceipted(olderThan: Long, maxResends: Int): List<Message> = db.query(
        "SELECT $msgCols FROM messages m JOIN message_keys mk ON mk.message_id = m.id " +
            "WHERE m.outgoing = 1 AND m.kind = ? AND m.status = ? AND m.ts < ? AND m.resend_count < ? " +
            "AND NOT EXISTS (SELECT 1 FROM outbox o WHERE o.message_id = m.id)",
        MsgKind.TEXT, MsgStatus.SENT, olderThan, maxResends, map = ::message,
    )

    fun incrementResend(id: String) = db.exec("UPDATE messages SET resend_count = resend_count + 1 WHERE id = ?", id)

    // --- chunks ---

    fun storeChunk(contactId: Long, wireId: String, part: Int, parts: Int, body: String) {
        // Bounded per contact: a hostile peer can't fill storage with chunks that never complete.
        if (db.long("SELECT COUNT(*) FROM chunks WHERE contact_id = ?", contactId) >= MAX_CHUNKS_PER_CONTACT) {
            db.exec(
                "DELETE FROM chunks WHERE contact_id = ? AND created_at = (SELECT MIN(created_at) FROM chunks WHERE contact_id = ?)",
                contactId, contactId,
            )
        }
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
    )

    private val mbCols =
        "id, contact_id, purpose, send_secret, owner_secret, tag, state, expires_at, created_at, invite_used, invite_expires_at, " +
            "replaced_at, drain_until, invite_spk_id, invite_kyber_id"

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

    fun insertMailbox(purpose: Int, sendSecret: ByteArray, ownerSecret: ByteArray, tag: ByteArray): Long = db.insert(
        "INSERT INTO mailboxes (purpose, send_secret, owner_secret, tag, state, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        purpose, sendSecret, ownerSecret, tag, Mailbox.STATE_CREATING, System.currentTimeMillis(),
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

    // --- outbox ---

    fun enqueue(contactId: Long, messageId: String?, kind: Int, content: ByteArray?): Long {
        val now = System.currentTimeMillis()
        val sealed = content?.let { vault.sealBlob("outbox", it) }
        return db.insert(
            "INSERT INTO outbox (contact_id, message_id, kind, content, idem, next_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            contactId, messageId, kind, sealed, Rand.bytes(16), now, now,
        )
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
    )

    fun outboxAll(): List<OutboxItem> = db.query(
        "SELECT seq, contact_id, message_id, kind, content, blob, idem, attempts, next_at FROM outbox ORDER BY contact_id, seq", map = ::outbox,
    )

    fun outboxSetBlob(seq: Long, blob: ByteArray) = db.exec("UPDATE outbox SET blob = ?, content = NULL WHERE seq = ?", blob, seq)

    fun outboxBackoff(seq: Long, attempts: Int, nextAt: Long) =
        db.exec("UPDATE outbox SET attempts = ?, next_at = ? WHERE seq = ?", attempts, nextAt, seq)

    fun outboxDelete(seq: Long) = db.exec("DELETE FROM outbox WHERE seq = ?", seq)

    fun outboxRemaining(messageId: String): Long = db.long("SELECT COUNT(*) FROM outbox WHERE message_id = ?", messageId)

    fun outboxEarliest(): Long? = db.queryOne("SELECT MIN(next_at) FROM outbox") { if (it.isNull(0)) null else it.getLong(0) }
}
