package app.goldfishsend.core

import android.util.Log
import app.goldfishsend.crypto.BoundPrekeys
import app.goldfishsend.crypto.IdentityCheck
import app.goldfishsend.db.Mailbox
import app.goldfishsend.db.MsgKind
import app.goldfishsend.db.MsgStatus
import app.goldfishsend.db.OutboxKind
import app.goldfishsend.db.RESEND_WINDOW_MS
import app.goldfishsend.net.Gateway
import app.goldfishsend.net.ServerApi
import app.goldfishsend.proto.B64
import app.goldfishsend.proto.Chunker
import app.goldfishsend.proto.Content
import app.goldfishsend.proto.E2eBlob
import app.goldfishsend.proto.GroupBlob
import app.goldfishsend.db.memberRoutes
import app.goldfishsend.proto.Padding
import app.goldfishsend.proto.PushEnvelope
import app.goldfishsend.proto.Sanitize
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.sync.withLock
import org.signal.libsignal.protocol.DuplicateMessageException
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.state.IdentityKeyStore
import org.signal.libsignal.protocol.SessionCipher
import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.message.PreKeySignalMessage
import org.signal.libsignal.protocol.message.SignalMessage

/** Send/receive pipeline: push envelope → mailbox → libsignal → padded Content → handlers. */
object Messenger {
    private const val TAG = "Messenger"
    val LOCAL = SignalProtocolAddress("self", 1)

    fun remote(contactId: Long) = SignalProtocolAddress("c$contactId", 1)

    /** The chat currently on screen (null = none), so it isn't counted as unread or notified. */
    val openChat = MutableStateFlow<Long?>(null)

    private const val MAX_TIMER = 28 * 86400L

    /** The longest a message held behind a changed safety number is kept: as long as the server keeps one. */
    private const val HELD_MAX_MS = 14 * 86_400_000L

    // ---------- receive ----------

    /** Entry point for every decrypted UnifiedPush payload, with the UnifiedPush [instance] it arrived on. */
    suspend fun onPushPayload(bytes: ByteArray, instance: String) {
        val s = Graph.realSession ?: Graph.tryAutoUnlock()
        if (s == null) {
            // Kept for the next real unlock. No notification for one the inbox refused (it's gone), while a decoy profile
            // is on screen (it would give it away), or if the user chose silence while locked: the chat can't be told
            // apart yet, so that's the only way to keep hidden chats silent then too.
            val kept = LockedInbox.putPush(instance, bytes)
            if (kept && PushEnvelope.parse(bytes) is PushEnvelope.Message && Graph.session.value?.decoy != true && !Graph.prefs.quietWhileLocked) {
                Notifier.newMessage(Graph.app, null, null)
            }
            return
        }
        handle(s, bytes, instance)
    }

    suspend fun handle(s: Session, bytes: ByteArray, instance: String) {
        val env = PushEnvelope.parse(bytes) ?: return
        // Each mailbox is woken only through its own instance's endpoint. A push for another mailbox is dropped without a
        // reply, so the server can't learn which endpoints belong to one person by sending one mailbox's push (a
        // verification code, say) to another mailbox's endpoint and watching who answers.
        if (s.repo.mailboxByTag(env.tag)?.pushInstance != instance) {
            return
        }
        when (env) {
            is PushEnvelope.Verification -> Mailboxes.onVerification(s, env.tag, env.code)
            is PushEnvelope.Message -> receive(s, env.tag, env.blob)
        }
    }

    private class Decrypted(val contactId: Long, val content: Content, val newContact: Boolean)

    /** A PreKey message from an existing contact carried a different identity key than the one we trust. */
    private class IdentityChanged(val contactId: Long, val newKey: ByteArray) : Exception()

    /** One message. Whatever goes wrong with it, it's dropped and the next one is processed ([ReceiveGuard]). */
    private suspend fun receive(s: Session, tag: ByteArray, raw: ByteArray) {
        ReceiveGuard.runSuspend("message") { receiveOne(s, tag, raw) }
    }

    private suspend fun receiveOne(s: Session, tag: ByteArray, raw: ByteArray) {
        val mb = s.repo.mailboxByTag(tag) ?: return
        if (mb.purpose == Mailbox.PURPOSE_GROUP) {
            // A group inbox: only group blobs (docs/groups.md), from whichever member the sender hint names.
            if (GroupBlob.isGroup(raw)) {
                Groups.receive(s, mb, raw)
            }
            return
        }
        val blob = E2eBlob.decode(raw) ?: return
        val d = try {
            s.lock.withLock { decrypt(s, mb, blob) }
        } catch (e: DuplicateMessageException) {
            return
        } catch (e: IdentityChanged) {
            onIdentityChanged(s, e, tag, raw)
            return
        } catch (e: Exception) {
            Log.w(TAG, "dropping undecryptable message: ${e.javaClass.simpleName}")
            return
        } ?: return
        dispatch(s, d)
        Mailboxes.onMessageOnMailbox(s, s.repo.mailbox(mb.id) ?: mb)
        s.db.notifyChanged()
    }

    private fun decrypt(s: Session, mb: Mailbox, blob: E2eBlob): Decrypted? = s.db.tx {
        val newContact = mb.contactId == null
        if (newContact) {
            // A new contact may only appear on a mailbox that was advertised in an invite, using that invite's own
            // prekey. Pool or never-advertised mailboxes, or a hello re-tagged by a hostile relay onto another
            // mailbox, are rejected.
            if (blob.type != E2eBlob.PREKEY || !mb.inviteUsed || mb.inviteSpkId == null) {
                return@tx null
            }
            if (PreKeySignalMessage(blob.body).signedPreKeyId != mb.inviteSpkId) {
                return@tx null
            }
        }
        val cid = mb.contactId ?: s.repo.createContact(
            name = Invites.DEFAULT_NAME,
            // Never verified on the inviter's side: whoever showed the code can't tell who scanned it (a photo, a
            // shared screen). Only the scanner, who saw the code on the inviter's own phone, starts out verified.
            verified = false,
            timerSecs = Graph.prefs.defaultTimerSecs,
            outServer = null,
            outSecret = null,
        )
        val padded = if (blob.type == E2eBlob.PREKEY) {
            val m = PreKeySignalMessage(blob.body)
            // A session may only start from the prekeys this chat's own invite advertised (none, for a chat we started by
            // scanning). So a hello re-tagged onto an existing chat's mailbox, or one built from our group cards'
            // last-resort prekeys, can't take the chat over.
            val store = chatStore(s, if (newContact) listOf(mb) else s.repo.mailboxesForContact(cid))
            if (!newContact && !s.signal.isTrustedIdentity(remote(cid), m.identityKey, IdentityKeyStore.Direction.RECEIVING)) {
                // Only an authentic message counts as an identity change: it's checked in a scratch store first, so a
                // forged one is dropped here without recording anything.
                IdentityCheck.authenticate(store, LOCAL, remote(cid), m)
                throw IdentityChanged(cid, m.identityKey.serialize())
            }
            val pt = SessionCipher(store, LOCAL, remote(cid)).decrypt(m)
            if (newContact) {
                s.repo.setContactIdentity(cid, m.identityKey.serialize())
            }
            pt
        } else {
            SessionCipher(s.signal, LOCAL, remote(cid)).decrypt(SignalMessage(blob.body))
        }
        val content = Content.decode(Padding.unpad(padded))
        if (newContact) {
            // The first message on an invite mailbox must be hello; otherwise roll everything back.
            require(content is Content.Hello) { "first message must be hello" }
            s.repo.bindMailbox(mb.id, cid)
        }
        s.repo.setReceivedAny(cid)
        Decrypted(cid, content, newContact)
    }

    /** The store a 1:1 PreKey message is decrypted with: it lends only the prekeys that [boxes] advertised in invites. */
    private fun chatStore(s: Session, boxes: List<Mailbox>): BoundPrekeys {
        val signed = boxes.mapNotNull { it.inviteSpkId }.toSet()
        // Never a group card's last-resort prekey, even if a key id were ever reused.
        val kyber = boxes.mapNotNull { it.inviteKyberId }.filterNot { s.signal.isLastResort(it) }.toSet()
        return BoundPrekeys(s.signal, signed, kyber)
    }

    private suspend fun dispatch(s: Session, d: Decrypted) {
        val cid = d.contactId
        val c0 = d.content
        if (c0 is Content.Chunk) {
            // Any content split into parts (docs/groups.md, "Chunking"): reassemble, then handle the whole.
            if (c0.parts !in 2..Chunker.MAX_PARTS || c0.part !in 0 until c0.parts || c0.data.length > 4096) {
                return
            }
            val key = "k:" + c0.id.take(32)
            s.repo.storeChunk(cid, key, c0.part, c0.parts, c0.data)
            val joined = s.repo.assembleChunks(cid, key, c0.parts) ?: return
            val inner = runCatching { Content.decode(B64.dec(joined)) }.getOrNull() ?: return
            if (inner !is Content.Chunk && inner !is Content.Hello) {
                dispatch(s, Decrypted(cid, inner, false))
            }
            return
        }
        if (c0.groupId != null) {
            // Group content over our 1:1 session: invitations, forwarded cards, rosters while invited.
            Groups.onDirect(s, cid, c0)
            return
        }
        when (val c = c0) {
            is Content.Chunk, is Content.GText, is Content.GReceipt, is Content.GDelete, is Content.GState -> Unit
            is Content.Hello -> {
                val secret = runCatching { B64.dec(c.sendSecret) }.getOrNull()
                if (secret == null || secret.size != 32 || !ServerApi.isValidContactServer(c.server)) {
                    return
                }
                if (c.serverKey != null && !Gateway.isFingerprint(c.serverKey)) {
                    return
                }
                s.repo.updateContactOutbound(cid, c.server, secret, c.serverKey)
                val contact = s.repo.contact(cid)
                val name = Sanitize.name(c.name)
                if (name != null && contact?.name == Invites.DEFAULT_NAME) {
                    s.repo.renameContact(cid, name)
                }
                if (d.newContact) {
                    systemMessage(s, cid, "Messages are end-to-end encrypted.")
                    systemMessage(s, cid, "To make sure it's really them, compare safety numbers in their contact info.")
                    s.repo.touchContact(cid, false)
                    notify(s, cid, "Connected")
                }
                Graph.scope.launchSafe { Mailboxes.ensurePool(s) }
                Outbox.kick()
            }
            is Content.Text -> onText(s, cid, c)
            is Content.Receipt -> {
                val st = if (c.kind == Content.Receipt.READ) MsgStatus.READ else MsgStatus.DELIVERED
                s.repo.raiseStatus(cid, c.ids.take(500), st)
            }
            is Content.Timer -> {
                val secs = c.secs.coerceIn(0, MAX_TIMER)
                if (s.repo.contact(cid)?.timerSecs != secs) {
                    s.repo.setTimer(cid, secs)
                    systemMessage(s, cid, "Disappearing messages: ${timerLabel(secs)}")
                }
            }
            is Content.Delete -> {
                s.repo.deleteIncomingByWire(cid, c.ids.take(500))
                // The deleted text may still be in a notification.
                Notifier.cancel(Graph.app)
            }
            is Content.Mailbox -> {
                val secret = runCatching { B64.dec(c.sendSecret) }.getOrNull()
                val keyOk = c.serverKey == null || Gateway.isFingerprint(c.serverKey)
                if (secret != null && secret.size == 32 && keyOk && ServerApi.isValidContactServer(c.server)) {
                    // E2E-authenticated by the contact, so a new server fingerprint here resolves a pending identity change.
                    s.repo.updateContactOutbound(cid, c.server, secret, c.serverKey)
                    s.db.notifyChanged()
                    Outbox.kick()
                }
            }
        }
    }

    private suspend fun onText(s: Session, cid: Long, t: Content.Text) {
        val parts = t.parts ?: 1
        val body = if (parts > 1) {
            val part = t.part ?: return
            if (part !in 0 until parts || parts > 64) {
                return
            }
            s.repo.storeChunk(cid, t.id, part, parts, t.body)
            s.repo.assembleChunks(cid, t.id, parts) ?: return
        } else {
            t.body
        }
        val now = System.currentTimeMillis()
        // The chat's own timer is the ceiling: a contact can't make messages outlive it, or keep them forever.
        val exp = Sanitize.effectiveTimer(s.repo.contact(cid)?.timerSecs ?: 0, t.exp)
        val expiresAt = if (exp > 0 && !Graph.prefs.timerStartsOnRead) now + exp * 1000 else null
        val inserted = s.repo.insertMessage(
            contactId = cid,
            wireId = t.id.take(64),
            outgoing = false,
            kind = MsgKind.TEXT,
            body = body,
            ts = Sanitize.timestamp(t.ts, now),
            receivedAt = now,
            expSecs = exp,
            viewOnce = t.once == true,
            expiresAt = expiresAt,
            status = MsgStatus.DELIVERED,
        )
        sendControl(s, cid, Content.Receipt(listOf(t.id), Content.Receipt.DELIVERED))
        if (inserted == null) {
            return
        }
        val visible = openChat.value == cid && AppVisibility.foreground
        s.repo.touchContact(cid, incrementUnread = !visible)
        if (visible) {
            markChatRead(s, cid)
        } else {
            notify(s, cid, if (t.once == true) "View-once message" else body)
        }
        Sweeper.schedule(s)
    }

    // ---------- send ----------

    /**
     * A contact's identity key changed, and a message under the new key decrypted (reinstall, new phone, or someone
     * impersonating them). The change is never accepted by itself, verified contact or not: their messages are held
     * and nothing is sent until the user reviews it. Someone who really reinstalled can't reach a 1:1 mailbox again
     * anyway (they lost its secret and our prekeys), so an automatic switch would only ever serve an impostor.
     */
    private fun onIdentityChanged(s: Session, e: IdentityChanged, tag: ByteArray, raw: ByteArray) {
        val contact = s.repo.contact(e.contactId) ?: return
        val now = System.currentTimeMillis()
        // Held messages disappear on the chat's timer like any other, and are never kept longer than the server would.
        val keep = if (contact.timerSecs > 0) minOf(contact.timerSecs * 1000, HELD_MAX_MS) else HELD_MAX_MS
        s.repo.holdIncoming(contact.id, e.newKey, tag, raw, now + keep)
        if (contact.pendingIdentity == null || !contact.pendingIdentity.contentEquals(e.newKey)) {
            s.repo.setPendingIdentity(contact.id, e.newKey)
            systemMessage(
                s, contact.id,
                "${contact.name}'s safety number changed. Messages are paused until you review it in their contact info.",
            )
            notify(s, contact.id, "Safety number changed")
        }
        Sweeper.schedule(s)
        s.db.notifyChanged()
    }

    /**
     * The user compared [reviewed] (the new safety number on screen) and accepted it. Does nothing, and returns false, if
     * the pending key has changed since. Delivers only the held messages that came with [reviewed], drops any others,
     * and resumes sending.
     */
    suspend fun acceptIdentityChange(s: Session, cid: Long, reviewed: ByteArray): Boolean {
        val contact = s.repo.contact(cid) ?: return false
        val accepted = s.lock.withLock {
            s.db.tx {
                s.repo.acceptPendingIdentity(cid, reviewed).also { ok ->
                    if (ok) {
                        s.signal.saveIdentity(remote(cid), IdentityKey(reviewed))
                    }
                }
            }
        }
        if (!accepted) {
            return false
        }
        val held = s.repo.heldIncoming(cid, reviewed, System.currentTimeMillis())
        s.repo.clearHeldIncoming(cid)
        systemMessage(s, cid, "You accepted ${contact.name}'s new safety number.")
        for ((tag, blob) in held) {
            receive(s, tag, blob)
        }
        s.db.notifyChanged()
        Outbox.kick()
        return true
    }

    /**
     * The user rejected the new safety number [reviewed]: the messages that came with it are discarded and the chat
     * carries on with the key it had. False if the pending key has changed since.
     */
    fun rejectIdentityChange(s: Session, cid: Long, reviewed: ByteArray): Boolean {
        val contact = s.repo.contact(cid) ?: return false
        if (!s.repo.rejectPendingIdentity(cid, reviewed)) {
            return false
        }
        systemMessage(s, cid, "You kept ${contact.name}'s previous safety number. Messages from the new one were discarded.")
        s.db.notifyChanged()
        Outbox.kick()
        return true
    }

    /**
     * Hidden chats post nothing, unless the user allowed it and this isn't a decoy session. Even then the notification
     * is generic, with no name and no text. (While locked, the chat isn't known yet: see [onPushPayload].)
     */
    internal fun notify(s: Session, cid: Long, text: String?) {
        val c = s.repo.contact(cid)
        if (c?.hidden == true) {
            if (!s.decoy && s.repo.kvString(app.goldfishsend.security.AppLock.KV_NOTIFY_HIDDEN) == "1") {
                Notifier.newMessage(Graph.app, null, null)
            }
            return
        }
        Notifier.newMessage(Graph.app, c?.name, text)
    }

    fun systemMessage(s: Session, cid: Long, text: String) {
        s.repo.insertMessage(cid, "sys-" + Content.newId(), false, MsgKind.SYSTEM, text, System.currentTimeMillis(), null, 0, false, null, MsgStatus.READ)
    }

    fun sendText(s: Session, cid: Long, body: String, viewOnce: Boolean = false) {
        val contact = s.repo.contact(cid) ?: return
        if (contact.isGroup) {
            Groups.sendText(s, cid, body, viewOnce)
            return
        }
        val wire = Content.newId()
        val now = System.currentTimeMillis()
        val exp = contact.timerSecs
        val localId = s.repo.insertMessage(
            cid, wire, true, MsgKind.TEXT, body, now, null, exp, viewOnce,
            if (exp > 0) now + exp * 1000 else null, MsgStatus.QUEUED,
        ) ?: return
        enqueueText(s, contact.receivedAny, cid, localId, wire, body, now, exp, viewOnce)
        s.repo.touchContact(cid, false)
        s.db.notifyChanged()
        Sweeper.schedule(s)
        Outbox.kick()
    }

    private fun enqueueText(s: Session, receivedAny: Boolean, cid: Long, localId: String, wire: String, body: String, ts: Long, exp: Long, once: Boolean) {
        val max = if (receivedAny) Padding.MAX_PLAINTEXT else Padding.MAX_PREKEY_PLAINTEXT
        val parts = Chunker.split(wire, body, ts, exp.takeIf { it > 0 }, once.takeIf { it }, max)
        s.db.tx {
            for (p in parts) {
                s.repo.enqueue(cid, localId, OutboxKind.CONTENT, p.encode())
            }
        }
    }

    /**
     * Re-sends messages that never got a delivery receipt (the push server may have dropped them), for up to
     * [RESEND_WINDOW_MS] after sending: the recipient remembers what it removed for longer than that, so a re-send never
     * brings back a message they viewed once, deleted or let expire.
     */
    fun resendUnreceipted(s: Session) {
        val now = System.currentTimeMillis()
        for (m in s.repo.unreceipted(now - 6 * 3600_000L, now - RESEND_WINDOW_MS, 3)) {
            val c = s.repo.contact(m.contactId) ?: continue
            // Groups don't send delivery receipts (docs/groups.md), so "no receipt" means nothing there.
            if (c.isGroup) {
                continue
            }
            s.repo.incrementResend(m.id)
            enqueueText(s, c.receivedAny, m.contactId, m.id, m.wireId, m.body, m.ts, m.expSecs, m.viewOnce)
        }
        Outbox.kick()
    }

    /** Re-queues an existing outgoing message's content (manual retry). */
    fun sendControlRaw(s: Session, m: app.goldfishsend.db.Message) {
        val c = s.repo.contact(m.contactId) ?: return
        if (c.isGroup) {
            Groups.resend(s, m)
            s.db.notifyChanged()
            return
        }
        enqueueText(s, c.receivedAny, m.contactId, m.id, m.wireId, m.body, m.ts, m.expSecs, m.viewOnce)
        s.db.notifyChanged()
    }

    fun sendControl(s: Session, cid: Long, content: Content) {
        s.repo.enqueue(cid, null, OutboxKind.CONTENT, content.encode())
        Outbox.kick()
    }

    /** Control content that may not fit one message (group cards, rosters): split into `chunk` parts if needed. */
    fun sendControlChunked(s: Session, cid: Long, content: Content) {
        val c = s.repo.contact(cid) ?: return
        val max = if (c.receivedAny) Padding.MAX_PLAINTEXT else Padding.MAX_PREKEY_PLAINTEXT
        for (p in Chunker.splitContent(content, max)) {
            s.repo.enqueue(cid, null, OutboxKind.CONTENT, p.encode())
        }
        Outbox.kick()
    }

    fun setTimer(s: Session, cid: Long, secs: Long) {
        s.repo.setTimer(cid, secs)
        systemMessage(s, cid, "You set disappearing messages to ${timerLabel(secs).lowercase()}")
        sendControl(s, cid, Content.Timer(secs))
        s.db.notifyChanged()
    }

    fun deleteForEveryone(s: Session, messageId: String) {
        val m = s.repo.message(messageId) ?: return
        if (m.outgoing) {
            if (s.repo.contact(m.contactId)?.isGroup == true) {
                Groups.deleteForEveryone(s, m.contactId, m.wireId)
            } else {
                sendControl(s, m.contactId, Content.Delete(listOf(m.wireId)))
            }
        }
        s.repo.deleteMessage(messageId)
        s.db.notifyChanged()
        Notifier.cancel(Graph.app)
    }

    /**
     * Opens a received view-once message exactly once: the body is read into memory, then the row and its key are
     * deleted before anything is displayed. Returns null if it was already viewed.
     */
    fun consumeViewOnce(s: Session, messageId: String): String? {
        val m = s.repo.message(messageId) ?: return null
        if (!m.viewOnce || m.outgoing) {
            return null
        }
        s.repo.deleteMessage(messageId)
        s.db.notifyChanged()
        Notifier.cancel(Graph.app)
        return m.body
    }

    /** Clears a chat: every message goes, and the message root key is replaced so stale copies can't be opened either. */
    fun clearChat(s: Session, cid: Long) {
        s.repo.clearConversation(cid)
        runCatching { Shredder.runPending(s) }
        s.db.notifyChanged()
        Notifier.cancel(Graph.app)
    }

    fun deleteForMe(s: Session, messageId: String) {
        s.repo.deleteMessage(messageId)
        s.db.notifyChanged()
        Notifier.cancel(Graph.app)
    }

    fun markChatRead(s: Session, cid: Long) {
        val ids = s.repo.markRead(cid, System.currentTimeMillis())
        if (ids.isNotEmpty()) {
            if (s.repo.contact(cid)?.isGroup == true) {
                Groups.sendReadReceipts(s, cid, ids)
            } else if (Graph.prefs.readReceipts) {
                sendControl(s, cid, Content.Receipt(ids, Content.Receipt.READ))
            }
            Sweeper.schedule(s)
            s.db.notifyChanged()
        }
        Notifier.cancel(Graph.app)
    }

    /**
     * Deletes a contact everywhere: local state at once, and our inbound mailboxes on the server. Those are recorded as
     * doomed in the same transaction and retried until the server confirms ([OwnerOps]), so being offline
     * or rate-limited now doesn't leave a blocked contact able to write to us.
     */
    suspend fun deleteContact(s: Session, cid: Long) {
        val members = if (s.repo.contact(cid)?.isGroup == true) {
            // Leave first (best effort), so the others stop sending to us, and try to get the goodbyes out.
            runCatching { Groups.leave(s, cid) }
            runCatching { Outbox.process(s) }
            s.repo.memberRoutes(cid).keys
        } else {
            emptySet()
        }
        s.db.tx {
            // All of them, including mailboxes replaced by rotation that are still draining.
            s.repo.doomMailboxes(s.repo.mailboxesForContact(cid), Graph.prefs.serverUrl, Graph.prefs.serverKey)
            s.repo.deleteContact(cid)
        }
        if (members.isNotEmpty()) {
            s.lock.withLock { Groups.forgetSessions(s, members) }
        }
        s.repo.markNeedsVacuum()
        runCatching { Shredder.runPending(s) }
        s.db.notifyChanged()
        Notifier.cancel(Graph.app)
        // Their push instances are unregistered now; the deletes go to the server one by one, a few minutes apart.
        OwnerOps.kick(s)
    }
}

/** Tracks whether any activity is visible (set by the Application's lifecycle observer). */
object AppVisibility {
    @Volatile
    var foreground: Boolean = false
}
