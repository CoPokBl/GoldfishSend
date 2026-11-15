package app.goldfishsend.core

import android.util.Log
import app.goldfishsend.db.Mailbox
import app.goldfishsend.db.setRotateNeeded
import app.goldfishsend.net.ApiException
import app.goldfishsend.net.CreateMailboxRequest
import app.goldfishsend.net.MailboxItem
import app.goldfishsend.net.PowSolution
import app.goldfishsend.net.RotateRequest
import app.goldfishsend.proto.B64
import app.goldfishsend.proto.MailboxCrypto
import app.goldfishsend.proto.Pow
import app.goldfishsend.proto.ProtoJson
import java.time.LocalDate
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.Serializable

@Serializable
data class PushEndpointData(val url: String, val p256dh: String, val auth: String)

/**
 * Inbound mailbox lifecycle: create (PoW + verification push), pool for instant invites, rotate on endpoint change,
 * refresh before expiry, and delete. None of this is ever surfaced in the UI.
 */
object Mailboxes {
    private const val TAG = "Mailboxes"
    const val POOL_TARGET = 2
    private const val VERIFY_TIMEOUT_MS = 120_000L
    private const val ROTATIONS_PER_PASS = 3

    /** The server's max message TTL (14 days) plus a day of margin. */
    private const val DRAIN_MS = 15 * 86_400_000L

    private val waiters = ConcurrentHashMap<String, CompletableDeferred<Unit>>()
    private val poolMutex = Mutex()
    private val rotateMutex = Mutex()

    private val _busy = kotlinx.coroutines.flow.MutableStateFlow(false)

    /** True while a mailbox is being prepared in the background (drives a subtle spinner). */
    val busy: kotlinx.coroutines.flow.StateFlow<Boolean> = _busy

    /**
     * A mailbox being created: [solved] is the estimated progress of its proof of work, or null once that's done and
     * the server's confirmation push is awaited.
     */
    class Progress(val solved: Float?)

    private val _progress = kotlinx.coroutines.flow.MutableStateFlow<Progress?>(null)

    /** Progress of the mailbox being created right now, or null. Proof of work can take tens of seconds on a phone. */
    val progress: kotlinx.coroutines.flow.StateFlow<Progress?> = _progress

    fun endpoint(s: Session): PushEndpointData? =
        s.repo.kvString("push_endpoint")?.let { ProtoJson.decodeFromString(PushEndpointData.serializer(), it) }

    fun item(m: Mailbox) = MailboxItem(B64.enc(m.sendSecret), B64.enc(m.ownerSecret))

    /** Creates and verifies one mailbox on our server. Returns null if push isn't ready yet. */
    suspend fun create(s: Session, purpose: Int): Mailbox? {
        if (s.decoy) {
            return null
        }
        val ep = endpoint(s) ?: return null
        val send = MailboxCrypto.newSecret()
        val owner = MailboxCrypto.newSecret()
        val tag = MailboxCrypto.tag(send)
        val id = s.repo.insertMailbox(purpose, send, owner, tag)
        val key = B64.enc(tag)
        val waiter = CompletableDeferred<Unit>()
        waiters[key] = waiter
        _busy.value = true
        try {
            val api = Graph.api()
            val ch = api.powChallenge()
            val hashes = java.util.concurrent.atomic.AtomicLong()
            _progress.value = Progress(0f)
            val nonce = kotlinx.coroutines.coroutineScope {
                val ticker = launch {
                    while (true) {
                        kotlinx.coroutines.delay(250)
                        _progress.value = Progress(app.goldfishsend.proto.Pow.estimatedProgress(hashes.get(), ch.difficulty))
                    }
                }
                try {
                    Outbox.solvePow(ch.challenge, ch.difficulty, hashes)
                } finally {
                    ticker.cancel()
                }
            }
            _progress.value = Progress(null)
            api.createMailbox(
                CreateMailboxRequest(
                    pow = PowSolution(ch.challenge, B64.enc(nonce)),
                    sendSecret = B64.enc(send),
                    ownerHash = B64.enc(MailboxCrypto.ownerHash(owner)),
                    endpoint = ep.url,
                    p256dh = ep.p256dh,
                    auth = ep.auth,
                ),
            )
            // The verification push may already have been handled while the request was in flight.
            if (s.repo.mailbox(id)?.state != Mailbox.STATE_ACTIVE) {
                s.repo.setMailboxState(id, Mailbox.STATE_PENDING_VERIFY)
            }
            withTimeout(VERIFY_TIMEOUT_MS) {
                if (s.repo.mailbox(id)?.state != Mailbox.STATE_ACTIVE) {
                    waiter.await()
                }
            }
            s.db.notifyChanged()
            return s.repo.mailbox(id)
        } catch (e: TimeoutCancellationException) {
            // Left pending: a late verification push (e.g. after unlock) still activates it, and cleanup removes it otherwise.
            Log.i(TAG, "verification push did not arrive in time")
            return null
        } catch (e: ApiException) {
            s.repo.deleteMailboxRow(id)
            throw e
        } finally {
            waiters.remove(key)
            _busy.value = false
            _progress.value = null
        }
    }

    /** Handles a verification push (type 0x02): a new mailbox or a rotation batch. */
    suspend fun onVerification(s: Session, tag: ByteArray, code: ByteArray) {
        val api = Graph.api()
        val rotation = s.repo.rotation(tag)
        if (rotation != null) {
            val boxes = rotation.mapNotNull { s.repo.mailbox(it) }
            if (boxes.isNotEmpty()) {
                val r = api.verify(boxes.map(::item), code)
                if (r.endpointGone) {
                    onEndpointGone(s)
                }
                for (b in boxes) {
                    s.repo.setMailboxState(b.id, Mailbox.STATE_ACTIVE, r.expiresAt)
                }
            }
            s.repo.deleteRotation(tag)
            return
        }
        val mb = s.repo.mailboxByTag(tag) ?: return
        if (mb.state == Mailbox.STATE_ACTIVE) {
            return
        }
        val r = api.verify(listOf(item(mb)), code)
        if (r.endpointGone) {
            onEndpointGone(s)
        }
        s.repo.setMailboxState(mb.id, Mailbox.STATE_ACTIVE, r.expiresAt)
        waiters[B64.enc(tag)]?.complete(Unit)
    }

    /** Keeps [POOL_TARGET] ready mailboxes so "Add contact" is instant. Safe to call often. */
    suspend fun ensurePool(s: Session) {
        if (s.decoy) {
            return
        }
        if (poolMutex.isLocked) {
            return
        }
        poolMutex.withLock {
            val have = s.repo.pooledMailboxes().size + s.repo.pendingCount().toInt()
            repeat((POOL_TARGET - have).coerceAtLeast(0)) {
                create(s, Mailbox.PURPOSE_QR) ?: return
            }
        }
    }

    /** Pooled mailbox if available, otherwise a freshly created one. */
    /** Claims a pool mailbox (atomically), or creates and claims a new one. */
    suspend fun take(s: Session, purpose: Int): Mailbox? {
        val provisional = System.currentTimeMillis() + 25 * 3600_000L
        s.repo.claimPoolMailbox(purpose, provisional)?.let { return it }
        repeat(3) {
            val created = create(s, purpose) ?: return null
            if (s.repo.claimMailbox(created.id, purpose, provisional)) {
                return s.repo.mailbox(created.id)
            }
            // Someone else claimed the fresh one first. Try the pool again.
            s.repo.claimPoolMailbox(purpose, provisional)?.let { return it }
        }
        return null
    }

    suspend fun takeForContact(s: Session, contactId: Long): Mailbox? {
        s.repo.mailboxForContact(contactId)?.let { return it }
        val mb = take(s, Mailbox.PURPOSE_CONTACT) ?: return null
        s.repo.bindMailbox(mb.id, contactId)
        Graph.scope.launchSafe { ensurePool(s) }
        return s.repo.mailbox(mb.id)
    }

    suspend fun onNewEndpoint(s: Session, data: PushEndpointData) {
        if (s.decoy) {
            return
        }
        val old = endpoint(s)
        s.repo.kvPutString("push_endpoint", ProtoJson.encodeToString(PushEndpointData.serializer(), data))
        Graph.prefs.pushStatus = "ok"
        Graph.prefs.pushHost = runCatching { java.net.URI(data.url).host }.getOrNull()
        if (old != null && old != data) {
            s.repo.kvPutString("rotation_needed", "1")
            rotateAll(s)
        }
        ensurePool(s)
    }

    /** Points every mailbox at the current endpoint. Each batch of 100 is confirmed by one verification push. */
    suspend fun rotateAll(s: Session) = rotateMutex.withLock {
        if (s.decoy) {
            return@withLock
        }
        val ep = endpoint(s) ?: return@withLock
        // Unverified mailboxes would be purged by the server anyway.
        for (m in s.repo.allMailboxes().filter { it.state != Mailbox.STATE_ACTIVE }) {
            s.repo.deleteMailboxRow(m.id)
        }
        // Only verified mailboxes can rotate (the server returns 404 for pending ones).
        val boxes = s.repo.activeMailboxes()
        s.repo.clearRotations()
        val api = Graph.api()
        for (batch in boxes.chunked(100)) {
            try {
                s.repo.addRotation(batch.first().tag, batch.map { it.id })
                api.rotate(RotateRequest(batch.map(::item), ep.url, ep.p256dh, ep.auth))
            } catch (e: ApiException) {
                if (e.status != 404) {
                    // 429 (rotation budget) or network: rotation_needed stays set, and maintenance retries later.
                    throw e
                }
                // Some mailbox in the batch is unknown to the server (expired or purged). Rotate one by one and replace the gone ones.
                s.repo.deleteRotation(batch.first().tag)
                for (m in batch) {
                    try {
                        s.repo.addRotation(m.tag, listOf(m.id))
                        api.rotate(RotateRequest(listOf(item(m)), ep.url, ep.p256dh, ep.auth))
                    } catch (e2: ApiException) {
                        s.repo.deleteRotation(m.tag)
                        if (e2.status != 404) {
                            throw e2
                        }
                        replaceGone(s, m)
                    }
                }
            }
        }
        s.repo.kvPutString("rotation_needed", null)
    }

    /**
     * The server no longer knows this mailbox. Pool mailboxes are just dropped. For a contact's mailbox, create a fresh one
     * and tell the contact through the E2E `mailbox` message, so they keep reaching us.
     */
    private suspend fun replaceGone(s: Session, m: Mailbox) {
        s.repo.deleteMailboxRow(m.id)
        val cid = m.contactId ?: return
        if (m.purpose == Mailbox.PURPOSE_GROUP) {
            // A group inbox: a new one goes out to the members in a new card.
            s.repo.setRotateNeeded(cid, true)
            Graph.scope.launchSafe { Groups.rotatePending(s) }
            return
        }
        val fresh = take(s, Mailbox.PURPOSE_CONTACT) ?: return
        s.repo.bindMailbox(fresh.id, cid)
        Messenger.sendControl(s, cid, app.goldfishsend.proto.Content.Mailbox(Graph.prefs.serverUrl, B64.enc(fresh.sendSecret), Graph.ownServerKey()))
    }

    /**
     * Mailbox rotation (Prefs.mailboxRotationDays). Each contact periodically gets a fresh inbound mailbox, announced through
     * the E2E `mailbox` message, so the server can't watch one mailbox's traffic for long. The old mailbox keeps working
     * until the contact is seen using the new one (see [onMessageOnMailbox]), then for one more max-TTL so in-flight messages
     * still arrive. Only then is it deleted. A few contacts rotate per pass, which spreads the proof-of-work cost.
     */
    suspend fun rotateContacts(s: Session) {
        if (s.decoy) {
            return
        }
        val now = System.currentTimeMillis()
        for (m in s.repo.drainedMailboxes(now)) {
            runCatching { deleteRemote(listOf(item(m))) }.onSuccess { s.repo.deleteMailboxRow(m.id) }
        }
        val days = Graph.prefs.mailboxRotationDays
        if (days <= 0 || endpoint(s) == null) {
            return
        }
        val due = s.repo.contactsDueForRotation(now - days * 86_400_000L)
        for (cid in due.take(ROTATIONS_PER_PASS)) {
            val contact = s.repo.contact(cid) ?: continue
            if (contact.pendingIdentity != null || contact.unreachable) {
                continue
            }
            val old = s.repo.mailboxForContact(cid) ?: continue
            val fresh = take(s, Mailbox.PURPOSE_CONTACT) ?: return
            s.repo.bindMailbox(fresh.id, cid)
            s.repo.markReplaced(old.id, now)
            Messenger.sendControl(s, cid, app.goldfishsend.proto.Content.Mailbox(Graph.prefs.serverUrl, B64.enc(fresh.sendSecret), Graph.ownServerKey()))
        }
        if (due.isNotEmpty()) {
            Graph.scope.launchSafe { ensurePool(s) }
        }
    }

    /**
     * The user trusted a new identity key for our own server. Tell every contact, through the E2E `mailbox` message (same
     * mailbox, new `serverKey`), so their pins follow and their messages keep reaching us.
     */
    fun announceServerKey(s: Session, serverKey: String) {
        if (s.decoy) {
            return
        }
        for (c in s.repo.people()) {
            val mb = s.repo.mailboxForContact(c.id) ?: continue
            Messenger.sendControl(s, c.id, app.goldfishsend.proto.Content.Mailbox(Graph.prefs.serverUrl, B64.enc(mb.sendSecret), serverKey))
        }
        // Groups learn it from a new card.
        Graph.scope.launchSafe { Groups.announceServerKey(s) }
    }

    /**
     * Trusts the new identity key [presented] for our own server (after the user reviewed it and re-authenticated), and
     * announces it to every contact.
     */
    fun trustNewServerKey(s: Session, presented: String) {
        if (s.decoy) {
            return
        }
        Graph.prefs.serverKey = presented
        Graph.prefs.serverKeyChanged = null
        announceServerKey(s, presented)
        Graph.scope.launchSafe {
            runCatching { cleanup(s) }
            runCatching { ensurePool(s) }
        }
    }

    /** A message arrived on [mb]. If it's a contact's current mailbox, their older ones can start draining. */
    fun onMessageOnMailbox(s: Session, mb: Mailbox) {
        val cid = mb.contactId ?: return
        if (mb.replacedAt == null) {
            s.repo.startDraining(cid, mb.id, System.currentTimeMillis() + DRAIN_MS)
        }
    }

    /**
     * The server says it can't reach our push endpoint any more (protocol.md `endpointGone`). Ask the distributor for a
     * fresh registration, then point every mailbox at the current endpoint again. If the endpoint didn't change, the
     * rotation's verification push makes the server probe it again. At most once every 6 hours, so a server that keeps
     * saying so can't make us loop.
     */
    private fun onEndpointGone(s: Session) {
        val now = System.currentTimeMillis()
        val last = s.repo.kvString("endpoint_gone_at")?.toLongOrNull() ?: 0L
        if (now - last < 6 * 3600_000L) {
            return
        }
        s.repo.kvPutString("endpoint_gone_at", now.toString())
        s.repo.kvPutString("rotation_needed", "1")
        Graph.scope.launchSafe {
            runCatching { app.goldfishsend.push.PushHub.register(Graph.app) }
            runCatching { rotateAll(s) }
        }
    }

    /** Extends any mailbox expiring within 60 days. */
    suspend fun refreshAll(s: Session) {
        if (s.decoy) {
            return
        }
        val soon = LocalDate.now().plusDays(60).toString()
        val due = s.repo.activeMailboxes().filter { it.expiresAt == null || it.expiresAt < soon }
        val api = Graph.api()
        for (batch in due.chunked(100)) {
            val r = api.refresh(batch.map(::item))
            if (r.endpointGone) {
                onEndpointGone(s)
            }
            for (b in batch) {
                s.repo.setMailboxExpiry(b.id, r.expiresAt)
            }
        }
    }

    suspend fun deleteRemote(items: List<MailboxItem>) {
        if (items.isEmpty()) {
            return
        }
        val api = Graph.api()
        for (batch in items.chunked(100)) {
            api.delete(batch)
        }
    }

    /** Removes mailboxes from unused, expired invites and abandoned creations. */
    suspend fun cleanup(s: Session) {
        if (s.decoy) {
            return
        }
        val now = System.currentTimeMillis()
        val abandoned = s.repo.abandonedInviteMailboxes(now - 3600_000L)
        // The invite can never be used now, so its one-time prekeys go too (forward secrecy).
        s.lock.withLock {
            s.db.tx {
                for (m in abandoned) {
                    m.inviteSpkId?.let { s.signal.removeSignedPreKey(it) }
                    m.inviteKyberId?.let { s.signal.removeKyberPreKey(it) }
                }
            }
        }
        runCatching { deleteRemote(abandoned.map(::item)) }.onSuccess {
            for (m in abandoned) {
                s.repo.deleteMailboxRow(m.id)
            }
        }
        for (m in s.repo.staleCreating(now - 15 * 60_000L)) {
            s.repo.deleteMailboxRow(m.id)
        }
        if (s.repo.kvString("rotation_needed") == "1") {
            runCatching { rotateAll(s) }
        }
    }
}
