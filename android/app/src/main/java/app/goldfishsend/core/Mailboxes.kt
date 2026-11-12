package app.goldfishsend.core

import android.util.Log
import app.goldfishsend.db.Mailbox
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

    private val waiters = ConcurrentHashMap<String, CompletableDeferred<Unit>>()
    private val poolMutex = Mutex()
    private val rotateMutex = Mutex()

    private val _busy = kotlinx.coroutines.flow.MutableStateFlow(false)

    /** True while a mailbox is being prepared in the background (drives a subtle spinner). */
    val busy: kotlinx.coroutines.flow.StateFlow<Boolean> = _busy

    fun endpoint(s: Session): PushEndpointData? =
        s.repo.kvString("push_endpoint")?.let { ProtoJson.decodeFromString(PushEndpointData.serializer(), it) }

    fun item(m: Mailbox) = MailboxItem(B64.enc(m.sendSecret), B64.enc(m.ownerSecret))

    /** Creates and verifies one mailbox on our server. Returns null if push isn't ready yet. */
    suspend fun create(s: Session, purpose: Int): Mailbox? {
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
            val nonce = Pow.solve(B64.dec(ch.challenge), ch.difficulty)
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
        s.repo.setMailboxState(mb.id, Mailbox.STATE_ACTIVE, r.expiresAt)
        waiters[B64.enc(tag)]?.complete(Unit)
    }

    /** Keeps [POOL_TARGET] ready mailboxes so "Add contact" is instant. Safe to call often. */
    suspend fun ensurePool(s: Session) {
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
    suspend fun take(s: Session, purpose: Int): Mailbox? {
        s.repo.pooledMailboxes().firstOrNull()?.let { return it }
        return create(s, purpose)
    }

    suspend fun takeForContact(s: Session, contactId: Long): Mailbox? {
        s.repo.mailboxForContact(contactId)?.let { return it }
        val mb = take(s, Mailbox.PURPOSE_CONTACT) ?: return null
        s.repo.bindMailbox(mb.id, contactId)
        Graph.scope.launchSafe { ensurePool(s) }
        return s.repo.mailbox(mb.id)
    }

    suspend fun onNewEndpoint(s: Session, data: PushEndpointData) {
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
        val fresh = take(s, Mailbox.PURPOSE_CONTACT) ?: return
        s.repo.bindMailbox(fresh.id, cid)
        Messenger.sendControl(s, cid, app.goldfishsend.proto.Content.Mailbox(Graph.prefs.serverUrl, B64.enc(fresh.sendSecret)))
    }

    /** Extends any mailbox expiring within 60 days. */
    suspend fun refreshAll(s: Session) {
        val soon = LocalDate.now().plusDays(60).toString()
        val due = s.repo.activeMailboxes().filter { it.expiresAt == null || it.expiresAt < soon }
        val api = Graph.api()
        for (batch in due.chunked(100)) {
            val r = api.refresh(batch.map(::item))
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
        val now = System.currentTimeMillis()
        val abandoned = s.repo.abandonedInviteMailboxes(now - 3600_000L)
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
