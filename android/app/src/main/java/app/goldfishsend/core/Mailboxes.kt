package app.goldfishsend.core

import android.util.Log
import app.goldfishsend.db.Mailbox
import app.goldfishsend.db.setRotateNeeded
import app.goldfishsend.net.ApiException
import app.goldfishsend.net.CreateMailboxRequest
import app.goldfishsend.net.MailboxItem
import app.goldfishsend.net.PowChallenge
import app.goldfishsend.net.PowSolution
import app.goldfishsend.net.RotateRequest
import app.goldfishsend.net.ServerApi
import app.goldfishsend.net.ServerPin
import app.goldfishsend.proto.B64
import app.goldfishsend.proto.MailboxCrypto
import app.goldfishsend.proto.Pow
import app.goldfishsend.proto.ProtoJson
import java.time.LocalDate
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.Serializable

@Serializable
data class PushEndpointData(val url: String, val p256dh: String, val auth: String)

/**
 * Inbound mailbox lifecycle: create (PoW + verification push), pool for instant invites, rotate on endpoint change,
 * refresh before expiry, and delete.
 *
 * Creating a mailbox costs a proof of work on our own server (several seconds on a phone, much more on a busy network),
 * so a pool of [POOL_TARGET] verified mailboxes is kept ready, filled one at a time in the app's scope. Whoever needs a
 * mailbox takes one from the pool, or waits for the fill to deliver the next: leaving the screen doesn't waste the work.
 */
object Mailboxes {
    private const val TAG = "Mailboxes"

    /**
     * Ready mailboxes kept in the pool. Three cover the usual bursts (add a contact, start a group, show a code) without a
     * wait. Each is one more row on the server per user (a few hundred bytes, and a proof of work once).
     */
    const val POOL_TARGET = 3
    private const val VERIFY_TIMEOUT_MS = 120_000L
    private const val ROTATIONS_PER_PASS = 3
    private const val BUSY_RETRIES = 4

    /** Longer than the server keeps a staged endpoint waiting for its verification (10 minutes by default, plus jitter). */
    private const val ROTATION_VERIFY_WINDOW_MS = 30 * 60_000L

    /** Before the first measurement: a guess at Argon2 calls per second (a mid-range phone at 16 MiB, 4 threads). */
    private const val DEFAULT_CALLS_PER_SECOND = 25.0

    /** The server's max message TTL (14 days) plus a day of margin. */
    private const val DRAIN_MS = 15 * 86_400_000L

    /** A mailbox nobody refreshes is gone from the server after its lifetime (90 days by default); a day of margin. */
    private const val DOOMED_KEEP_MS = 91 * 86_400_000L

    private val waiters = ConcurrentHashMap<String, CompletableDeferred<Unit>>()
    private val rotateMutex = Mutex()

    private val fillLock = Any()
    private var fill: Deferred<Boolean>? = null

    /** Bumped each time a mailbox joins the pool. */
    private val poolVersion = MutableStateFlow(0)

    /** Measured speed of the last proof of work, for the next time estimate. */
    @Volatile
    private var callsPerSecond = DEFAULT_CALLS_PER_SECOND

    private val _busy = MutableStateFlow(false)

    /** True while a mailbox is being prepared in the background (drives a subtle spinner). */
    val busy: StateFlow<Boolean> = _busy

    /**
     * A mailbox being created. [solved] is the estimated progress of its proof of work, or null once that's done and the
     * server's confirmation push is awaited. [remainingSeconds] is a rough estimate of the time left, or null when there
     * isn't one: at first, and once the average has passed ([overdue]).
     */
    class Progress(val solved: Float?, val remainingSeconds: Long? = null, val overdue: Boolean = false)

    private val _progress = MutableStateFlow<Progress?>(null)

    /** Progress of the mailbox being created right now, or null. */
    val progress: StateFlow<Progress?> = _progress

    /**
     * The session closed (its scope cancels any creation). Clears the spinner and progress at once, so nothing of the
     * real profile's work shows in whatever opens next.
     */
    fun ended() {
        synchronized(fillLock) {
            fill?.cancel()
            fill = null
        }
        _busy.value = false
        _progress.value = null
    }

    fun endpoint(s: Session): PushEndpointData? =
        s.repo.kvString("push_endpoint")?.let { ProtoJson.decodeFromString(PushEndpointData.serializer(), it) }

    fun item(m: Mailbox) = MailboxItem(B64.enc(m.sendSecret), B64.enc(m.ownerSecret))

    /**
     * Creates and verifies one mailbox on our server, for the pool. Returns null if push isn't ready yet, or the
     * verification push didn't arrive in time.
     *
     * The proof of work has no time limit ([Pow.Lane.OWN_MAILBOX]): it fetches fresh challenges as they near expiry, and
     * only stops if cancelled. The local row is only written once it's solved, so cleanup of abandoned creations can't
     * remove one that's still being worked on.
     */
    private suspend fun create(s: Session, purpose: Int): Mailbox? {
        if (s.decoy) {
            return null
        }
        val ep = endpoint(s) ?: return null
        val send = MailboxCrypto.newSecret()
        val owner = MailboxCrypto.newSecret()
        val tag = MailboxCrypto.tag(send)
        val key = B64.enc(tag)
        val waiter = CompletableDeferred<Unit>()
        waiters[key] = waiter
        _busy.value = true
        var id: Long? = null
        // Set once the row should stay: active, or pending a late verification push.
        var keep = false
        try {
            val api = Graph.api()
            var attempt = 0
            while (true) {
                val (ch, nonce) = solve(api)
                _progress.value = Progress(null)
                val request = CreateMailboxRequest(
                    pow = PowSolution(ch.challenge, B64.enc(nonce)),
                    sendSecret = B64.enc(send),
                    ownerHash = B64.enc(MailboxCrypto.ownerHash(owner)),
                    endpoint = ep.url,
                    p256dh = ep.p256dh,
                    auth = ep.auth,
                )
                if (id == null) {
                    id = s.repo.insertMailbox(purpose, send, owner, tag)
                }
                try {
                    submit(api, request)
                    break
                } catch (e: ApiException) {
                    // pow_invalid: the challenge expired or was used up on the way (a slow network). Solve another.
                    if (e.code != "pow_invalid" || ++attempt >= 2) {
                        throw e
                    }
                }
            }
            val mid = id!!
            // The verification push may already have been handled while the request was in flight.
            if (s.repo.mailbox(mid)?.state != Mailbox.STATE_ACTIVE) {
                s.repo.setMailboxState(mid, Mailbox.STATE_PENDING_VERIFY)
            }
            withTimeout(VERIFY_TIMEOUT_MS) {
                if (s.repo.mailbox(mid)?.state != Mailbox.STATE_ACTIVE) {
                    waiter.await()
                }
            }
            keep = true
            s.db.notifyChanged()
            return s.repo.mailbox(mid)
        } catch (e: TimeoutCancellationException) {
            // Left pending: a late verification push (e.g. after unlock) still activates it, and cleanup removes it otherwise.
            Log.i(TAG, "verification push did not arrive in time")
            keep = true
            return null
        } finally {
            // Failed or cancelled before the server took it: the local row goes (unless the push already activated it).
            if (!keep) {
                id?.let { if (s.repo.mailbox(it)?.state != Mailbox.STATE_ACTIVE) s.repo.deleteMailboxRow(it) }
            }
            waiters.remove(key)
            _busy.value = false
            _progress.value = null
        }
    }

    /** The proof of work for one creation, with progress and a time estimate on [progress]. */
    private suspend fun solve(api: app.goldfishsend.net.ServerApi): Pair<PowChallenge, ByteArray> {
        val hashes = AtomicLong()
        var current: PowChallenge? = null
        val start = System.nanoTime()
        _progress.value = Progress(0f)
        return coroutineScope {
            val ticker = launch {
                while (true) {
                    delay(250)
                    val d = current?.difficulty ?: continue
                    _progress.value = progressOf(hashes.get(), d, (System.nanoTime() - start) / 1e9)
                }
            }
            try {
                val nonce = try {
                    Pow.solveOwn({ api.powChallenge().also { current = it }.toPow() }, hashes).second
                } catch (e: Pow.TooHardException) {
                    throw ApiException("bad_server", 502, retryAfterSeconds = 3600)
                }
                val seconds = (System.nanoTime() - start) / 1e9
                if (seconds > 3 && hashes.get() >= 8) {
                    callsPerSecond = hashes.get() / seconds
                }
                // The challenge that was solved is the latest one fetched.
                val ch = current!!
                ch to nonce
            } finally {
                ticker.cancel()
            }
        }
    }

    /** Progress after [calls] Argon2 calls in [seconds], at [difficulty]. */
    internal fun progressOf(calls: Long, difficulty: Int, seconds: Double): Progress {
        val rate = if (seconds > 3 && calls >= 8) calls / seconds else callsPerSecond
        val left = Pow.remainingSeconds(difficulty, rate, seconds)
        return Progress(Pow.estimatedProgress(calls, difficulty), left, overdue = left == null && seconds > 5)
    }

    /**
     * Sends the creation request. A 503 with a short Retry-After means every verification slot on the server was busy: the
     * challenge was kept for us, so the same solution is retried after a moment instead of being thrown away.
     */
    private suspend fun submit(api: app.goldfishsend.net.ServerApi, request: CreateMailboxRequest) {
        var attempt = 0
        while (true) {
            try {
                api.createMailbox(request)
                return
            } catch (e: ApiException) {
                // A longer Retry-After is another kind of 503 (the push service is paused), which used the challenge up.
                if (e.status != 503 || (e.retryAfterSeconds ?: 1L) > 2 || ++attempt >= BUSY_RETRIES) {
                    throw e
                }
                delay((e.retryAfterSeconds ?: 1L).coerceAtLeast(1L) * 1000L)
            }
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
            // Under the rotation lock: while rotateAll is still sending later batches, none pending doesn't mean done.
            rotateMutex.withLock {
                if (s.repo.rotationsPendingSince() == null && s.repo.kvString("rotation_needed") == "1") {
                    rotationDone(s)
                }
            }
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


    /**
     * Starts filling the pool to [POOL_TARGET] (unless it's already being filled) in the session's scope, so it carries
     * on whoever stops waiting for it (but not past a lock), and returns that job. Mailboxes are made one at a time.
     */
    private fun startFill(s: Session): Deferred<Boolean> = synchronized(fillLock) {
        fill?.takeIf { it.isActive } ?: s.scope.async {
            try {
                fillPool(s)
            } finally {
                // Wakes anyone in take(), whether a mailbox came or not.
                poolVersion.update { it + 1 }
            }
        }.also { fill = it }
    }

    /** True if the pool is full, false if a creation came back empty (push not ready, or no confirmation push). */
    private suspend fun fillPool(s: Session): Boolean {
        while (s.repo.pooledMailboxes().size < POOL_TARGET) {
            create(s, Mailbox.PURPOSE_QR) ?: return false
            poolVersion.update { it + 1 }
        }
        return true
    }

    /** Keeps [POOL_TARGET] ready mailboxes so "Add contact" is instant. Safe to call often; returns when the pool is full. */
    suspend fun ensurePool(s: Session) {
        if (s.decoy) {
            return
        }
        startFill(s).await()
    }

    /** Like [ensurePool], without waiting. */
    fun kickPool(s: Session) {
        if (!s.decoy) {
            startFill(s)
        }
    }

    /**
     * Claims a pool mailbox (atomically). If none is ready, waits for the pool fill to deliver the next one: the wait can
     * be long (a proof of work), and if the caller gives up, the fill carries on and the mailbox stays in the pool for next
     * time. Returns null if the fill stopped without one (push not ready, or the verification push didn't arrive), and
     * throws the fill's error if it failed.
     */
    suspend fun take(s: Session, purpose: Int): Mailbox? {
        if (s.decoy) {
            return null
        }
        val provisional = System.currentTimeMillis() + 25 * 3600_000L
        while (true) {
            s.repo.claimPoolMailbox(purpose, provisional)?.let {
                kickPool(s)
                return it
            }
            // The fill bumps poolVersion for every new mailbox and once more when it ends, so this wakes for either.
            val seen = poolVersion.value
            val job = startFill(s)
            poolVersion.first { it != seen }
            if (job.isCompleted) {
                // The fill ended. Something may still have reached the pool meanwhile.
                s.repo.claimPoolMailbox(purpose, provisional)?.let {
                    kickPool(s)
                    return it
                }
                // Rethrows the fill's error, if it failed. False: it couldn't make one (push not ready, or no confirmation).
                if (!job.await()) {
                    return null
                }
            }
        }
    }

    /**
     * The contact's mailbox, or a ready one from the pool bound to them, without waiting for a proof of work. Null means
     * none is ready: the pool fill has been started (the outbox retries shortly, instead of holding a send slot meanwhile).
     */
    fun readyForContact(s: Session, contactId: Long): Mailbox? {
        s.repo.mailboxForContact(contactId)?.let { return it }
        if (s.decoy) {
            return null
        }
        val mb = s.repo.claimPoolMailbox(Mailbox.PURPOSE_CONTACT, System.currentTimeMillis() + 25 * 3600_000L)
        kickPool(s)
        mb ?: return null
        s.repo.bindMailbox(mb.id, contactId)
        return s.repo.mailbox(mb.id)
    }

    suspend fun onNewEndpoint(s: Session, data: PushEndpointData) {
        if (s.decoy) {
            return
        }
        val old = endpoint(s)
        s.repo.kvPutString("push_endpoint", ProtoJson.encodeToString(PushEndpointData.serializer(), data))
        Graph.prefs.pushStatus = "ok"
        val host = runCatching { java.net.URI(data.url).host }.getOrNull()
        Graph.prefs.pushHost = host
        if (old != null && old != data) {
            s.repo.kvPutString("rotation_needed", "1")
            val oldHost = runCatching { java.net.URI(old.url).host }.getOrNull()
            if (oldHost != null && oldHost != host && Graph.prefs.pushHostUnconfirmed == null) {
                // Until the server confirms the new endpoint, it still wakes us through the old push service.
                Graph.prefs.pushHostUnconfirmed = oldHost
            }
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
        // The server only stages the new endpoint until its verification push is answered. rotation_needed stays set until
        // every batch is verified ([onVerification]), so a push that's lost or comes too late is retried by [cleanup].
        if (s.repo.rotationsPendingSince() == null) {
            rotationDone(s)
        }
    }

    /** Every mailbox is confirmed on the current endpoint. */
    private fun rotationDone(s: Session) {
        s.repo.kvPutString("rotation_needed", null)
        Graph.prefs.pushHostUnconfirmed = null
    }

    /**
     * The server no longer knows this mailbox. Pool mailboxes are just dropped. For a contact's mailbox, create a fresh one
     * and tell the contact through the E2E `mailbox` message, so they keep reaching us.
     */
    private suspend fun replaceGone(s: Session, m: Mailbox) {
        s.repo.deleteMailboxRow(m.id)
        // One already replaced (draining after a rotation) needs nothing new: the contact or group has a newer one.
        if (m.replacedAt != null) {
            return
        }
        val cid = m.contactId ?: return
        if (m.purpose == Mailbox.PURPOSE_GROUP) {
            // A group inbox: a new one goes out to the members in a new card.
            s.repo.setRotateNeeded(cid, true)
            s.scope.launchSafe { Groups.rotatePending(s) }
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
            s.scope.launchSafe { ensurePool(s) }
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
        s.scope.launchSafe { Groups.announceServerKey(s) }
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
        s.scope.launchSafe {
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
            // Registering is the device's, not the session's, so it goes on if the app locks meanwhile.
            runCatching { app.goldfishsend.push.PushHub.register(Graph.app) }
            // The rotation is the session's. Once it's locked, cleanup does it after the next unlock (rotation_needed).
            s.scope.launchSafe { rotateAll(s) }
        }
    }

    /**
     * Extends any mailbox expiring within 60 days. The server refuses a whole batch (404) if it doesn't know one mailbox in
     * it, so that batch is refreshed one by one and the gone ones are replaced: otherwise one lost mailbox would keep every
     * other one in its batch (and all later batches) from being refreshed until they all expire.
     */
    suspend fun refreshAll(s: Session) {
        if (s.decoy) {
            return
        }
        val soon = LocalDate.now().plusDays(60).toString()
        val due = s.repo.activeMailboxes().filter { it.expiresAt == null || it.expiresAt < soon }
        val api = Graph.api()
        for (batch in due.chunked(100)) {
            val r = try {
                api.refresh(batch.map(::item))
            } catch (e: ApiException) {
                if (e.status != 404) {
                    throw e
                }
                for (m in batch) {
                    val one = try {
                        api.refresh(listOf(item(m)))
                    } catch (e2: ApiException) {
                        if (e2.status != 404) {
                            throw e2
                        }
                        replaceGone(s, m)
                        continue
                    }
                    if (one.endpointGone) {
                        onEndpointGone(s)
                    }
                    s.repo.setMailboxExpiry(m.id, one.expiresAt)
                }
                continue
            }
            if (r.endpointGone) {
                onEndpointGone(s)
            }
            for (b in batch) {
                s.repo.setMailboxExpiry(b.id, r.expiresAt)
            }
        }
    }

    /**
     * Deletes [items] on the server. The server answers 404 for a whole batch if any one of them is unknown, so one that's
     * already gone (expired, or deleted by a call whose answer was lost) can't hold up the rest: the batch is then sent
     * item by item, and an unknown one counts as deleted.
     */
    suspend fun deleteRemote(items: List<MailboxItem>, api: ServerApi = Graph.api()) {
        if (items.isEmpty()) {
            return
        }
        for (batch in items.chunked(100)) {
            try {
                api.delete(batch)
            } catch (e: ApiException) {
                if (e.status != 404) {
                    throw e
                }
                for (one in batch.takeIf { it.size > 1 }.orEmpty()) {
                    try {
                        api.delete(listOf(one))
                    } catch (e1: ApiException) {
                        if (e1.status != 404) {
                            throw e1
                        }
                    }
                }
            }
        }
    }

    /**
     * Deletes on the server the mailboxes of chats that are gone ([app.goldfishsend.db.Repo.doomMailboxes]). Each stays
     * recorded until its server confirms, and this runs again with every maintenance pass. One on a server we no longer
     * use is deleted there, but only if we know that server's fingerprint (otherwise the secrets would go to whoever
     * answers). Past the server's mailbox lifetime they're gone there anyway, and are forgotten.
     */
    suspend fun deleteDoomed(s: Session) {
        if (s.decoy) {
            return
        }
        s.repo.forgetDoomedBefore(System.currentTimeMillis() - DOOMED_KEEP_MS)
        for ((where, boxes) in s.repo.doomedMailboxes().groupBy { it.server to it.serverKey }) {
            val (server, key) = where
            val api = when {
                server == Graph.prefs.serverUrl -> Graph.api()
                key != null -> Graph.api(server, ServerPin(key))
                else -> continue
            }
            runCatching { deleteRemote(boxes.map { MailboxItem(B64.enc(it.sendSecret), B64.enc(it.ownerSecret)) }, api) }.onSuccess {
                for (b in boxes) {
                    s.repo.forgetDoomed(b.sendSecret)
                }
            }
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
        runCatching { deleteDoomed(s) }
        // A rotation never verified (the push was lost, came after the server's deadline, or verify failed): start again,
        // unless one is still within its verification window.
        val pending = s.repo.rotationsPendingSince()
        if (s.repo.kvString("rotation_needed") == "1" && (pending == null || pending < now - ROTATION_VERIFY_WINDOW_MS)) {
            runCatching { rotateAll(s) }
        }
    }
}
