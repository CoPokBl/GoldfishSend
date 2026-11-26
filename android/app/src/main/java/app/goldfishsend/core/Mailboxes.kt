package app.goldfishsend.core

import android.util.Log
import app.goldfishsend.db.Mailbox
import app.goldfishsend.db.OutboxKind
import app.goldfishsend.db.setRotateNeeded
import app.goldfishsend.net.ApiException
import app.goldfishsend.net.CreateMailboxRequest
import app.goldfishsend.net.MailboxItem
import app.goldfishsend.net.PowChallenge
import app.goldfishsend.net.PowSolution
import app.goldfishsend.proto.B64
import app.goldfishsend.proto.MailboxCrypto
import app.goldfishsend.proto.Pow
import app.goldfishsend.proto.Rand
import app.goldfishsend.push.PushHub
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
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
 * Inbound mailbox lifecycle: create (PoW + verification push), pool for instant invites, move to a new endpoint, refresh
 * before expiry, and delete.
 *
 * Creating a mailbox costs a proof of work on our own server (several seconds on a phone, much more on a busy network),
 * so a pool of [POOL_TARGET] verified mailboxes is kept ready, filled one at a time in the app's scope. Whoever needs a
 * mailbox takes one from the pool, or waits for the fill to deliver the next: leaving the screen doesn't waste the work.
 *
 * Every mailbox has a UnifiedPush instance of its own ([PushHub]), so its own endpoint, and the server can't link the
 * mailboxes of different contacts or groups by endpoint. For the same reason the owner requests (refresh, rotation,
 * delete) carry one mailbox each and go out one at a time, spread over time ([OwnerOps]).
 */
object Mailboxes {
    private const val TAG = "Mailboxes"

    /**
     * Ready mailboxes kept in the pool. Three cover the usual bursts (add a contact, start a group, show a code) without a
     * wait. Each is one more row on the server per user (a few hundred bytes, and a proof of work once), and one more
     * registration with the push app.
     */
    const val POOL_TARGET = 3
    private const val VERIFY_TIMEOUT_MS = 120_000L
    private const val ROTATIONS_PER_PASS = 3
    private const val BUSY_RETRIES = 4

    /** Longer than the server keeps a staged endpoint waiting for its verification (10 to 20 minutes by default). */
    private const val ROTATION_VERIFY_WINDOW_MS = 30 * 60_000L

    /** The server says an endpoint is gone: that instance is registered again at most this often. */
    private const val ENDPOINT_GONE_EVERY_MS = 6 * 3600_000L

    /** Before the first measurement: a guess at Argon2 calls per second (a mid-range phone at 16 MiB, 4 threads). */
    private const val DEFAULT_CALLS_PER_SECOND = 25.0

    /** The server's max message TTL (14 days) plus a day of margin. */
    private const val DRAIN_MS = 15 * 86_400_000L

    private val waiters = ConcurrentHashMap<String, CompletableDeferred<Unit>>()

    /** Serialises verifications with the bookkeeping of rotations that are still outstanding. */
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

    /** Stops the pool fill and waits until it has (the server is about to change). */
    suspend fun stopFill() {
        val job = synchronized(fillLock) {
            fill.also { fill = null }
        }
        job?.cancelAndJoin()
    }

    fun item(m: Mailbox) = MailboxItem(B64.enc(m.sendSecret), B64.enc(m.ownerSecret))

    /** The endpoint [m]'s instance has now, or null if it has none yet. */
    fun endpointOf(s: Session, m: Mailbox): PushEndpointData? =
        m.pushInstance?.let { s.repo.pushInstance(it) }?.endpoint?.let(PushHub::decode)

    /**
     * Creates and verifies one mailbox on our server, for the pool, on an instance of its own. Returns null if push isn't
     * ready (no push app, or it refused or didn't answer a new registration), or the verification push didn't arrive in
     * time.
     *
     * The proof of work has no time limit ([Pow.Lane.OWN_MAILBOX]): it fetches fresh challenges as they near expiry, and
     * only stops if cancelled. The local row is only written once it's solved, so cleanup of abandoned creations can't
     * remove one that's still being worked on.
     */
    private suspend fun create(s: Session, purpose: Int): Mailbox? {
        if (s.decoy) {
            return null
        }
        // Registered before the proof of work, so a push app that refuses another registration costs no work.
        val (instance, ep) = PushHub.fresh(s) ?: return null
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
                    // From here on the instance is this mailbox's alone: if the creation fails it's unregistered, never
                    // given to another mailbox, since the server may have seen its endpoint.
                    id = s.repo.insertMailbox(purpose, send, owner, tag, instance)
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
            // Failed or cancelled before the server took it: the local row goes (unless the push already activated it),
            // and its instance with it.
            if (!keep) {
                id?.let {
                    if (s.repo.mailbox(it)?.state != Mailbox.STATE_ACTIVE) {
                        s.repo.deleteMailboxRow(it)
                        PushHub.sweep(s)
                    }
                }
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

    /**
     * Handles a verification push (type 0x02): for a new mailbox, or for one that was pointed at a new endpoint. The
     * verify request carries just that mailbox, like every owner request.
     */
    suspend fun onVerification(s: Session, tag: ByteArray, code: ByteArray) {
        val rotation = s.repo.rotation(tag)
        if (rotation != null) {
            val api = Graph.ownerApi()
            for (b in rotation.mapNotNull { s.repo.mailbox(it) }) {
                val r = api.verify(item(b), code)
                s.repo.setMailboxState(b.id, Mailbox.STATE_ACTIVE, r.expiresAt, OwnerSchedule.refreshAt(r.expiresAt, System.currentTimeMillis(), Rand::double))
                if (r.endpointGone) {
                    onEndpointGone(s, b)
                }
            }
            s.repo.deleteRotation(tag)
            checkRotationsDone(s)
            return
        }
        val mb = s.repo.mailboxByTag(tag) ?: return
        if (mb.state == Mailbox.STATE_ACTIVE) {
            return
        }
        val r = Graph.api().verify(item(mb), code)
        s.repo.setMailboxState(mb.id, Mailbox.STATE_ACTIVE, r.expiresAt, OwnerSchedule.refreshAt(r.expiresAt, System.currentTimeMillis(), Rand::double))
        if (r.endpointGone) {
            onEndpointGone(s, mb)
        }
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


    /**
     * [instance] has a new endpoint, or its first. It's stored, and a mailbox on it that the server knows is pointed at
     * the new one a few minutes later ([OwnerOps]), on its own: a push app that changes every endpoint at once (another
     * push app was chosen, or its server moved) doesn't make us send them to the server together.
     */
    suspend fun onNewEndpoint(s: Session, instance: String, data: PushEndpointData) {
        if (s.decoy) {
            return
        }
        val inst = s.repo.pushInstance(instance)
        if (inst == null) {
            // Not one of ours (any more): its mailbox is gone. Nothing should reach us through it.
            PushHub.dropStray(instance)
            return
        }
        val old = inst.endpoint?.let(PushHub::decode)
        s.repo.setInstanceEndpoint(instance, PushHub.encode(data))
        Graph.prefs.pushStatus = "ok"
        val host = runCatching { java.net.URI(data.url).host }.getOrNull()
        Graph.prefs.pushHost = host
        PushHub.endpointStored(instance, data)
        if (old != null && old != data) {
            val now = System.currentTimeMillis()
            val boxes = s.repo.mailboxesOnInstance(instance).filter { it.state == Mailbox.STATE_ACTIVE }
            for (m in boxes) {
                s.repo.setRotateAt(m.id, now + OwnerSchedule.rotateDelay(Rand::double))
            }
            val oldHost = runCatching { java.net.URI(old.url).host }.getOrNull()
            if (boxes.isNotEmpty() && oldHost != null && oldHost != host && Graph.prefs.pushHostUnconfirmed == null) {
                // Until the server confirms the new endpoint, it still wakes us through the old push service.
                Graph.prefs.pushHostUnconfirmed = oldHost
            }
            OwnerOps.kick(s)
        }
        if (!inst.used) {
            // A spare's endpoint (at setup, the first one): the pool can be filled now.
            kickPool(s)
        }
    }

    /** Every mailbox is confirmed on its instance's current endpoint. */
    private fun rotationDone() {
        Graph.prefs.pushHostUnconfirmed = null
    }

    /** Once no mailbox is still moving to a new endpoint, the old push service no longer wakes us. */
    internal suspend fun checkRotationsDone(s: Session) = rotateMutex.withLock {
        if (!s.repo.rotationsOutstanding()) {
            rotationDone()
        }
    }

    /**
     * The server no longer knows [m] (it answered 404). A pool mailbox, or one already replaced and draining, is just
     * dropped. A group inbox is replaced in a new card. For a contact's mailbox, a fresh one is bound and announced
     * through the E2E `mailbox` message, and the gone one dropped, in one transaction: if no fresh one can be had right
     * now, the contact keeps the old row and this is tried again later, so a contact is never left without a mailbox.
     */
    internal suspend fun replaceGone(s: Session, m: Mailbox) {
        val cid = m.contactId
        // One already replaced (draining after a rotation) needs nothing new: the contact or group has a newer one.
        if (cid == null || m.replacedAt != null) {
            s.repo.deleteMailboxRow(m.id)
            PushHub.sweep(s)
            return
        }
        val later = System.currentTimeMillis() + OwnerSchedule.retryDelay(Rand::double)
        // Nothing more goes to the server about it until it's replaced (or the next try).
        s.repo.setRotateAt(m.id, null)
        s.repo.setRefreshAt(m.id, later)
        if (m.purpose == Mailbox.PURPOSE_GROUP) {
            // The rotation retires it once the new inbox is in the card, and it's deleted after draining.
            s.repo.setRotateNeeded(cid, true)
            s.scope.launchSafe { Groups.rotatePending(s) }
            return
        }
        val serverKey = try {
            Graph.ownServerKey()
        } catch (e: ApiException) {
            return
        }
        val fresh = try {
            take(s, Mailbox.PURPOSE_CONTACT)
        } catch (e: ApiException) {
            null
        } ?: return
        val announce = app.goldfishsend.proto.Content.Mailbox(Graph.prefs.serverUrl, B64.enc(fresh.sendSecret), serverKey)
        s.db.tx {
            s.repo.bindMailbox(fresh.id, cid)
            s.repo.enqueue(cid, null, OutboxKind.CONTENT, announce.encode())
            s.repo.deleteMailboxRow(m.id)
        }
        Outbox.kick()
        PushHub.sweep(s)
    }

    /**
     * Mailbox rotation (Prefs.mailboxRotationDays). Each contact periodically gets a fresh inbound mailbox, announced through
     * the E2E `mailbox` message, so the server can't watch one mailbox's traffic for long. The fresh one has an instance
     * (so an endpoint) of its own, so the server can't link it to the old one either. The old mailbox keeps working until
     * the contact is seen using the new one (see [onMessageOnMailbox]), then for one more max-TTL so in-flight messages
     * still arrive. Only then is it deleted. A few contacts rotate per pass, which spreads the proof-of-work cost.
     */
    suspend fun rotateContacts(s: Session) {
        if (s.decoy) {
            return
        }
        val now = System.currentTimeMillis()
        val drained = s.repo.drainedMailboxes(now)
        if (drained.isNotEmpty()) {
            // Deleted on the server one at a time, spread out like every owner request.
            s.repo.doomMailboxes(drained, Graph.prefs.serverUrl, Graph.prefs.serverKey)
            OwnerOps.kick(s)
        }
        val days = Graph.prefs.mailboxRotationDays
        if (days <= 0) {
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
     * The server says it can't reach [m]'s endpoint any more (protocol.md `endpointGone`). Its instance is registered with
     * the distributor again, and its mailbox pointed at the endpoint again: if the endpoint didn't change, the rotation's
     * verification push makes the server probe it again. At most once every 6 hours per instance, so a server that keeps
     * saying so can't make us loop.
     */
    internal fun onEndpointGone(s: Session, m: Mailbox) {
        val name = m.pushInstance ?: return
        val inst = s.repo.pushInstance(name) ?: return
        val now = System.currentTimeMillis()
        if (now - (inst.goneAt ?: 0L) < ENDPOINT_GONE_EVERY_MS) {
            return
        }
        s.repo.setInstanceGoneAt(name, now)
        for (b in s.repo.mailboxesOnInstance(name).filter { it.state == Mailbox.STATE_ACTIVE }) {
            s.repo.setRotateAt(b.id, now + OwnerSchedule.rotateDelay(Rand::double))
        }
        s.scope.launchSafe {
            runCatching { PushHub.reregister(name) }
            OwnerOps.kick(s)
        }
    }

    /**
     * Removes mailboxes from unused, expired invites and abandoned creations, and sends again rotations that were never
     * verified.
     */
    suspend fun cleanup(s: Session) {
        if (s.decoy) {
            return
        }
        val now = System.currentTimeMillis()
        val abandoned = s.repo.abandonedInviteMailboxes(now - 3600_000L)
        s.lock.withLock {
            s.db.tx {
                // The invite can never be used now, so its one-time prekeys go too (forward secrecy).
                for (m in abandoned) {
                    m.inviteSpkId?.let { s.signal.removeSignedPreKey(it) }
                    m.inviteKyberId?.let { s.signal.removeKyberPreKey(it) }
                }
                // Deleted on the server one at a time, spread out like every owner request.
                s.repo.doomMailboxes(abandoned, Graph.prefs.serverUrl, Graph.prefs.serverKey)
            }
        }
        for (m in s.repo.staleCreating(now - 15 * 60_000L)) {
            s.repo.deleteMailboxRow(m.id)
        }
        // A rotation never verified (the push was lost, came after the server's deadline, or verify failed): sent again,
        // once it's past its verification window.
        for ((tag, ids) in s.repo.staleRotations(now - ROTATION_VERIFY_WINDOW_MS)) {
            s.repo.deleteRotation(tag)
            for (id in ids) {
                s.repo.setRotateAt(id, now + OwnerSchedule.rotateDelay(Rand::double))
            }
        }
        OwnerOps.kick(s)
    }
}
