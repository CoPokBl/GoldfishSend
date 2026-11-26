package app.goldfishsend.core

import androidx.work.Constraints
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import app.goldfishsend.db.DoomedMailbox
import app.goldfishsend.db.Mailbox
import app.goldfishsend.net.ApiException
import app.goldfishsend.net.MailboxItem
import app.goldfishsend.net.ServerPin
import app.goldfishsend.proto.B64
import app.goldfishsend.proto.Rand
import app.goldfishsend.push.PushHub
import app.goldfishsend.work.OwnerOpsWorker
import java.util.concurrent.TimeUnit
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Owner requests to our server: refreshing a mailbox before it expires, pointing it at its instance's new endpoint, and
 * deleting it once its chat is gone. Each request carries one mailbox, and they go out one at a time with a random gap
 * of a few minutes between them ([OwnerSchedule]), each on a connection of its own ([Graph.ownerApi]). So the server
 * sees neither a request nor a burst that names several of our mailboxes, and can't tell which ones belong together.
 *
 * Each mailbox's next refresh, rotation and delete time is stored with it. A WorkManager job runs at the first one due,
 * sends that one request, and schedules itself for the next. Rotations go first (messages wait at the server until they
 * are done), then deletes, then refreshes (which have a month's margin).
 */
object OwnerOps {
    private const val WORK = "owner-ops"

    /** The time before which no other owner request may go out (the end of the gap after the last one). */
    private const val KV_NOT_BEFORE = "owner_not_before"

    /** A mailbox nobody refreshes is gone from the server after its lifetime (90 days by default); a day of margin. */
    private const val DOOMED_KEEP_MS = 91 * 86_400_000L

    private val mutex = Mutex()

    @Volatile
    private var running = false

    /** When the job is scheduled to run next, as far as this process knows. */
    @Volatile
    private var scheduledFor: Long? = null

    /**
     * Unregisters the instances of mailboxes that are gone, and makes sure the next due request runs on time. Safe to
     * call often: after anything that changes what's due.
     */
    fun kick(s: Session) {
        if (s.decoy || s.closed) {
            return
        }
        PushHub.sweep(s)
        schedule(s)
    }

    private fun schedule(s: Session) {
        if (running) {
            // The run under way schedules the next one when it ends.
            return
        }
        val now = System.currentTimeMillis()
        val at = OwnerSchedule.nextRun(s.repo.nextOwnerOpAt(), notBefore(s), now) ?: return
        val current = scheduledFor
        if (current != null && current in now..at) {
            return
        }
        scheduledFor = at
        val req = OneTimeWorkRequestBuilder<OwnerOpsWorker>()
            .setInitialDelay(at - now, TimeUnit.MILLISECONDS)
            .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
            .build()
        WorkManager.getInstance(Graph.app).enqueueUniqueWork(WORK, ExistingWorkPolicy.REPLACE, req)
    }

    private fun notBefore(s: Session): Long = s.repo.kvString(KV_NOT_BEFORE)?.toLongOrNull() ?: 0L

    /** Sends the one request that's due first, if it's time, then schedules the next. */
    suspend fun runDue(s: Session) {
        if (s.decoy) {
            return
        }
        mutex.withLock {
            running = true
            try {
                scheduledFor = null
                s.repo.forgetDoomedBefore(System.currentTimeMillis() - DOOMED_KEEP_MS)
                val now = System.currentTimeMillis()
                if (now >= notBefore(s) && runOne(s, now)) {
                    s.repo.kvPutString(KV_NOT_BEFORE, (System.currentTimeMillis() + OwnerSchedule.gap(Rand::double)).toString())
                }
            } finally {
                running = false
            }
        }
        kick(s)
    }

    /** True if a request went to a server. */
    private suspend fun runOne(s: Session, now: Long): Boolean {
        s.repo.nextRotation(now)?.let { return rotate(s, it, now) }
        s.repo.nextDoomed(now)?.let { return delete(s, it, now) }
        s.repo.nextRefresh(now)?.let { return refresh(s, it, now) }
        return false
    }

    private fun later(now: Long, e: Exception? = null): Long =
        now + OwnerSchedule.retryDelay(Rand::double, (e as? ApiException)?.retryAfterSeconds)

    /** Points [m] at its instance's current endpoint. The server confirms with a verification push sent there. */
    private suspend fun rotate(s: Session, m: Mailbox, now: Long): Boolean {
        val ep = Mailboxes.endpointOf(s, m)
        if (ep == null) {
            // Nothing to move to (yet): the next endpoint for its instance schedules it again.
            s.repo.setRotateAt(m.id, null)
            Mailboxes.checkRotationsDone(s)
            return false
        }
        s.repo.addRotation(m.tag, listOf(m.id))
        try {
            Graph.ownerApi().rotate(Mailboxes.item(m), ep.url, ep.p256dh, ep.auth)
            s.repo.setRotateAt(m.id, null)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            s.repo.deleteRotation(m.tag)
            if ((e as? ApiException)?.status == 404) {
                // Unknown to the server (expired or purged). A pending one can't rotate either: it has to be made again.
                Mailboxes.replaceGone(s, m)
                Mailboxes.checkRotationsDone(s)
            } else {
                // 429 (the mailbox's rotation budget) or the network: later.
                s.repo.setRotateAt(m.id, later(now, e))
            }
        }
        return true
    }

    private suspend fun refresh(s: Session, m: Mailbox, now: Long): Boolean {
        try {
            val r = Graph.ownerApi().refresh(Mailboxes.item(m))
            s.repo.setMailboxExpiry(m.id, r.expiresAt, OwnerSchedule.refreshAt(r.expiresAt, System.currentTimeMillis(), Rand::double))
            if (r.endpointGone) {
                Mailboxes.onEndpointGone(s, m)
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            if ((e as? ApiException)?.status == 404) {
                Mailboxes.replaceGone(s, m)
            } else {
                s.repo.setRefreshAt(m.id, later(now, e))
            }
        }
        return true
    }

    /**
     * Deletes [d] on its server. One on a server we no longer use is deleted there, but only if we know that server's
     * fingerprint (otherwise the secrets would go to whoever answers). Past the server's mailbox lifetime it's gone there
     * anyway, and is forgotten.
     */
    private suspend fun delete(s: Session, d: DoomedMailbox, now: Long): Boolean {
        val api = when {
            d.server == Graph.prefs.serverUrl -> Graph.ownerApi()
            d.serverKey != null -> Graph.ownerApi(d.server, ServerPin(d.serverKey))
            else -> {
                s.repo.setDeleteAt(d.sendSecret, now + 86_400_000L)
                return false
            }
        }
        try {
            api.delete(MailboxItem(B64.enc(d.sendSecret), B64.enc(d.ownerSecret)))
            s.repo.forgetDoomed(d.sendSecret)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            if ((e as? ApiException)?.status == 404) {
                // Already gone (expired, or deleted by a call whose answer was lost).
                s.repo.forgetDoomed(d.sendSecret)
            } else {
                s.repo.setDeleteAt(d.sendSecret, later(now, e))
            }
        }
        return true
    }
}
