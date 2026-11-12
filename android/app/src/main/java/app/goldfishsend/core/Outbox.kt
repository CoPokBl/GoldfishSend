package app.goldfishsend.core

import androidx.work.Constraints
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import app.goldfishsend.db.MsgStatus
import app.goldfishsend.db.OutboxItem
import app.goldfishsend.db.OutboxKind
import app.goldfishsend.net.ApiException
import app.goldfishsend.proto.B64
import app.goldfishsend.proto.Content
import app.goldfishsend.proto.E2eBlob
import app.goldfishsend.proto.Padding
import app.goldfishsend.proto.Pow
import app.goldfishsend.proto.Rand
import app.goldfishsend.work.OutboxWorker
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.signal.libsignal.protocol.SessionCipher

/**
 * Reliable, ordered outbound delivery. Each row is encrypted exactly once (the ciphertext is stored), then retried with the
 * same idempotency key until accepted, so retries never duplicate messages or desync the ratchet.
 */
object Outbox {
    private val mutex = Mutex()

    /** Starts sending now (in process) and schedules WorkManager as a durable fallback. */
    fun kick() {
        Graph.session.value?.let { s -> Graph.scope.launchSafe { runAndSchedule(s) } }
        val req = OneTimeWorkRequestBuilder<OutboxWorker>()
            .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
            .build()
        WorkManager.getInstance(Graph.app).enqueueUniqueWork("outbox", ExistingWorkPolicy.KEEP, req)
    }

    suspend fun runAndSchedule(s: Session) {
        val next = process(s) ?: return
        val delay = (next - System.currentTimeMillis()).coerceAtLeast(1_000L)
        val req = OneTimeWorkRequestBuilder<OutboxWorker>()
            .setInitialDelay(delay, TimeUnit.MILLISECONDS)
            .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
            .build()
        WorkManager.getInstance(Graph.app).enqueueUniqueWork("outbox-retry", ExistingWorkPolicy.REPLACE, req)
    }

    /** Sends everything that's due. Returns the earliest pending retry time, or null if the outbox is empty. */
    suspend fun process(s: Session): Long? = mutex.withLock {
        val now = System.currentTimeMillis()
        for ((_, items) in s.repo.outboxAll().groupBy { it.contactId }) {
            for (item in items) {
                if (item.nextAt > now) {
                    break
                }
                if (!sendOne(s, item)) {
                    // Preserve per-contact ordering: stop this contact's queue until the head succeeds.
                    break
                }
            }
        }
        s.repo.outboxEarliest()
    }

    private suspend fun sendOne(s: Session, item: OutboxItem): Boolean {
        val contact = s.repo.contact(item.contactId) ?: run {
            s.repo.outboxDelete(item.seq)
            return true
        }
        val server = contact.outServer
        val secret = contact.outSecret
        if (server == null || secret == null) {
            return false
        }
        try {
            var blob = item.blob
            if (blob == null) {
                val plaintext = when (item.kind) {
                    OutboxKind.HELLO -> {
                        val mb = Mailboxes.takeForContact(s, item.contactId) ?: run {
                            backoff(s, item, null)
                            return false
                        }
                        Content.Hello(Graph.prefs.serverUrl, B64.enc(mb.sendSecret), s.repo.displayName).encode()
                    }
                    else -> s.repo.openOutboxContent(item) ?: run {
                        s.repo.outboxDelete(item.seq)
                        return true
                    }
                }
                blob = s.lock.withLock {
                    s.db.tx {
                        val msg = SessionCipher(s.signal, Messenger.LOCAL, Messenger.remote(item.contactId)).encrypt(Padding.pad(plaintext))
                        val b = E2eBlob(msg.type, msg.serialize()).encode()
                        s.repo.outboxSetBlob(item.seq, b)
                        b
                    }
                }
                if (blob.size > E2eBlob.MAX_BYTES) {
                    fail(s, item)
                    return true
                }
            }
            val api = Graph.api(server)
            try {
                api.sendMessage(secret, blob, item.idem, null)
            } catch (e: ApiException) {
                // A 429 may be the per-IP limit (shared IP / Tor). Pay with proof of work once and retry.
                // If it's the per-mailbox limit the retry fails too, and we fall back to normal backoff.
                if (e.status != 429 || item.attempts >= 3) {
                    throw e
                }
                val ch = api.powChallenge()
                val nonce = Pow.solve(B64.dec(ch.challenge), ch.difficulty)
                api.sendMessage(secret, blob, item.idem, null, "${ch.challenge}.${B64.enc(nonce)}")
            }
            s.repo.outboxDelete(item.seq)
            item.messageId?.let { id ->
                if (s.repo.outboxRemaining(id) == 0L) {
                    val m = s.repo.message(id)
                    if (m != null && (m.status == MsgStatus.QUEUED || m.status == MsgStatus.FAILED)) {
                        s.repo.setStatus(id, MsgStatus.SENT)
                    }
                }
            }
            if (contact.unreachable) {
                s.repo.setUnreachable(contact.id, false)
            }
            s.db.notifyChanged()
            return true
        } catch (e: ApiException) {
            when {
                e.status == 404 -> {
                    s.repo.setUnreachable(contact.id, true)
                    fail(s, item)
                    return true
                }
                e.status == 413 -> {
                    fail(s, item)
                    return true
                }
                e.status == 507 -> {
                    // mailbox_full: the recipient has been offline a long time. Keep it queued (shown as "sending").
                    backoff(s, item, maxOf(e.retryAfterSeconds ?: 0, 3600))
                    return false
                }
                e.retryable -> {
                    backoff(s, item, e.retryAfterSeconds)
                    return false
                }
                else -> {
                    fail(s, item)
                    return true
                }
            }
        }
    }

    private fun backoff(s: Session, item: OutboxItem, retryAfter: Long?) {
        val attempts = item.attempts + 1
        val base = (5_000L shl attempts.coerceAtMost(9)).coerceAtMost(30 * 60_000L)
        val jitter = (base * (Rand.int(40) - 20)) / 100
        val delay = maxOf(base + jitter, (retryAfter ?: 0) * 1000)
        s.repo.outboxBackoff(item.seq, attempts, System.currentTimeMillis() + delay)
    }

    private fun fail(s: Session, item: OutboxItem) {
        s.repo.outboxDelete(item.seq)
        item.messageId?.let { s.repo.setStatus(it, MsgStatus.FAILED) }
        s.db.notifyChanged()
    }

    /** Retries a failed message (user tapped "retry"). */
    fun retry(s: Session, messageId: String) {
        val m = s.repo.message(messageId) ?: return
        s.repo.setStatus(messageId, MsgStatus.QUEUED)
        s.repo.setUnreachable(m.contactId, false)
        Messenger.sendControlRaw(s, m)
        kick()
    }
}
