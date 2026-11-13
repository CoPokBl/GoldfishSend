package app.goldfishsend.core

import android.util.Log
import app.goldfishsend.db.MemberRoute
import app.goldfishsend.db.MsgStatus
import app.goldfishsend.db.OutboxItem
import app.goldfishsend.db.memberRoutes
import app.goldfishsend.db.setMemberPendingServerKey
import app.goldfishsend.db.setMemberUnreachable
import app.goldfishsend.net.ApiException
import app.goldfishsend.net.BatchItem
import app.goldfishsend.net.BatchResult
import app.goldfishsend.net.BatchUnsupportedException
import app.goldfishsend.net.MessageBatch
import app.goldfishsend.net.ServerApi
import app.goldfishsend.net.ServerPin
import app.goldfishsend.proto.B64
import app.goldfishsend.proto.E2eBlob
import app.goldfishsend.proto.Rand
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.sync.withLock

/**
 * Group fan-out (docs/groups.md): one outbox row per member, kept in order per member, encrypted once and then sent with
 * `POST /v1/messages/batch` per server (at most 32 items and 16 KiB per request). A slow member, or one whose server's
 * identity changed, only holds up their own rows.
 */
object GroupOutbox {
    private const val TAG = "GroupOutbox"

    /** Servers without the batch endpoint (until when): sent one by one meanwhile. */
    private val noBatch = ConcurrentHashMap<String, Long>()

    /** Sends everything due for group [cid], a member's head row at a time, until nothing more goes out. */
    suspend fun drain(s: Session, cid: Long) {
        repeat(64) {
            if (!pass(s, cid)) {
                return
            }
        }
    }

    private class Ready(val item: OutboxItem, val member: String, val route: MemberRoute, var blob: ByteArray? = null)

    /** One round: every member's due head row. Returns true if anything was delivered (so the next rows can go). */
    private suspend fun pass(s: Session, cid: Long): Boolean {
        val now = System.currentTimeMillis()
        val rows = s.repo.outboxFor(cid)
        if (rows.isEmpty()) {
            return false
        }
        val routes = s.repo.memberRoutes(cid)
        val heads = LinkedHashMap<String, OutboxItem>()
        val waiting = HashSet<String>()
        for (r in rows) {
            val member = r.memberKey
            if (member == null) {
                s.repo.outboxDelete(r.seq)
                continue
            }
            if (member in heads || member in waiting) {
                continue
            }
            if (r.nextAt > now) {
                waiting += member
                continue
            }
            heads[member] = r
        }
        val ready = mutableListOf<Ready>()
        for ((member, item) in heads) {
            val route = routes[member]
            when {
                // No card any more (gone and pruned): nothing can reach them.
                route == null -> dropMember(s, cid, member)
                // Their inbox is gone, or their server's identity changed: wait for a new card (or the old key again).
                route.unreachable || route.pendingServerKey != null -> backoff(s, item, 3600)
                else -> ready += Ready(item, member, route)
            }
        }
        if (ready.isEmpty()) {
            return false
        }
        encrypt(s, ready)
        var progress = false
        val byServer = ready.filter { it.blob != null }.groupBy { it.route.card.inbox.server to it.route.card.inbox.serverKey }
        for ((key, list) in byServer) {
            val (server, serverKey) = key
            for (batch in split(list)) {
                if (send(s, cid, server, serverKey, batch)) {
                    progress = true
                }
            }
        }
        if (progress) {
            s.db.notifyChanged()
        }
        return progress
    }

    /** Encrypts rows that have no ciphertext yet, exactly once each (the blob is stored before it's sent). */
    private suspend fun encrypt(s: Session, ready: List<Ready>) {
        val engine = Groups.engine(s)
        s.lock.withLock {
            for (r in ready) {
                r.blob = r.item.blob ?: try {
                    s.db.tx {
                        val plaintext = s.repo.openOutboxContent(r.item) ?: return@tx null
                        val b = engine.encryptTo(r.member, r.route.card, plaintext)
                        s.repo.outboxSetBlob(r.item.seq, b)
                        b
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "can't encrypt to member: ${e.javaClass.simpleName}")
                    null
                }
                val b = r.blob
                if (b == null || b.size > E2eBlob.MAX_BYTES) {
                    r.blob = null
                    failRow(s, r.item)
                }
            }
        }
    }

    private fun split(list: List<Ready>): List<List<Ready>> {
        val out = mutableListOf<List<Ready>>()
        var cur = mutableListOf<Ready>()
        var size = 1
        for (r in list) {
            val add = MessageBatch.ITEM_HEADER + r.blob!!.size
            if (cur.isNotEmpty() && (cur.size == MessageBatch.MAX_ITEMS || size + add > MessageBatch.MAX_BODY)) {
                out += cur
                cur = mutableListOf()
                size = 1
            }
            cur += r
            size += add
        }
        if (cur.isNotEmpty()) {
            out += cur
        }
        return out
    }

    /** Sends one batch to [server]. Returns true if any item was accepted. */
    private suspend fun send(s: Session, cid: Long, server: String, serverKey: String, batch: List<Ready>): Boolean {
        val members = batch.map { it.member }.toSet()
        val api = Graph.api(server, pin(s, cid, members, serverKey))
        val items = batch.map { BatchItem(B64.dec(it.route.card.inbox.sendSecret), it.item.idem, null, it.blob!!) }
        val results: List<BatchResult> = try {
            if ((noBatch[server] ?: 0L) > System.currentTimeMillis()) {
                singles(api, items)
            } else {
                try {
                    withPow(api, batch) { pow -> api.sendBatch(items, pow) }
                } catch (e: BatchUnsupportedException) {
                    noBatch[server] = System.currentTimeMillis() + 6 * 3600_000L
                    singles(api, items)
                }
            }
        } catch (e: ApiException) {
            // The whole batch failed (client rate limit, server or network): retry it whole, same idempotency keys.
            for (r in batch) {
                backoff(s, r.item, e.retryAfterSeconds ?: if (e.status == 404) 3600 else null)
            }
            return false
        }
        var progress = false
        batch.zip(results).forEach { (r, res) ->
            when (res.status) {
                202 -> {
                    s.repo.outboxDelete(r.item.seq)
                    settle(s, r.item.messageId)
                    progress = true
                }
                404 -> {
                    // Their inbox is gone (rotated or deleted). Their next card points to the new one.
                    s.repo.setMemberUnreachable(cid, r.member, true)
                    backoff(s, r.item, 3600)
                }
                else -> backoff(s, r.item, res.retryAfter ?: if (res.status == 507) 3600 else null)
            }
        }
        return progress
    }

    /** Pays a per-IP or per-network limit with a proof of work and tries once more, like single sends. */
    private suspend fun <T> withPow(api: ServerApi, batch: List<Ready>, call: suspend (String?) -> T): T = try {
        call(null)
    } catch (e: ApiException) {
        if (!e.powCanHelp || batch.maxOf { it.item.attempts } >= 3) {
            throw e
        }
        val ch = api.powChallenge()
        val nonce = Outbox.solvePow(ch.challenge, ch.difficulty)
        call("${ch.challenge}.${B64.enc(nonce)}")
    }

    /** A server without the batch endpoint: one request per item, with the same per-item results. */
    private suspend fun singles(api: ServerApi, items: List<BatchItem>): List<BatchResult> = items.map { i ->
        try {
            BatchResult(202, id = api.sendMessage(i.sendSecret, i.blob, i.idempotencyKey, i.ttlSeconds))
        } catch (e: ApiException) {
            if (e.status == 404 || e.status == 429 || e.status == 507) {
                BatchResult(e.status, error = e.code, scope = e.scope, retryAfter = e.retryAfterSeconds)
            } else {
                throw e
            }
        }
    }

    /**
     * A member's server, pinned to the fingerprint in their card. A different key holds their rows until they send a new
     * card (E2E-authenticated) or the server proves the pinned key again.
     */
    private fun pin(s: Session, cid: Long, members: Set<String>, serverKey: String) = ServerPin(
        expected = serverKey,
        onMismatch = { fp ->
            for (m in members) {
                s.repo.setMemberPendingServerKey(cid, m, fp)
            }
            s.db.notifyChanged()
        },
        onVerified = {
            for (m in members) {
                s.repo.setMemberPendingServerKey(cid, m, null)
            }
        },
    )

    private fun backoff(s: Session, item: OutboxItem, retryAfter: Long?) {
        val attempts = item.attempts + 1
        val base = (5_000L shl attempts.coerceAtMost(9)).coerceAtMost(30 * 60_000L)
        val jitter = (base * (Rand.int(40) - 20)) / 100
        val delay = maxOf(base + jitter, (retryAfter ?: 0) * 1000)
        s.repo.outboxBackoff(item.seq, attempts, System.currentTimeMillis() + delay)
    }

    private fun failRow(s: Session, item: OutboxItem) {
        s.repo.outboxDelete(item.seq)
        settle(s, item.messageId)
    }

    private fun dropMember(s: Session, cid: Long, member: String) {
        for (id in s.repo.outboxDropMember(cid, member)) {
            settle(s, id)
        }
    }

    /** A message with nothing left queued has gone to everyone it could. */
    private fun settle(s: Session, messageId: String?) {
        val id = messageId ?: return
        if (s.repo.outboxRemaining(id) == 0L) {
            val m = s.repo.message(id) ?: return
            if (m.status == MsgStatus.QUEUED || m.status == MsgStatus.FAILED) {
                s.repo.setStatus(id, MsgStatus.SENT)
            }
        }
    }
}
