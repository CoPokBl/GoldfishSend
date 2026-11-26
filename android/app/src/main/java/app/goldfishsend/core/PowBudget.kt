package app.goldfishsend.core

import app.goldfishsend.net.ApiException
import app.goldfishsend.net.ServerApi
import app.goldfishsend.proto.Pow
import app.goldfishsend.proto.ProtoJson
import kotlinx.serialization.Serializable

/**
 * How much proof of work contacts' servers can make the phone do over time ([Pow.Lane.CONTACT_SEND] only caps one
 * solve). A contact's server can answer every send, including the automatic delivery receipts, with a send limit and a
 * challenge at the lane's maximum, so without a budget it could keep the solver running in the background for hours.
 *
 * Work is counted in KiB of expected Argon2 work (2^difficulty × memoryKiB × iterations, as in [Pow.refusal]), so a
 * normal send challenge (6 bits of 16 MiB) costs 1/32 of a worst-case one. Each server has a bucket of two worst-case
 * solves that refills by one every [SERVER_REFILL_MS]; all contacts' servers together share another of two that refills
 * by one every [GLOBAL_REFILL_MS]. That still covers about 200 normal paid sends a day to each server (a worst-case one
 * can get about 6). A server that refuses a send it
 * was paid for gets nothing more for [REFUSED_COOLDOWN_MS]. The state lives in the encrypted database (it names
 * servers), so restarting the process doesn't refill it.
 */
object PowBudget {
    /** The worst case one solve may cost. */
    val MAX_SOLVE: Long = Pow.Lane.CONTACT_SEND.maxWorkKiB
    val CAPACITY: Long = 2 * MAX_SOLVE

    const val SERVER_REFILL_MS = 6 * 3600_000L
    const val GLOBAL_REFILL_MS = 3 * 3600_000L
    const val REFUSED_COOLDOWN_MS = 6 * 3600_000L

    private const val KV = "pow_budget"

    /** [tokens] as of [at]. [coolUntil]: no work for this server before then. */
    @Serializable
    data class Bucket(val tokens: Long, val at: Long, val coolUntil: Long = 0)

    @Serializable
    data class State(val global: Bucket? = null, val servers: Map<String, Bucket> = emptyMap())

    /** Tokens in [b] at [now]. A missing bucket is full; a clock that went backwards refills nothing. */
    fun level(b: Bucket?, refillMs: Long, now: Long): Long {
        b ?: return CAPACITY
        // Capped at the time to fill up, so the multiplication can't overflow.
        val elapsed = (now - b.at).coerceIn(0, refillMs * CAPACITY / MAX_SOLVE)
        return (b.tokens + elapsed * MAX_SOLVE / refillMs).coerceIn(0, CAPACITY)
    }

    /** Milliseconds until [b] holds [work], or 0 now. */
    private fun waitFor(b: Bucket?, refillMs: Long, work: Long, now: Long): Long {
        val missing = work - level(b, refillMs, now)
        return if (missing <= 0) 0 else (missing * refillMs + MAX_SOLVE - 1) / MAX_SOLVE
    }

    /**
     * Charges [work] to [server] and to the shared bucket. Returns the new state, or null and how long to wait (ms) if
     * either can't afford it, or the server is cooling down after a refused paid send.
     */
    fun charge(state: State, server: String, work: Long, now: Long): Pair<State?, Long> {
        val sb = state.servers[server]
        val cooling = (sb?.coolUntil ?: 0) - now
        val wait = maxOf(cooling, waitFor(sb, SERVER_REFILL_MS, work, now), waitFor(state.global, GLOBAL_REFILL_MS, work, now))
        if (wait > 0) {
            return null to wait
        }
        val next = State(
            Bucket(level(state.global, GLOBAL_REFILL_MS, now) - work, now),
            state.servers + (server to Bucket(level(sb, SERVER_REFILL_MS, now) - work, now)),
        )
        return prune(next, now) to 0
    }

    /** [server] took a proof of work and still refused the send: no more work for it for a while. */
    fun refused(state: State, server: String, now: Long): State {
        val sb = state.servers[server]
        val b = Bucket(level(sb, SERVER_REFILL_MS, now), now, now + REFUSED_COOLDOWN_MS)
        return prune(state.copy(servers = state.servers + (server to b)), now)
    }

    /** Forgets servers whose bucket is full again and that aren't cooling down: they're the same as never seen. */
    fun prune(state: State, now: Long): State = state.copy(
        servers = state.servers.filter { (_, b) -> b.coolUntil > now || level(b, SERVER_REFILL_MS, now) < CAPACITY },
        global = state.global?.takeIf { level(it, GLOBAL_REFILL_MS, now) < CAPACITY },
    )

    private fun load(s: Session): State =
        s.repo.kvString(KV)?.let { runCatching { ProtoJson.decodeFromString(State.serializer(), it) }.getOrNull() } ?: State()

    private fun store(s: Session, state: State) {
        val empty = state.global == null && state.servers.isEmpty()
        s.repo.kvPutString(KV, if (empty) null else ProtoJson.encodeToString(State.serializer(), state))
    }

    /**
     * Pays for a send-limit proof of work of [p] on [server] from the budget, before any of it is done. Throws a
     * retryable `rate_limited` [ApiException] (with a Retry-After) if the budget can't afford it right now.
     */
    @Synchronized
    fun spend(s: Session, server: String, p: Pow.Params, now: Long = System.currentTimeMillis()) {
        val work = (1L shl p.difficulty.coerceIn(0, 62)) * p.memoryKiB * p.iterations
        val (next, wait) = charge(load(s), server, work, now)
        if (next == null) {
            val seconds = ((wait + 999) / 1000).coerceIn(1, ServerApi.MAX_RETRY_AFTER_SECONDS)
            throw ApiException("rate_limited", 429, retryAfterSeconds = seconds)
        }
        store(s, next)
    }

    @Synchronized
    fun refused(s: Session, server: String, now: Long = System.currentTimeMillis()) {
        store(s, refused(load(s), server, now))
    }
}
