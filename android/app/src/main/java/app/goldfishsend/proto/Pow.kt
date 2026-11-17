package app.goldfishsend.proto

import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlin.random.Random
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters

/**
 * Memory-hard proof of work (`gf/pow/v2`, docs/protocol.md): find an 8-byte big-endian nonce such that
 * Argon2id(password = "gf/pow/v2" ‖ challenge ‖ nonce, salt = challenge, m, t, p = 1, 32 bytes) has at least
 * `difficulty` leading zero bits. That takes about 2^difficulty Argon2 calls, and the search is memoryless: stopping and
 * starting again (even on a new challenge) loses nothing.
 *
 * Two lanes, with different trust ([Lane]):
 *  - [Lane.OWN_MAILBOX]: creating a mailbox on our own server. Generous caps that cover the server's highest difficulty,
 *    no time limit (it's cancellable, and it fetches a fresh challenge before the old one expires), and priority.
 *  - [Lane.CONTACT_SEND]: paying a send limit on a contact's server, which may be hostile. Tight caps, a timeout, and it
 *    pauses whenever our own mailbox creation needs the solver.
 *
 * Either way, threads × memory stays within a budget the heap can afford, and only one search runs at a time.
 */
object Pow {
    const val SCHEME = "gf/pow/v2"
    private val PREFIX = SCHEME.utf8()

    const val MIN_MEMORY_KIB = 8
    const val MAX_MEMORY_KIB = 64 * 1024
    const val MAX_ITERATIONS = 4

    /** Who is asking, and so how much work we'll do for them. */
    enum class Lane(val maxDifficulty: Int, val maxWorkKiB: Long, val timeoutMs: Long?) {
        /**
         * Our own server, for a mailbox. Expected work (2^difficulty × m × t, in KiB) up to twice the default server's
         * worst case (8 + 6 + 2 bits of 16 MiB calls), which is an hour or more on a phone: it only happens to a network
         * under heavy load. No timeout: the user can cancel, and it keeps going while the app runs.
         */
        OWN_MAILBOX(24, (1L shl 17) * 16 * 1024, null),

        /** A contact's server, to get past a send limit: at most 2^11 calls of 16 MiB (a minute or two), and 180 s. */
        CONTACT_SEND(20, (1L shl 11) * 16 * 1024, 180_000L),
    }

    /** Solver threads: enough to use a phone's big cores, few enough to leave the rest of the app responsive. */
    const val MAX_THREADS = 4

    /** Argon2 memory across all solver threads, at most. Also capped at a third of the heap, see [threadsFor]. */
    const val MEMORY_BUDGET_KIB = 80 * 1024

    /** How long before a challenge expires we stop searching it and fetch a new one (network round trip, clock drift). */
    const val EXPIRY_MARGIN_MS = 30_000L

    data class Params(val difficulty: Int, val memoryKiB: Int, val iterations: Int)

    /** A challenge to solve, valid for [validForMs] from when it was fetched. */
    class Challenge(val bytes: ByteArray, val params: Params, val validForMs: Long)

    class TooHardException(val params: Params, val why: String) : Exception("proof of work $params refused: $why")

    /** Why [p] is refused in [lane], or null if it's acceptable. */
    fun refusal(p: Params, lane: Lane): String? = when {
        p.difficulty !in 0..lane.maxDifficulty -> "difficulty"
        p.memoryKiB !in MIN_MEMORY_KIB..MAX_MEMORY_KIB -> "memory"
        p.iterations !in 1..MAX_ITERATIONS -> "iterations"
        (1L shl p.difficulty) * p.memoryKiB * p.iterations > lane.maxWorkKiB -> "work"
        else -> null
    }

    fun leadingZeroBits(hash: ByteArray): Int {
        var bits = 0
        for (b in hash) {
            val v = b.toInt() and 0xff
            if (v == 0) {
                bits += 8
                continue
            }
            bits += Integer.numberOfLeadingZeros(v) - 24
            break
        }
        return bits
    }

    fun nonceBytes(n: Long): ByteArray {
        val out = ByteArray(8)
        writeNonce(n, out, 0)
        return out
    }

    private fun writeNonce(n: Long, out: ByteArray, offset: Int) {
        for (i in 0 until 8) {
            out[offset + i] = (n ushr (56 - 8 * i)).toByte()
        }
    }

    /** One Argon2 instance per thread. It keeps its m KiB between calls, since the salt (the challenge) doesn't change. */
    private class Hasher(challenge: ByteArray, memoryKiB: Int, iterations: Int) {
        private val gen = Argon2BytesGenerator().apply {
            init(
                Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                    .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                    .withMemoryAsKB(memoryKiB)
                    .withIterations(iterations)
                    .withParallelism(1)
                    .withSalt(challenge)
                    .build(),
            )
        }
        private val password = PREFIX + challenge + ByteArray(8)
        private val out = ByteArray(32)

        fun hash(nonce: Long): ByteArray {
            writeNonce(nonce, password, PREFIX.size + 32)
            gen.generateBytes(password, out)
            return out
        }
    }

    /** The Argon2id output for one nonce (32 bytes). */
    fun hash(challenge: ByteArray, nonce: ByteArray, memoryKiB: Int, iterations: Int): ByteArray {
        require(challenge.size == 32 && nonce.size == 8)
        var n = 0L
        for (b in nonce) {
            n = (n shl 8) or (b.toLong() and 0xff)
        }
        return Hasher(challenge, memoryKiB, iterations).hash(n).copyOf()
    }

    /** Whether [nonce] solves [challenge] (any parameters within the widest lane's caps). */
    fun check(challenge: ByteArray, nonce: ByteArray, p: Params): Boolean {
        require(nonce.size == 8)
        return refusal(p, Lane.OWN_MAILBOX) == null && leadingZeroBits(hash(challenge, nonce, p.memoryKiB, p.iterations)) >= p.difficulty
    }

    /**
     * How many solver threads to run: at most [MAX_THREADS] and the core count, and only as many m-KiB Argon2 instances
     * as fit in [MEMORY_BUDGET_KIB] and a third of [maxHeapBytes], so a low-memory device solves more slowly instead of
     * running out of memory. Always at least one: a single instance of up to 64 MiB is what the app's own key
     * derivation already uses.
     */
    fun threadsFor(
        memoryKiB: Int,
        cores: Int = Runtime.getRuntime().availableProcessors(),
        maxHeapBytes: Long = Runtime.getRuntime().maxMemory(),
    ): Int {
        val budgetKiB = minOf(MEMORY_BUDGET_KIB.toLong(), maxHeapBytes / 1024 / 3)
        // BouncyCastle keeps each 1 KiB block in its own object: about 4% on top.
        val perThreadKiB = memoryKiB.toLong() * 104 / 100 + 64
        return minOf(MAX_THREADS.toLong(), cores.toLong(), budgetKiB / perThreadKiB).toInt().coerceAtLeast(1)
    }

    /**
     * Single-threaded search over nonces start, start+stride, ... until one works or [shouldStop] (checked before every
     * Argon2 call, so stopping takes at most one call). [onHash] runs after each call.
     */
    fun solveRange(
        challenge: ByteArray,
        p: Params,
        start: Long,
        stride: Long,
        onHash: () -> Unit = {},
        shouldStop: () -> Boolean = { false },
    ): ByteArray? {
        val hasher = Hasher(challenge, p.memoryKiB, p.iterations)
        var n = start
        while (!shouldStop()) {
            val h = hasher.hash(n)
            onHash()
            if (leadingZeroBits(h) >= p.difficulty) {
                return nonceBytes(n)
            }
            n += stride
        }
        return null
    }

    /** How long to search a challenge valid for [validForMs] before fetching another. */
    fun searchWindowMs(validForMs: Long): Long =
        if (validForMs > 2 * EXPIRY_MARGIN_MS) validForMs - EXPIRY_MARGIN_MS else (validForMs / 2).coerceAtLeast(1)

    /** Solver threads come from the IO pool, so a long search can't starve Dispatchers.Default. */
    private val solverDispatcher = Dispatchers.IO.limitedParallelism(MAX_THREADS)

    /** The solver's threads and memory: one search at a time, so the memory budget holds whoever asks. */
    private val cpu = Mutex()

    /** Own-server searches that are running or waiting. A contact search pauses while this is above zero. */
    private val ownWanted = MutableStateFlow(0)

    /** Own-server searches run one after another (the mailbox pool fills one at a time anyway). */
    private val ownLane = Mutex()

    /** Whether an own-server search is running or waiting (for tests). */
    val ownBusy: Boolean get() = ownWanted.value > 0

    private fun monotonicMs() = System.nanoTime() / 1_000_000

    /**
     * Solves for our own server's mailbox creation. [next] fetches a challenge. When one is about to expire unsolved, the
     * search moves on to a fresh one: nothing is lost, since every Argon2 call is an independent try. There's no time limit,
     * so callers decide when to give up by cancelling. [hashes] counts every call across challenges (for progress).
     *
     * @throws TooHardException if a challenge is outside [Lane.OWN_MAILBOX]'s caps.
     */
    suspend fun solveOwn(
        next: suspend () -> Challenge,
        hashes: AtomicLong? = null,
        clock: () -> Long = ::monotonicMs,
    ): Pair<Challenge, ByteArray> {
        ownWanted.update { it + 1 }
        try {
            return ownLane.withLock { cpu.withLock { searchOwn(next, hashes, clock) } }
        } finally {
            ownWanted.update { it - 1 }
        }
    }

    private suspend fun searchOwn(next: suspend () -> Challenge, hashes: AtomicLong?, clock: () -> Long): Pair<Challenge, ByteArray> {
        while (true) {
            val ch = next()
            refusal(ch.params, Lane.OWN_MAILBOX)?.let { throw TooHardException(ch.params, it) }
            require(ch.bytes.size == 32)
            val until = clock() + searchWindowMs(ch.validForMs)
            search(ch.bytes, ch.params, hashes) { clock() >= until }?.let { return ch to it }
        }
    }

    /**
     * Solves a challenge from a contact's server ([Lane.CONTACT_SEND]): tight caps, a timeout, and it steps aside whenever
     * our own mailbox creation wants the solver, carrying on afterwards (the time spent paused counts toward the timeout).
     *
     * @throws TooHardException if the parameters are outside the lane's caps.
     * @throws kotlinx.coroutines.TimeoutCancellationException on timeout.
     */
    suspend fun solveContact(
        challenge: ByteArray,
        p: Params,
        timeoutMs: Long = Lane.CONTACT_SEND.timeoutMs!!,
        hashes: AtomicLong? = null,
    ): ByteArray {
        refusal(p, Lane.CONTACT_SEND)?.let { throw TooHardException(p, it) }
        require(challenge.size == 32)
        return withTimeout(timeoutMs) { searchContact(challenge, p, hashes) }
    }

    private suspend fun searchContact(challenge: ByteArray, p: Params, hashes: AtomicLong?): ByteArray {
        while (true) {
            ownWanted.first { it == 0 }
            val r = cpu.withLock {
                if (ownWanted.value > 0) null else search(challenge, p, hashes) { ownWanted.value > 0 }
            }
            if (r != null) {
                return r
            }
        }
    }

    /**
     * A parallel search on up to [threadsFor] threads, from a random starting nonce (so a resumed search doesn't redo
     * old tries). Returns null when [stop] says so. Cancelling the caller stops every worker within one Argon2 call.
     */
    private suspend fun search(challenge: ByteArray, p: Params, hashes: AtomicLong?, stop: () -> Boolean): ByteArray? =
        withContext(solverDispatcher) {
            val workers = threadsFor(p.memoryKiB)
            val found = AtomicBoolean(false)
            // Below 2^62, so start + k·stride stays positive for any realistic search.
            val base = Random.nextLong(1L shl 62)
            val r = coroutineScope {
                (0 until workers).map { w ->
                    async {
                        ensureActive()
                        val job = coroutineContext[Job]
                        val r = solveRange(challenge, p, base + w, workers.toLong(), { hashes?.incrementAndGet() }) {
                            found.get() || job?.isActive == false || stop()
                        }
                        if (r != null) {
                            found.set(true)
                        }
                        r
                    }
                }.awaitAll().firstOrNull { it != null }
            }
            ensureActive()
            r
        }

    /**
     * How far a search is after [hashes] tries, for a progress bar. A solution takes 2^difficulty tries on average but
     * can come at any moment, so this is the chance of having found one by then (stretched so the average lands near
     * 80%). It never reaches 1: the bar fills when the solution is found.
     */
    fun estimatedProgress(hashes: Long, difficulty: Int): Float {
        val expected = Math.scalb(1.0, difficulty.coerceIn(0, 62))
        return (1 - Math.exp(-1.6 * hashes / expected)).toFloat().coerceIn(0f, 0.99f)
    }

    /**
     * Expected seconds still to go, for a time estimate: the expected total (2^difficulty calls at [callsPerSecond]) minus
     * [elapsedSeconds], or null once that's passed (the search is memoryless, so past the average there's no honest
     * countdown, only "taking longer than usual").
     */
    fun remainingSeconds(difficulty: Int, callsPerSecond: Double, elapsedSeconds: Double): Long? {
        if (callsPerSecond <= 0) {
            return null
        }
        val left = Math.scalb(1.0, difficulty.coerceIn(0, 62)) / callsPerSecond - elapsedSeconds
        return if (left > 0) Math.ceil(left).toLong() else null
    }
}
