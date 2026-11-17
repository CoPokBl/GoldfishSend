package app.goldfishsend.proto

import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters

/**
 * Memory-hard proof of work (`gf/pow/v2`, docs/protocol.md): find an 8-byte big-endian nonce such that
 * Argon2id(password = "gf/pow/v2" ‖ challenge ‖ nonce, salt = challenge, m, t, p = 1, 32 bytes) has at least
 * `difficulty` leading zero bits. That takes about 2^difficulty Argon2 calls.
 *
 * The server picks the parameters, and the server may be a stranger's (a contact's self-hosted one), so they're checked
 * first: memory, iterations, difficulty and the expected total work are capped, threads × memory stays within a budget
 * the heap can afford, and the search gives up after [TIMEOUT_MS].
 */
object Pow {
    const val SCHEME = "gf/pow/v2"
    private val PREFIX = SCHEME.utf8()

    const val MAX_DIFFICULTY = 20
    const val MIN_MEMORY_KIB = 8
    const val MAX_MEMORY_KIB = 64 * 1024
    const val MAX_ITERATIONS = 4

    /**
     * Expected work, in KiB of Argon2 memory filled: 2^difficulty × m × t. This is what the default server asks at its
     * worst (base 6 bits plus 8 under load, at 16 MiB, t = 1): minutes on a phone, so the timeout usually ends it first.
     * Anything bigger is refused without trying.
     */
    const val MAX_WORK_KIB = (1L shl 14) * 16 * 1024

    /** Solver threads: enough to use a phone's big cores, few enough to leave the rest of the app responsive. */
    const val MAX_THREADS = 4

    /** Argon2 memory across all solver threads, at most. Also capped at a third of the heap, see [threadsFor]. */
    const val MEMORY_BUDGET_KIB = 80 * 1024

    /** Gives up after this long, so a hostile server can never stall the app indefinitely. */
    const val TIMEOUT_MS = 180_000L

    data class Params(val difficulty: Int, val memoryKiB: Int, val iterations: Int)

    class TooHardException(val params: Params, val why: String) : Exception("proof of work $params refused: $why")

    /** Why [p] is refused, or null if it's acceptable. */
    fun refusal(p: Params): String? = when {
        p.difficulty !in 0..MAX_DIFFICULTY -> "difficulty"
        p.memoryKiB !in MIN_MEMORY_KIB..MAX_MEMORY_KIB -> "memory"
        p.iterations !in 1..MAX_ITERATIONS -> "iterations"
        (1L shl p.difficulty) * p.memoryKiB * p.iterations > MAX_WORK_KIB -> "work"
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

    fun check(challenge: ByteArray, nonce: ByteArray, p: Params): Boolean {
        require(nonce.size == 8)
        return refusal(p) == null && leadingZeroBits(hash(challenge, nonce, p.memoryKiB, p.iterations)) >= p.difficulty
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

    /** Solver threads come from the IO pool, so a long search can't starve Dispatchers.Default. */
    private val solverDispatcher = Dispatchers.IO.limitedParallelism(MAX_THREADS)

    /** One search at a time, so the memory budget holds however many servers ask at once. */
    private val oneAtATime = Mutex()

    /**
     * Parallel solver on up to [threadsFor] threads. Cancelling the caller stops every worker within one Argon2 call, and
     * it gives up after [timeoutMs] (not counting the wait for another search to finish).
     *
     * [hashes], if given, counts the Argon2 calls so far (for [estimatedProgress]).
     *
     * @throws TooHardException if the challenge's parameters are refused (see [refusal]).
     * @throws kotlinx.coroutines.TimeoutCancellationException on timeout.
     */
    suspend fun solve(challenge: ByteArray, p: Params, timeoutMs: Long = TIMEOUT_MS, hashes: AtomicLong? = null): ByteArray {
        refusal(p)?.let { throw TooHardException(p, it) }
        require(challenge.size == 32)
        return oneAtATime.withLock { search(challenge, p, timeoutMs, hashes) }
    }

    private suspend fun search(challenge: ByteArray, p: Params, timeoutMs: Long, hashes: AtomicLong?): ByteArray {
        return withTimeout(timeoutMs) {
            withContext(solverDispatcher) {
                val workers = threadsFor(p.memoryKiB)
                val found = AtomicBoolean(false)
                coroutineScope {
                    val jobs = (0 until workers).map { w ->
                        async {
                            ensureActive()
                            val job = coroutineContext[Job]
                            val r = solveRange(challenge, p, w.toLong(), workers.toLong(), { hashes?.incrementAndGet() }) {
                                found.get() || job?.isActive == false
                            }
                            if (r != null) {
                                found.set(true)
                            }
                            r
                        }
                    }
                    jobs.awaitAll().firstOrNull { it != null } ?: throw kotlinx.coroutines.CancellationException("cancelled")
                }
            }
        }
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
}
