package app.goldfishsend.proto

import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.Job

/**
 * Hashcash proof of work: find an 8-byte big-endian nonce such that
 * SHA256("gf/pow/v1" ‖ challenge ‖ nonce) has at least `difficulty` leading zero bits.
 */
object Pow {
    private val PREFIX = "gf/pow/v1".utf8()

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
        for (i in 0 until 8) {
            out[i] = (n ushr (56 - 8 * i)).toByte()
        }
        return out
    }

    fun check(challenge: ByteArray, nonce: ByteArray, difficulty: Int): Boolean {
        require(nonce.size == 8)
        return leadingZeroBits(Hash.sha256(PREFIX, challenge, nonce)) >= difficulty
    }

    /**
     * The hardest challenge we'll attempt. The server's base difficulty is about 20 bits, and adaptive load adds a few
     * more. Anything above this comes from a broken or hostile server (possibly a contact's), and would pin every core.
     */
    const val MAX_DIFFICULTY = 28

    /** Gives up after this long, so a hostile server can never stall the app indefinitely. */
    const val TIMEOUT_MS = 180_000L

    class TooHardException(val difficulty: Int) : Exception("proof of work difficulty $difficulty is out of range")

    /** Single-threaded search over nonces start, start+stride, start+2*stride, ... until found or [shouldStop]. */
    fun solveRange(challenge: ByteArray, difficulty: Int, start: Long, stride: Long, shouldStop: () -> Boolean = { false }): ByteArray? {
        val base = MessageDigest.getInstance("SHA-256")
        base.update(PREFIX)
        base.update(challenge)
        val nonce = ByteArray(8)
        var n = start
        var iter = 0
        while (true) {
            for (i in 0 until 8) {
                nonce[i] = (n ushr (56 - 8 * i)).toByte()
            }
            val md = base.clone() as MessageDigest
            md.update(nonce)
            if (leadingZeroBits(md.digest()) >= difficulty) {
                return nonce.copyOf()
            }
            n += stride
            iter++
            if ((iter and 0x3ff) == 0 && shouldStop()) {
                return null
            }
        }
    }

    /**
     * Parallel solver using all cores, on Dispatchers.Default. It's cancellable (cancelling the caller stops every worker
     * within ~1024 hashes) and gives up after [timeoutMs].
     *
     * @throws TooHardException if [difficulty] is outside 0..[MAX_DIFFICULTY].
     * @throws kotlinx.coroutines.TimeoutCancellationException on timeout.
     */
    suspend fun solve(challenge: ByteArray, difficulty: Int, timeoutMs: Long = TIMEOUT_MS): ByteArray {
        if (difficulty !in 0..MAX_DIFFICULTY) {
            throw TooHardException(difficulty)
        }
        return withTimeout(timeoutMs) {
            withContext(Dispatchers.Default) {
                val workers = Runtime.getRuntime().availableProcessors().coerceIn(1, 8)
                val found = AtomicBoolean(false)
                coroutineScope {
                    val jobs = (0 until workers).map { w ->
                        async {
                            ensureActive()
                            val job = coroutineContext[Job]
                            val r = solveRange(challenge, difficulty, w.toLong(), workers.toLong()) {
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
}
