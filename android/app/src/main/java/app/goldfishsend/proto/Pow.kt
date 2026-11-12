package app.goldfishsend.proto

import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext

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

    /** Single-threaded search over nonces start, start+stride, start+2*stride, ... */
    fun solveRange(challenge: ByteArray, difficulty: Int, start: Long, stride: Long, stop: AtomicBoolean? = null): ByteArray? {
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
            if (stop != null && (iter and 0x3ff) == 0 && stop.get()) {
                return null
            }
        }
    }

    /** Parallel solver using all cores; runs on Dispatchers.Default. */
    suspend fun solve(challenge: ByteArray, difficulty: Int): ByteArray = withContext(Dispatchers.Default) {
        val workers = Runtime.getRuntime().availableProcessors().coerceIn(1, 8)
        val stop = AtomicBoolean(false)
        coroutineScope {
            val jobs = (0 until workers).map { w ->
                async {
                    ensureActive()
                    val r = solveRange(challenge, difficulty, w.toLong(), workers.toLong(), stop)
                    if (r != null) {
                        stop.set(true)
                    }
                    r
                }
            }
            jobs.awaitAll().first { it != null }!!
        }
    }
}
