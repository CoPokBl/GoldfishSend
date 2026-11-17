package app.goldfishsend

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import app.goldfishsend.proto.Pow
import app.goldfishsend.proto.Rand
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

private fun unhex(s: String) = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }

/** The Argon2id proof of work on Android's runtime (ART, the app's BouncyCastle build). */
@RunWith(AndroidJUnit4::class)
class PowDeviceTest {
    /** Entries copied from docs/test-vectors/pow-v2.json (which the JVM tests check in full). */
    @Test
    fun matchesTheServerVectors() {
        for ((c, n, m, t, h) in listOf(
            listOf("1874900bd67b8c7e072c4e96446b1325a0f82b96595d38ea4d629968e8230e27", "0000000000000000", "16384", "1",
                "7769a1ba2ff021909437a16d37dbbb29c7ab4da5e7498d894ef695c25c0b80ed"),
            listOf("b026ab1112983b1b3c8e586305bafe84a03b0f44d38f59d9ecfec210e36e0a69", "0000000000000002", "1024", "3",
                "39d3cbcfbec56120b65c4e00435de1c1269bf7211f86e3111bc6941f3299903f"),
        )) {
            assertEquals(h, hex(Pow.hash(unhex(c), unhex(n), m.toInt(), t.toInt())))
        }
        val first = Pow.solveRange(unhex("7f932532ad9e11ff82fe0767327e93c385bbff4018ebe55c09d13fea83af4c4c"), Pow.Params(6, 64, 1), 0, 1)
        assertEquals("000000000000000b", hex(first!!))
    }

    @Test
    fun solvesTheDefaultParametersWithinTheTimeout() = runBlocking {
        val ch = Rand.bytes(32)
        val hashes = AtomicLong()
        val p = Pow.Params(4, 16 * 1024, 1)
        val start = System.currentTimeMillis()
        val nonce = Pow.solveOwn({ Pow.Challenge(ch, p, 300_000) }, hashes).second
        Log.i("PowDeviceTest", "difficulty 4 at 16 MiB: ${hashes.get()} calls in ${System.currentTimeMillis() - start} ms")
        assertTrue(Pow.check(ch, nonce, p))
        assertTrue(Pow.threadsFor(16 * 1024) in 1..Pow.MAX_THREADS)
    }

    /**
     * Timings for choosing the parameters. Only with `-e gfPowBench 1`:
     * `adb shell am instrument -w -e class app.goldfishsend.PowDeviceTest -e gfPowBench 1 ...`, then read logcat (tag POWBENCH).
     */
    @Test
    fun benchmark() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("gfPowBench") != null)
        val ch = Rand.bytes(32)
        for (mib in listOf(8, 16, 32)) {
            val m = mib * 1024
            val never = Pow.Params(256, m, 1)
            var n = 0
            Pow.solveRange(ch, never, 0, 1, { n++ }) { n >= 3 }
            val calls = 20
            val times = LongArray(calls)
            n = 0
            var last = System.nanoTime()
            Pow.solveRange(ch, never, 0, 1, {
                val now = System.nanoTime()
                times[n] = now - last
                last = now
                n++
            }) { n >= calls }
            times.sort()
            val threads = Pow.threadsFor(m)
            val done = AtomicLong()
            val t0 = System.nanoTime()
            runBlocking {
                coroutineScope {
                    (0 until threads).map { w ->
                        async(Dispatchers.IO) {
                            Pow.solveRange(ch, never, w.toLong(), threads.toLong(), { done.incrementAndGet() }) { done.get() >= calls * threads }
                        }
                    }.awaitAll()
                }
            }
            val perCall = (System.nanoTime() - t0) / 1e6 / done.get()
            Log.i("POWBENCH", "m=$mib MiB: ${"%.1f".format(times[calls / 2] / 1e6)} ms per call on one thread, " +
                "${"%.1f".format(perCall)} ms per call on $threads threads " +
                "(cores ${Runtime.getRuntime().availableProcessors()}, heap ${Runtime.getRuntime().maxMemory() shr 20} MiB)")
        }
    }
}
