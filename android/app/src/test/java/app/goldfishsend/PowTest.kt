package app.goldfishsend

import app.goldfishsend.proto.Pow
import app.goldfishsend.proto.Rand
import java.io.File
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Test

private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

private fun unhex(s: String) = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }

/** Small parameters, so solving takes milliseconds. */
private fun small(difficulty: Int) = Pow.Params(difficulty, 64, 1)

class PowTest {
    @Test
    fun leadingZeroBits() {
        assertEquals(0, Pow.leadingZeroBits(byteArrayOf(0x80.toByte())))
        assertEquals(7, Pow.leadingZeroBits(byteArrayOf(0x01)))
        assertEquals(8, Pow.leadingZeroBits(byteArrayOf(0x00, 0xff.toByte())))
        assertEquals(12, Pow.leadingZeroBits(byteArrayOf(0x00, 0x08)))
        assertEquals(16, Pow.leadingZeroBits(byteArrayOf(0, 0)))
        assertEquals(256, Pow.leadingZeroBits(ByteArray(32)))
    }

    @Test
    fun nonceIsBigEndian() {
        assertEquals("0000000000000102", hex(Pow.nonceBytes(0x0102)))
        assertEquals("ffffffffffffffff", hex(Pow.nonceBytes(-1)))
    }

    @Test
    fun parallelSolverProducesValidNonce() = runBlocking {
        val ch = Rand.bytes(32)
        val hashes = AtomicLong()
        val nonce = Pow.solve(ch, small(6), hashes = hashes)
        assertEquals(8, nonce.size)
        assertTrue(Pow.check(ch, nonce, small(6)))
        assertTrue("counts Argon2 calls for the progress bar", hashes.get() >= 1)
    }

    @Test
    fun aSolutionIsBoundToItsChallengeAndParameters() {
        val ch = Rand.bytes(32)
        val nonce = Pow.solveRange(ch, small(8), 0, 1)!!
        val zeros = Pow.leadingZeroBits(Pow.hash(ch, nonce, 64, 1))
        assertTrue(zeros >= 8)
        assertFalse(Pow.check(ch, nonce, small(zeros + 1)))
        // Same nonce, other memory size: an unrelated hash (false with probability 1 - 2^-8).
        assertEquals(Pow.leadingZeroBits(Pow.hash(ch, nonce, 72, 1)) >= 8, Pow.check(ch, nonce, Pow.Params(8, 72, 1)))
    }
}

/** docs/test-vectors/pow-v2.json, written by the server's PowVectorTests: BouncyCastle for Java must agree with it. */
class PowVectorsTest {
    private val root: JsonObject by lazy {
        var dir: File? = File("").absoluteFile
        while (dir != null && !File(dir, "docs/protocol.md").exists()) {
            dir = dir.parentFile
        }
        Json.parseToJsonElement(File(dir ?: error("repo root not found"), "docs/test-vectors/pow-v2.json").readText()).jsonObject
    }

    private fun JsonObject.str(key: String) = getValue(key).jsonPrimitive.content

    private fun JsonObject.int(key: String) = getValue(key).jsonPrimitive.int

    @Test
    fun hashesMatchTheServer() {
        assertEquals(Pow.SCHEME, root.str("scheme"))
        val cases = root.getValue("hashes").jsonArray.map { it.jsonObject }
        assertTrue(cases.size >= 10)
        for (c in cases) {
            val challenge = unhex(c.str("challenge"))
            val nonce = unhex(c.str("nonce"))
            val m = c.int("memoryKiB")
            val t = c.int("iterations")
            val hash = Pow.hash(challenge, nonce, m, t)
            assertEquals("$c", c.str("hash"), hex(hash))
            val zeros = c.int("leadingZeroBits")
            assertEquals(zeros, Pow.leadingZeroBits(hash))
            assertTrue(Pow.check(challenge, nonce, Pow.Params(minOf(zeros, Pow.MAX_DIFFICULTY), m, t)))
            assertFalse(Pow.check(challenge, nonce, Pow.Params(zeros + 1, m, t)))
        }
    }

    @Test
    fun theSearchFromZeroFindsTheServersFirstSolution() {
        for (c in root.getValue("solutions").jsonArray.map { it.jsonObject }) {
            val p = Pow.Params(c.int("difficulty"), c.int("memoryKiB"), c.int("iterations"))
            assertEquals(c.str("nonce"), hex(Pow.solveRange(unhex(c.str("challenge")), p, 0, 1)!!))
        }
    }
}

/** A hostile or broken server (possibly a contact's) must not be able to pin the cores or the memory. */
class PowLimitsTest {
    @Test
    fun theDefaultServersParametersAreAccepted_UpToItsWorstCase() {
        assertNull(Pow.refusal(Pow.Params(6, 16 * 1024, 1)))
        assertNull(Pow.refusal(Pow.Params(6 + 6 + 2, 16 * 1024, 1)))
        assertNull(Pow.refusal(Pow.Params(Pow.MAX_DIFFICULTY, 8, 1)))
        assertNull(Pow.refusal(Pow.Params(12, 64 * 1024, 1)))
    }

    @Test
    fun unreasonableParametersAreRefused() {
        val refused = mapOf(
            Pow.Params(-1, 64, 1) to "difficulty",
            Pow.Params(Pow.MAX_DIFFICULTY + 1, 8, 1) to "difficulty",
            Pow.Params(64, 64, 1) to "difficulty",
            Pow.Params(Int.MAX_VALUE, 64, 1) to "difficulty",
            Pow.Params(0, 7, 1) to "memory",
            Pow.Params(0, 64 * 1024 + 1, 1) to "memory",
            Pow.Params(0, 4 * 1024 * 1024, 1) to "memory",
            Pow.Params(0, -1, 1) to "memory",
            Pow.Params(0, 64, 0) to "iterations",
            Pow.Params(0, 64, 5) to "iterations",
            Pow.Params(0, 64, 1000) to "iterations",
            Pow.Params(15, 16 * 1024, 1) to "work",
            Pow.Params(14, 16 * 1024, 2) to "work",
            Pow.Params(13, 64 * 1024, 1) to "work",
        )
        for ((p, why) in refused) {
            assertEquals("$p", why, Pow.refusal(p))
        }
    }

    @Test
    fun refusedChallengesFailImmediately() = runBlocking {
        for (p in listOf(Pow.Params(Pow.MAX_DIFFICULTY + 1, 64, 1), Pow.Params(1, 1 shl 20, 1), Pow.Params(18, 16 * 1024, 1))) {
            val start = System.currentTimeMillis()
            try {
                Pow.solve(ByteArray(32), p)
                fail("$p should be refused")
            } catch (e: Pow.TooHardException) {
                assertEquals(p, e.params)
                assertTrue(System.currentTimeMillis() - start < 1_000)
            }
        }
    }

    @Test
    fun threadsAreCappedByCoresAndMemory() {
        val big = 512L shl 20
        assertEquals(4, Pow.threadsFor(16 * 1024, cores = 8, maxHeapBytes = big))
        assertEquals(2, Pow.threadsFor(16 * 1024, cores = 2, maxHeapBytes = big))
        assertEquals(1, Pow.threadsFor(16 * 1024, cores = 1, maxHeapBytes = big))
        // The 80 MiB budget: one 64 MiB instance, or four 16 MiB ones.
        assertEquals(1, Pow.threadsFor(64 * 1024, cores = 8, maxHeapBytes = big))
        assertEquals(2, Pow.threadsFor(32 * 1024, cores = 8, maxHeapBytes = big))
        // A third of a small heap: 128 MiB allows two 16 MiB instances, and 64 MiB still gets one thread.
        assertEquals(2, Pow.threadsFor(16 * 1024, cores = 8, maxHeapBytes = 128L shl 20))
        assertEquals(1, Pow.threadsFor(16 * 1024, cores = 8, maxHeapBytes = 64L shl 20))
        assertEquals(4, Pow.threadsFor(64, cores = 8, maxHeapBytes = 64L shl 20))
        for (m in listOf(8, 1024, 16 * 1024, 64 * 1024)) {
            for (heap in listOf(48L shl 20, 128L shl 20, 256L shl 20, 4L shl 30)) {
                val threads = Pow.threadsFor(m, cores = 16, maxHeapBytes = heap)
                assertTrue(threads in 1..Pow.MAX_THREADS)
                assertTrue("m=$m heap=$heap", threads == 1 || threads.toLong() * m <= Pow.MEMORY_BUDGET_KIB)
            }
        }
    }

    @Test
    fun solverTimesOut() = runBlocking {
        val start = System.currentTimeMillis()
        try {
            Pow.solve(ByteArray(32) { 9 }, Pow.Params(Pow.MAX_DIFFICULTY, 64, 1), timeoutMs = 300)
            fail("should time out")
        } catch (e: TimeoutCancellationException) {
            assertTrue("stopped promptly", System.currentTimeMillis() - start < 5_000)
        }
    }

    @Test
    fun cancellingStopsEveryWorkerWithinACall() = runBlocking {
        val hashes = AtomicLong()
        val job = async(Dispatchers.Default) { Pow.solve(Rand.bytes(32), Pow.Params(16, 1024, 1), hashes = hashes) }
        while (hashes.get() < 8) {
            delay(10)
        }
        job.cancel()
        val start = System.currentTimeMillis()
        try {
            job.await()
            fail("should be cancelled")
        } catch (e: CancellationException) {
            // Expected.
        }
        assertTrue("stopped within about one Argon2 call", System.currentTimeMillis() - start < 2_000)
        val after = hashes.get()
        delay(300)
        assertEquals("no worker keeps hashing after cancellation", after, hashes.get())
    }

    @Test
    fun easyChallengesStillSolve() = runBlocking {
        val ch = ByteArray(32) { 3 }
        assertTrue(Pow.check(ch, Pow.solve(ch, small(4)), small(4)))
    }
}

/**
 * Argon2id speed on this JVM, as a rough proxy for a phone (run with -Pgf.powBench). The device test PowBenchmarkDeviceTest
 * measures the same on Android.
 */
class PowBenchmarkTest {
    @Test
    fun argon2Timings() {
        assumeTrue(System.getProperty("gf.powBench") != null)
        for (line in PowBench.run()) {
            println("POWBENCH $line")
        }
    }
}
