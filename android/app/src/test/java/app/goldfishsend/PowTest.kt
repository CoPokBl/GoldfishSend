package app.goldfishsend

import app.goldfishsend.core.Mailboxes
import app.goldfishsend.proto.Pow
import app.goldfishsend.proto.Rand
import app.goldfishsend.ui.components.mailboxWaitText
import java.io.File
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
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

/** A challenge source for [Pow.solveOwn] that hands out fresh [p] challenges valid for [validForMs]. */
private fun challenges(p: Pow.Params, validForMs: Long = 300_000, fetched: AtomicInteger = AtomicInteger()): suspend () -> Pow.Challenge = {
    fetched.incrementAndGet()
    Pow.Challenge(Rand.bytes(32), p, validForMs)
}

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
    fun bothLanesProduceValidNonces() = runBlocking {
        val hashes = AtomicLong()
        val (ch, nonce) = Pow.solveOwn(challenges(small(6)), hashes)
        assertTrue(Pow.check(ch.bytes, nonce, small(6)))
        assertTrue("counts Argon2 calls for the progress bar", hashes.get() >= 1)
        val other = Rand.bytes(32)
        assertTrue(Pow.check(other, Pow.solveContact(other, small(6)), small(6)))
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
            assertTrue(Pow.check(challenge, nonce, Pow.Params(minOf(zeros, Pow.Lane.CONTACT_SEND.maxDifficulty), m, t)))
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

/**
 * The two lanes: our own server may ask for a lot (up to its maximum under load), a contact's server only a little. A
 * hostile or broken server must not be able to pin the cores or the memory.
 */
class PowLanesTest {
    private val own = Pow.Lane.OWN_MAILBOX
    private val contact = Pow.Lane.CONTACT_SEND

    @Test
    fun ourServer_MayAskUpToTwiceItsDefaultMaximum() {
        // Defaults: base 8, +6 for a busy network, +2 under global load, at 16 MiB.
        assertNull(Pow.refusal(Pow.Params(8, 16 * 1024, 1), own))
        assertNull(Pow.refusal(Pow.Params(8 + 6 + 2, 16 * 1024, 1), own))
        assertNull(Pow.refusal(Pow.Params(17, 16 * 1024, 1), own))
        assertEquals("work", Pow.refusal(Pow.Params(18, 16 * 1024, 1), own))
        assertNull(Pow.refusal(Pow.Params(24, 8, 1), own))
        assertEquals("difficulty", Pow.refusal(Pow.Params(25, 8, 1), own))
        assertNull(own.timeoutMs)
    }

    @Test
    fun aContactsServer_GetsOnlyAMinuteOrTwo() {
        // The default send challenge (6 bits) is fine, and so is some headroom.
        assertNull(Pow.refusal(Pow.Params(6, 16 * 1024, 1), contact))
        assertNull(Pow.refusal(Pow.Params(11, 16 * 1024, 1), contact))
        // What our own server may ask for creation is far too much here.
        assertEquals("work", Pow.refusal(Pow.Params(8 + 6 + 2, 16 * 1024, 1), contact))
        assertEquals("work", Pow.refusal(Pow.Params(12, 16 * 1024, 1), contact))
        assertEquals("work", Pow.refusal(Pow.Params(10, 64 * 1024, 1), contact))
        assertEquals("difficulty", Pow.refusal(Pow.Params(21, 8, 1), contact))
        assertEquals(180_000L, contact.timeoutMs)
    }

    @Test
    fun unreasonableParametersAreRefusedInBothLanes() {
        val refused = mapOf(
            Pow.Params(-1, 64, 1) to "difficulty",
            Pow.Params(64, 64, 1) to "difficulty",
            Pow.Params(Int.MAX_VALUE, 64, 1) to "difficulty",
            Pow.Params(0, 7, 1) to "memory",
            Pow.Params(0, 64 * 1024 + 1, 1) to "memory",
            Pow.Params(0, 4 * 1024 * 1024, 1) to "memory",
            Pow.Params(0, -1, 1) to "memory",
            Pow.Params(0, 64, 0) to "iterations",
            Pow.Params(0, 64, 5) to "iterations",
            Pow.Params(0, 64, 1000) to "iterations",
        )
        for (lane in Pow.Lane.entries) {
            for ((p, why) in refused) {
                assertEquals("$lane $p", why, Pow.refusal(p, lane))
            }
        }
    }

    @Test
    fun refusedChallengesFailImmediately() = runBlocking {
        val start = System.currentTimeMillis()
        for (p in listOf(Pow.Params(12, 16 * 1024, 1), Pow.Params(1, 1 shl 20, 1), Pow.Params(21, 64, 1))) {
            try {
                Pow.solveContact(ByteArray(32), p)
                fail("$p should be refused for a contact")
            } catch (e: Pow.TooHardException) {
                assertEquals(p, e.params)
            }
        }
        try {
            Pow.solveOwn(challenges(Pow.Params(18, 16 * 1024, 1)))
            fail("should be refused for our own server too")
        } catch (e: Pow.TooHardException) {
            assertEquals("work", e.why)
        }
        assertTrue(System.currentTimeMillis() - start < 2_000)
        assertFalse(Pow.ownBusy)
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
}

class PowSolverTest {
    @Test
    fun aContactSolveTimesOut() = runBlocking {
        val start = System.currentTimeMillis()
        try {
            Pow.solveContact(ByteArray(32) { 9 }, Pow.Params(20, 8, 1), timeoutMs = 300)
            fail("should time out")
        } catch (e: TimeoutCancellationException) {
            assertTrue("stopped promptly", System.currentTimeMillis() - start < 5_000)
        }
    }

    /**
     * Our own server's challenge lasts a few minutes, and a solve may take longer. Before one expires the solver fetches
     * a fresh one and carries on, and the work count (and so the progress bar) keeps growing instead of starting over.
     */
    @Test
    fun anOwnSolveMovesToAFreshChallengeBeforeExpiry_AndKeepsCounting() = runBlocking {
        val fetched = AtomicInteger()
        val hashes = AtomicLong()
        // A clock that ticks once per Argon2 call: each challenge (valid for "100 ms") is searched for 50 calls. The
        // first three are practically unsolvable in that (24 bits), the fourth is easy.
        val next: suspend () -> Pow.Challenge = {
            val n = fetched.incrementAndGet()
            Pow.Challenge(Rand.bytes(32), if (n <= 3) Pow.Params(24, 8, 1) else small(2), 100)
        }
        val (ch, nonce) = Pow.solveOwn(next, hashes, clock = { hashes.get() })
        assertEquals(4, fetched.get())
        assertEquals(small(2), ch.params)
        assertTrue(Pow.check(ch.bytes, nonce, ch.params))
        assertTrue("work across all four challenges is counted: ${hashes.get()}", hashes.get() >= 150)
        assertEquals(2.5f, Pow.searchWindowMs(5_000) / 1000f, 0f)
        assertEquals(270_000L, Pow.searchWindowMs(300_000))
    }

    @Test
    fun anOwnSolveHasNoTimeLimit_ButIsCancellable() = runBlocking {
        val hashes = AtomicLong()
        val job = async(Dispatchers.Default) { Pow.solveOwn(challenges(Pow.Params(20, 1024, 1)), hashes) }
        withTimeout(10_000) {
            while (hashes.get() < 8) {
                delay(10)
            }
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
        assertFalse(Pow.ownBusy)
    }

    /** A contact's server can't hold up our own mailbox creation: its search steps aside, then carries on. */
    @Test
    fun ourOwnMailboxGoesAheadOfAContactsSolve() = runBlocking {
        val contactHashes = AtomicLong()
        val contact = async(Dispatchers.Default) {
            Pow.solveContact(Rand.bytes(32), Pow.Params(20, 8, 1), timeoutMs = 60_000, hashes = contactHashes)
        }
        try {
            withTimeout(10_000) {
                while (contactHashes.get() < 50) {
                    delay(10)
                }
            }
            val ownHashes = AtomicLong()
            val start = System.currentTimeMillis()
            // Our search runs for a known stretch: its first challenge (practically unsolvable) is searched for 400 calls
            // of a "clock" that ticks per call, then an easy one.
            val fetched = AtomicInteger()
            val next: suspend () -> Pow.Challenge = {
                val n = fetched.incrementAndGet()
                Pow.Challenge(Rand.bytes(32), if (n == 1) Pow.Params(20, 1024, 1) else small(1), 800)
            }
            val own = async(Dispatchers.Default) { Pow.solveOwn(next, ownHashes, clock = { ownHashes.get() }) }
            withTimeout(10_000) {
                while (ownHashes.get() < 20) {
                    delay(2)
                }
            }
            // Ours is mid-search (well before its 400th call): the contact's must be standing still.
            val pausedAt = contactHashes.get()
            withTimeout(10_000) {
                while (ownHashes.get() < 200) {
                    delay(2)
                }
            }
            val duringOwn = contactHashes.get() - pausedAt
            val (ch, nonce) = own.await()
            assertTrue(Pow.check(ch.bytes, nonce, ch.params))
            assertTrue("own solve wasn't queued behind the contact's: ${System.currentTimeMillis() - start} ms",
                System.currentTimeMillis() - start < 30_000)
            assertEquals("the contact search paused while ours ran", 0L, duringOwn)
            // And it carries on afterwards.
            withTimeout(10_000) {
                while (contactHashes.get() < pausedAt + 20) {
                    delay(10)
                }
            }
        } finally {
            contact.cancel()
        }
    }
}

class PowProgressTest {
    @Test
    fun remainingTimeCountsDownToTheAverage_ThenStops() {
        // 2^8 calls at 25 a second: about 10 s in all.
        assertEquals(11L, Pow.remainingSeconds(8, 25.0, 0.0))
        assertEquals(6L, Pow.remainingSeconds(8, 25.0, 5.0))
        assertNull(Pow.remainingSeconds(8, 25.0, 11.0))
        assertNull(Pow.remainingSeconds(8, 0.0, 1.0))
    }

    @Test
    fun progressUsesTheMeasuredSpeedOnceThereIsOne() {
        // 400 calls in 10 s is 40 a second: 256 calls take 6.4 s on average, so it's past that already.
        val late = Mailboxes.progressOf(400, 8, 10.0)
        assertNull(late.remainingSeconds)
        assertTrue(late.overdue)
        assertTrue(late.solved!! > 0.8f)
        // 100 calls in 10 s: 25.6 s expected in all.
        val early = Mailboxes.progressOf(100, 8, 10.0)
        assertEquals(16L, early.remainingSeconds)
        assertFalse(early.overdue)
    }

    @Test
    fun theWaitIsExplainedInPlainWords() {
        assertEquals("Almost done. Waiting for your server to confirm.", mailboxWaitText(Mailboxes.Progress(null)))
        assertEquals("A few seconds left", mailboxWaitText(Mailboxes.Progress(0.5f, 7)))
        assertEquals("About 25 seconds left", mailboxWaitText(Mailboxes.Progress(0.2f, 23)))
        assertEquals("About a minute left", mailboxWaitText(Mailboxes.Progress(0.2f, 70)))
        assertEquals("About 12 minutes left", mailboxWaitText(Mailboxes.Progress(0.1f, 700)))
        assertTrue(mailboxWaitText(Mailboxes.Progress(0.9f, null, overdue = true)).startsWith("Taking longer than usual"))
        assertTrue(mailboxWaitText(Mailboxes.Progress(0.01f, 7200)).contains("hour"))
    }
}

/**
 * Argon2id speed on this JVM, as a rough proxy for a phone (run with -Pgf.powBench). The device test PowDeviceTest
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
