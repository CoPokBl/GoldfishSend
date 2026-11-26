package app.goldfishsend

import app.goldfishsend.core.InboxSlots
import app.goldfishsend.core.IndexKey
import app.goldfishsend.core.LockedInbox
import app.goldfishsend.core.ReceiveGuard
import app.goldfishsend.proto.Aead
import app.goldfishsend.proto.Rand
import java.io.File
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** A software stand-in for the Keystore index key. */
internal class TestIndexKey : IndexKey {
    private var key: ByteArray? = Rand.bytes(32)
    private val aad = "test".toByteArray()

    override val overhead: Int = Aead.NONCE + 16

    override fun seal(plain: ByteArray): ByteArray = Aead.seal(key ?: Rand.bytes(32).also { key = it }, plain, aad)

    override fun open(sealed: ByteArray): ByteArray? = key?.let { runCatching { Aead.open(it, sealed, aad) }.getOrNull() }

    override fun destroy() {
        key = null
    }
}

/** Builds small inboxes whose items are their own "sealed" form (the drain's open is the identity). */
internal object TestInbox {
    const val MAX = 64

    fun slots(dir: File, n: Int = 16, key: IndexKey = TestIndexKey()) = InboxSlots(File(dir, "slots.bin"), key, n, 3 + MAX)

    fun tag(c: Char) = ByteArray(8) { c.code.toByte() }

    fun put(s: InboxSlots, body: String, tag: ByteArray = tag('a')): Boolean =
        s.put(tag, LockedInbox.pack(LockedInbox.KIND_PUSH, body.toByteArray(), MAX)!!)

    suspend fun drain(s: InboxSlots, closed: () -> Boolean = { false }, handle: suspend (String) -> Unit) =
        LockedInbox.drainSlots(s, closed, { it }) { _, body -> handle(String(body)) }
}

class LockedInboxTest {
    @get:Rule
    val tmp = TemporaryFolder()

    /** Before: one file per push, with its real arrival time and size, so a copy of the files dated and counted them. */
    @Test
    fun theFileShowsNeitherCountNorTime() = runBlocking {
        val dir = tmp.newFolder("inbox")
        val s = TestInbox.slots(dir)
        s.prepare()
        val f = File(dir, "slots.bin")
        val size = f.length()
        for (i in 0 until 5) {
            assertTrue(TestInbox.put(s, "m$i"))
        }
        assertEquals(listOf("slots.bin"), dir.list()!!.toList())
        assertEquals(size, f.length())
        assertEquals(InboxSlots.FIXED_MTIME, f.lastModified())
        TestInbox.drain(s) { }
        assertEquals(size, f.length())
        assertEquals(InboxSlots.FIXED_MTIME, f.lastModified())
        assertTrue(s.isEmpty())
    }

    @Test
    fun theIndexOpensOnlyWithItsKey() {
        val dir = tmp.newFolder("inbox")
        val key = TestIndexKey()
        assertTrue(TestInbox.put(TestInbox.slots(dir, key = key), "kept"))
        // Read back by a fresh instance: the same key finds it, another key (or a destroyed one) finds nothing.
        assertEquals(1, TestInbox.slots(dir, key = key).entries().size)
        assertTrue(TestInbox.slots(dir, key = TestIndexKey()).entries().isEmpty())
        key.destroy()
        assertTrue(TestInbox.slots(dir, key = key).entries().isEmpty())
    }

    /**
     * Before: one global cap, so 500 junk pushes from one mailbox (or one hostile relay) made every later push from
     * anyone else bounce until unlock, each with a "New message" notification.
     */
    @Test
    fun oneSenderCantPushOutEveryoneElse() = runBlocking {
        val s = TestInbox.slots(tmp.newFolder("inbox"), n = 8)
        val flood = TestInbox.tag('f')
        for (i in 0 until 8) {
            assertTrue("alone, one sender may use every slot", TestInbox.put(s, "junk$i", flood))
        }
        assertFalse("but not push out what's there", TestInbox.put(s, "junk8", flood))
        assertTrue(TestInbox.put(s, "carol", TestInbox.tag('c')))
        assertTrue(TestInbox.put(s, "dave", TestInbox.tag('d')))
        assertTrue(TestInbox.put(s, "carol2", TestInbox.tag('c')))
        assertFalse(TestInbox.put(s, "junk9", flood))
        val seen = mutableListOf<String>()
        TestInbox.drain(s) { seen += it }
        // The flood's newest gave way; everyone else's arrived, in order.
        assertEquals(listOf("junk0", "junk1", "junk2", "junk3", "junk4", "carol", "dave", "carol2"), seen)
    }

    @Test
    fun onlyTheNewestEndpointChangeIsKept() {
        val s = TestInbox.slots(tmp.newFolder("inbox"))
        val tag = ByteArray(8) { 0xFF.toByte() }
        val first = LockedInbox.pack(LockedInbox.KIND_ENDPOINT, "one".toByteArray(), TestInbox.MAX)!!
        val second = LockedInbox.pack(LockedInbox.KIND_ENDPOINT, "two".toByteArray(), TestInbox.MAX)!!
        assertTrue(s.put(tag, first, replace = true))
        assertTrue(s.put(tag, second, replace = true))
        val e = s.entries().single()
        assertArrayEquals(second, s.claim(e, 3))
    }

    /**
     * Before: locking during a drain closed the database under it; every item still queued then failed, used up one of
     * its three tries (or was deleted outright, as a message's failure was swallowed), so a few short unlocks lost the
     * whole backlog.
     */
    @Test
    fun lockingMidDrainCostsNoRetries() = runBlocking {
        val s = TestInbox.slots(tmp.newFolder("inbox"))
        for (m in listOf("a", "b", "c")) {
            TestInbox.put(s, m)
        }
        val before = ReceiveGuard.dropped
        // Five short unlocks, each locking while the first item is under way: the database goes, and the receive path
        // swallows the failure. Nothing may be used up.
        repeat(5) {
            var locked = false
            TestInbox.drain(s, { locked }) { locked = true }
        }
        // Then unlocks that each get through one item before locking under the next.
        val done = mutableListOf<String>()
        repeat(3) {
            var locked = false
            var calls = 0
            TestInbox.drain(s, { locked }) { m ->
                if (++calls == 2) {
                    locked = true
                } else {
                    done += m
                }
            }
        }
        assertEquals(listOf("a", "b", "c"), done)
        assertTrue(s.isEmpty())
        assertEquals(before, ReceiveGuard.dropped)
    }

    @Test
    fun pushesParkedDuringADrainArePickedUp() = runBlocking {
        val s = TestInbox.slots(tmp.newFolder("inbox"))
        TestInbox.put(s, "first")
        val seen = mutableListOf<String>()
        TestInbox.drain(s) { m ->
            seen += m
            if (m == "first") {
                TestInbox.put(s, "late")
            }
        }
        assertEquals(listOf("first", "late"), seen)
    }

    @Test
    fun itemsArePaddedToOneSize() {
        val a = LockedInbox.pack(LockedInbox.KIND_PUSH, ByteArray(1), 100)!!
        val b = LockedInbox.pack(LockedInbox.KIND_PUSH, ByteArray(100), 100)!!
        assertEquals(a.size, b.size)
        assertNull(LockedInbox.pack(LockedInbox.KIND_PUSH, ByteArray(101), 100))
        val (kind, body) = LockedInbox.unpack(b)!!
        assertEquals(LockedInbox.KIND_PUSH, kind)
        assertEquals(100, body.size)
        assertNull(LockedInbox.unpack(byteArrayOf(1, 0x7f, 0)))
    }
}
