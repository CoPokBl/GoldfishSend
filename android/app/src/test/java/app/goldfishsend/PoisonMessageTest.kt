package app.goldfishsend

import app.goldfishsend.core.LockedInbox
import app.goldfishsend.core.ReceiveGuard
import app.goldfishsend.group.GroupEvent
import app.goldfishsend.group.GroupModel
import app.goldfishsend.proto.B64
import app.goldfishsend.proto.Rand
import app.goldfishsend.proto.Role
import java.io.File
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** One message that fails to process (malformed, hostile, or hitting a bug) is skipped; it never wedges what comes after. */
class PoisonMessageTest {
    @get:Rule
    val tmp = TemporaryFolder()

    @After
    fun reset() {
        ReceiveGuard.onDrop = null
    }

    private fun item(dir: File, name: String, body: String, age: Long): File =
        File(dir, "$name.0.bin").apply {
            writeBytes(byteArrayOf(LockedInbox.KIND_PUSH) + body.toByteArray())
            setLastModified(1_000_000L + age)
        }

    /**
     * Before: an Error (here a stack overflow) escaped the drain loop, so nothing queued behind it was ever processed, and the
     * item was never counted, so every unlock hit it again. A native crash did the same.
     */
    @Test
    fun aPoisonItemInTheLockedInboxIsSkippedThenDropped() = runBlocking {
        val dir = tmp.newFolder("inbox")
        item(dir, "a", "first", 1)
        item(dir, "b", "poison", 2)
        item(dir, "c", "after", 3)
        val handled = mutableListOf<String>()
        val before = ReceiveGuard.dropped
        repeat(4) {
            LockedInbox.drainDir(dir, { it }) { _, body ->
                val text = String(body)
                if (text == "poison") {
                    throw StackOverflowError()
                }
                handled += text
            }
        }
        // The others went through once; the poison item was tried three times, then dropped and counted.
        assertEquals(listOf("first", "after"), handled)
        assertTrue(dir.listFiles().isNullOrEmpty())
        assertEquals(before + 1, ReceiveGuard.dropped)
    }

    /** An item that kills the process while it's processed (simulated by aborting the drain) is counted before it's tried. */
    @Test
    fun anItemThatKillsTheProcessIsNotRetriedForever() = runBlocking {
        val dir = tmp.newFolder("inbox")
        item(dir, "a", "crash", 1)
        item(dir, "b", "after", 2)
        val handled = mutableListOf<String>()
        var crashes = 0
        repeat(5) {
            try {
                LockedInbox.drainDir(dir, { it }) { _, body ->
                    if (String(body) == "crash") {
                        crashes++
                        throw CancellationException("process died")
                    }
                    handled += String(body)
                }
            } catch (e: CancellationException) {
                // The "restart".
            }
        }
        assertEquals(3, crashes)
        assertEquals(listOf("after"), handled)
        assertTrue(dir.listFiles().isNullOrEmpty())
    }

    @Test
    fun anUnreadableItemIsDeleted() = runBlocking {
        val dir = tmp.newFolder("inbox")
        item(dir, "a", "x", 1)
        LockedInbox.drainDir(dir, { throw IllegalStateException("sealed to an old key") }) { _, _ -> error("not opened") }
        assertTrue(dir.listFiles().isNullOrEmpty())
    }

    @Test
    fun theGuardDropsAndCountsWithoutContent() {
        val seen = mutableListOf<String>()
        ReceiveGuard.log = { seen += it }
        try {
            val before = ReceiveGuard.dropped
            assertEquals(null, ReceiveGuard.run("message") { throw OutOfMemoryError("secret body") })
            assertEquals(7, ReceiveGuard.run("message") { 7 })
            assertEquals(before + 1, ReceiveGuard.dropped)
            assertEquals(listOf("dropped a message (message): OutOfMemoryError"), seen)
            assertFalse(seen.single().contains("secret"))
        } finally {
            ReceiveGuard.log = null
        }
    }

    /**
     * Before: held messages (a newcomer's texts that overtook their acceptance) were replayed inside the transaction that
     * accepted the roster, so one that failed rolled the acceptance back. Every later roster replayed it again, and the
     * group couldn't move on (until the held message expired, a week later).
     */
    @Test
    fun aHeldMessageThatFailsDoesNotWedgeTheGroup() {
        val net = GroupNet()
        val alice = net.peer("alice")
        val bob = net.peer("bob")
        val carol = net.peer("carol")
        alice.befriend(bob)
        alice.befriend(carol)
        val gid = B64.enc(Rand.bytes(32))
        bob.failOnText = "poison"
        val drops = mutableListOf<String>()
        ReceiveGuard.onDrop = { where, _ -> drops += where }
        alice.create(gid, "Trip", bob, carol)
        net.deliverAll()
        bob.join(gid)
        net.deliverAll()
        // Bob gets Carol's texts before anything telling him she's in (Alice's roster admitting her): they're held.
        val late = mutableListOf<GroupNet.Envelope>()
        net.filter = { e ->
            val fromAlice = e is GroupNet.Envelope.ToInbox && e.to == bob && e.from == alice || e is GroupNet.Envelope.Direct && e.to == bob
            if (fromAlice) {
                late += e
            }
            !fromAlice
        }
        carol.join(gid)
        net.deliverAll()
        carol.say(gid, "poison")
        carol.say(gid, "fine")
        net.deliverAll()
        assertEquals(Role.INVITED, bob.view(gid).role(carol.id))
        assertEquals(2, bob.store.held(gid).size)
        net.filter = { true }
        net.queue.addAll(late)
        net.deliverAll()
        assertEquals(Role.MEMBER, bob.view(gid).role(carol.id))
        assertEquals(alice.roster(gid).hashB64, bob.roster(gid).hashB64)
        assertTrue(bob.texts.any { it.third == "fine" })
        assertEquals(listOf("held group message"), drops)
        // And the group carries on.
        alice.publish(gid, app.goldfishsend.proto.RosterOp.Meta(name = "Trip 2"))
        net.deliverAll()
        assertEquals("Trip 2", bob.roster(gid).roster.name)
        assertEquals(GroupModel.JOINED, bob.model(gid).state)
        assertTrue(bob.events.any { it.second == GroupEvent.Joined(carol.id) })
    }
}
