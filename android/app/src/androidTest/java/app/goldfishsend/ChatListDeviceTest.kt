package app.goldfishsend

import androidx.test.ext.junit.runners.AndroidJUnit4
import app.goldfishsend.core.Graph
import app.goldfishsend.core.LockedInbox
import app.goldfishsend.crypto.BucketKeys
import app.goldfishsend.db.Db
import app.goldfishsend.db.MsgKind
import app.goldfishsend.db.MsgStatus
import app.goldfishsend.db.OutboxKind
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** The chat list's preview, and the outbox state the chat shows as "Waiting to send". */
@RunWith(AndroidJUnit4::class)
class ChatListDeviceTest {
    @Before
    fun clean() {
        Graph.lock()
        Graph.vault.destroyAll()
        BucketKeys.destroyAll()
        Db.deleteFiles(Graph.app)
        LockedInbox.clear()
        Graph.prefs.clear()
    }

    @After
    fun tearDown() = clean()

    @Test
    fun thePreviewIsTheLastRealMessageNotASystemLine() = runBlocking<Unit> {
        val s = Graph.openSession(Graph.vault.setup(null))
        val cid = s.repo.createContact("Bob", false, 0, "https://x.example", ByteArray(32))
        s.repo.insertMessage(cid, "a", false, MsgKind.TEXT, "see you at 7", 1_000, 1_000, 0, false, null, MsgStatus.DELIVERED)
        s.repo.insertMessage(cid, "s", false, MsgKind.SYSTEM, "Messages were erased when your phone restarted.", 2_000, null, 0, false, null, MsgStatus.READ)
        val group = s.repo.createContact("Club", false, 0, "https://x.example", ByteArray(32))
        s.repo.insertMessage(group, "g", false, MsgKind.SYSTEM, "You created the group.", 3_000, null, 0, false, null, MsgStatus.READ)

        val rows = s.repo.chatSummaries(System.currentTimeMillis()).associateBy { it.contact.id }
        assertEquals("see you at 7", rows.getValue(cid).lastBody)
        assertEquals(1_000L, rows.getValue(cid).lastTs)
        // Only system lines: nothing to preview.
        assertNull(rows.getValue(group).lastBody)
    }

    @Test
    fun messagesWhoseSendingFailedOnceAreWaiting() = runBlocking<Unit> {
        val s = Graph.openSession(Graph.vault.setup(null))
        val cid = s.repo.createContact("Bob", false, 0, "https://x.example", ByteArray(32))
        val failed = s.repo.insertMessage(cid, "w1", true, MsgKind.TEXT, "one", 1, null, 0, false, null, MsgStatus.QUEUED)!!
        val fresh = s.repo.insertMessage(cid, "w2", true, MsgKind.TEXT, "two", 2, null, 0, false, null, MsgStatus.QUEUED)!!
        val seq = s.repo.enqueue(cid, failed, OutboxKind.CONTENT, byteArrayOf(1))
        s.repo.enqueue(cid, fresh, OutboxKind.CONTENT, byteArrayOf(2))
        assertEquals(emptySet<String>(), s.repo.waitingMessageIds(cid))

        val later = System.currentTimeMillis() + 60_000
        s.repo.outboxBackoff(seq, 1, later)
        assertEquals(setOf(failed), s.repo.waitingMessageIds(cid))

        // "Retry" makes it due now.
        val now = System.currentTimeMillis()
        s.repo.outboxRetryNow(cid, now)
        assertEquals(now, s.repo.outboxFor(cid).first { it.seq == seq }.nextAt)
    }
}
