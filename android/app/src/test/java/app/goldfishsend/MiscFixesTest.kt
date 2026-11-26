package app.goldfishsend

import app.goldfishsend.core.DuplicateReceipts
import app.goldfishsend.core.Outbox
import app.goldfishsend.db.GONE_KEEP_MS
import app.goldfishsend.db.OutboxItem
import app.goldfishsend.db.OutboxKind
import app.goldfishsend.db.RESEND_WINDOW_MS
import app.goldfishsend.db.resendDeadline
import app.goldfishsend.net.ApiException
import java.io.File
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Re-send deadlines, coalesced duplicate receipts and error texts. */
class MiscFixesTest {
    private val day = 86_400_000L

    // ---- Re-sends stay inside the window the recipient's tombstones cover ----

    @Test
    fun aReSendCanNeverArriveAfterTheRecipientForgotItRemovedTheMessage() {
        val ts = 1_700_000_000_000L
        // The first copy arrived no earlier than ts, so a tombstone made when it was removed lasts until ts + GONE_KEEP_MS
        // at least. The last copy leaves by the deadline, and the server holds it for at most 14 days.
        assertTrue(resendDeadline(ts) + 14 * day < ts + GONE_KEEP_MS)
    }

    @Test
    fun aManualRetryHasTheSameWindowAsAutomaticReSends() {
        val ts = 1_700_000_000_000L
        assertTrue(Outbox.canRetry(ts, ts + day))
        assertTrue(Outbox.canRetry(ts, ts + RESEND_WINDOW_MS))
        // Before: a retry a month later re-sent the same wire id, and a message the recipient had viewed once or deleted
        // (their tombstone long gone) came back.
        assertFalse(Outbox.canRetry(ts, ts + RESEND_WINDOW_MS + 1))
        assertFalse(Outbox.canRetry(ts, ts + 30 * day))
    }

    @Test
    fun aQueuedReSendExpiresAtItsDeadlineEvenIfItWasQueuedInTime() {
        val ts = 1_700_000_000_000L
        val copy = row(notAfter = resendDeadline(ts))
        assertFalse(copy.expired(ts + 6 * day))
        assertFalse(copy.expired(resendDeadline(ts)))
        // Queued on day 6, still waiting (backoff, full mailbox) on day 8: it must not leave any more.
        assertTrue(copy.expired(resendDeadline(ts) + 1))
    }

    @Test
    fun anOriginalSendHasNoDeadline() {
        assertFalse(row(notAfter = null).expired(Long.MAX_VALUE))
    }

    private fun row(notAfter: Long?) = OutboxItem(
        seq = 1, contactId = 1, messageId = "m", kind = OutboxKind.CONTENT, content = ByteArray(1), blob = null,
        idem = ByteArray(16), attempts = 0, nextAt = 0, notAfter = notAfter,
    )

    // ---- Duplicate receipts ----

    @Test
    fun theFirstCopyGetsAReceiptAndCopiesRightAfterItDoNot() {
        val r = DuplicateReceipts()
        val t = 1_000_000L
        assertTrue(r.shouldSend(1, "w", t))
        // Before: every copy got its own receipt, so a contact re-sending one message made us send without end.
        for (i in 1..100) {
            assertFalse(r.shouldSend(1, "w", t + i * 1000L))
        }
    }

    @Test
    fun aReSendHoursLaterStillGetsAReceiptSoTheSenderStops() {
        val r = DuplicateReceipts()
        val t = 1_000_000L
        assertTrue(r.shouldSend(1, "w", t))
        assertFalse(r.shouldSend(1, "w", t + DuplicateReceipts.QUIET_MS - 1))
        assertTrue(r.shouldSend(1, "w", t + DuplicateReceipts.QUIET_MS))
        // The quiet period runs from the last receipt sent.
        assertFalse(r.shouldSend(1, "w", t + DuplicateReceipts.QUIET_MS + 1))
        assertTrue(r.shouldSend(1, "w", t + 6 * 3_600_000L))
    }

    @Test
    fun messagesAndContactsAreCountedApart() {
        val r = DuplicateReceipts()
        assertTrue(r.shouldSend(1, "a", 0))
        assertTrue(r.shouldSend(1, "b", 0))
        assertTrue(r.shouldSend(2, "a", 0))
        assertFalse(r.shouldSend(1, "a", 1))
    }

    @Test
    fun aClockSetBackDoesNotSilenceReceipts() {
        val r = DuplicateReceipts()
        assertTrue(r.shouldSend(1, "w", 10 * DuplicateReceipts.QUIET_MS))
        assertTrue(r.shouldSend(1, "w", 0))
    }

    @Test
    fun memoryIsBoundedAndForgetsTheLeastRecentFirst() {
        val r = DuplicateReceipts(capacity = 3)
        for (w in listOf("a", "b", "c")) {
            assertTrue(r.shouldSend(1, w, 0))
        }
        // "a" was seen most recently, so "b" is forgotten when "d" comes in.
        assertFalse(r.shouldSend(1, "a", 1))
        assertTrue(r.shouldSend(1, "d", 1))
        assertTrue(r.shouldSend(1, "b", 2))
        assertFalse(r.shouldSend(1, "a", 2))
    }

    // ---- Error texts ----

    @Test
    fun everyCodeTheAppThrowsHasItsOwnText() {
        val fallback = ApiException.humanize("no such code")
        val sources = File("src/main/java").walkTopDown().filter { it.extension == "kt" }.map { it.readText() }.joinToString("\n")
        val thrown = Regex("""(?:ApiException|BlockedRequestException)\("([a-z_]+)"""").findAll(sources).map { it.groupValues[1] }.toSet()
        assertTrue("found the codes", "stopped" in thrown && "locked" in thrown && "network" in thrown)
        for (code in thrown) {
            assertNotEquals("no text for '$code'", fallback, ApiException.humanize(code))
        }
    }
}
