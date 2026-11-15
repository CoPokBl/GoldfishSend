package app.goldfishsend

import app.goldfishsend.db.Message
import app.goldfishsend.db.MsgKind
import app.goldfishsend.db.MsgStatus
import app.goldfishsend.ui.ChatRows
import app.goldfishsend.ui.DayLabels
import app.goldfishsend.ui.DayRow
import app.goldfishsend.ui.MessageRow
import app.goldfishsend.ui.UnreadRow
import java.time.LocalDate
import java.time.format.DateTimeFormatter
import java.util.Locale
import java.util.TimeZone
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ChatRowsTest {
    private val day = 86_400_000L

    private fun msg(
        id: String,
        ts: Long,
        outgoing: Boolean = false,
        read: Boolean = true,
        kind: Int = MsgKind.TEXT,
        status: Int = MsgStatus.DELIVERED,
    ) = Message(
        id = id, contactId = 1, wireId = id, outgoing = outgoing, kind = kind, body = id, ts = ts,
        receivedAt = ts, readAt = if (read || outgoing) ts else null, expSecs = 0, viewOnce = false, expiresAt = null, status = status,
    )

    /** UTC days, so the test doesn't depend on the machine's zone. */
    private val utc = { ts: Long -> ChatRows.epochDay(ts, TimeZone.getTimeZone("UTC")) }

    private fun keys(rows: List<app.goldfishsend.ui.ChatRow>) = rows.map { it.key }

    @Test
    fun aDaySeparatorGoesAboveEachDaysFirstMessage() {
        // Newest first: two today, one yesterday, two three days ago.
        val today = 20_000 * day
        val list = listOf(
            msg("e", today + 5000), msg("d", today + 1000),
            msg("c", today - day + 10),
            msg("b", today - 3 * day + 7000), msg("a", today - 3 * day + 10),
        )
        val rows = ChatRows.build(list, null, emptySet(), false, utc)
        assertEquals(listOf("e", "d", "day:20000", "c", "day:19999", "b", "a", "day:19997"), keys(rows))
        assertEquals(20_000L, (rows[0] as MessageRow).day)
        assertEquals(19_997L, (rows.last() as DayRow).day)
    }

    @Test
    fun noMessagesNoRows() {
        assertTrue(ChatRows.build(emptyList(), null, emptySet(), false, utc).isEmpty())
    }

    @Test
    fun theNewMessagesDividerGoesAboveTheFirstUnreadAndBelowItsDaySeparator() {
        val today = 20_000 * day
        val list = listOf(
            msg("u2", today + 3000, read = false),
            msg("u1", today + 2000, read = false),
            msg("r", today - 100),
        )
        val first = ChatRows.firstUnread(list)
        assertEquals("u1", first)
        val rows = ChatRows.build(list, first, emptySet(), false, utc)
        // On screen, top to bottom: day of r, r, day of u1, "New messages", u1, u2.
        assertEquals(listOf("u2", "u1", "unread", "day:20000", "r", "day:19999"), keys(rows))
        assertTrue(rows[2] is UnreadRow)
    }

    @Test
    fun firstUnreadIgnoresOwnMessagesAndSystemLines() {
        val list = listOf(
            msg("mine", 50, outgoing = true),
            msg("sys", 40, read = false, kind = MsgKind.SYSTEM),
            msg("u", 30, read = false),
            msg("old", 20),
        )
        assertEquals("u", ChatRows.firstUnread(list))
        assertNull(ChatRows.firstUnread(list.filter { it.id != "u" }))
        assertNull(ChatRows.firstUnread(emptyList()))
    }

    @Test
    fun unseenCountsIncomingMessagesNewerThanTheLastSeen() {
        val list = listOf(
            msg("in3", 60), msg("out", 50, outgoing = true), msg("sys", 45, kind = MsgKind.SYSTEM),
            msg("in2", 40), msg("in1", 30), msg("seen", 20),
        )
        assertEquals(3, ChatRows.unseen(list, 20))
        assertEquals(1, ChatRows.unseen(list, 40))
        assertEquals(0, ChatRows.unseen(list, 60))
    }

    @Test
    fun queuedMessagesAreWaitingWhenTheOutboxSaysSoOrSendingIsPausedOrTheyreStuck() {
        val list = listOf(
            msg("q2", 2000, outgoing = true, status = MsgStatus.QUEUED),
            msg("q1", 1000, outgoing = true, status = MsgStatus.QUEUED),
            msg("sent", 500, outgoing = true, status = MsgStatus.SENT),
        )
        fun waiting(rows: List<app.goldfishsend.ui.ChatRow>) = rows.filterIsInstance<MessageRow>().filter { it.waiting }.map { it.m.id }
        assertEquals(listOf("q1"), waiting(ChatRows.build(list, null, setOf("q1", "sent"), false, utc)))
        assertEquals(listOf("q2", "q1"), waiting(ChatRows.build(list, null, emptySet(), true, utc)))
        assertEquals(listOf("q1"), waiting(ChatRows.build(list, null, emptySet(), false, utc, staleBefore = 1500)))
        assertFalse(ChatRows.build(list, null, emptySet(), false, utc).any { it is MessageRow && it.waiting })
    }

    @Test
    fun localDaysFollowTheTimeZone() {
        // 23:30 UTC is already the next day in Berlin.
        val ts = LocalDate.of(2026, 3, 1).toEpochDay() * day + 23 * 3_600_000L + 30 * 60_000L
        val utcDay = ChatRows.epochDay(ts, TimeZone.getTimeZone("UTC"))
        assertEquals(LocalDate.of(2026, 3, 1).toEpochDay(), utcDay)
        assertEquals(utcDay + 1, ChatRows.epochDay(ts, TimeZone.getTimeZone("Europe/Berlin")))
        // Before 1970 still rounds down.
        assertEquals(-1L, ChatRows.epochDay(-1, TimeZone.getTimeZone("UTC")))
    }

    @Test
    fun dayLabels() {
        val labels = DayLabels(
            Locale.US,
            DateTimeFormatter.ofPattern("MMMM d", Locale.US),
            DateTimeFormatter.ofPattern("MMMM d, yyyy", Locale.US),
        )
        val today = LocalDate.of(2026, 11, 15).toEpochDay() // a Sunday
        assertEquals("Today", labels.label(today, today))
        assertEquals("Yesterday", labels.label(today - 1, today))
        assertEquals("Friday", labels.label(today - 2, today))
        assertEquals("Monday", labels.label(today - 6, today))
        assertEquals("November 8", labels.label(today - 7, today))
        assertEquals("January 1", labels.label(LocalDate.of(2026, 1, 1).toEpochDay(), today))
        assertEquals("December 31, 2025", labels.label(LocalDate.of(2025, 12, 31).toEpochDay(), today))
        // A sender's clock ahead of ours: a date, not "Today".
        assertEquals("November 16", labels.label(today + 1, today))
    }

    @Test
    fun weekdaysAreCapitalised() {
        val fr = Locale.FRANCE
        val labels = DayLabels(fr, DateTimeFormatter.ofPattern("d MMMM", fr), DateTimeFormatter.ofPattern("d MMMM yyyy", fr))
        val today = LocalDate.of(2026, 11, 15).toEpochDay()
        assertEquals("Vendredi", labels.label(today - 2, today))
    }
}
