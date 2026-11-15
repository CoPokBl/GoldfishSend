package app.goldfishsend.ui

import app.goldfishsend.db.Message
import app.goldfishsend.db.MsgKind
import app.goldfishsend.db.MsgStatus
import java.time.LocalDate
import java.time.format.DateTimeFormatter
import java.time.format.TextStyle
import java.util.Locale
import java.util.TimeZone

/**
 * One row of a conversation. A chat's rows are newest first, because the list is laid out from the bottom: a day's
 * separator therefore comes *after* that day's messages, and the "New messages" divider after the first unread one.
 */
sealed interface ChatRow {
    val key: String

    /** The local day (days since the epoch) the row belongs to. */
    val day: Long
}

/** A message. [waiting]: an outgoing message whose sending failed at least once and that will be retried. */
data class MessageRow(val m: Message, override val day: Long, val waiting: Boolean) : ChatRow {
    override val key: String get() = m.id
}

data class DayRow(override val day: Long) : ChatRow {
    override val key: String get() = "day:$day"
}

data class UnreadRow(override val day: Long) : ChatRow {
    override val key: String get() = "unread"
}

object ChatRows {
    private const val DAY_MS = 86_400_000L

    /** How long a message may show as "sending" before it's shown as waiting. */
    const val SENDING_MS = 20_000L

    fun epochDay(ts: Long, zone: TimeZone): Long = Math.floorDiv(ts + zone.getOffset(ts), DAY_MS)

    /**
     * The rows for [messages] (newest first): a [DayRow] above each day's first message, and an [UnreadRow] above
     * [unreadFrom]. [waiting] holds messages that are waiting to be retried; with [allQueuedWaiting] (sending to the
     * contact is paused) every queued message is, and so is any still queued that was sent before [staleBefore] (stuck
     * for a reason the outbox didn't record, it shouldn't look like it's being sent forever).
     */
    fun build(
        messages: List<Message>,
        unreadFrom: String?,
        waiting: Set<String>,
        allQueuedWaiting: Boolean,
        dayOf: (Long) -> Long,
        staleBefore: Long = Long.MIN_VALUE,
    ): List<ChatRow> {
        val out = ArrayList<ChatRow>(messages.size + messages.size / 8 + 2)
        var i = 0
        var day = if (messages.isEmpty()) 0L else dayOf(messages[0].ts)
        while (i < messages.size) {
            val m = messages[i]
            val queued = m.outgoing && m.status == MsgStatus.QUEUED
            out.add(MessageRow(m, day, queued && (allQueuedWaiting || m.id in waiting || m.ts < staleBefore)))
            if (m.id == unreadFrom) {
                out.add(UnreadRow(day))
            }
            val olderDay = if (i + 1 < messages.size) dayOf(messages[i + 1].ts) else null
            if (olderDay != day) {
                out.add(DayRow(day))
                day = olderDay ?: day
            }
            i++
        }
        return out
    }

    /** The oldest unread incoming message, where the "New messages" divider goes, or null if everything was read. */
    fun firstUnread(messages: List<Message>): String? =
        messages.lastOrNull { !it.outgoing && it.kind == MsgKind.TEXT && it.readAt == null }?.id

    /** Incoming messages newer than [seenUpTo] (a message timestamp): the count on the "scroll to latest" button. */
    fun unseen(messages: List<Message>, seenUpTo: Long): Int {
        var n = 0
        for (m in messages) {
            if (m.ts <= seenUpTo) {
                break
            }
            if (!m.outgoing && m.kind == MsgKind.TEXT) {
                n++
            }
        }
        return n
    }
}

/**
 * Labels for day separators: "Today", "Yesterday", the weekday within the last week, then the date, with the year
 * only when it isn't this year.
 */
class DayLabels(private val locale: Locale, private val monthDay: DateTimeFormatter, private val fullDate: DateTimeFormatter) {
    fun label(day: Long, today: Long): String {
        val ago = today - day
        val date = LocalDate.ofEpochDay(day)
        return when {
            ago == 0L -> "Today"
            ago == 1L -> "Yesterday"
            ago in 2..6 -> date.dayOfWeek.getDisplayName(TextStyle.FULL, locale).replaceFirstChar { it.titlecase(locale) }
            date.year == LocalDate.ofEpochDay(today).year -> monthDay.format(date)
            else -> fullDate.format(date)
        }
    }
}
