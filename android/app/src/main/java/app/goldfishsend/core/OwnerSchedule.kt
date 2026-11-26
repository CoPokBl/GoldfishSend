package app.goldfishsend.core

import java.time.LocalDate
import java.time.ZoneOffset

/**
 * When owner requests (refresh, endpoint rotation, delete) go to the server. Each request carries one mailbox, and
 * requests for different mailboxes are spread out, so the server can't tell from one request, or from a burst of them,
 * which mailboxes belong to the same person. Pure (the randomness comes in as [rnd], uniform in [0, 1)) so it can be
 * tested; [OwnerOps] applies it.
 */
object OwnerSchedule {
    private const val MINUTE = 60_000L
    private const val HOUR = 60 * MINUTE
    private const val DAY = 24 * HOUR

    /**
     * The quiet time between two owner requests, 3 to 12 minutes. Long enough that consecutive requests don't share a
     * connection (each opens its own anyway) and mostly not a Tor circuit (reused for up to 10 minutes), short enough that
     * pointing 30 mailboxes at a new push app takes a few hours, not days.
     */
    const val MIN_GAP_MS = 3 * MINUTE
    const val MAX_GAP_MS = 12 * MINUTE

    fun gap(rnd: () -> Double): Long = MIN_GAP_MS + (rnd() * (MAX_GAP_MS - MIN_GAP_MS)).toLong()

    /**
     * When to refresh a mailbox the server says expires on [expiresAt] (`YYYY-MM-DD`, the start of that day in UTC):
     * somewhere between a third and two thirds of the time left, so 30 to 60 days from now for a fresh 90-day mailbox.
     * Mailboxes refreshed or verified together don't stay in step, and there's always a month's margin for retries.
     * Unknown or past: within the next day.
     */
    fun refreshAt(expiresAt: String?, now: Long, rnd: () -> Double): Long {
        val exp = expiresAt?.let { runCatching { LocalDate.parse(it).atStartOfDay(ZoneOffset.UTC).toInstant().toEpochMilli() }.getOrNull() }
        val left = (exp ?: 0L) - now
        if (exp == null || left <= 0) {
            return now + (rnd() * DAY).toLong()
        }
        return now + left / 3 + (rnd() * (left / 3)).toLong()
    }

    /** A refresh or rotation that failed for a reason that may pass (network, rate limit): try again in 1 to 6 hours. */
    fun retryDelay(rnd: () -> Double, retryAfterSeconds: Long? = null): Long {
        val jittered = HOUR + (rnd() * 5 * HOUR).toLong()
        return maxOf(jittered, (retryAfterSeconds ?: 0L).coerceAtMost(86_400L) * 1000L)
    }

    /**
     * How long after its endpoint changed a mailbox is pointed at the new one: up to 10 minutes. When every endpoint
     * changes at once (a new push app), the gap between requests spreads them further.
     */
    fun rotateDelay(rnd: () -> Double): Long = (rnd() * 10 * MINUTE).toLong()

    /** How long after its chat went a mailbox is deleted on the server: up to 10 minutes, then spread by the gap. */
    fun deleteDelay(rnd: () -> Double): Long = (rnd() * 10 * MINUTE).toLong()

    /**
     * When to run next: when the first request is due, but not before [notBefore] (the end of the gap after the last
     * request). Null if nothing is waiting.
     */
    fun nextRun(nextDue: Long?, notBefore: Long, now: Long): Long? = nextDue?.let { maxOf(it, notBefore, now) }
}
