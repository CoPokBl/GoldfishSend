package app.goldfishsend.proto

/** Pure rules for untrusted values that arrive from contacts. Kept Android-free for JVM tests. */
object Sanitize {
    const val MAX_NAME = 64

    /** Oldest timestamp a received message may claim: the server's max TTL (14 days), resends and clock skew. */
    const val MAX_BACKDATE_MS = 30L * 86_400_000L

    /** Longest disappearing timer accepted (matches the settings choices). */
    const val MAX_TIMER_SECS = 28 * 86400L

    /**
     * A contact-chosen display name: control and format characters (including bidi overrides such as U+202E, which can
     * make "evil.apk" read as "kpa.live"), surrogates without pairs and other invisibles are removed, whitespace is
     * collapsed, and the result is capped at [MAX_NAME] code points. Returns null if nothing printable is left.
     */
    fun name(raw: String?): String? {
        if (raw == null) {
            return null
        }
        val sb = StringBuilder()
        var lastSpace = true
        var count = 0
        var i = 0
        while (i < raw.length && count < MAX_NAME) {
            val cp = raw.codePointAt(i)
            i += Character.charCount(cp)
            val type = Character.getType(cp)
            val drop = type == Character.CONTROL.toInt() ||
                type == Character.FORMAT.toInt() ||
                type == Character.SURROGATE.toInt() ||
                type == Character.PRIVATE_USE.toInt() ||
                type == Character.UNASSIGNED.toInt() ||
                type == Character.LINE_SEPARATOR.toInt() ||
                type == Character.PARAGRAPH_SEPARATOR.toInt()
            if (drop) {
                continue
            }
            if (Character.isWhitespace(cp) || Character.isSpaceChar(cp)) {
                if (!lastSpace) {
                    sb.append(' ')
                    count++
                    lastSpace = true
                }
                continue
            }
            sb.appendCodePoint(cp)
            count++
            lastSpace = false
        }
        return sb.toString().trim().ifEmpty { null }
    }

    /** A received message's claimed send time, kept between [MAX_BACKDATE_MS] ago and now. */
    fun timestamp(claimed: Long, now: Long): Long = claimed.coerceIn(now - MAX_BACKDATE_MS, now)

    /**
     * The expiry a received message gets. The local chat timer is the ceiling: a contact can make a message disappear
     * sooner, but can't make it outlive the timer you set for the chat (or keep it forever by omitting `exp`).
     * 0 means "no expiry".
     */
    fun effectiveTimer(localSecs: Long, senderSecs: Long?): Long {
        val local = localSecs.coerceIn(0, MAX_TIMER_SECS)
        val sender = (senderSecs ?: 0).coerceIn(0, MAX_TIMER_SECS)
        return when {
            local > 0 && sender > 0 -> minOf(local, sender)
            local > 0 -> local
            else -> sender
        }
    }
}
