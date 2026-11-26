package app.goldfishsend.core

/**
 * Coalesces delivery receipts for copies of a message we already have (or removed). A copy arrives when the sender
 * didn't get our receipt and re-sends ([Messenger.resendUnreceipted], hours apart), so it still needs one, or the sender
 * never stops. Copies closer together than [quietMs] to the last receipt for the same message get none: a contact
 * sending one message over and over can't make us answer every copy (each receipt costs us a send).
 *
 * In memory, per session: after a restart the next copy gets a receipt again, which only costs one more. Bounded to
 * [capacity] messages, the least recently seen forgotten first; getting around it takes that many distinct messages,
 * each one shown in the chat.
 */
internal class DuplicateReceipts(private val quietMs: Long = QUIET_MS, private val capacity: Int = 512) {
    private val last = object : LinkedHashMap<String, Long>(16, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Long>?): Boolean = size > capacity
    }

    /** Whether to send a receipt for message [wireId] from [contactId] now, and if so, remembers it was sent. */
    @Synchronized
    fun shouldSend(contactId: Long, wireId: String, now: Long = System.currentTimeMillis()): Boolean {
        val key = "$contactId/$wireId"
        val prev = last[key]
        // A clock set back counts as quiet having passed, rather than silencing receipts until it catches up.
        if (prev != null && now >= prev && now - prev < quietMs) {
            return false
        }
        last[key] = now
        return true
    }

    @Synchronized
    fun clear() {
        last.clear()
    }

    companion object {
        /** Well under the hours between automatic re-sends, so every one of those gets its receipt. */
        const val QUIET_MS = 3_600_000L
    }
}
