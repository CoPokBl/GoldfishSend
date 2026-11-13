package app.goldfishsend.security

import java.util.concurrent.atomic.AtomicBoolean

/**
 * Best-effort clearing of freed memory after the app locks (similar in spirit to Molly's RAM shredder).
 *
 * The session's own secrets are zeroed directly when it closes (master key, message keys, SQLCipher with
 * cipher_memory_security). But decrypted message text also passed through immutable Strings, Compose state and
 * libraries, and the JVM can't wipe those in place. Once the UI is torn down they're garbage. This forces a
 * collection, then fills the freed heap with fresh, zero-initialised arrays, so the allocator hands those regions
 * back zeroed. It can't reach other processes or memory the OS has already swapped or compressed (zram).
 */
object MemoryScrubber {
    private val running = AtomicBoolean(false)

    /** Runs on a background thread. Concurrent calls coalesce into one. */
    fun scrubAsync() {
        if (!running.compareAndSet(false, true)) {
            return
        }
        Thread({
            try {
                scrub()
            } finally {
                running.set(false)
            }
        }, "gf-memory-scrub").apply {
            priority = Thread.MIN_PRIORITY
            start()
        }
    }

    internal fun scrub(targetFraction: Double = 0.6, chunkBytes: Int = 1 shl 20) {
        val rt = Runtime.getRuntime()
        rt.gc()
        @Suppress("DEPRECATION")
        rt.runFinalization()
        rt.gc()

        // Fill most of the free heap. Leave headroom so we never cause an OutOfMemoryError in the app.
        val free = rt.maxMemory() - (rt.totalMemory() - rt.freeMemory())
        val budget = (free * targetFraction).toLong().coerceAtLeast(0)
        val chunks = ArrayList<ByteArray>((budget / chunkBytes).toInt().coerceAtLeast(0))
        var filled = 0L
        try {
            while (filled + chunkBytes <= budget) {
                // New arrays are zeroed by the runtime. Touching each page makes sure it's actually committed.
                val chunk = ByteArray(chunkBytes)
                var i = 0
                while (i < chunk.size) {
                    chunk[i] = 0
                    i += 4096
                }
                chunks += chunk
                filled += chunkBytes
            }
        } catch (_: OutOfMemoryError) {
            // Reached the practical limit, which is fine.
        } finally {
            chunks.clear()
            rt.gc()
        }
    }
}
