package app.goldfishsend.core

import java.util.concurrent.atomic.AtomicLong
import kotlin.coroutines.cancellation.CancellationException

/**
 * Processing of one incoming message. Whatever it throws, that message is dropped (counted, and logged by class name
 * only, never content) and the caller goes on with the next, so one malformed or hostile message can't crash the app or
 * wedge the inbox behind it. Android-free, so the JVM tests use it too.
 */
object ReceiveGuard {
    private val count = AtomicLong()

    /** Messages dropped because processing them failed, since the process started. */
    val dropped: Long
        get() = count.get()

    /** Set by the app to its logger. */
    @Volatile
    var log: ((String) -> Unit)? = null

    /** Called for every drop (tests use it to fail on drops that shouldn't happen). */
    @Volatile
    var onDrop: ((String, Throwable) -> Unit)? = null

    inline fun <T> run(where: String, block: () -> T): T? = try {
        block()
    } catch (e: CancellationException) {
        throw e
    } catch (e: Throwable) {
        drop(where, e)
        null
    }

    suspend fun <T> runSuspend(where: String, block: suspend () -> T): T? = try {
        block()
    } catch (e: CancellationException) {
        throw e
    } catch (e: Throwable) {
        drop(where, e)
        null
    }

    fun drop(where: String, e: Throwable) {
        count.incrementAndGet()
        log?.invoke("dropped a message ($where): ${e.javaClass.simpleName}")
        onDrop?.invoke(where, e)
    }
}
