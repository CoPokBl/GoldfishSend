package app.goldfishsend.core

import android.util.Log
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update

/**
 * Work started from a screen that may wait on a new mailbox (create a group, join one): it runs in the app's scope, so
 * it still finishes if the user leaves the screen, and the result applies without them (the group appears, the join
 * goes through). A screen that comes back finds it by [key] and shows its progress again. Nothing here runs once the app
 * process is gone, the same as any other work.
 */
object Actions {
    private val jobs = ConcurrentHashMap<String, Deferred<*>>()
    private val _running = MutableStateFlow<Set<String>>(emptySet())

    /** Keys of the actions still running. */
    val running: StateFlow<Set<String>> = _running

    /** Starts [block] under [key], or returns the one already running under it. */
    @Suppress("UNCHECKED_CAST")
    fun <T> start(key: String, block: suspend () -> T): Deferred<T> = synchronized(jobs) {
        jobs[key]?.takeIf { it.isActive }?.let { return it as Deferred<T> }
        val job = Graph.scope.async(start = CoroutineStart.LAZY) {
            try {
                block()
            } catch (e: Exception) {
                if (e !is kotlinx.coroutines.CancellationException) {
                    Log.i("Actions", "$key failed: ${e.javaClass.simpleName}")
                }
                throw e
            } finally {
                val self = coroutineContext[kotlinx.coroutines.Job]
                synchronized(jobs) {
                    // Only this job's entry: a newer one under the same key stays.
                    if (self != null && jobs.remove(key, self)) {
                        _running.update { it - key }
                    }
                }
            }
        }
        jobs[key] = job
        _running.update { it + key }
        job.start()
        job
    }

    /** Stops the action under [key]. A mailbox it was waiting for still finishes, into the pool. */
    fun cancel(key: String) {
        jobs[key]?.cancel()
    }

    fun groupCreate() = "group-create"

    fun groupJoin(cid: Long) = "group-join:$cid"
}
