package app.goldfishsend.core

import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.async
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive

/**
 * Work started from a screen that may wait on a new mailbox (create a group, join one): it runs in the session's scope
 * ([Session.scope]), so it still finishes if the user leaves the screen, and the result applies without them (the group
 * appears, the join goes through). A screen that comes back finds it by [key] and shows its progress again.
 *
 * Each action belongs to the session that started it ([owner], its scope). Locking cancels it and forgets it ([ended]),
 * so nothing a real session started can show up, fail or be cancelled from whatever opens next (a decoy session in
 * particular). Nothing here runs once the app process is gone, the same as any other work.
 */
object Actions {
    private class Entry(val owner: CoroutineScope, val job: Deferred<*>)

    private val jobs = HashMap<String, Entry>()
    private val _running = MutableStateFlow<Set<String>>(emptySet())
    private val _failures = MutableStateFlow<List<Failure>>(emptyList())

    /** Keys of the actions still running. */
    val running: StateFlow<Set<String>> = _running

    /** An action that failed, what to tell the user, and the session ([owner]) it belonged to. */
    class Failure(val key: String, val message: String, val owner: CoroutineScope)

    /**
     * Failures not shown yet. The app shows them wherever the user is (they may have left the screen that started the
     * action), then [consume]s them. Only the session that started an action shows its failure: they can name a group.
     */
    val failures: StateFlow<List<Failure>> = _failures

    fun consume(f: Failure) {
        _failures.update { it - f }
    }

    fun clearFailures() {
        _failures.value = emptyList()
    }

    /** The session behind [owner] closed: forget its actions and failures at once (its scope cancels the jobs). */
    fun ended(owner: CoroutineScope) {
        synchronized(jobs) {
            jobs.entries.removeAll { it.value.owner === owner }
            _running.value = jobs.keys.toSet()
        }
        _failures.update { list -> list.filter { it.owner !== owner } }
    }

    /**
     * Starts [block] under [key] in [owner] (the session's scope), or returns the one already running under it. If it
     * fails (not cancelled, and its session still open), [describe] says what to tell the user, and the message joins
     * [failures].
     */
    @Suppress("UNCHECKED_CAST")
    fun <T> start(owner: CoroutineScope, key: String, describe: (Throwable) -> String, block: suspend () -> T): Deferred<T> = synchronized(jobs) {
        jobs[key]?.takeIf { it.job.isActive }?.let { return it.job as Deferred<T> }
        val job = owner.async(start = CoroutineStart.LAZY) {
            try {
                block()
            } catch (e: Exception) {
                // A session that closed mid-way cancels its scope first, so whatever this failed with then isn't news.
                if (e !is kotlinx.coroutines.CancellationException && currentCoroutineContext().isActive) {
                    Log.i("Actions", "$key failed: ${e.javaClass.simpleName}")
                    val f = Failure(key, describe(e), owner)
                    _failures.update { it + f }
                }
                throw e
            } finally {
                val self = coroutineContext[kotlinx.coroutines.Job]
                synchronized(jobs) {
                    // Only this job's entry: a newer one under the same key stays.
                    if (self != null && jobs[key]?.job === self) {
                        jobs.remove(key)
                        _running.update { it - key }
                    }
                }
            }
        }
        jobs[key] = Entry(owner, job)
        _running.update { it + key }
        job.start()
        job
    }

    /** Stops the action under [key]. A mailbox it was waiting for still finishes, into the pool. */
    fun cancel(key: String) {
        synchronized(jobs) { jobs[key] }?.job?.cancel()
    }

    fun groupCreate() = "group-create"

    fun groupJoin(cid: Long) = "group-join:$cid"
}
