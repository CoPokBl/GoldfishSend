package app.goldfishsend

import app.goldfishsend.core.Actions
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ActionsTest {
    /** Stands in for a session's scope. */
    private val owner = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    @After
    fun clean() {
        Actions.ended(owner)
        owner.cancel()
        Actions.clearFailures()
    }

    @Test
    fun aFailureWaitsToBeShownUntilConsumed() = runBlocking {
        val job = Actions.start(owner, "t-fail", describe = { e -> "Couldn't do it. ${e.message}" }) {
            throw IllegalStateException("boom")
        }
        runCatching { job.await() }
        val f = Actions.failures.value.single()
        assertEquals("t-fail", f.key)
        assertEquals("Couldn't do it. boom", f.message)
        assertTrue(f.owner === owner)
        Actions.consume(f)
        assertTrue(Actions.failures.value.isEmpty())
    }

    @Test
    fun aCancelledActionIsNotAFailure() = runBlocking {
        val never = CompletableDeferred<Unit>()
        val job = Actions.start(owner, "t-cancel", describe = { "should not show" }) { never.await() }
        Actions.cancel("t-cancel")
        runCatching { job.await() }
        assertTrue(Actions.failures.value.isEmpty())
    }

    @Test
    fun lockingClearsFailures() = runBlocking {
        runCatching { Actions.start(owner, "t-lock", describe = { "Couldn't join “Picnic”." }) { error("x") }.await() }
        assertEquals(1, Actions.failures.value.size)
        Actions.ended(owner)
        assertTrue(Actions.failures.value.isEmpty())
    }

    @Test
    fun aClosedSessionsActionIsForgottenAtOnceAndCantReportBack() = runBlocking {
        val session = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        val gate = CompletableDeferred<Unit>()
        val job = Actions.start(session, "group-create", describe = { "Couldn't create “Union organisers”." }) {
            // Like a database call that can't be interrupted: it carries on past the cancel, then fails on the closed DB.
            withContext(NonCancellable) {
                gate.await()
                error("database closed")
            }
        }
        assertTrue("group-create" in Actions.running.value)
        // Lock: the session's actions are forgotten straight away, then its scope is cancelled.
        Actions.ended(session)
        session.cancel()
        assertTrue(Actions.running.value.isEmpty())
        gate.complete(Unit)
        runCatching { job.await() }
        // Nothing for whatever session opens next to show, or to cancel.
        assertTrue(Actions.failures.value.isEmpty())
        assertTrue(Actions.running.value.isEmpty())
    }

    @Test
    fun aLockWithNoSessionOpenYetStillCounts() {
        // An unlock in progress reads the epoch first and won't publish its session once it moved (Graph.publish).
        val before = app.goldfishsend.core.Graph.lockEpoch
        app.goldfishsend.core.Graph.lock()
        assertEquals(before + 1, app.goldfishsend.core.Graph.lockEpoch)
    }

    @Test
    fun anotherSessionsKeyStartsAfresh() = runBlocking {
        val first = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        val never = CompletableDeferred<Unit>()
        val a = Actions.start(first, "group-create", describe = { "" }) { never.await() }
        Actions.ended(first)
        first.cancel()
        val b = Actions.start(owner, "group-create", describe = { "" }) { 42 }
        assertTrue(a !== b)
        assertEquals(42, b.await())
    }
}
