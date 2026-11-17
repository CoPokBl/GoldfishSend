package app.goldfishsend

import app.goldfishsend.core.Actions
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ActionsTest {
    @After
    fun clean() {
        Actions.clearFailures()
    }

    @Test
    fun aFailureWaitsToBeShownUntilConsumed() = runBlocking {
        val job = Actions.start("t-fail", describe = { e -> "Couldn't do it. ${e.message}" }) {
            throw IllegalStateException("boom")
        }
        runCatching { job.await() }
        val f = Actions.failures.value.single()
        assertEquals("t-fail", f.key)
        assertEquals("Couldn't do it. boom", f.message)
        Actions.consume(f)
        assertTrue(Actions.failures.value.isEmpty())
    }

    @Test
    fun aCancelledActionIsNotAFailure() = runBlocking {
        val never = CompletableDeferred<Unit>()
        val job = Actions.start("t-cancel", describe = { "should not show" }) { never.await() }
        Actions.cancel("t-cancel")
        runCatching { job.await() }
        assertTrue(Actions.failures.value.isEmpty())
    }

    @Test
    fun lockingClearsFailures() = runBlocking {
        runCatching { Actions.start("t-lock", describe = { "Couldn't join “Picnic”." }) { error("x") }.await() }
        assertEquals(1, Actions.failures.value.size)
        Actions.clearFailures()
        assertTrue(Actions.failures.value.isEmpty())
    }
}
