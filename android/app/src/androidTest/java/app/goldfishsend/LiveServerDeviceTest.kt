package app.goldfishsend

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import app.goldfishsend.core.Graph
import app.goldfishsend.net.ApiException
import app.goldfishsend.net.GatewayState
import app.goldfishsend.net.ServerApi
import app.goldfishsend.net.ServerPin
import app.goldfishsend.proto.B64
import app.goldfishsend.proto.Rand
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Talks to a real GoldfishSend server through the encrypted gateway. Skipped unless run with
 * `-Pandroid.testInstrumentationRunnerArguments.gfLiveServer=http://10.0.2.2:5234` and `gfLiveKey=<b64u fingerprint>`.
 */
@RunWith(AndroidJUnit4::class)
class LiveServerDeviceTest {
    private val args = InstrumentationRegistry.getArguments()
    private val server: String? = args.getString("gfLiveServer")
    private val key: String? = args.getString("gfLiveKey")

    /** Outside runBlocking, so a missing server address is reported as skipped rather than failed. */
    @Before
    fun requireServer() {
        assumeTrue(server != null && key != null)
    }

    private fun api(pin: String? = key, clock: () -> Long = { System.currentTimeMillis() }) =
        ServerApi(server!!, Graph.httpClient(), ServerPin(pin), GatewayState.Memory(), clock)

    @Test
    fun gatewayWorksEndToEnd() = runBlocking {
        val api = api()
        assertEquals(key, api.identity())
        val info = api.info()
        assertEquals(2, info.protocol)
        val ch = api.powChallenge()
        assertEquals(app.goldfishsend.proto.Pow.SCHEME, ch.scheme)
        assertNull(app.goldfishsend.proto.Pow.refusal(ch.params, app.goldfishsend.proto.Pow.Lane.OWN_MAILBOX))
        val send = api.powChallenge(forSend = true)
        assertEquals("send", send.purpose)
        assertNull(app.goldfishsend.proto.Pow.refusal(send.params, app.goldfishsend.proto.Pow.Lane.CONTACT_SEND))

        val blob = Rand.bytes(600)
        val id = api.uploadInvite(blob, 600)
        assertArrayEquals(blob, api.fetchInvite(id))
        assertNull(api.fetchInvite(id))

        try {
            api.sendMessage(Rand.bytes(32), Rand.bytes(200), Rand.bytes(16), null)
            fail("send to an unknown mailbox must fail")
        } catch (e: ApiException) {
            assertEquals(404, e.status)
        }
    }

    @Test
    fun batchSendReportsEachItem() = runBlocking {
        val items = (1..3).map { app.goldfishsend.net.BatchItem(Rand.bytes(32), Rand.bytes(16), null, Rand.bytes(300)) }
        val results = api().sendBatch(items)
        assertEquals(3, results.size)
        // Unknown mailboxes: each item fails on its own, the batch as a whole succeeds.
        assertTrue(results.all { it.status == 404 })
    }

    @Test
    fun trustOnFirstUseLearnsTheRealKey() = runBlocking {
        assertEquals(key, api(pin = null).identity())
    }

    @Test
    fun wrongPinIsRefused() = runBlocking {
        try {
            api(pin = B64.enc(ByteArray(32) { 9 })).info()
            fail("a mismatched pin must be refused")
        } catch (e: ApiException) {
            assertEquals("server_identity_changed", e.code)
        }
    }

    @Test
    fun clockSkewIsCorrected() = runBlocking {
        val skewed = api(clock = { System.currentTimeMillis() + 3_600_000 })
        assertEquals(2, skewed.info().protocol)
    }
}
