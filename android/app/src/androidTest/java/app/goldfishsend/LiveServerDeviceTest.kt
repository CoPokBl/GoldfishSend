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

    private fun api(pin: String? = key, clock: () -> Long = { System.currentTimeMillis() }) =
        ServerApi(server!!, Graph.httpClient(), ServerPin(pin), GatewayState.Memory(), clock)

    @Test
    fun gatewayWorksEndToEnd() = runBlocking {
        assumeTrue(server != null && key != null)
        val api = api()
        assertEquals(key, api.identity())
        val info = api.info()
        assertEquals(2, info.protocol)
        assertTrue(api.powChallenge().difficulty >= 0)

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
    fun trustOnFirstUseLearnsTheRealKey() = runBlocking {
        assumeTrue(server != null && key != null)
        assertEquals(key, api(pin = null).identity())
    }

    @Test
    fun wrongPinIsRefused() = runBlocking {
        assumeTrue(server != null && key != null)
        try {
            api(pin = B64.enc(ByteArray(32) { 9 })).info()
            fail("a mismatched pin must be refused")
        } catch (e: ApiException) {
            assertEquals("server_identity_changed", e.code)
        }
    }

    @Test
    fun clockSkewIsCorrected() = runBlocking {
        assumeTrue(server != null && key != null)
        val skewed = api(clock = { System.currentTimeMillis() + 3_600_000 })
        assertEquals(2, skewed.info().protocol)
    }
}
