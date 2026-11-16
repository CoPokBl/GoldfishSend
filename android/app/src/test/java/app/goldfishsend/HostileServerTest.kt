package app.goldfishsend

import app.goldfishsend.net.ApiException
import app.goldfishsend.net.GatewayCodec
import app.goldfishsend.net.GatewayState
import app.goldfishsend.net.ServerApi
import app.goldfishsend.net.ServerPin
import java.util.concurrent.ConcurrentLinkedQueue
import kotlinx.coroutines.runBlocking
import mockwebserver3.MockWebServer
import okhttp3.OkHttpClient
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

/**
 * A contact's server is chosen by the contact. A 2xx it answers with a body that doesn't parse used to escape as a
 * parser exception (not an ApiException), which skipped the outbox's backoff and cancelled the sends to every other
 * contact running at the same time.
 */
class HostileServerTest {
    private lateinit var server: MockWebServer
    private val replies = ConcurrentLinkedQueue<GatewayCodec.InnerResponse>()
    private lateinit var api: ServerApi

    @Before
    fun up() {
        val gw = GatewayTestServer()
        server = MockWebServer()
        server.dispatcher = gw.Dispatch { replies.poll() ?: GatewayTestServer.json(500, """{"error":"no reply queued"}""") }
        server.start()
        api = ServerApi(server.url("/").toString(), OkHttpClient(), ServerPin(gw.fp), GatewayState.Memory())
    }

    @After
    fun down() = server.close()

    @Test
    fun aMalformedSuccessIsARetryableApiError() = runBlocking {
        // Found by fuzzing: kotlinx.serialization throws StringIndexOutOfBoundsException on this one.
        for (body in listOf("""{"id":"7""", "not json", "")) {
            replies += GatewayTestServer.json(202, body)
            try {
                api.sendMessage(ByteArray(32), byteArrayOf(1), ByteArray(16), null)
                fail("accepted $body")
            } catch (e: ApiException) {
                assertEquals("bad_server", e.code)
                assertTrue(e.retryable)
            }
        }
    }
}
