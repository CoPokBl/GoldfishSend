package app.goldfishsend

import app.goldfishsend.net.ApiException
import app.goldfishsend.net.GatewayCodec
import app.goldfishsend.net.GatewayState
import app.goldfishsend.net.MailboxItem
import app.goldfishsend.net.ServerApi
import app.goldfishsend.net.ServerPin
import app.goldfishsend.proto.B64
import java.util.concurrent.ConcurrentLinkedQueue
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import okhttp3.OkHttpClient
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

/**
 * HTTP contract checks against docs/protocol.md: paths, methods, headers, content types and error parsing, as seen by
 * the server inside the encrypted gateway.
 */
class ServerApiTest {
    private lateinit var server: MockWebServer
    private lateinit var gw: GatewayTestServer
    private lateinit var dispatch: GatewayTestServer.Dispatch
    private val replies = ConcurrentLinkedQueue<GatewayCodec.InnerResponse>()
    private lateinit var state: GatewayState
    private lateinit var api: ServerApi

    @Before
    fun up() {
        gw = GatewayTestServer()
        dispatch = gw.Dispatch { replies.poll() ?: GatewayTestServer.json(500, """{"error":"no reply queued"}""") }
        server = MockWebServer()
        server.dispatcher = dispatch
        server.start()
        state = GatewayState.Memory()
        api = ServerApi(server.url("/base/").toString(), OkHttpClient(), ServerPin(gw.fp), state)
    }

    @After
    fun down() = server.close()

    private fun reply(status: Int, body: String, vararg headers: Pair<String, String>) {
        replies += GatewayTestServer.json(status, body, *headers)
    }

    private fun last(): GatewayCodec.InnerRequest = dispatch.received.last()

    private fun GatewayCodec.InnerRequest.header(name: String) = headers.firstOrNull { it.first == name }?.second

    @Test
    fun everythingGoesThroughTheGateway() = runBlocking {
        reply(202, """{"id":"x"}""")
        api.sendMessage(ByteArray(32), byteArrayOf(1), ByteArray(16), null)
        val key = server.takeRequest()
        assertEquals("GET", key.method)
        assertEquals("/base/v1/key", key.url.encodedPath)
        val outer = server.takeRequest()
        assertEquals("POST", outer.method)
        assertEquals("/base/v1/gw", outer.url.encodedPath)
        assertEquals("application/octet-stream", outer.headers["Content-Type"])
        // Nothing of the inner request is visible outside: no GF-* headers, no path.
        assertNull(outer.headers["GF-Send-Token"])
        assertEquals(1, dispatch.keyFetches)
    }

    @Test
    fun sendMessageUsesOctetStreamAndHeaders() = runBlocking {
        reply(202, """{"id":"AAAAAAAAAAAAAAAAAAAAAA"}""")
        val secret = ByteArray(32) { 1 }
        val idem = ByteArray(16) { 2 }
        val id = api.sendMessage(secret, byteArrayOf(3, 4, 5), idem, 3600, pow = "Y2g.bm9uY2U")
        assertEquals("AAAAAAAAAAAAAAAAAAAAAA", id)
        val r = last()
        assertEquals(GatewayCodec.POST, r.method)
        assertEquals("/v1/messages", r.path)
        assertEquals("application/octet-stream", r.header("content-type"))
        assertEquals(B64.enc(secret), r.header("gf-send-token"))
        assertEquals(B64.enc(idem), r.header("gf-idempotency-key"))
        assertEquals("3600", r.header("gf-ttl"))
        assertEquals("Y2g.bm9uY2U", r.header("gf-pow"))
        assertArrayEquals(byteArrayOf(3, 4, 5), r.body)
        assertTrue(Math.abs(r.timestamp - System.currentTimeMillis() / 1000) < 5)
    }

    @Test
    fun noPowHeaderUnlessGiven() = runBlocking {
        reply(202, """{"id":"x"}""")
        api.sendMessage(ByteArray(32), byteArrayOf(1), ByteArray(16), null)
        assertNull(last().header("gf-pow"))
        assertNull(last().header("gf-ttl"))
    }

    @Test
    fun mailboxFullIsRetryableWithRetryAfter() = runBlocking {
        reply(507, """{"error":"mailbox_full"}""", "retry-after" to "3600")
        try {
            api.sendMessage(ByteArray(32), byteArrayOf(1), ByteArray(16), null)
            fail("expected 507")
        } catch (e: ApiException) {
            assertEquals("mailbox_full", e.code)
            assertEquals(507, e.status)
            assertEquals(3600L, e.retryAfterSeconds)
            assertTrue(e.retryable)
            assertEquals("Waiting for them to come back online.", e.human)
        }
    }

    @Test
    fun rateLimitScopeDecidesWhetherPowHelps() = runBlocking {
        val cases = listOf("ip" to true, "network" to true, "mailbox" to false, "global" to false, null to false)
        for ((scope, powHelps) in cases) {
            val body = if (scope == null) """{"error":"rate_limited"}""" else """{"error":"rate_limited","scope":"$scope"}"""
            reply(429, body, "retry-after" to "5")
            try {
                api.sendMessage(ByteArray(32), byteArrayOf(1), ByteArray(16), null)
                fail()
            } catch (e: ApiException) {
                assertEquals(scope, e.scope)
                assertEquals("scope=$scope", powHelps, e.powCanHelp)
                assertTrue(e.retryable)
            }
        }
    }

    @Test
    fun powChallengeCarriesItsParameters() = runBlocking {
        reply(200, """{"scheme":"gf/pow/v2","challenge":"AAAA","difficulty":6,"memoryKiB":16384,"iterations":1,"expiresAt":1}""")
        val ch = api.powChallenge()
        assertEquals("gf/pow/v2", ch.scheme)
        assertEquals(app.goldfishsend.proto.Pow.Params(6, 16384, 1), ch.params)
    }

    @Test
    fun errorCodesParsed() = runBlocking {
        reply(429, """{"error":"rate_limited"}""", "retry-after" to "12")
        try {
            api.powChallenge()
            fail()
        } catch (e: ApiException) {
            assertEquals("rate_limited", e.code)
            assertEquals(12L, e.retryAfterSeconds)
            assertTrue(e.retryable)
        }
        replies += GatewayCodec.InnerResponse(404, emptyList(), "not json".toByteArray())
        try {
            api.info()
            fail()
        } catch (e: ApiException) {
            assertEquals("http_404", e.code)
            assertTrue(!e.retryable)
        }
    }

    @Test
    fun inviteUploadAndOneTimeFetch() = runBlocking {
        reply(201, """{"id":"aWQ"}""")
        assertEquals("aWQ", api.uploadInvite(byteArrayOf(9), 900))
        val up = last()
        assertEquals("/v1/invites", up.path)
        assertEquals("application/octet-stream", up.header("content-type"))
        assertEquals("900", up.header("gf-ttl"))

        replies += GatewayCodec.InnerResponse(200, listOf("content-type" to "application/octet-stream"), byteArrayOf(7, 8))
        assertArrayEquals(byteArrayOf(7, 8), api.fetchInvite("aWQ"))
        assertEquals("/v1/invites/aWQ", last().path)
        assertEquals(GatewayCodec.GET, last().method)

        reply(404, """{"error":"not_found"}""")
        assertNull(api.fetchInvite("aWQ"))
    }

    @Test
    fun mailboxEndpointsShape() = runBlocking {
        val item = MailboxItem("c2VuZA", "b3duZXI")
        reply(202, """{"status":"pending_verification"}""")
        api.rotate(app.goldfishsend.net.RotateRequest(listOf(item), "https://push.example/x", "cGs", "YXV0aA"))
        val r = last()
        assertEquals(GatewayCodec.PUT, r.method)
        assertEquals("/v1/mailboxes/endpoint", r.path)
        assertEquals("application/json", r.header("content-type"))
        val body = Json.parseToJsonElement(r.body.toString(Charsets.UTF_8)).jsonObject
        assertEquals("https://push.example/x", body["endpoint"]!!.jsonPrimitive.content)
        assertTrue(body["items"].toString().contains("\"sendSecret\":\"c2VuZA\""))

        reply(200, """{"expiresAt":"2027-02-11"}""")
        assertEquals("2027-02-11", api.verify(listOf(item), ByteArray(16)).expiresAt)
        val v = Json.parseToJsonElement(last().body.toString(Charsets.UTF_8)).jsonObject
        assertEquals(B64.enc(ByteArray(16)), v["code"]!!.jsonPrimitive.content)

        replies += GatewayCodec.InnerResponse(204, emptyList(), ByteArray(0))
        api.delete(listOf(item))
        assertEquals("/v1/mailboxes/delete", last().path)
    }

    // --- transport and identity ---

    @Test
    fun verifiedKeyIsCachedAcrossInstances() = runBlocking {
        reply(200, INFO)
        reply(200, INFO)
        api.info()
        ServerApi(server.url("/base/").toString(), OkHttpClient(), ServerPin(gw.fp), state).info()
        assertEquals(1, dispatch.keyFetches)
    }

    @Test
    fun firstUseRecordsTheFingerprint() = runBlocking {
        var learned: String? = null
        var verified = 0
        val tofu = ServerApi(
            server.url("/base/").toString(), OkHttpClient(),
            ServerPin(null, onFirstUse = { learned = it }, onVerified = { verified++ }), state,
        )
        reply(200, INFO)
        assertEquals(gw.fp, tofu.identity())
        assertEquals(gw.fp, learned)
        tofu.info()
        assertEquals(1, verified)
    }

    @Test
    fun mismatchFailsClosedAndNeverRepins() = runBlocking {
        val other = GatewayTestServer(ByteArray(96) { (it + 7).toByte() })
        var mismatch: String? = null
        var firstUse = false
        val pinned = ServerApi(
            server.url("/base/").toString(), OkHttpClient(),
            ServerPin(other.fp, onFirstUse = { firstUse = true }, onMismatch = { mismatch = it }), GatewayState.Memory(),
        )
        try {
            pinned.info()
            fail("expected server_identity_changed")
        } catch (e: ApiException) {
            assertEquals("server_identity_changed", e.code)
            assertEquals(gw.fp, e.presentedKey)
        }
        assertEquals(gw.fp, mismatch)
        assertTrue(!firstUse)
        // Nothing was sent through the gateway.
        assertTrue(dispatch.received.isEmpty())
    }

    @Test
    fun unknownKeyRefetchesOnceThenFailsClosed() = runBlocking {
        reply(200, INFO)
        api.info()
        // The server now answers 421 to everything (an attacker could send this in plaintext).
        dispatch.override = { r ->
            if (r.url.encodedPath.endsWith("/v1/gw")) MockResponse.Builder().code(421).body("""{"error":"unknown_key"}""").build() else null
        }
        try {
            api.info()
            fail()
        } catch (e: ApiException) {
            // The refetched key still matched the pin, so this is just a misbehaving server: retried later, never re-pinned.
            assertEquals("bad_server", e.code)
            assertTrue(e.retryable)
        }
        assertEquals(2, dispatch.keyFetches)
    }

    @Test
    fun unknownKeyThenSuccessAfterRefetch() = runBlocking {
        reply(200, INFO)
        api.info()
        var once = true
        dispatch.override = { r ->
            if (once && r.url.encodedPath.endsWith("/v1/gw")) {
                once = false
                MockResponse.Builder().code(421).build()
            } else {
                null
            }
        }
        reply(200, INFO)
        assertEquals(3983, api.info().maxMessageBytes)
        assertEquals(2, dispatch.keyFetches)
    }

    @Test
    fun clockSkewRetriesOnceWithTheServersClock() = runBlocking {
        var now = 1_000_000_000_000L
        val skewed = ServerApi(server.url("/base/").toString(), OkHttpClient(), ServerPin(gw.fp), state, clock = { now })
        val serverTime = now / 1000 + 7200
        reply(400, """{"error":"clock_skew","serverTime":$serverTime}""")
        reply(200, INFO)
        skewed.info()
        assertEquals(2, dispatch.received.size)
        assertEquals(now / 1000, dispatch.received[0].timestamp)
        assertEquals(serverTime, dispatch.received[1].timestamp)
        // Only once per call: a second skew is reported.
        reply(400, """{"error":"clock_skew","serverTime":${serverTime + 9999}}""")
        reply(400, """{"error":"clock_skew","serverTime":${serverTime + 99999}}""")
        try {
            skewed.info()
            fail()
        } catch (e: ApiException) {
            assertEquals("clock_skew", e.code)
        }
    }

    @Test
    fun replayedRequestIsResealedOnce() = runBlocking {
        reply(409, """{"error":"replay"}""")
        reply(202, """{"id":"ok"}""")
        assertEquals("ok", api.sendMessage(ByteArray(32), byteArrayOf(1), ByteArray(16) { 3 }, null))
        assertEquals(2, dispatch.received.size)
        assertArrayEquals(dispatch.received[0].body, dispatch.received[1].body)
    }

    @Test
    fun outerErrorsAreUntrusted() = runBlocking {
        reply(200, INFO)
        api.info()
        for ((code, body) in listOf(404 to """{"error":"not_found"}""", 400 to """{"error":"mailbox_full"}""", 401 to "")) {
            dispatch.override = { r -> if (r.url.encodedPath.endsWith("/v1/gw")) MockResponse.Builder().code(code).body(body).build() else null }
            try {
                api.sendMessage(ByteArray(32), byteArrayOf(1), ByteArray(16), null)
                fail()
            } catch (e: ApiException) {
                // A plaintext 404 must never look like the server's not_found (that would mark the contact unreachable).
                assertEquals("bad_server", e.code)
                assertTrue(e.status != 404)
                assertTrue(e.retryable)
            }
        }
        dispatch.override = { r ->
            if (r.url.encodedPath.endsWith("/v1/gw")) MockResponse.Builder().code(429).addHeader("Retry-After", "999999").build() else null
        }
        try {
            api.info()
            fail()
        } catch (e: ApiException) {
            assertEquals("rate_limited", e.code)
            assertEquals(3600L, e.retryAfterSeconds)
            assertNull(e.scope)
        }
    }

    @Test
    fun tamperedResponseIsRejected() = runBlocking {
        reply(200, INFO)
        api.info()
        dispatch.override = { r ->
            if (r.url.encodedPath.endsWith("/v1/gw")) {
                MockResponse.Builder().code(200).body(okio.Buffer().write(ByteArray(600) { 1 })).build()
            } else {
                null
            }
        }
        try {
            api.info()
            fail()
        } catch (e: ApiException) {
            assertEquals("bad_server", e.code)
        }
    }

    @Test
    fun oversizedResponsesAreRejected() = runBlocking {
        dispatch.override = { r ->
            if (r.url.encodedPath.endsWith("/v1/key")) MockResponse.Builder().code(200).body(okio.Buffer().write(ByteArray(8192))).build() else null
        }
        try {
            api.info()
            fail()
        } catch (e: ApiException) {
            assertEquals("response_too_large", e.code)
        }
        reply(200, INFO)
        dispatch.override = { r ->
            if (r.url.encodedPath.endsWith("/v1/gw")) {
                MockResponse.Builder().code(200).body(okio.Buffer().write(ByteArray(ServerApi.MAX_RESPONSE_BYTES.toInt() + 1))).build()
            } else {
                null
            }
        }
        try {
            api.info()
            fail()
        } catch (e: ApiException) {
            assertEquals("response_too_large", e.code)
        }
    }

    @Test
    fun malformedKeyBlobIsRejected() = runBlocking {
        dispatch.override = { r ->
            if (r.url.encodedPath.endsWith("/v1/key")) MockResponse.Builder().code(200).body(okio.Buffer().write(ByteArray(1250))).build() else null
        }
        try {
            ServerApi(server.url("/base/").toString(), OkHttpClient(), ServerPin(null), GatewayState.Memory()).identity()
            fail()
        } catch (e: ApiException) {
            assertEquals("bad_server", e.code)
        }
    }

    @Test
    fun tooLargeRequestFailsLocally() = runBlocking {
        try {
            api.sendMessage(ByteArray(32), ByteArray(20_000), ByteArray(16), null)
            fail()
        } catch (e: ApiException) {
            assertEquals("too_large", e.code)
            assertEquals(413, e.status)
        }
        assertTrue(dispatch.received.isEmpty())
    }

    companion object {
        const val INFO = """{"protocol":2,"vapidPublicKey":"x","maxMessageBytes":3983}"""
    }
}
