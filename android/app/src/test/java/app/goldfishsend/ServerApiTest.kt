package app.goldfishsend

import app.goldfishsend.net.ApiException
import app.goldfishsend.net.MailboxItem
import app.goldfishsend.net.ServerApi
import app.goldfishsend.proto.B64
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

/** HTTP contract checks against docs/protocol.md (paths, methods, headers, content types, error parsing). */
class ServerApiTest {
    private lateinit var server: MockWebServer
    private lateinit var api: ServerApi

    @Before
    fun up() {
        server = MockWebServer()
        server.start()
        api = ServerApi(server.url("/base/").toString(), OkHttpClient())
    }

    @After
    fun down() = server.close()

    private fun json(code: Int, body: String, vararg headers: Pair<String, String>) =
        MockResponse.Builder().code(code).body(body).addHeader("Content-Type", "application/json").apply {
            for ((k, v) in headers) addHeader(k, v)
        }.build()

    @Test
    fun sendMessageUsesOctetStreamAndHeaders() = runBlocking {
        server.enqueue(json(202, """{"id":"AAAAAAAAAAAAAAAAAAAAAA"}"""))
        val secret = ByteArray(32) { 1 }
        val idem = ByteArray(16) { 2 }
        val id = api.sendMessage(secret, byteArrayOf(3, 4, 5), idem, 3600, pow = "Y2g.bm9uY2U")
        assertEquals("AAAAAAAAAAAAAAAAAAAAAA", id)
        val r = server.takeRequest()
        assertEquals("POST", r.method)
        assertEquals("/base/v1/messages", r.url.encodedPath)
        assertEquals("application/octet-stream", r.headers["Content-Type"])
        assertEquals(B64.enc(secret), r.headers["GF-Send-Token"])
        assertEquals(B64.enc(idem), r.headers["GF-Idempotency-Key"])
        assertEquals("3600", r.headers["GF-TTL"])
        assertEquals("Y2g.bm9uY2U", r.headers["GF-PoW"])
        assertArrayEquals(byteArrayOf(3, 4, 5), r.body!!.toByteArray())
    }

    @Test
    fun noPowHeaderUnlessGiven() = runBlocking {
        server.enqueue(json(202, """{"id":"x"}"""))
        api.sendMessage(ByteArray(32), byteArrayOf(1), ByteArray(16), null)
        val r = server.takeRequest()
        assertNull(r.headers["GF-PoW"])
        assertNull(r.headers["GF-TTL"])
    }

    @Test
    fun mailboxFullIsRetryableWithRetryAfter() = runBlocking {
        server.enqueue(json(507, """{"error":"mailbox_full"}""", "Retry-After" to "3600"))
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
    fun errorCodesParsed() = runBlocking {
        server.enqueue(json(429, """{"error":"rate_limited"}""", "Retry-After" to "12"))
        try {
            api.powChallenge()
            fail()
        } catch (e: ApiException) {
            assertEquals("rate_limited", e.code)
            assertEquals(12L, e.retryAfterSeconds)
            assertTrue(e.retryable)
        }
        server.enqueue(MockResponse.Builder().code(404).body("not json").build())
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
        server.enqueue(json(201, """{"id":"aWQ"}"""))
        assertEquals("aWQ", api.uploadInvite(byteArrayOf(9), 900))
        val up = server.takeRequest()
        assertEquals("/base/v1/invites", up.url.encodedPath)
        assertEquals("application/octet-stream", up.headers["Content-Type"])
        assertEquals("900", up.headers["GF-TTL"])

        server.enqueue(MockResponse.Builder().code(200).body(okio.Buffer().write(byteArrayOf(7, 8))).build())
        assertArrayEquals(byteArrayOf(7, 8), api.fetchInvite("aWQ"))
        assertEquals("/base/v1/invites/aWQ", server.takeRequest().url.encodedPath)

        server.enqueue(json(404, """{"error":"not_found"}"""))
        assertNull(api.fetchInvite("aWQ"))
    }

    @Test
    fun mailboxEndpointsShape() = runBlocking {
        val item = MailboxItem("c2VuZA", "b3duZXI")
        server.enqueue(json(202, """{"status":"pending_verification"}"""))
        api.rotate(app.goldfishsend.net.RotateRequest(listOf(item), "https://push.example/x", "cGs", "YXV0aA"))
        val r = server.takeRequest()
        assertEquals("PUT", r.method)
        assertEquals("/base/v1/mailboxes/endpoint", r.url.encodedPath)
        val body = Json.parseToJsonElement(r.body!!.utf8()).jsonObject
        assertEquals("https://push.example/x", body["endpoint"]!!.jsonPrimitive.content)
        assertTrue(body["items"].toString().contains("\"sendSecret\":\"c2VuZA\""))

        server.enqueue(json(200, """{"expiresAt":"2027-02-11"}"""))
        assertEquals("2027-02-11", api.verify(listOf(item), ByteArray(16)).expiresAt)
        val v = Json.parseToJsonElement(server.takeRequest().body!!.utf8()).jsonObject
        assertEquals(B64.enc(ByteArray(16)), v["code"]!!.jsonPrimitive.content)

        server.enqueue(MockResponse.Builder().code(204).build())
        api.delete(listOf(item))
        assertEquals("/base/v1/mailboxes/delete", server.takeRequest().url.encodedPath)
    }
}
