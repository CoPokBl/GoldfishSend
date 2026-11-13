package app.goldfishsend

import app.goldfishsend.net.Gateway
import app.goldfishsend.net.GatewayCodec
import app.goldfishsend.net.ServerKey
import app.goldfishsend.proto.B64
import java.io.File
import java.math.BigInteger
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Test

@Serializable
data class VectorExchange(val innerRequest: String, val outerRequest: String, val innerResponse: String, val outerResponse: String)

@Serializable
data class VectorFile(val serverKey: String, val blob: String, val fp: String, val exchanges: List<VectorExchange>)

/** Gateway v1 crypto and codec (docs/protocol.md "Encrypted transport and server identity"). */
class GatewayTest {
    private val gw = GatewayTestServer()

    @Test
    fun blobAndFingerprintFromTheTestKey() {
        assertEquals(Gateway.BLOB_SIZE, gw.blob.size)
        assertEquals(1250, gw.blob.size)
        assertEquals(0x01.toByte(), gw.blob[0])
        assertEquals(0x04.toByte(), gw.blob[1 + 1184])
        assertArrayEquals(app.goldfishsend.proto.Hash.sha256("gf/server-key/v1".toByteArray(), gw.blob), gw.key.fingerprint)
        // Known answer: pinned so any change to key derivation or the blob format is caught here first.
        assertEquals(TEST_FP, gw.fp)
        assertEquals(TEST_BLOB_SHA256, hex(app.goldfishsend.proto.Hash.sha256(gw.blob)))
        assertArrayEquals(gw.key.fingerprint.copyOf(8), gw.key.keyId)
    }

    @Test
    fun malformedBlobsAreRejected() {
        assertNull(ServerKey.parse(ByteArray(1250)))
        assertNull(ServerKey.parse(gw.blob.copyOf(1249)))
        assertNull(ServerKey.parse(gw.blob + 0))
        val badVersion = gw.blob.copyOf().also { it[0] = 2 }
        assertNull(ServerKey.parse(badVersion))
        // Compressed or off-curve P-256 points.
        val compressed = gw.blob.copyOf().also { it[1185] = 0x02 }
        assertNull(ServerKey.parse(compressed))
        val offCurve = gw.blob.copyOf().also { it[1249] = (it[1249] + 1).toByte() }
        assertNull(ServerKey.parse(offCurve))
        assertNotNull(ServerKey.parse(gw.blob))
    }

    @Test
    fun roundTrip() {
        val inner = GatewayCodec.encodeRequest(
            GatewayCodec.InnerRequest(GatewayCodec.POST, 1_700_000_000, "/v1/messages", listOf("gf-ttl" to "60"), ByteArray(100) { 5 }),
        )
        val sealed = Gateway.seal(gw.key, inner)
        assertEquals(Gateway.HEADER_SIZE + Gateway.ENC_SIZE + inner.size + Gateway.TAG_SIZE, sealed.body.size)
        val opened = gw.open(sealed.body)
        assertArrayEquals(inner, opened.innerBytes)
        assertArrayEquals(sealed.respSecret, opened.respSecret)
        assertEquals("/v1/messages", opened.inner.path)
        val respInner = GatewayTestServer.json(200, """{"id":"x"}""")
        val outerResp = gw.seal(opened.respSecret, respInner)
        val back = GatewayCodec.decodeResponse(Gateway.openResponse(sealed.respSecret, outerResp))
        assertEquals(200, back.status)
        assertEquals("""{"id":"x"}""", back.body.toString(Charsets.UTF_8))
    }

    @Test
    fun eachRequestUsesFreshKeys() {
        val inner = GatewayCodec.encodeRequest(GatewayCodec.InnerRequest(GatewayCodec.GET, 1, "/v1/info", emptyList(), ByteArray(0)))
        val a = Gateway.seal(gw.key, inner)
        val b = Gateway.seal(gw.key, inner)
        assertTrue(!a.enc.contentEquals(b.enc))
        assertTrue(!a.respSecret.contentEquals(b.respSecret))
    }

    @Test
    fun tamperingIsDetected() {
        val inner = GatewayCodec.encodeRequest(GatewayCodec.InnerRequest(GatewayCodec.GET, 1, "/v1/info", emptyList(), ByteArray(0)))
        val sealed = Gateway.seal(gw.key, inner)
        for (i in listOf(0, 5, 100, Gateway.HEADER_SIZE + 1100, sealed.body.size - 1)) {
            val bad = sealed.body.copyOf().also { it[i] = (it[i].toInt() xor 1).toByte() }
            try {
                gw.open(bad)
                fail("tampered byte $i accepted")
            } catch (e: Exception) {
                // expected
            }
        }
        val resp = gw.seal(sealed.respSecret, GatewayTestServer.json(200, "{}"))
        val badResp = resp.copyOf().also { it[40] = (it[40].toInt() xor 1).toByte() }
        try {
            Gateway.openResponse(sealed.respSecret, badResp)
            fail()
        } catch (e: Exception) {
            // expected
        }
        try {
            Gateway.openResponse(ByteArray(32), resp)
            fail("opened under the wrong secret")
        } catch (e: Exception) {
            // expected
        }
    }

    @Test
    fun paddingBuckets() {
        assertEquals(512, GatewayCodec.paddedSize(1))
        assertEquals(512, GatewayCodec.paddedSize(512))
        assertEquals(1024, GatewayCodec.paddedSize(513))
        assertEquals(2048, GatewayCodec.paddedSize(1025))
        assertEquals(4096, GatewayCodec.paddedSize(4096))
        assertEquals(8192, GatewayCodec.paddedSize(4097))
        assertEquals(17408, GatewayCodec.paddedSize(8193))
        assertEquals(17408, GatewayCodec.paddedSize(17408))
        assertEquals(20480, GatewayCodec.paddedSize(17409))
        assertEquals(65536, GatewayCodec.paddedSize(65536))
        // A ~4 KiB message lands in the 8 KiB bucket, whatever its exact size.
        val small = GatewayCodec.encodeRequest(GatewayCodec.InnerRequest(GatewayCodec.POST, 1, "/v1/messages", emptyList(), ByteArray(4100)))
        val big = GatewayCodec.encodeRequest(GatewayCodec.InnerRequest(GatewayCodec.POST, 1, "/v1/messages", emptyList(), ByteArray(6000)))
        assertEquals(8192, small.size)
        assertEquals(8192, big.size)
    }

    @Test
    fun requestCodecLayout() {
        val r = GatewayCodec.InnerRequest(GatewayCodec.PUT, 0x0102030405060708, "/v1/x", listOf("gf-a" to "bc"), byteArrayOf(9, 9))
        val b = GatewayCodec.encodeRequest(r)
        val expect = byteArrayOf(
            3, 1, 2, 3, 4, 5, 6, 7, 8, // method, timestamp
            0, 5, '/'.code.toByte(), 'v'.code.toByte(), '1'.code.toByte(), '/'.code.toByte(), 'x'.code.toByte(),
            1, 4, 'g'.code.toByte(), 'f'.code.toByte(), '-'.code.toByte(), 'a'.code.toByte(), 0, 2, 'b'.code.toByte(), 'c'.code.toByte(),
            0, 0, 0, 2, 9, 9,
        )
        assertArrayEquals(expect, b.copyOf(expect.size))
        assertTrue(b.copyOfRange(expect.size, b.size).all { it == 0.toByte() })
        val back = GatewayCodec.decodeRequest(b)
        assertEquals(r.method, back.method)
        assertEquals(r.timestamp, back.timestamp)
        assertEquals(r.path, back.path)
        assertEquals(r.headers, back.headers)
        assertArrayEquals(r.body, back.body)
    }

    @Test
    fun responseCodecBounds() {
        val r = GatewayCodec.InnerResponse(429, listOf("retry-after" to "5"), "{}".toByteArray())
        val b = GatewayCodec.encodeResponse(r)
        assertEquals(512, b.size)
        assertEquals(0x01.toByte(), b[0])
        assertEquals(0xAD.toByte(), b[1])
        val back = GatewayCodec.decodeResponse(b)
        assertEquals(429, back.status)
        assertEquals("5", back.header("Retry-After"))
        // Lengths pointing past the end are rejected, never read out of bounds.
        val truncated = b.copyOf(6)
        try {
            GatewayCodec.decodeResponse(truncated)
            fail()
        } catch (e: GatewayCodec.FormatException) {
            // expected
        }
        val huge = b.copyOf().also {
            val bodyLenAt = 2 + 1 + 1 + "retry-after".length + 2 + 1
            it[bodyLenAt] = 0x7f
        }
        try {
            GatewayCodec.decodeResponse(huge)
            fail()
        } catch (e: GatewayCodec.FormatException) {
            // expected
        }
        try {
            GatewayCodec.decodeResponse(byteArrayOf(0, 0, 0, 0, 0, 0, 0))
            fail("status 0 accepted")
        } catch (e: GatewayCodec.FormatException) {
            // expected
        }
    }

    @Test
    fun requestBounds() {
        for (bad in listOf("/v1/gw", "/v1/key", "/v2/x", "v1/info", "/v1/key?x=1")) {
            try {
                GatewayCodec.encodeRequest(GatewayCodec.InnerRequest(GatewayCodec.GET, 1, bad, emptyList(), ByteArray(0)))
                fail("accepted $bad")
            } catch (e: IllegalArgumentException) {
                // expected
            }
        }
        try {
            GatewayCodec.encodeRequest(GatewayCodec.InnerRequest(GatewayCodec.POST, 1, "/v1/messages", emptyList(), ByteArray(17_400)))
            fail()
        } catch (e: GatewayCodec.FormatException) {
            // expected
        }
    }

    @Test
    fun fingerprintDisplayAndInput() {
        val display = Gateway.displayFingerprint(gw.fp)
        assertEquals(52 + 12, display.length)
        assertTrue(display.matches(Regex("([A-Z2-7]{4} ){12}[A-Z2-7]{4}")))
        assertEquals(gw.fp, Gateway.parseFingerprintInput(display))
        assertEquals(gw.fp, Gateway.parseFingerprintInput(display.lowercase().replace(" ", "")))
        assertEquals(gw.fp, Gateway.parseFingerprintInput("  ${gw.fp} "))
        assertNull(Gateway.parseFingerprintInput("hello"))
        assertNull(Gateway.parseFingerprintInput(display.dropLast(1)))
        assertTrue(Gateway.isFingerprint(gw.fp))
        assertTrue(!Gateway.isFingerprint(gw.fp.dropLast(1)))
        assertTrue(!Gateway.isFingerprint(null))
        // RFC 4648 test vectors.
        assertEquals("MZXW6YTBOI", Gateway.base32("foobar".toByteArray()))
        assertEquals("MY", Gateway.base32("f".toByteArray()))
    }

    // --- interop vectors ---

    private fun vectorsDir(): File {
        var dir: File? = File("").absoluteFile
        while (dir != null && !File(dir, "docs/protocol.md").exists()) {
            dir = dir.parentFile
        }
        return File(dir ?: error("repo root not found"), "docs/test-vectors")
    }

    private fun exchange(method: Int, path: String, headers: List<Pair<String, String>>, body: ByteArray, resp: GatewayCodec.InnerResponse, seed: Int): VectorExchange {
        val inner = GatewayCodec.encodeRequest(GatewayCodec.InnerRequest(method, 1_767_225_600, path, headers, body))
        val sealed = Gateway.sealWith(gw.key, inner, ByteArray(32) { (seed + it).toByte() }, BigInteger.valueOf(0x1234567L + seed))
        val innerResp = GatewayCodec.encodeResponse(resp)
        val outerResp = Gateway.sealResponse(sealed.respSecret, innerResp, ByteArray(32) { (seed * 3 + it).toByte() })
        return VectorExchange(hex(inner), hex(sealed.body), hex(innerResp), hex(outerResp))
    }

    /** Regenerates docs/test-vectors/gateway-client.json. Runs only with GF_WRITE_VECTORS=1. */
    @Test
    fun writeClientVectors() {
        assumeTrue(System.getenv("GF_WRITE_VECTORS") == "1")
        val exchanges = listOf(
            exchange(
                GatewayCodec.GET, "/v1/info", emptyList(), ByteArray(0),
                GatewayTestServer.json(200, """{"protocol":2,"vapidPublicKey":"BAAA","maxMessageBytes":3983}"""), 1,
            ),
            exchange(
                GatewayCodec.POST, "/v1/messages",
                listOf(
                    "content-type" to "application/octet-stream",
                    "gf-send-token" to B64.enc(ByteArray(32) { 0x11 }),
                    "gf-idempotency-key" to B64.enc(ByteArray(16) { 0x22 }),
                    "gf-ttl" to "86400",
                ),
                ByteArray(4000) { (it * 7).toByte() },
                GatewayTestServer.json(202, """{"id":"AAAAAAAAAAAAAAAAAAAAAA"}"""), 2,
            ),
        )
        val file = VectorFile(B64.enc(GatewayTestServer.TEST_SECRET), hex(gw.blob), gw.fp, exchanges)
        val out = File(vectorsDir(), "gateway-client.json")
        out.parentFile.mkdirs()
        out.writeText(Json { prettyPrint = true }.encodeToString(VectorFile.serializer(), file) + "\n")
    }

    /** Our own committed vectors still decrypt (guards against format drift on this side). */
    @Test
    fun clientVectorsVerify() {
        val f = File(vectorsDir(), "gateway-client.json")
        assumeTrue(f.exists())
        verifyVectors(Json.decodeFromString(VectorFile.serializer(), f.readText()))
    }

    /** The server's vectors (written by its tests) decrypt with our implementation. Skipped until that file exists. */
    @Test
    fun serverVectorsVerify() {
        val f = File(vectorsDir(), "gateway-server.json")
        assumeTrue("docs/test-vectors/gateway-server.json not present yet", f.exists())
        verifyVectors(Json { ignoreUnknownKeys = true }.decodeFromString(VectorFile.serializer(), f.readText()))
    }

    private fun verifyVectors(v: VectorFile) {
        val server = GatewayTestServer(B64.dec(v.serverKey))
        assertEquals("blob", v.blob, hex(server.blob))
        assertEquals("fp", v.fp, server.fp)
        assertTrue(v.exchanges.isNotEmpty())
        for (x in v.exchanges) {
            val opened = server.open(unhex(x.outerRequest))
            assertEquals(x.innerRequest, hex(opened.innerBytes))
            val resp = Gateway.openResponse(opened.respSecret, unhex(x.outerResponse))
            assertEquals(x.innerResponse, hex(resp))
            GatewayCodec.decodeResponse(resp)
        }
    }

    companion object {
        const val TEST_FP = "xbEXX4E5yV8WWKo4_9R4peZP2OQbggdFnKCqHc6gX9g"
        const val TEST_BLOB_SHA256 = "a97384aa454bf6724048784fb8a6b745c3978f52120f5729eb11e50589037a41"

        fun hex(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }

        fun unhex(s: String): ByteArray = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }
}
