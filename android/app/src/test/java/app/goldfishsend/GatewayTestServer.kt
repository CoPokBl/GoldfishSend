package app.goldfishsend

import app.goldfishsend.net.Gateway
import app.goldfishsend.net.GatewayCodec
import app.goldfishsend.net.ServerKey
import java.math.BigInteger
import javax.crypto.Cipher
import mockwebserver3.Dispatcher
import mockwebserver3.MockResponse
import mockwebserver3.RecordedRequest
import org.bouncycastle.crypto.kems.MLKEMExtractor
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.params.MLKEMParameters
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters
import org.bouncycastle.math.ec.ECPoint

/**
 * The server side of gateway v1, for tests only: it derives the public key blob from a 96-byte `ServerKey` secret
 * (`mlkemSeed(64) ‖ p256Scalar(32)`) and decapsulates requests, the same way the real server does.
 */
class GatewayTestServer(val secret: ByteArray = TEST_SECRET) {
    private val mlkemPriv = MLKEMPrivateKeyParameters(MLKEMParameters.ml_kem_768, secret.copyOf(64))
    private val scalar = BigInteger(1, secret.copyOfRange(64, 96))
    private val p256Priv = ECPrivateKeyParameters(scalar, Gateway.curve)

    val blob: ByteArray = byteArrayOf(Gateway.VERSION) + mlkemPriv.publicKey +
        Gateway.curve.g.multiply(scalar).normalize().getEncoded(false)
    val key: ServerKey = ServerKey.parse(blob)!!
    val fp: String = key.fingerprintB64

    class Opened(val inner: GatewayCodec.InnerRequest, val innerBytes: ByteArray, val respSecret: ByteArray, val enc: ByteArray)

    /** Decapsulates an outer request body, or throws. */
    fun open(body: ByteArray): Opened {
        require(body.size > Gateway.HEADER_SIZE + Gateway.ENC_SIZE + Gateway.TAG_SIZE)
        require(body[0] == Gateway.VERSION)
        val header = body.copyOf(Gateway.HEADER_SIZE)
        require(header.copyOfRange(1, Gateway.HEADER_SIZE).contentEquals(key.keyId)) { "unknown key" }
        val enc = body.copyOfRange(Gateway.HEADER_SIZE, Gateway.HEADER_SIZE + Gateway.ENC_SIZE)
        val ctM = enc.copyOf(Gateway.MLKEM_CT_SIZE)
        val ctX = enc.copyOfRange(Gateway.MLKEM_CT_SIZE, Gateway.ENC_SIZE)
        val ssM = MLKEMExtractor(mlkemPriv).extractSecret(ctM)
        val point: ECPoint = Gateway.curve.curve.decodePoint(ctX)
        val ssX = Gateway.ecdh(p256Priv, point)
        val (reqKey, respSecret) = Gateway.deriveSecrets(key.fingerprint, enc, ssM, ssX)
        val inner = Gateway.aesGcm(Cipher.DECRYPT_MODE, reqKey, header, body.copyOfRange(Gateway.HEADER_SIZE + Gateway.ENC_SIZE, body.size))
        return Opened(GatewayCodec.decodeRequest(inner), inner, respSecret, enc)
    }

    fun seal(respSecret: ByteArray, resp: GatewayCodec.InnerResponse, respNonce: ByteArray = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }): ByteArray =
        Gateway.sealResponse(respSecret, GatewayCodec.encodeResponse(resp), respNonce)

    /**
     * A MockWebServer dispatcher: `GET <base>v1/key` returns [blob]; `POST <base>v1/gw` is opened and handed to
     * [handler]. Every opened inner request is recorded in [received].
     */
    inner class Dispatch(private val handler: (GatewayCodec.InnerRequest) -> GatewayCodec.InnerResponse) : Dispatcher() {
        val received = java.util.Collections.synchronizedList(mutableListOf<GatewayCodec.InnerRequest>())
        var keyFetches = 0

        /** Overrides for the plain routes, consulted first (return null to fall through). */
        var override: ((RecordedRequest) -> MockResponse?)? = null

        override fun dispatch(request: RecordedRequest): MockResponse {
            override?.invoke(request)?.let { return it }
            val path = request.url.encodedPath
            return when {
                request.method == "GET" && path.endsWith("/v1/key") -> {
                    keyFetches++
                    MockResponse.Builder().code(200).addHeader("Content-Type", "application/octet-stream")
                        .body(okio.Buffer().write(blob)).build()
                }
                request.method == "POST" && path.endsWith("/v1/gw") -> {
                    val opened = try {
                        open(request.body!!.toByteArray())
                    } catch (e: Exception) {
                        return MockResponse.Builder().code(400).body("""{"error":"bad_request"}""").build()
                    }
                    received += opened.inner
                    val resp = handler(opened.inner)
                    MockResponse.Builder().code(200).addHeader("Content-Type", "application/octet-stream")
                        .body(okio.Buffer().write(seal(opened.respSecret, resp))).build()
                }
                else -> MockResponse.Builder().code(404).build()
            }
        }
    }

    companion object {
        /** The test key from docs/protocol.md "Interop vectors": bytes 0x00..0x5f. */
        val TEST_SECRET = ByteArray(96) { it.toByte() }

        fun json(status: Int, body: String, vararg headers: Pair<String, String>) =
            GatewayCodec.InnerResponse(status, listOf("content-type" to "application/json") + headers.toList(), body.toByteArray())
    }
}
