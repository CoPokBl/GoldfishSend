package app.goldfishsend.net

import app.goldfishsend.proto.B64
import app.goldfishsend.proto.Hash
import app.goldfishsend.proto.utf8
import app.goldfishsend.proto.wipe
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement
import org.bouncycastle.crypto.ec.CustomNamedCurves
import org.bouncycastle.crypto.kems.MLKEMGenerator
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.crypto.params.MLKEMParameters
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters
import org.bouncycastle.math.ec.ECPoint
import org.bouncycastle.util.BigIntegers

/**
 * A server's identity key (docs/protocol.md, "Encrypted transport and server identity"): an ML-KEM-768 encapsulation key
 * plus a P-256 public key. Its fingerprint is the server's identity, pinned by clients per server.
 */
class ServerKey private constructor(
    val blob: ByteArray,
    internal val mlkem: MLKEMPublicKeyParameters,
    internal val p256: ECPoint,
    val fingerprint: ByteArray,
) {
    val fingerprintB64: String = B64.enc(fingerprint)
    val keyId: ByteArray get() = fingerprint.copyOf(Gateway.KEY_ID_SIZE)

    companion object {
        /** Parses a key blob, or returns null if it's malformed (wrong version or length, or an invalid P-256 point). */
        fun parse(blob: ByteArray): ServerKey? {
            if (blob.size != Gateway.BLOB_SIZE || blob[0] != Gateway.VERSION) {
                return null
            }
            return try {
                val ek = blob.copyOfRange(1, 1 + Gateway.MLKEM_EK_SIZE)
                val pk = blob.copyOfRange(1 + Gateway.MLKEM_EK_SIZE, Gateway.BLOB_SIZE)
                if (pk[0] != 0x04.toByte()) {
                    return null
                }
                val point = Gateway.curve.curve.decodePoint(pk).normalize()
                if (point.isInfinity || !point.isValid) {
                    return null
                }
                ServerKey(blob.copyOf(), MLKEMPublicKeyParameters(MLKEMParameters.ml_kem_768, ek), point, Gateway.fingerprint(blob))
            } catch (e: Exception) {
                null
            }
        }
    }
}

/** The result of sealing one request: the outer body to POST, and the secret that opens its response. */
class SealedRequest(val body: ByteArray, val respSecret: ByteArray, val enc: ByteArray)

/** Gateway v1 crypto. Pure JVM (Bouncy Castle lightweight API plus JCA), so it's unit-tested without Android. */
object Gateway {
    const val VERSION: Byte = 0x01
    const val MLKEM_EK_SIZE = 1184
    const val MLKEM_CT_SIZE = 1088
    const val P256_SIZE = 65
    const val BLOB_SIZE = 1 + MLKEM_EK_SIZE + P256_SIZE
    const val ENC_SIZE = MLKEM_CT_SIZE + P256_SIZE
    const val KEY_ID_SIZE = 8
    const val HEADER_SIZE = 1 + KEY_ID_SIZE
    const val TAG_SIZE = 16
    const val RESP_NONCE_SIZE = 32
    const val FP_SIZE = 32

    private val FP_LABEL = "gf/server-key/v1".utf8()
    private val TH_LABEL = "gf/gw/v1".utf8()
    private val REQ_INFO = "gf/gw/v1 req".utf8()
    private val RESP_INFO = "gf/gw/v1 resp".utf8()
    private val RESP_KEY_INFO = "gf/gw/v1 resp key".utf8()
    private val RESP_AAD = "gf/gw/v1 resp".utf8()
    private val ZERO_NONCE = ByteArray(12)

    internal val curve: ECDomainParameters = CustomNamedCurves.getByName("secp256r1").let {
        ECDomainParameters(it.curve, it.g, it.n, it.h, it.seed)
    }

    private val rng = SecureRandom()

    /** `SHA-256("gf/server-key/v1" ‖ blob)`. */
    fun fingerprint(blob: ByteArray): ByteArray = Hash.sha256(FP_LABEL, blob)

    /** True if [s] is a b64u fingerprint (32 bytes). */
    fun isFingerprint(s: String?): Boolean = s != null && s.length == 43 && runCatching { B64.dec(s).size == FP_SIZE }.getOrDefault(false)

    /** RFC 4648 base32 (no padding) in groups of 4, for comparing by eye. */
    fun displayFingerprint(fpB64: String): String {
        val bytes = runCatching { B64.dec(fpB64) }.getOrNull() ?: return fpB64
        return base32(bytes).chunked(4).joinToString(" ")
    }

    /**
     * A fingerprint typed or pasted by the user: either the display form (base32, any spacing or case) or b64u. Returns
     * the b64u form, or null if it isn't a fingerprint.
     */
    fun parseFingerprintInput(raw: String): String? {
        val compact = raw.filterNot { it.isWhitespace() }
        if (isFingerprint(compact)) {
            return compact
        }
        val b32 = raw.filterNot { it.isWhitespace() || it == '-' }.uppercase()
        if (b32.length != 52) {
            return null
        }
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        val out = ByteArrayOutputStream(32)
        var buffer = 0
        var bits = 0
        for (ch in b32) {
            val v = alphabet.indexOf(ch)
            if (v < 0) {
                return null
            }
            buffer = (buffer shl 5) or v
            bits += 5
            if (bits >= 8) {
                out.write((buffer ushr (bits - 8)) and 0xff)
                bits -= 8
            }
        }
        val bytes = out.toByteArray()
        return if (bytes.size == FP_SIZE) B64.enc(bytes) else null
    }

    fun base32(data: ByteArray): String {
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        val sb = StringBuilder((data.size * 8 + 4) / 5)
        var buffer = 0
        var bits = 0
        for (b in data) {
            buffer = (buffer shl 8) or (b.toInt() and 0xff)
            bits += 8
            while (bits >= 5) {
                sb.append(alphabet[(buffer ushr (bits - 5)) and 31])
                bits -= 5
            }
        }
        if (bits > 0) {
            sb.append(alphabet[(buffer shl (5 - bits)) and 31])
        }
        return sb.toString()
    }

    /** Encapsulates [inner] (an already padded inner request) to [key]. */
    fun seal(key: ServerKey, inner: ByteArray): SealedRequest {
        val m = ByteArray(32).also { rng.nextBytes(it) }
        val scalar = BigIntegers.createRandomInRange(BigInteger.ONE, curve.n.subtract(BigInteger.ONE), rng)
        try {
            return sealWith(key, inner, m, scalar)
        } finally {
            m.wipe()
        }
    }

    /** Deterministic encapsulation, for test vectors only: [mlkemRandomness] is ML-KEM's 32-byte `m`. */
    fun sealWith(key: ServerKey, inner: ByteArray, mlkemRandomness: ByteArray, ephemeralScalar: BigInteger): SealedRequest {
        val kem = MLKEMGenerator.internalGenerateEncapsulated(key.mlkem, mlkemRandomness)
        val ssM = kem.secret
        val ctM = kem.encapsulation
        val ePriv = ECPrivateKeyParameters(ephemeralScalar, curve)
        val ctX = curve.g.multiply(ephemeralScalar).normalize().getEncoded(false)
        val ssX = ecdh(ePriv, key.p256)
        val enc = ctM + ctX
        val secrets = deriveSecrets(key.fingerprint, enc, ssM, ssX)
        ssM.wipe()
        ssX.wipe()
        val header = byteArrayOf(VERSION) + key.keyId
        val ct = aesGcm(Cipher.ENCRYPT_MODE, secrets.first, header, inner)
        secrets.first.wipe()
        return SealedRequest(header + enc + ct, secrets.second, enc)
    }

    /** `(reqKey, respSecret)` from the hybrid shared secrets (spec steps 4 and 5). */
    fun deriveSecrets(fp: ByteArray, enc: ByteArray, ssM: ByteArray, ssX: ByteArray): Pair<ByteArray, ByteArray> {
        val th = Hash.sha256(TH_LABEL, fp, enc)
        val ikm = ssM + ssX
        val prk = Hkdf.extract(th, ikm)
        ikm.wipe()
        val reqKey = Hkdf.expand(prk, REQ_INFO, 32)
        val respSecret = Hkdf.expand(prk, RESP_INFO, 32)
        prk.wipe()
        return reqKey to respSecret
    }

    /** Opens a gateway response body (`respNonce ‖ ciphertext`). Throws if it doesn't authenticate. */
    fun openResponse(respSecret: ByteArray, body: ByteArray): ByteArray {
        require(body.size >= RESP_NONCE_SIZE + TAG_SIZE) { "response too short" }
        val key = responseKey(respSecret, body.copyOf(RESP_NONCE_SIZE))
        try {
            return aesGcm(Cipher.DECRYPT_MODE, key, RESP_AAD, body.copyOfRange(RESP_NONCE_SIZE, body.size))
        } finally {
            key.wipe()
        }
    }

    /** Server side of the response encapsulation (used by tests and vector generation). */
    fun sealResponse(respSecret: ByteArray, inner: ByteArray, respNonce: ByteArray): ByteArray {
        require(respNonce.size == RESP_NONCE_SIZE)
        val key = responseKey(respSecret, respNonce)
        try {
            return respNonce + aesGcm(Cipher.ENCRYPT_MODE, key, RESP_AAD, inner)
        } finally {
            key.wipe()
        }
    }

    private fun responseKey(respSecret: ByteArray, respNonce: ByteArray): ByteArray {
        val rprk = Hkdf.extract(respNonce, respSecret)
        try {
            return Hkdf.expand(rprk, RESP_KEY_INFO, 32)
        } finally {
            rprk.wipe()
        }
    }

    /** P-256 ECDH: the shared point's x-coordinate (32 bytes). */
    fun ecdh(priv: ECPrivateKeyParameters, pub: ECPoint): ByteArray {
        val agreement = ECDHBasicAgreement()
        agreement.init(priv)
        return BigIntegers.asUnsignedByteArray(32, agreement.calculateAgreement(ECPublicKeyParameters(pub, curve)))
    }

    fun aesGcm(mode: Int, key: ByteArray, aad: ByteArray, input: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(128, ZERO_NONCE))
        c.updateAAD(aad)
        return c.doFinal(input)
    }
}

/** HKDF-SHA-256 (RFC 5869). */
object Hkdf {
    fun extract(salt: ByteArray, ikm: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(if (salt.isEmpty()) ByteArray(32) else salt, "HmacSHA256"))
        return mac.doFinal(ikm)
    }

    fun expand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        require(length in 1..255 * 32)
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(prk, "HmacSHA256"))
        val out = ByteArrayOutputStream(length)
        var t = ByteArray(0)
        var counter = 1
        while (out.size() < length) {
            mac.update(t)
            mac.update(info)
            mac.update(counter.toByte())
            t = mac.doFinal()
            out.write(t, 0, minOf(t.size, length - out.size()))
            counter++
        }
        return out.toByteArray()
    }
}

/** The plaintext inside the gateway (docs/protocol.md "Inner request" / "Inner response"), big-endian, zero-padded. */
object GatewayCodec {
    val BUCKETS = intArrayOf(512, 1024, 2048, 4096, 8192, 17408)
    const val MAX_INNER_REQUEST = 17408

    const val GET = 1
    const val POST = 2
    const val PUT = 3
    const val DELETE = 4

    class FormatException(msg: String) : Exception(msg)

    data class InnerRequest(
        val method: Int,
        val timestamp: Long,
        val path: String,
        val headers: List<Pair<String, String>>,
        val body: ByteArray,
    )

    data class InnerResponse(val status: Int, val headers: List<Pair<String, String>>, val body: ByteArray) {
        fun header(name: String): String? = headers.firstOrNull { it.first.equals(name, ignoreCase = true) }?.second
    }

    fun methodCode(method: String): Int = when (method.uppercase()) {
        "GET" -> GET
        "POST" -> POST
        "PUT" -> PUT
        "DELETE" -> DELETE
        else -> throw IllegalArgumentException("unsupported method $method")
    }

    /** The smallest bucket that fits [n]. Larger sizes round up to a multiple of 4096 (responses only). */
    fun paddedSize(n: Int): Int {
        for (b in BUCKETS) {
            if (n <= b) {
                return b
            }
        }
        return (n + 4095) / 4096 * 4096
    }

    fun encodeRequest(r: InnerRequest): ByteArray {
        require(r.path.startsWith("/v1/") && r.path != "/v1/gw" && r.path != "/v1/key" && !r.path.startsWith("/v1/gw?") &&
            !r.path.startsWith("/v1/key?")) { "bad inner path" }
        val out = ByteArrayOutputStream()
        out.write(r.method)
        out.write(ByteBuffer.allocate(8).putLong(r.timestamp).array())
        writeU16Bytes(out, r.path.utf8())
        writeHeaders(out, r.headers)
        writeU32Bytes(out, r.body)
        val raw = out.toByteArray()
        if (raw.size > MAX_INNER_REQUEST) {
            throw FormatException("inner request too large")
        }
        return raw.copyOf(paddedSize(raw.size))
    }

    fun decodeRequest(b: ByteArray): InnerRequest {
        val r = Reader(b)
        val method = r.u8()
        if (method !in GET..DELETE) {
            throw FormatException("bad method")
        }
        val ts = r.u64()
        val path = r.bytes(r.u16()).toString(Charsets.UTF_8)
        val headers = readHeaders(r)
        val body = r.bytes(r.u32())
        return InnerRequest(method, ts, path, headers, body)
    }

    fun encodeResponse(r: InnerResponse): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(r.status ushr 8)
        out.write(r.status and 0xff)
        writeHeaders(out, r.headers)
        writeU32Bytes(out, r.body)
        val raw = out.toByteArray()
        return raw.copyOf(paddedSize(raw.size))
    }

    fun decodeResponse(b: ByteArray): InnerResponse {
        val r = Reader(b)
        val status = r.u16()
        if (status !in 100..599) {
            throw FormatException("bad status")
        }
        val headers = readHeaders(r)
        val body = r.bytes(r.u32())
        return InnerResponse(status, headers, body)
    }

    private fun writeHeaders(out: ByteArrayOutputStream, headers: List<Pair<String, String>>) {
        require(headers.size <= 255)
        out.write(headers.size)
        for ((name, value) in headers) {
            val n = name.lowercase().toByteArray(Charsets.US_ASCII)
            val v = value.toByteArray(Charsets.US_ASCII)
            require(n.isNotEmpty() && n.size <= 255 && v.size <= 0xffff)
            out.write(n.size)
            out.write(n)
            out.write(v.size ushr 8)
            out.write(v.size and 0xff)
            out.write(v)
        }
    }

    private fun readHeaders(r: Reader): List<Pair<String, String>> {
        val count = r.u8()
        val out = ArrayList<Pair<String, String>>(count)
        repeat(count) {
            val name = r.bytes(r.u8()).toString(Charsets.US_ASCII)
            val value = r.bytes(r.u16()).toString(Charsets.US_ASCII)
            out += name to value
        }
        return out
    }

    private fun writeU16Bytes(out: ByteArrayOutputStream, b: ByteArray) {
        require(b.size <= 0xffff)
        out.write(b.size ushr 8)
        out.write(b.size and 0xff)
        out.write(b)
    }

    private fun writeU32Bytes(out: ByteArrayOutputStream, b: ByteArray) {
        out.write(ByteBuffer.allocate(4).putInt(b.size).array())
        out.write(b)
    }

    private class Reader(private val b: ByteArray) {
        private var pos = 0

        private fun need(n: Int) {
            if (n < 0 || n > b.size - pos) {
                throw FormatException("truncated")
            }
        }

        fun u8(): Int {
            need(1)
            return b[pos++].toInt() and 0xff
        }

        fun u16(): Int = (u8() shl 8) or u8()

        fun u32(): Int {
            need(4)
            val v = ByteBuffer.wrap(b, pos, 4).int
            pos += 4
            if (v < 0) {
                throw FormatException("length out of range")
            }
            return v
        }

        fun u64(): Long {
            need(8)
            val v = ByteBuffer.wrap(b, pos, 8).long
            pos += 8
            return v
        }

        fun bytes(n: Int): ByteArray {
            need(n)
            val out = b.copyOfRange(pos, pos + n)
            pos += n
            return out
        }
    }
}
