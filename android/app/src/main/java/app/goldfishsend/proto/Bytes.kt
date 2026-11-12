package app.goldfishsend.proto

import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** base64url without padding, as required by docs/protocol.md. */
object B64 {
    private val encoder = Base64.getUrlEncoder().withoutPadding()
    private val decoder = Base64.getUrlDecoder()

    fun enc(bytes: ByteArray): String = encoder.encodeToString(bytes)

    fun dec(s: String): ByteArray = decoder.decode(s)
}

object Rand {
    private val rng = SecureRandom()

    fun bytes(n: Int): ByteArray = ByteArray(n).also { rng.nextBytes(it) }

    fun int(bound: Int): Int = rng.nextInt(bound)

    fun long(): Long = rng.nextLong()
}

object Hash {
    fun sha256(vararg parts: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        for (p in parts) {
            md.update(p)
        }
        return md.digest()
    }

    fun hmacSha256(key: ByteArray, vararg parts: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        for (p in parts) {
            mac.update(p)
        }
        return mac.doFinal()
    }
}

fun ByteArray.wipe() {
    fill(0)
}

fun String.utf8(): ByteArray = toByteArray(Charsets.UTF_8)
