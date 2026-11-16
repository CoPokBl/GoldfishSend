package app.goldfishsend.proto

import java.net.URLDecoder
import java.net.URLEncoder
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlinx.serialization.Serializable

/** InviteBundle JSON (protocol.md). */
@Serializable
data class InviteBundle(
    val v: Int = 2,
    val server: String,
    /** The fingerprint (b64u) of [server]'s identity key. */
    val serverKey: String? = null,
    val sendSecret: String,
    val registrationId: Int,
    val deviceId: Int = 1,
    val identityKey: String,
    val signedPreKeyId: Int,
    val signedPreKey: String,
    val signedPreKeySig: String,
    val kyberPreKeyId: Int,
    val kyberPreKey: String,
    val kyberPreKeySig: String,
    val name: String? = null,
) {
    fun encode(): ByteArray = BundleJson.encodeToString(serializer(), this).utf8()

    companion object {
        fun decode(bytes: ByteArray): InviteBundle = BundleJson.decodeUntrusted(serializer(), bytes.toString(Charsets.UTF_8))
    }
}

/** The spec lists `v` and `deviceId` explicitly, so always encode defaults. A null `name` is omitted. */
private val BundleJson = kotlinx.serialization.json.Json {
    ignoreUnknownKeys = true
    encodeDefaults = true
    explicitNulls = false
}

/**
 * `gfsend://invite#v=2&s=<server>&f=<server fingerprint>&i=<id>&k=<key>`. [serverKey] pins the inviter's server before
 * anything is fetched from it.
 */
data class InviteLink(val server: String, val serverKey: String, val id: String, val key: ByteArray) {
    fun toUri(): String {
        val s = URLEncoder.encode(server, "UTF-8")
        return "$SCHEME_PREFIX#v=2&s=$s&f=$serverKey&i=$id&k=${B64.enc(key)}"
    }

    override fun equals(other: Any?): Boolean =
        other is InviteLink && other.server == server && other.serverKey == serverKey && other.id == id && other.key.contentEquals(key)

    override fun hashCode(): Int = server.hashCode() * 31 + id.hashCode()

    companion object {
        const val SCHEME_PREFIX = "gfsend://invite"

        /**
         * The link inside [raw]. People often copy the whole shared message ("Let's chat… gfsend://invite#…"), so the
         * link may be surrounded by other text. It runs up to the first whitespace.
         */
        private fun extract(raw: String): String? {
            val start = raw.indexOf(SCHEME_PREFIX)
            if (start < 0) {
                return null
            }
            val end = (start until raw.length).firstOrNull { raw[it].isWhitespace() } ?: raw.length
            return raw.substring(start, end)
        }

        private fun params(raw: String): Map<String, String>? {
            val text = extract(raw) ?: return null
            val hash = text.indexOf('#')
            if (hash < 0) {
                return null
            }
            return text.substring(hash + 1).split('&').mapNotNull {
                val eq = it.indexOf('=')
                if (eq <= 0) null else it.substring(0, eq) to it.substring(eq + 1)
            }.toMap()
        }

        /** A link from an app version before server identity keys. It can't be accepted: ask for a new one. */
        fun isOutdated(raw: String): Boolean = params(raw)?.get("v") == "1"

        fun parse(raw: String): InviteLink? {
            val params = params(raw) ?: return null
            if (params["v"] != "2") {
                return null
            }
            return try {
                val server = URLDecoder.decode(params["s"] ?: return null, "UTF-8")
                val fp = params["f"] ?: return null
                val id = params["i"] ?: return null
                val key = B64.dec(params["k"] ?: return null)
                if (key.size != 32 || B64.dec(id).size != 16 || fp.length != 43 || B64.dec(fp).size != 32) {
                    return null
                }
                InviteLink(server, fp, id, key)
            } catch (e: IllegalArgumentException) {
                null
            }
        }
    }
}

/** AES-256-GCM helpers: nonce(12) ‖ ciphertext‖tag. */
object Aead {
    const val NONCE = 12

    fun seal(key: ByteArray, plaintext: ByteArray, aad: ByteArray): ByteArray {
        val nonce = Rand.bytes(NONCE)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        c.updateAAD(aad)
        return nonce + c.doFinal(plaintext)
    }

    fun open(key: ByteArray, blob: ByteArray, aad: ByteArray): ByteArray {
        require(blob.size > NONCE + 16) { "ciphertext too short" }
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, blob, 0, NONCE))
        c.updateAAD(aad)
        return c.doFinal(blob, NONCE, blob.size - NONCE)
    }
}

object InviteCrypto {
    private val AAD = "gf/invite/v1".utf8()

    fun encrypt(key: ByteArray, bundle: InviteBundle): ByteArray = Aead.seal(key, bundle.encode(), AAD)

    fun decrypt(key: ByteArray, blob: ByteArray): InviteBundle = InviteBundle.decode(Aead.open(key, blob, AAD))
}
