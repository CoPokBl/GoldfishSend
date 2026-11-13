package app.goldfishsend.proto

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json

/** E2E Content JSON (protocol.md, "Content"). Discriminator field is `t`. */
@Serializable
sealed class Content {
    @Serializable
    @SerialName("hello")
    data class Hello(val server: String, val sendSecret: String, val name: String? = null, val serverKey: String? = null) : Content()

    @Serializable
    @SerialName("text")
    data class Text(
        val id: String,
        val body: String,
        val ts: Long,
        val exp: Long? = null,
        val once: Boolean? = null,
        val part: Int? = null,
        val parts: Int? = null,
    ) : Content()

    @Serializable
    @SerialName("receipt")
    data class Receipt(val ids: List<String>, val kind: String) : Content() {
        companion object {
            const val DELIVERED = "delivered"
            const val READ = "read"
        }
    }

    @Serializable
    @SerialName("timer")
    data class Timer(val secs: Long) : Content()

    @Serializable
    @SerialName("delete")
    data class Delete(val ids: List<String>) : Content()

    @Serializable
    @SerialName("mailbox")
    data class Mailbox(val server: String, val sendSecret: String, val serverKey: String? = null) : Content()

    fun encode(): ByteArray = ProtoJson.encodeToString(serializer(), this).utf8()

    companion object {
        fun decode(bytes: ByteArray): Content = ProtoJson.decodeFromString(serializer(), bytes.toString(Charsets.UTF_8))

        fun newId(): String = B64.enc(Rand.bytes(12))
    }
}

val ProtoJson = Json {
    classDiscriminator = "t"
    ignoreUnknownKeys = true
    explicitNulls = false
    encodeDefaults = false
}

/**
 * Splits a text body into parts so that each padded Content fits [maxPadded].
 * Splits on code-point boundaries.
 */
object Chunker {
    fun split(id: String, body: String, ts: Long, exp: Long?, once: Boolean?, maxPadded: Int): List<Content.Text> {
        val single = Content.Text(id, body, ts, exp, once)
        if (Padding.paddedSize(single.encode().size) <= maxPadded) {
            return listOf(single)
        }
        // Overhead of a chunk envelope with large part numbers, then budget the rest for the body.
        val overhead = Content.Text(id, "", ts, exp, once, 9999, 9999).encode().size
        val budget = maxPadded - 1 - overhead - 16
        val pieces = mutableListOf<String>()
        var i = 0
        while (i < body.length) {
            var end = i
            var bytes = 0
            while (end < body.length) {
                val cp = body.codePointAt(end)
                val cpLen = Character.charCount(cp)
                val encBytes = jsonBytes(body.substring(end, end + cpLen))
                if (bytes + encBytes > budget) {
                    break
                }
                bytes += encBytes
                end += cpLen
            }
            if (end == i) {
                end = i + Character.charCount(body.codePointAt(i))
            }
            pieces += body.substring(i, end)
            i = end
        }
        return pieces.mapIndexed { idx, p -> Content.Text(id, p, ts, exp, once, idx, pieces.size) }
    }

    /** UTF-8 size of [s] once JSON-escaped, without the surrounding quotes. */
    private fun jsonBytes(s: String): Int = ProtoJson.encodeToString(String.serializer(), s).utf8().size - 2
}
