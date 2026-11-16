package app.goldfishsend.proto

import kotlinx.serialization.KSerializer
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

    /** Any content too large for one message, split into parts (docs/groups.md, "Chunking"). Never nested. */
    @Serializable
    @SerialName("chunk")
    data class Chunk(val id: String, val part: Int, val parts: Int, val data: String) : Content()

    // --- groups (docs/groups.md). `g` is the group id. ---

    @Serializable
    @SerialName("gtext")
    data class GText(
        val g: String,
        val id: String,
        val body: String,
        val ts: Long,
        val exp: Long? = null,
        val once: Boolean? = null,
    ) : Content()

    @Serializable
    @SerialName("greceipt")
    data class GReceipt(val g: String, val ids: List<String>, val kind: String) : Content()

    @Serializable
    @SerialName("gdelete")
    data class GDelete(val g: String, val ids: List<String>) : Content()

    @Serializable
    @SerialName("groster")
    data class GRoster(val g: String, val roster: String, val sig: String) : Content()

    @Serializable
    @SerialName("gcard")
    data class GCard(val g: String, val card: String, val sig: String) : Content()

    @Serializable
    @SerialName("gsync")
    data class GSync(val g: String, val have: Long) : Content()

    @Serializable
    @SerialName("gleave")
    data class GLeave(val g: String) : Content()

    /** The group this content belongs to, or null for 1:1 content. */
    val groupId: String?
        get() = when (this) {
            is GText -> g
            is GReceipt -> g
            is GDelete -> g
            is GRoster -> g
            is GCard -> g
            is GSync -> g
            is GLeave -> g
            else -> null
        }

    fun encode(): ByteArray = ProtoJson.encodeToString(serializer(), this).utf8()

    companion object {
        fun decode(bytes: ByteArray): Content = ProtoJson.decodeUntrusted(serializer(), bytes.toString(Charsets.UTF_8))

        fun newId(): String = B64.enc(Rand.bytes(12))
    }
}

/**
 * Decodes JSON from someone else. Anything malformed is an [IllegalArgumentException] (kotlinx.serialization's own
 * SerializationException is one); the parser also throws others, for example StringIndexOutOfBoundsException on `{"v":"7`.
 */
fun <T> Json.decodeUntrusted(ser: KSerializer<T>, text: String): T = try {
    decodeFromString(ser, text)
} catch (e: IllegalArgumentException) {
    throw e
} catch (e: RuntimeException) {
    throw IllegalArgumentException("malformed JSON", e)
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

    /** At most this many parts per chunked content. */
    const val MAX_PARTS = 64

    /**
     * Splits any content into `chunk` parts whose padded encodings fit [maxPadded], or returns it unchanged if it already
     * fits. The parts carry slices of the content's JSON bytes (b64u).
     */
    fun splitContent(content: Content, maxPadded: Int): List<Content> {
        val bytes = content.encode()
        if (Padding.paddedSize(bytes.size) <= maxPadded) {
            return listOf(content)
        }
        val id = Content.newId()
        val overhead = Content.Chunk(id, 9999, 9999, "").encode().size
        // b64u turns 3 bytes into 4 characters; keep a margin for the padding marker.
        val budget = ((maxPadded - 1 - overhead - 8) / 4) * 3
        require(budget > 0) { "chunk budget too small" }
        val slices = bytes.toList().chunked(budget).map { it.toByteArray() }
        require(slices.size <= MAX_PARTS) { "content too large" }
        return slices.mapIndexed { i, b -> Content.Chunk(id, i, slices.size, B64.enc(b)) }
    }

    /** UTF-8 size of [s] once JSON-escaped, without the surrounding quotes. */
    private fun jsonBytes(s: String): Int = ProtoJson.encodeToString(String.serializer(), s).utf8().size - 2
}
