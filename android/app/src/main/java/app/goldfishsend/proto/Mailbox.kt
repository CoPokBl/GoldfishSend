package app.goldfishsend.proto

/** Client-side derivations from protocol.md. */
object MailboxCrypto {
    private val TAG_PREFIX = "gf/mbx-tag".utf8()

    const val SECRET_BYTES = 32
    const val TAG_BYTES = 8

    fun tag(sendSecret: ByteArray): ByteArray = Hash.sha256(TAG_PREFIX, sendSecret).copyOf(TAG_BYTES)

    fun ownerHash(ownerSecret: ByteArray): ByteArray = Hash.sha256(ownerSecret)

    fun newSecret(): ByteArray = Rand.bytes(SECRET_BYTES)
}

/** Push payload envelope (plaintext inside the RFC 8291 layer). */
sealed class PushEnvelope(val tag: ByteArray) {
    class Message(tag: ByteArray, val blob: ByteArray) : PushEnvelope(tag)

    class Verification(tag: ByteArray, val code: ByteArray) : PushEnvelope(tag)

    companion object {
        const val VERSION: Byte = 0x01
        const val TYPE_MESSAGE: Byte = 0x01
        const val TYPE_VERIFICATION: Byte = 0x02
        const val HEADER = 10
        const val CODE_BYTES = 16

        fun parse(bytes: ByteArray): PushEnvelope? {
            if (bytes.size < HEADER || bytes[0] != VERSION) {
                return null
            }
            val tag = bytes.copyOfRange(2, HEADER)
            val body = bytes.copyOfRange(HEADER, bytes.size)
            return when (bytes[1]) {
                TYPE_MESSAGE -> if (body.isNotEmpty()) Message(tag, body) else null
                // The server may pad the verification body with random bytes so it looks like a message. The code is
                // always the first 16 bytes.
                TYPE_VERIFICATION -> if (body.size >= CODE_BYTES) Verification(tag, body.copyOf(CODE_BYTES)) else null
                else -> null
            }
        }

        /** Builds an envelope; used by tests and for symmetry with the server. */
        fun build(type: Byte, tag: ByteArray, body: ByteArray): ByteArray {
            require(tag.size == MailboxCrypto.TAG_BYTES)
            return byteArrayOf(VERSION, type) + tag + body
        }
    }
}

/**
 * A 1:1 blob inside its wrapping ([BlobWrap]): 1 byte libsignal CiphertextMessage type, then the serialized ciphertext.
 * The server only ever sees it wrapped.
 */
class E2eBlob(val type: Int, val body: ByteArray) {
    fun encode(): ByteArray = byteArrayOf(type.toByte()) + body

    companion object {
        const val PREKEY = 3
        const val WHISPER = 2

        /** protocol.md: maxMessageBytes, the largest wrapped blob the server takes. */
        const val MAX_BYTES = 3983

        fun decode(bytes: ByteArray): E2eBlob? {
            if (bytes.size < 2) {
                return null
            }
            val t = bytes[0].toInt()
            if (t != PREKEY && t != WHISPER) {
                return null
            }
            return E2eBlob(t, bytes.copyOfRange(1, bytes.size))
        }
    }
}
