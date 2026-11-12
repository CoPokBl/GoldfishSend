package app.goldfishsend.proto

/**
 * ISO/IEC 7816-4 padding to the next multiple of [BLOCK] bytes (protocol.md, "E2E blob").
 * Append 0x80, then 0x00 up to the boundary. A message that is already block-aligned still gains a full block.
 */
object Padding {
    const val BLOCK = 256

    /** Max padded plaintext while the session may still produce PreKey messages. */
    const val MAX_PREKEY_PLAINTEXT = 2048

    /** Max padded plaintext for normal (Whisper) messages. */
    const val MAX_PLAINTEXT = 3584

    fun paddedSize(len: Int): Int = ((len + 1 + BLOCK - 1) / BLOCK) * BLOCK

    fun pad(data: ByteArray): ByteArray {
        val out = ByteArray(paddedSize(data.size))
        data.copyInto(out)
        out[data.size] = 0x80.toByte()
        return out
    }

    fun unpad(padded: ByteArray): ByteArray {
        var i = padded.size - 1
        while (i >= 0 && padded[i] == 0.toByte()) {
            i--
        }
        require(i >= 0 && padded[i] == 0x80.toByte()) { "bad padding" }
        return padded.copyOf(i)
    }
}
