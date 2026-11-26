package app.goldfishsend.proto

/**
 * The outer layer of every blob the server relays (docs/protocol.md, "Blob"): `nonce(12) ‖ AES-256-GCM(wrapKey, nonce,
 * aad = "gf/blob/v1", plaintext = inner ‖ 0x80 ‖ 0x00…)`, exactly one of [SIZES] long.
 *
 * Without it the server would read libsignal's own headers: a PreKey message's identity key, registration id, base key
 * and prekey ids, and a normal message's ratchet key and counter. Those link one person's mailboxes and a group's
 * members. Wrapped, every blob is random-looking bytes of a few fixed sizes, the same for 1:1 and group traffic.
 *
 * The key is per mailbox, and the server never learns it: a 1:1 mailbox's comes with its `sendSecret` in the invite
 * bundle, `hello` or `mailbox` message, both end to end; a group inbox's is derived from its hint key ([groupKey]).
 */
object BlobWrap {
    private val AAD = "gf/blob/v1".utf8()
    private val GROUP_INFO = "gf/group-wrap/v1".utf8()

    const val KEY_BYTES = 32
    private const val TAG_BYTES = 16

    /**
     * Every blob is exactly one of these sizes. With the push envelope's 10-byte header and Web Push's 103 bytes they fill
     * a 1, 2, 3 or 4 KiB push, the sizes the server pads pushes to anyway.
     */
    val SIZES = intArrayOf(911, 1935, 2959, 3983)

    /** Nonce, tag and the padding marker. */
    const val OVERHEAD = Aead.NONCE + TAG_BYTES + 1

    /** The largest inner blob (type byte, hint and libsignal ciphertext) that fits. */
    val MAX_INNER: Int = SIZES.last() - OVERHEAD

    /** A fresh key for one of our 1:1 mailboxes. */
    fun newKey(): ByteArray = Rand.bytes(KEY_BYTES)

    /** A group inbox's wrap key, from its hint key, which only the group's members hold. */
    fun groupKey(hintKey: ByteArray): ByteArray = Hash.hkdf32(hintKey, ByteArray(0), GROUP_INFO)

    /** Seals [inner] under [key], padded to the smallest size that fits. Throws if it's larger than [MAX_INNER]. */
    fun seal(key: ByteArray, inner: ByteArray): ByteArray {
        require(key.size == KEY_BYTES) { "wrap key" }
        val size = SIZES.firstOrNull { it >= inner.size + OVERHEAD } ?: throw IllegalArgumentException("blob too large")
        val padded = ByteArray(size - Aead.NONCE - TAG_BYTES)
        inner.copyInto(padded)
        padded[inner.size] = 0x80.toByte()
        return Aead.seal(key, padded, AAD)
    }

    /** The inner blob, or null if [blob] isn't one of ours under [key] (wrong size, wrong key, or tampered with). */
    fun open(key: ByteArray, blob: ByteArray): ByteArray? {
        if (key.size != KEY_BYTES || blob.size !in SIZES) {
            return null
        }
        return try {
            val padded = Aead.open(key, blob, AAD)
            var i = padded.size - 1
            while (i >= 0 && padded[i] == 0.toByte()) {
                i--
            }
            if (i < 1 || padded[i] != 0x80.toByte()) null else padded.copyOf(i)
        } catch (e: Exception) {
            null
        }
    }
}
