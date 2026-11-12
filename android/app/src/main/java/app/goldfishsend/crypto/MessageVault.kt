package app.goldfishsend.crypto

import app.goldfishsend.proto.Aead
import app.goldfishsend.proto.Rand
import app.goldfishsend.proto.utf8
import app.goldfishsend.proto.wipe

/**
 * Per-message crypto-shredding (PLAN.md §10a). Each message body is encrypted with its own random key.
 * That key is stored wrapped by the message root key (MRK) in `message_keys`.
 * Deleting the key row makes the body unrecoverable. Destroying the MRK's Keystore wrapper makes every message unrecoverable.
 */
class MessageVault(private val mrk: ByteArray) {
    class Sealed(val wrappedKey: ByteArray, val ciphertext: ByteArray)

    fun seal(messageId: String, plaintext: ByteArray): Sealed {
        val k = Rand.bytes(32)
        try {
            val ct = Aead.seal(k, plaintext, ("gf/msg/" + messageId).utf8())
            val wk = Aead.seal(mrk, k, ("gf/msgkey/" + messageId).utf8())
            return Sealed(wk, ct)
        } finally {
            k.wipe()
        }
    }

    fun open(messageId: String, wrappedKey: ByteArray, ciphertext: ByteArray): ByteArray {
        val k = Aead.open(mrk, wrappedKey, ("gf/msgkey/" + messageId).utf8())
        try {
            return Aead.open(k, ciphertext, ("gf/msg/" + messageId).utf8())
        } finally {
            k.wipe()
        }
    }

    /** Encrypts transient blobs (outbox content, chunks) directly under the MRK. */
    fun sealBlob(label: String, plaintext: ByteArray): ByteArray = Aead.seal(mrk, plaintext, ("gf/blob/" + label).utf8())

    fun openBlob(label: String, blob: ByteArray): ByteArray = Aead.open(mrk, blob, ("gf/blob/" + label).utf8())

    fun wipe() {
        mrk.wipe()
    }
}
