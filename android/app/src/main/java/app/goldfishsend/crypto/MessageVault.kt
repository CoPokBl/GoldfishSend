package app.goldfishsend.crypto

import app.goldfishsend.proto.Aead
import app.goldfishsend.proto.Rand
import app.goldfishsend.proto.utf8
import app.goldfishsend.proto.wipe

/**
 * Per-message crypto-shredding (PLAN.md §10a). Each message body is encrypted with its own random key, stored wrapped in
 * `message_keys`. Messages with an expiry are wrapped under that expiry's time-bucket key (see [BucketKeys]), which is
 * destroyed when the bucket ends, even while locked. Others are wrapped by the message root key (MRK).
 * Deleting the key row makes the body unrecoverable. Destroying the MRK's Keystore wrapper makes every message unrecoverable.
 */
class MessageVault(private val mrk: ByteArray, private val buckets: Buckets? = null) {
    val bucketStore: Buckets?
        get() = buckets

    /** Source of bucket keys. [key] returns null if the bucket was destroyed (and [create] is false). */
    interface Buckets {
        fun key(bucket: Long, create: Boolean): ByteArray?

        fun wipe()
    }

    /** [bucket] is null when the key is wrapped by the MRK. */
    class Sealed(val wrappedKey: ByteArray, val ciphertext: ByteArray, val bucket: Long? = null)

    fun seal(messageId: String, plaintext: ByteArray, expiresAt: Long? = null): Sealed {
        val k = Rand.bytes(32)
        try {
            val ct = Aead.seal(k, plaintext, ("gf/msg/" + messageId).utf8())
            val (wk, bucket) = wrap(messageId, k, expiresAt)
            return Sealed(wk, ct, bucket)
        } finally {
            k.wipe()
        }
    }

    fun open(messageId: String, wrappedKey: ByteArray, ciphertext: ByteArray, bucket: Long? = null): ByteArray {
        val k = unwrap(messageId, wrappedKey, bucket)
        try {
            return Aead.open(k, ciphertext, ("gf/msg/" + messageId).utf8())
        } finally {
            k.wipe()
        }
    }

    /**
     * Re-wraps a message key when its expiry becomes known (start-on-read timers). Returns the new wrapped key and bucket,
     * or null if the old key can't be opened.
     */
    fun rewrap(messageId: String, wrappedKey: ByteArray, oldBucket: Long?, expiresAt: Long): Pair<ByteArray, Long?>? {
        val k = runCatching { unwrap(messageId, wrappedKey, oldBucket) }.getOrNull() ?: return null
        try {
            return wrap(messageId, k, expiresAt)
        } finally {
            k.wipe()
        }
    }

    private fun wrap(messageId: String, k: ByteArray, expiresAt: Long?): Pair<ByteArray, Long?> {
        val aad = ("gf/msgkey/" + messageId).utf8()
        if (expiresAt != null && buckets != null) {
            val b = BucketKeys.bucketOf(expiresAt)
            val bk = buckets.key(b, create = true)
            if (bk != null) {
                return Aead.seal(bk, k, aad) to b
            }
        }
        return Aead.seal(mrk, k, aad) to null
    }

    private fun unwrap(messageId: String, wrappedKey: ByteArray, bucket: Long?): ByteArray {
        val aad = ("gf/msgkey/" + messageId).utf8()
        if (bucket == null) {
            return Aead.open(mrk, wrappedKey, aad)
        }
        val bk = buckets?.key(bucket, create = false) ?: throw IllegalStateException("bucket key destroyed")
        return Aead.open(bk, wrappedKey, aad)
    }

    /** Encrypts transient blobs (outbox content, chunks) directly under the MRK. */
    fun sealBlob(label: String, plaintext: ByteArray): ByteArray = Aead.seal(mrk, plaintext, ("gf/blob/" + label).utf8())

    fun openBlob(label: String, blob: ByteArray): ByteArray = Aead.open(mrk, blob, ("gf/blob/" + label).utf8())

    fun wipe() {
        mrk.wipe()
        buckets?.wipe()
    }
}
