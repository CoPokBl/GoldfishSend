package app.goldfishsend.crypto

import app.goldfishsend.proto.Aead
import app.goldfishsend.proto.Rand
import app.goldfishsend.proto.utf8
import app.goldfishsend.proto.wipe

/**
 * Per-message crypto-shredding (android/README.md, "Security notes"). Each message body is encrypted with its own random key, stored wrapped in
 * `message_keys`. Messages with an expiry are wrapped under that expiry's time-bucket key (see [BucketKeys]), which is
 * destroyed when the bucket ends, even while locked. Others are wrapped by the message root key (MRK).
 * Deleting the key row makes the body unrecoverable. Destroying the MRK's Keystore wrapper makes every message unrecoverable.
 *
 * Deleting a row alone isn't enough against someone with a raw flash image: old copies of its pages (the rollback journal,
 * flash wear levelling) outlive the delete, and they open with the database key and the MRK. So after deletes the MRK is
 * rotated ([rewrapUnder], [resealUnder], [replaceRoot]; see core/Shredder): what's still live is re-wrapped under a fresh
 * root, and the old root's Keystore wrapper is destroyed, which leaves every stale copy unreadable.
 */
class MessageVault(mrk: ByteArray, private val buckets: Buckets? = null) {
    @Volatile
    private var mrk: ByteArray = mrk

    /**
     * Roots replaced in this session. Kept in RAM only, so a row read just before a rotation still opens. They're wiped
     * with the session, and nothing persistent can recover them.
     */
    private val retired = java.util.concurrent.CopyOnWriteArrayList<ByteArray>()

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
            return openUnderRoot(wrappedKey, aad)
        }
        val bk = buckets?.key(bucket, create = false) ?: throw IllegalStateException("bucket key destroyed")
        return Aead.open(bk, wrappedKey, aad)
    }

    /** Encrypts transient blobs (outbox content, chunks) directly under the MRK. */
    fun sealBlob(label: String, plaintext: ByteArray): ByteArray = Aead.seal(mrk, plaintext, ("gf/blob/" + label).utf8())

    fun openBlob(label: String, blob: ByteArray): ByteArray = openUnderRoot(blob, ("gf/blob/" + label).utf8())

    /** Opens with the current root, or one retired in this session. */
    private fun openUnderRoot(blob: ByteArray, aad: ByteArray): ByteArray {
        try {
            return Aead.open(mrk, blob, aad)
        } catch (e: Exception) {
            for (old in retired) {
                runCatching { Aead.open(old, blob, aad) }.getOrNull()?.let { return it }
            }
            throw e
        }
    }

    /** A message key wrapped by the root, re-wrapped under [next]. Null if it doesn't open (it's beyond saving then). */
    fun rewrapUnder(next: ByteArray, messageId: String, wrappedKey: ByteArray): ByteArray? {
        val aad = ("gf/msgkey/" + messageId).utf8()
        val k = runCatching { openUnderRoot(wrappedKey, aad) }.getOrNull() ?: return null
        try {
            return Aead.seal(next, k, aad)
        } finally {
            k.wipe()
        }
    }

    /** A [sealBlob] blob, sealed again under [next]. Null if it doesn't open. */
    fun resealUnder(next: ByteArray, label: String, blob: ByteArray): ByteArray? {
        val aad = ("gf/blob/" + label).utf8()
        val plain = runCatching { openUnderRoot(blob, aad) }.getOrNull() ?: return null
        try {
            return Aead.seal(next, plain, aad)
        } finally {
            plain.wipe()
        }
    }

    /**
     * Makes [next] the root (the vault takes ownership of it) once everything has been re-wrapped under it. The old root
     * stays in RAM until [wipe], for rows read just before. Returns a function that undoes the swap, for a rotation whose
     * transaction didn't commit.
     */
    fun replaceRoot(next: ByteArray): () -> Unit {
        val old = mrk
        retired += old
        mrk = next
        return {
            if (mrk === next) {
                mrk = old
                retired.remove(old)
            }
        }
    }

    fun wipe() {
        mrk.wipe()
        for (old in retired) {
            old.wipe()
        }
        retired.clear()
        buckets?.wipe()
    }
}
