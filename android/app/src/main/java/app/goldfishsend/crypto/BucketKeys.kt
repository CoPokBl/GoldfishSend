package app.goldfishsend.crypto

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import app.goldfishsend.db.Db
import app.goldfishsend.proto.Rand
import java.security.KeyStore
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Time-bucketed message keys, so disappearing messages are destroyed on time even while GoldfishSend is locked.
 *
 * A message with an expiry has its per-message key wrapped under a bucket key BK(h) for the hour h its expiry falls in.
 * BK(h) is stored in the DB, wrapped by a Keystore key "gf_mb_<h>". Once hour h is over, every message in that bucket has
 * expired, and the Keystore alias is deleted. That needs no session, so it happens from the expiry alarm even while
 * locked. Remnants of those rows (stale pages, the rollback journal, flash wear-levelling copies) are then unreadable
 * even to someone who later obtains the master key, because the only key that opened them no longer exists anywhere.
 *
 * Messages without an expiry stay wrapped under the message root key (MRK), which reboot and panic wipes destroy.
 */
object BucketKeys {
    const val HOUR_MS = 3_600_000L
    private const val PREFIX = "gf_mb_"
    private const val KV_PREFIX = "bk/"
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val TRANSFORM = "AES/GCM/NoPadding"

    /** The bucket a given expiry time belongs to. */
    fun bucketOf(expiresAt: Long): Long = expiresAt / HOUR_MS

    /** A bucket can be destroyed once its hour has fully passed: every expiry in it lies in the past. */
    fun isOver(bucket: Long, now: Long): Boolean = (bucket + 1) * HOUR_MS <= now

    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private fun aliases(ks: KeyStore = keyStore()): List<Pair<String, Long>> =
        ks.aliases().toList().filter { it.startsWith(PREFIX) }.mapNotNull { a -> a.removePrefix(PREFIX).toLongOrNull()?.let { a to it } }

    /** Deletes the Keystore keys of every finished bucket. Works without a session (locked app, expiry alarm). */
    fun shredExpired(now: Long = System.currentTimeMillis()): Int {
        val ks = keyStore()
        var n = 0
        for ((alias, bucket) in aliases(ks)) {
            if (isOver(bucket, now)) {
                runCatching { ks.deleteEntry(alias) }
                n++
            }
        }
        return n
    }

    /** The next time a bucket ends, for arming the expiry alarm while locked. */
    fun nextBucketEnd(): Long? = aliases().minOfOrNull { (it.second + 1) * HOUR_MS }

    /** Destroys every bucket key (reboot wipe, panic wipe). All expiring messages become unreadable instantly. */
    fun destroyAll() {
        val ks = runCatching { keyStore() }.getOrNull() ?: return
        for ((alias, _) in aliases(ks)) {
            runCatching { ks.deleteEntry(alias) }
        }
    }

    private fun createKey(alias: String): SecretKey {
        // No unlocked-device requirement: a message may arrive while the screen is locked and the app still open.
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE).run {
            init(spec)
            generateKey()
        }
    }

    /** The DB-backed store a session uses. It caches unwrapped bucket keys in memory until the session closes. */
    class DbStore(private val db: Db) : MessageVault.Buckets {
        private val cache = ConcurrentHashMap<Long, ByteArray>()

        override fun key(bucket: Long, create: Boolean): ByteArray? {
            cache[bucket]?.let { return it }
            val ks = keyStore()
            val alias = PREFIX + bucket
            val stored = db.queryOne("SELECT v FROM kv WHERE k = ?", KV_PREFIX + bucket) { it.getBlob(0) }
            if (stored != null && ks.containsAlias(alias)) {
                val bk = runCatching {
                    val c = Cipher.getInstance(TRANSFORM)
                    c.init(Cipher.DECRYPT_MODE, ks.getKey(alias, null) as SecretKey, GCMParameterSpec(128, stored, 0, 12))
                    c.doFinal(stored, 12, stored.size - 12)
                }.getOrNull()
                if (bk != null) {
                    cache[bucket] = bk
                    return bk
                }
            }
            if (!create) {
                return null
            }
            val bk = Rand.bytes(32)
            val key = if (ks.containsAlias(alias)) ks.getKey(alias, null) as SecretKey else createKey(alias)
            val c = Cipher.getInstance(TRANSFORM)
            c.init(Cipher.ENCRYPT_MODE, key)
            val blob = c.iv + c.doFinal(bk)
            db.exec("INSERT OR REPLACE INTO kv (k, v) VALUES (?, ?)", KV_PREFIX + bucket, blob)
            cache[bucket] = bk
            return bk
        }

        /** Removes the DB rows of finished buckets (their Keystore keys are gone or about to be). */
        fun pruneRows(now: Long) {
            val rows = db.query("SELECT k FROM kv WHERE k LIKE ?", "$KV_PREFIX%") { it.getString(0) }
            for (k in rows) {
                val b = k.removePrefix(KV_PREFIX).toLongOrNull() ?: continue
                if (isOver(b, now)) {
                    db.exec("DELETE FROM kv WHERE k = ?", k)
                    cache.remove(b)?.fill(0)
                }
            }
        }

        override fun wipe() {
            for (v in cache.values) {
                v.fill(0)
            }
            cache.clear()
        }
    }
}
