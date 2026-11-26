package app.goldfishsend.crypto

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import app.goldfishsend.core.IndexKey
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.ProviderException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * The locked inbox's index key: AES-256-GCM in the Android Keystore, so it never leaves the secure hardware and a copy
 * of the app's files can't open the index. It needs no user authentication and no unlocked phone, because pushes
 * arrive while both are locked. (Code running as the app on the live phone can still use it; it only hides counts and
 * order, and the pushes themselves stay sealed to the inbox key held in the encrypted DB.)
 */
class InboxIndexKey : IndexKey {
    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    override val overhead: Int = IV + TAG_BYTES

    override fun seal(plain: ByteArray): ByteArray {
        val c = Cipher.getInstance(TRANSFORM)
        c.init(Cipher.ENCRYPT_MODE, key(create = true))
        return c.iv + c.doFinal(plain)
    }

    override fun open(sealed: ByteArray): ByteArray? {
        val k = key(create = false) ?: return null
        return try {
            val c = Cipher.getInstance(TRANSFORM)
            c.init(Cipher.DECRYPT_MODE, k, GCMParameterSpec(TAG_BYTES * 8, sealed, 0, IV))
            c.doFinal(sealed, IV, sealed.size - IV)
        } catch (e: GeneralSecurityException) {
            // A bad tag: random filler, or a copy of the index written under a key since replaced.
            null
        } catch (e: ProviderException) {
            null
        }
    }

    override fun destroy() {
        runCatching { keyStore.deleteEntry(ALIAS) }
    }

    private fun key(create: Boolean): SecretKey? {
        (keyStore.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        if (!create) {
            return null
        }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        gen.init(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
                .build(),
        )
        return gen.generateKey()
    }

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val TRANSFORM = "AES/GCM/NoPadding"
        private const val ALIAS = "gf_inbox"
        private const val IV = 12
        private const val TAG_BYTES = 16
    }
}
