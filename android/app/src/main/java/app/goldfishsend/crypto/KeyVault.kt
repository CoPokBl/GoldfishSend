package app.goldfishsend.crypto

import android.content.Context
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import app.goldfishsend.proto.Aead
import app.goldfishsend.proto.B64
import app.goldfishsend.proto.Rand
import app.goldfishsend.proto.wipe
import java.security.KeyStore
import java.security.MessageDigest
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters

/**
 * Key hierarchy (PLAN.md §10a):
 *
 *   [optional passphrase] --Argon2id--> KEK --AES-GCM--> inner(MK)
 *   Android Keystore "gf_device" (StrongBox if present, unlocked-device-required) --AES-GCM--> outer(inner or MK)
 *
 * MK (master key, 32 bytes) only lives in RAM while the app is unlocked. The DB key and other keys are derived from it.
 * A second Keystore key "gf_msg" wraps the message root key, so wiping on reboot only needs that alias deleted.
 * The optional "gf_bio" key is biometric-bound and holds a second copy of MK for fingerprint/face unlock.
 */
class KeyVault(private val context: Context) {
    private val prefs: SharedPreferences = context.getSharedPreferences("gf_vault", Context.MODE_PRIVATE)
    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    val isSetUp: Boolean
        get() = prefs.contains(P_WRAPPED)

    val hasPassphrase: Boolean
        get() = prefs.getBoolean(P_HAS_PASS, false)

    val hasBiometric: Boolean
        get() = prefs.contains(P_BIO) && keyStore.containsAlias(ALIAS_BIO)

    val hasDuress: Boolean
        get() = prefs.contains(P_DURESS)

    val usesStrongBox: Boolean
        get() = prefs.getBoolean(P_STRONGBOX, false)

    /** Creates a fresh MK. Returns it, and the caller must wipe it when locking. */
    fun setup(passphrase: CharArray?): ByteArray {
        destroyAll()
        val mk = Rand.bytes(32)
        createKey(ALIAS_DEVICE, preferStrongBox = true, biometric = false)
        writeWrapped(mk, passphrase)
        return mk
    }

    fun unlockWithoutPassphrase(): ByteArray? {
        if (!isSetUp || hasPassphrase) {
            return null
        }
        return try {
            keystoreOpen(ALIAS_DEVICE, B64.dec(prefs.getString(P_WRAPPED, null)!!))
        } catch (e: Exception) {
            null
        }
    }

    /** Returns MK, or null for a wrong passphrase. Throws if the device key is unavailable (device locked). */
    fun unlockWithPassphrase(passphrase: CharArray): ByteArray? {
        val inner = keystoreOpen(ALIAS_DEVICE, B64.dec(prefs.getString(P_WRAPPED, null)!!))
        val salt = B64.dec(prefs.getString(P_SALT, null)!!)
        val kek = argon2(passphrase, salt)
        return try {
            Aead.open(kek, inner, AAD_MK)
        } catch (e: AEADBadTagException) {
            null
        } finally {
            kek.wipe()
            inner.wipe()
        }
    }

    fun isDuress(pin: CharArray): Boolean {
        val stored = prefs.getString(P_DURESS, null) ?: return false
        val salt = B64.dec(prefs.getString(P_DURESS_SALT, null)!!)
        val h = argon2(pin, salt)
        val eq = MessageDigest.isEqual(h, B64.dec(stored))
        h.wipe()
        return eq
    }

    fun setDuress(pin: CharArray?) {
        if (pin == null) {
            prefs.edit().remove(P_DURESS).remove(P_DURESS_SALT).apply()
            return
        }
        val salt = Rand.bytes(16)
        val h = argon2(pin, salt)
        prefs.edit().putString(P_DURESS, B64.enc(h)).putString(P_DURESS_SALT, B64.enc(salt)).apply()
        h.wipe()
    }

    /** Sets, changes or removes (null) the passphrase. Biometric unlock is reset when removed. */
    fun changePassphrase(mk: ByteArray, newPassphrase: CharArray?) {
        writeWrapped(mk, newPassphrase)
        if (newPassphrase == null) {
            disableBiometric()
            setDuress(null)
        }
    }

    // --- biometric ---

    fun biometricEncryptCipher(): Cipher {
        createKey(ALIAS_BIO, preferStrongBox = false, biometric = true)
        return Cipher.getInstance(TRANSFORM).apply { init(Cipher.ENCRYPT_MODE, secretKey(ALIAS_BIO)) }
    }

    fun enableBiometric(mk: ByteArray, authenticatedCipher: Cipher) {
        val ct = authenticatedCipher.doFinal(mk)
        val blob = authenticatedCipher.iv + ct
        prefs.edit().putString(P_BIO, B64.enc(blob)).apply()
    }

    fun biometricDecryptCipher(): Cipher? {
        val blob = prefs.getString(P_BIO, null)?.let { B64.dec(it) } ?: return null
        return try {
            Cipher.getInstance(TRANSFORM).apply {
                init(Cipher.DECRYPT_MODE, secretKey(ALIAS_BIO), GCMParameterSpec(128, blob, 0, 12))
            }
        } catch (e: Exception) {
            // Key invalidated (e.g. new fingerprint enrolled).
            disableBiometric()
            null
        }
    }

    fun unwrapWithBiometric(authenticatedCipher: Cipher): ByteArray? {
        val blob = prefs.getString(P_BIO, null)?.let { B64.dec(it) } ?: return null
        return try {
            authenticatedCipher.doFinal(blob, 12, blob.size - 12)
        } catch (e: Exception) {
            null
        }
    }

    fun disableBiometric() {
        prefs.edit().remove(P_BIO).apply()
        runCatching { keyStore.deleteEntry(ALIAS_BIO) }
    }

    // --- message root key (crypto-shredded on reboot wipe) ---

    fun wrapMessageRoot(mrk: ByteArray): ByteArray {
        if (!keyStore.containsAlias(ALIAS_MSG)) {
            createKey(ALIAS_MSG, preferStrongBox = false, biometric = false)
        }
        return keystoreSeal(ALIAS_MSG, mrk)
    }

    /** Null if the message key was destroyed (reboot/panic wipe) or the blob is invalid. */
    fun unwrapMessageRoot(blob: ByteArray): ByteArray? {
        if (!keyStore.containsAlias(ALIAS_MSG)) {
            return null
        }
        return try {
            keystoreOpen(ALIAS_MSG, blob)
        } catch (e: Exception) {
            null
        }
    }

    /** Instantly makes every stored message unreadable. Works while the app is locked. */
    fun destroyMessageKey() {
        runCatching { keyStore.deleteEntry(ALIAS_MSG) }
    }

    /** Destroys every key: everything encrypted becomes unrecoverable. */
    fun destroyAll() {
        for (alias in listOf(ALIAS_DEVICE, ALIAS_MSG, ALIAS_BIO)) {
            runCatching { keyStore.deleteEntry(alias) }
        }
        prefs.edit().clear().commit()
    }

    // --- internals ---

    private fun writeWrapped(mk: ByteArray, passphrase: CharArray?) {
        val edit = prefs.edit()
        if (passphrase == null || passphrase.isEmpty()) {
            edit.putString(P_WRAPPED, B64.enc(keystoreSeal(ALIAS_DEVICE, mk)))
                .putBoolean(P_HAS_PASS, false)
                .remove(P_SALT)
        } else {
            val salt = Rand.bytes(16)
            val kek = argon2(passphrase, salt)
            val inner = Aead.seal(kek, mk, AAD_MK)
            edit.putString(P_WRAPPED, B64.enc(keystoreSeal(ALIAS_DEVICE, inner)))
                .putBoolean(P_HAS_PASS, true)
                .putString(P_SALT, B64.enc(salt))
            kek.wipe()
            inner.wipe()
        }
        edit.commit()
    }

    private fun keystoreSeal(alias: String, plaintext: ByteArray): ByteArray {
        val c = Cipher.getInstance(TRANSFORM)
        c.init(Cipher.ENCRYPT_MODE, secretKey(alias))
        return c.iv + c.doFinal(plaintext)
    }

    private fun keystoreOpen(alias: String, blob: ByteArray): ByteArray {
        val c = Cipher.getInstance(TRANSFORM)
        c.init(Cipher.DECRYPT_MODE, secretKey(alias), GCMParameterSpec(128, blob, 0, 12))
        return c.doFinal(blob, 12, blob.size - 12)
    }

    private fun secretKey(alias: String): SecretKey = keyStore.getKey(alias, null) as SecretKey

    private fun createKey(alias: String, preferStrongBox: Boolean, biometric: Boolean) {
        runCatching { keyStore.deleteEntry(alias) }
        val strongBoxAvailable = context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        fun spec(strongBox: Boolean): KeyGenParameterSpec {
            val b = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
            if (biometric) {
                b.setUserAuthenticationRequired(true)
                    .setInvalidatedByBiometricEnrollment(true)
                if (android.os.Build.VERSION.SDK_INT >= 30) {
                    b.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                } else {
                    @Suppress("DEPRECATION")
                    b.setUserAuthenticationValidityDurationSeconds(-1)
                }
            } else {
                b.setUnlockedDeviceRequired(true)
            }
            if (strongBox) {
                b.setIsStrongBoxBacked(true)
            }
            return b.build()
        }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        if (preferStrongBox && strongBoxAvailable) {
            try {
                gen.init(spec(true))
                gen.generateKey()
                prefs.edit().putBoolean(P_STRONGBOX, true).apply()
                return
            } catch (e: StrongBoxUnavailableException) {
                // fall through to TEE
            } catch (e: Exception) {
                // Some StrongBox implementations reject unlocked-device-required; fall back to TEE.
            }
        }
        gen.init(spec(false))
        gen.generateKey()
        if (preferStrongBox) {
            prefs.edit().putBoolean(P_STRONGBOX, false).apply()
        }
    }

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val TRANSFORM = "AES/GCM/NoPadding"
        private const val ALIAS_DEVICE = "gf_device"
        private const val ALIAS_MSG = "gf_msg"
        private const val ALIAS_BIO = "gf_bio"
        private const val P_WRAPPED = "wrapped_mk"
        private const val P_HAS_PASS = "has_pass"
        private const val P_SALT = "salt"
        private const val P_BIO = "bio_mk"
        private const val P_DURESS = "duress"
        private const val P_DURESS_SALT = "duress_salt"
        private const val P_STRONGBOX = "strongbox"
        private val AAD_MK = "gf/mk/v1".toByteArray()

        /** Argon2id, m = 64 MiB, t = 3, p = 1. */
        fun argon2(passphrase: CharArray, salt: ByteArray): ByteArray {
            val params = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withMemoryAsKB(64 * 1024)
                .withIterations(3)
                .withParallelism(1)
                .withSalt(salt)
                .build()
            val gen = Argon2BytesGenerator()
            gen.init(params)
            val out = ByteArray(32)
            gen.generateBytes(passphrase, out)
            return out
        }
    }
}
