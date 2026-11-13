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
 *
 * Unlock methods ([UnlockMethod]):
 *  - NONE: MK is wrapped by "gf_device" only, and opens whenever the phone is unlocked.
 *  - APP_SECRET: an app PIN (typed on GoldfishSend's own keypad) or passphrase, stretched with Argon2id, wraps MK inside
 *    the device wrap. Supports duress PIN, fingerprint and erase-after-failed-attempts.
 *  - SCREEN_LOCK: MK is wrapped by "gf_syslock", a Keystore key that needs the phone's own credential (PIN, pattern,
 *    password or strong biometric) for every use. The OS handles the prompt, so the app never sees the secret. Removing
 *    the phone's screen lock invalidates the key, and the data becomes unrecoverable.
 */
enum class UnlockMethod { NONE, APP_SECRET, SCREEN_LOCK }

class KeyVault(private val context: Context) {
    private val prefs: SharedPreferences = context.getSharedPreferences("gf_vault", Context.MODE_PRIVATE)
    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    val isSetUp: Boolean
        get() = prefs.contains(P_WRAPPED)

    /** An app PIN or passphrase is set (UnlockMethod.APP_SECRET). */
    val hasPassphrase: Boolean
        get() = prefs.getBoolean(P_HAS_PASS, false)

    /** The app secret is a numeric PIN entered on the in-app keypad, not a passphrase typed with the keyboard. */
    val secretIsPin: Boolean
        get() = prefs.getString(P_SECRET_KIND, null) == KIND_PIN

    /** Screen-lock unlock needs per-use device-credential keys (Android 11+) and a secure lock screen. */
    fun screenLockSupported(): Boolean =
        android.os.Build.VERSION.SDK_INT >= 30 &&
            context.getSystemService(android.app.KeyguardManager::class.java).isDeviceSecure

    val hasScreenLock: Boolean
        get() = prefs.getBoolean(P_SCREENLOCK, false)

    /** Opening the app needs the user (app secret or phone screen lock), not just an unlocked phone. */
    val requiresUserUnlock: Boolean
        get() = hasPassphrase || hasScreenLock

    val unlockMethod: UnlockMethod
        get() = when {
            hasScreenLock -> UnlockMethod.SCREEN_LOCK
            hasPassphrase -> UnlockMethod.APP_SECRET
            else -> UnlockMethod.NONE
        }

    val hasBiometric: Boolean
        get() = prefs.contains(P_BIO) && keyStore.containsAlias(ALIAS_BIO)

    val usesStrongBox: Boolean
        get() = prefs.getBoolean(P_STRONGBOX, false)

    /** Creates a fresh MK. Returns it, and the caller must wipe it when locking. */
    fun setup(passphrase: CharArray?): ByteArray {
        destroyAll()
        val mk = Rand.bytes(32)
        createKey(ALIAS_DEVICE, preferStrongBox = true, biometric = false)
        writeWrapped(mk, passphrase)
        ensureDecoySlots()
        return mk
    }

    fun unlockWithoutPassphrase(): ByteArray? {
        if (!isSetUp || requiresUserUnlock) {
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

    // --- duress PIN and hidden-chats PIN ---
    //
    // Both slots always hold data of the same shape. When a feature is off, the slot contains random bytes that no PIN
    // opens, so the files on disk don't reveal whether a duress PIN or hidden chats exist. Whether they're on is
    // recorded only inside the encrypted database (see Repo kv "duress_on"/"hidden_on").

    /**
     * The duress PIN is a second wrapping of MK (Argon2id inside the device key), so it can really open the app,
     * either to erase it or to show a decoy view, depending on Prefs.duressAction.
     * Returns MK if [pin] is the duress PIN, otherwise null.
     */
    fun unlockWithDuress(pin: CharArray): ByteArray? {
        val blob = prefs.getString(P_DURESS, null)?.let { B64.dec(it) } ?: return null
        val salt = prefs.getString(P_DURESS_SALT, null)?.let { B64.dec(it) } ?: return null
        val kek = argon2(pin, salt)
        return try {
            val inner = keystoreOpen(ALIAS_DEVICE, blob)
            try {
                Aead.open(kek, inner, AAD_DURESS)
            } finally {
                inner.wipe()
            }
        } catch (e: Exception) {
            null
        } finally {
            kek.wipe()
        }
    }

    /** Sets the duress PIN (with the current MK), or replaces it with an unopenable decoy slot when [pin] is null. */
    fun setDuress(pin: CharArray?, mk: ByteArray?) {
        val salt = Rand.bytes(16)
        val inner = if (pin != null && mk != null) {
            val kek = argon2(pin, salt)
            Aead.seal(kek, mk, AAD_DURESS).also { kek.wipe() }
        } else {
            Aead.seal(Rand.bytes(32), Rand.bytes(32), AAD_DURESS)
        }
        val blob = if (keyStore.containsAlias(ALIAS_DEVICE)) keystoreSeal(ALIAS_DEVICE, inner) else Rand.bytes(inner.size + 28)
        inner.wipe()
        prefs.edit().putString(P_DURESS, B64.enc(blob)).putString(P_DURESS_SALT, B64.enc(salt)).commit()
    }

    /** Hidden-chats PIN: a plain Argon2id check (the app is already unlocked when it's entered). */
    fun isHiddenPin(pin: CharArray): Boolean {
        val stored = prefs.getString(P_HIDDEN, null)?.let { B64.dec(it) } ?: return false
        val salt = prefs.getString(P_HIDDEN_SALT, null)?.let { B64.dec(it) } ?: return false
        val h = argon2(pin, salt)
        val eq = MessageDigest.isEqual(h, stored)
        h.wipe()
        return eq
    }

    fun setHiddenPin(pin: CharArray?) {
        val salt = Rand.bytes(16)
        val h = if (pin != null) argon2(pin, salt) else Rand.bytes(32)
        prefs.edit().putString(P_HIDDEN, B64.enc(h)).putString(P_HIDDEN_SALT, B64.enc(salt)).commit()
        h.wipe()
    }

    /** Fills both slots with decoy data, if they're empty (setup, upgrade). */
    fun ensureDecoySlots() {
        if (!prefs.contains(P_DURESS) || !prefs.contains(P_DURESS_SALT)) {
            setDuress(null, null)
        }
        if (!prefs.contains(P_HIDDEN) || !prefs.contains(P_HIDDEN_SALT)) {
            setHiddenPin(null)
        }
    }

    /**
     * Sets, changes or removes (null) the app secret. This also switches away from SCREEN_LOCK. Biometric unlock and the
     * duress PIN are reset when the secret is removed.
     */
    fun changePassphrase(mk: ByteArray, newPassphrase: CharArray?, isPin: Boolean = false) {
        writeWrapped(mk, newPassphrase, isPin)
        if (newPassphrase == null) {
            disableBiometric()
            setDuress(null, null)
        }
    }

    // --- phone screen lock (system credential) ---

    /** For enabling SCREEN_LOCK. The cipher must be authenticated with a BiometricPrompt that allows DEVICE_CREDENTIAL. */
    fun screenLockEncryptCipher(): Cipher {
        createKey(ALIAS_SYSLOCK, preferStrongBox = false, biometric = false, screenLock = true)
        return Cipher.getInstance(TRANSFORM).apply { init(Cipher.ENCRYPT_MODE, secretKey(ALIAS_SYSLOCK)) }
    }

    /** Re-wraps MK so that only the phone's own credential opens it. Fingerprint shortcut and duress PIN no longer apply. */
    fun enableScreenLock(mk: ByteArray, authenticatedCipher: Cipher) {
        val blob = authenticatedCipher.iv + authenticatedCipher.doFinal(mk)
        prefs.edit()
            .putString(P_WRAPPED, B64.enc(blob))
            .putBoolean(P_SCREENLOCK, true)
            .putBoolean(P_HAS_PASS, false)
            .remove(P_SALT)
            .remove(P_SECRET_KIND)
            .commit()
        disableBiometric()
        setDuress(null, null)
    }

    /**
     * Returns null only when the key is permanently gone (the phone's screen lock was removed or reset), meaning the data
     * can never be opened again. Any other failure (a busy or temporarily unavailable Keystore) throws, so the caller can
     * retry instead of offering to erase everything.
     */
    fun screenLockDecryptCipher(): Cipher? {
        val blob = prefs.getString(P_WRAPPED, null)?.let { B64.dec(it) } ?: return null
        if (!keyStore.containsAlias(ALIAS_SYSLOCK)) {
            return null
        }
        return try {
            Cipher.getInstance(TRANSFORM).apply {
                init(Cipher.DECRYPT_MODE, secretKey(ALIAS_SYSLOCK), GCMParameterSpec(128, blob, 0, 12))
            }
        } catch (e: android.security.keystore.KeyPermanentlyInvalidatedException) {
            null
        }
    }

    fun unwrapWithScreenLock(authenticatedCipher: Cipher): ByteArray? {
        val blob = prefs.getString(P_WRAPPED, null)?.let { B64.dec(it) } ?: return null
        return try {
            authenticatedCipher.doFinal(blob, 12, blob.size - 12)
        } catch (e: Exception) {
            null
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
        for (alias in listOf(ALIAS_DEVICE, ALIAS_MSG, ALIAS_BIO, ALIAS_SYSLOCK)) {
            runCatching { keyStore.deleteEntry(alias) }
        }
        prefs.edit().clear().commit()
    }

    // --- internals ---

    private fun writeWrapped(mk: ByteArray, passphrase: CharArray?, isPin: Boolean = false) {
        if (!keyStore.containsAlias(ALIAS_DEVICE)) {
            createKey(ALIAS_DEVICE, preferStrongBox = true, biometric = false)
        }
        val edit = prefs.edit().putBoolean(P_SCREENLOCK, false)
        if (passphrase == null || passphrase.isEmpty()) {
            edit.putString(P_WRAPPED, B64.enc(keystoreSeal(ALIAS_DEVICE, mk)))
                .putBoolean(P_HAS_PASS, false)
                .remove(P_SALT)
                .remove(P_SECRET_KIND)
        } else {
            edit.putString(P_SECRET_KIND, if (isPin) KIND_PIN else KIND_PASSPHRASE)
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
        runCatching { keyStore.deleteEntry(ALIAS_SYSLOCK) }
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

    private fun createKey(alias: String, preferStrongBox: Boolean, biometric: Boolean, screenLock: Boolean = false) {
        runCatching { keyStore.deleteEntry(alias) }
        val strongBoxAvailable = context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        fun spec(strongBox: Boolean): KeyGenParameterSpec {
            val b = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
            if (screenLock) {
                // Every use needs the phone's PIN, pattern, password or a strong biometric. New fingerprints don't invalidate it,
                // but removing the screen lock does.
                if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.R) {
                    throw UnsupportedOperationException("Screen-lock unlock needs Android 11 or newer")
                }
                b.setUserAuthenticationRequired(true)
                    .setInvalidatedByBiometricEnrollment(false)
                    .setUserAuthenticationParameters(0, KeyProperties.AUTH_DEVICE_CREDENTIAL or KeyProperties.AUTH_BIOMETRIC_STRONG)
            } else if (biometric) {
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
        private const val ALIAS_SYSLOCK = "gf_syslock"
        private const val P_SCREENLOCK = "screenlock"
        private const val P_SECRET_KIND = "secret_kind"
        private const val KIND_PIN = "pin"
        private const val KIND_PASSPHRASE = "passphrase"
        private const val P_WRAPPED = "wrapped_mk"
        private const val P_HAS_PASS = "has_pass"
        private const val P_SALT = "salt"
        private const val P_BIO = "bio_mk"
        private const val P_DURESS = "duress"
        private const val P_DURESS_SALT = "duress_salt"
        private const val P_HIDDEN = "hidden_pin"
        private const val P_HIDDEN_SALT = "hidden_salt"
        private val AAD_DURESS = "gf/duress/v1".toByteArray()
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
