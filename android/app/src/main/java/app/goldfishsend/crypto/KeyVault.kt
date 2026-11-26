package app.goldfishsend.crypto

import android.content.Context
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import app.goldfishsend.core.DuressAction
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
 * Key hierarchy (android/README.md, "Security notes"):
 *
 *   [optional passphrase] --HMAC with Keystore "gf_pin"--> --Argon2id--> KEK --AES-GCM--> inner(MK)
 *   Android Keystore "gf_device" (StrongBox if present, unlocked-device-required) --AES-GCM--> outer(inner or MK)
 *
 * The "gf_pin" HMAC ([secretKek]) means every guess at the secret needs this phone's Keystore, even for someone who got
 * one decryption of the outer wrap. MK (master key, 32 bytes) only lives in RAM while the app is unlocked. The DB key
 * and other keys are derived from it.
 * A second Keystore key ("gf_msg_<random>", a new one for every root) wraps the message root key, so wiping on reboot
 * only needs that alias deleted.
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

    /** The current device-key alias. It changes on every master-key rotation (the old alias is deleted). */
    private val deviceAlias: String
        get() = prefs.getString(P_DEVICE_ALIAS, null) ?: ALIAS_DEVICE

    /** Creates a fresh MK. Returns it, and the caller must wipe it when locking. */
    fun setup(passphrase: CharArray?): ByteArray {
        destroyAll()
        val mk = Rand.bytes(32)
        createKey(deviceAlias, preferStrongBox = true, biometric = false)
        writeWrapped(mk, passphrase)
        ensureDecoySlots()
        return mk
    }

    fun unlockWithoutPassphrase(): ByteArray? {
        if (!isSetUp || requiresUserUnlock) {
            return null
        }
        return try {
            keystoreOpen(deviceAlias, B64.dec(prefs.getString(P_WRAPPED, null)!!))
        } catch (e: Exception) {
            null
        }
    }

    /** Returns MK, or null for a wrong passphrase. Throws if the device key is unavailable (device locked). */
    fun unlockWithPassphrase(passphrase: CharArray): ByteArray? {
        val inner = keystoreOpen(deviceAlias, B64.dec(prefs.getString(P_WRAPPED, null)!!))
        val salt = B64.dec(prefs.getString(P_SALT, null)!!)
        val kek = secretKek(passphrase, salt)
        return try {
            Aead.open(kek, inner, AAD_MK)
        } catch (e: AEADBadTagException) {
            null
        } finally {
            kek.wipe()
            inner.wipe()
        }
    }

    /**
     * The key-encryption key for the app secret (and the duress PIN): `argon2(HMAC_gf_pin(secret), salt)`. "gf_pin" is a
     * non-exportable Keystore HMAC key (StrongBox if present, unlocked-device-required), so the secret never reaches
     * Argon2 as typed. Without it, one decryption of the device wrap (malware or a forensic tool with code execution on
     * an unlocked phone, or an extracted device key) would hand over a blob whose PIN could be cracked anywhere, at any
     * speed, with no erase counter in the way. With it, every single guess needs this phone's Keystore again.
     * Throws if the key is unavailable (the phone is locked).
     */
    fun secretKek(secret: CharArray, salt: ByteArray): ByteArray {
        val bytes = utf8(secret)
        val pre = try {
            val mac = javax.crypto.Mac.getInstance("HmacSHA256")
            mac.init(keyStore.getKey(ALIAS_PIN, null) as SecretKey)
            mac.doFinal(bytes)
        } finally {
            bytes.wipe()
        }
        try {
            return argon2(pre, salt)
        } finally {
            pre.wipe()
        }
    }

    private fun ensurePinKey() {
        if (keyStore.containsAlias(ALIAS_PIN)) {
            return
        }
        val strongBox = context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        fun spec(sb: Boolean) = KeyGenParameterSpec.Builder(ALIAS_PIN, KeyProperties.PURPOSE_SIGN)
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUnlockedDeviceRequired(true)
            .apply { if (sb) setIsStrongBoxBacked(true) }
            .build()
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, ANDROID_KEYSTORE)
        if (strongBox) {
            try {
                gen.init(spec(true))
                gen.generateKey()
                return
            } catch (e: Exception) {
                // Fall back to the TEE, as for the device key.
            }
        }
        gen.init(spec(false))
        gen.generateKey()
    }

    // --- duress PIN and hidden-chats PIN ---
    //
    // Both slots always hold data of the same shape, sealed under a Keystore key. When a feature is off, the slot holds
    // filler that no PIN opens, so the files on disk don't reveal whether a duress PIN or hidden chats exist. Whether a
    // duress PIN is on is recorded only inside the encrypted database (Repo kv "duress_on"), and what it does is sealed
    // under the device key ([duressAction]). Whether hidden chats exist isn't recorded anywhere: not even the open real
    // profile can tell without their PIN (core/HiddenChats).

    /**
     * What a matching duress PIN opened: the decoy profile's database key, and [salt] and [secretTag]
     * (`HMAC(secretKek(pin, salt), label)`, see [decoySecretTag]), which let the decoy session recognise the duress PIN again
     * as its own app secret without asking the real vault. The caller wipes it.
     */
    class DuressMatch(val decoyKey: ByteArray, val salt: ByteArray, val secretTag: ByteArray) {
        fun wipe() {
            decoyKey.wipe()
            secretTag.wipe()
        }
    }

    /**
     * The duress slot holds `deviceKey(AEAD(secretKek(pin, salt), MARKER ‖ decoyKey))`. MARKER is a fixed constant and
     * decoyKey is random, made when the duress PIN is set: neither has anything to do with the master key, so nothing
     * reachable from the duress PIN can unwrap MK, the message root, the inbox key or any other real-data key. Because
     * the decoy profile's key lives inside the device-key wrap, the decoy database can't be attacked off the phone
     * either: every guess needs the Keystore, as for the real secret. Returns null for any other PIN (always after the
     * same single Argon2 run). Throws only if the device key is unavailable.
     */
    fun openDuress(pin: CharArray): DuressMatch? {
        val blob = prefs.getString(P_DURESS, null)?.let { B64.dec(it) }
        val salt = prefs.getString(P_DURESS_SALT, null)?.let { B64.dec(it) } ?: Rand.bytes(16)
        val kek = secretKek(pin, salt)
        if (blob == null) {
            kek.wipe()
            return null
        }
        return try {
            val inner = keystoreOpen(deviceAlias, blob)
            try {
                val pt = Aead.open(kek, inner, AAD_DURESS)
                try {
                    if (pt.size != DURESS_PAYLOAD || !MessageDigest.isEqual(pt.copyOfRange(0, 32), DURESS_MARKER)) {
                        null
                    } else {
                        DuressMatch(pt.copyOfRange(32, 64), salt.copyOf(), decoySecretTag(kek))
                    }
                } finally {
                    pt.wipe()
                }
            } finally {
                inner.wipe()
            }
        } catch (e: AEADBadTagException) {
            null
        } catch (e: IllegalArgumentException) {
            null
        } finally {
            kek.wipe()
        }
    }

    /** Convenience for checks that only need a yes or no. */
    fun isDuress(pin: CharArray): Boolean = runCatching { openDuress(pin) }.getOrNull()?.also { it.wipe() } != null

    /**
     * Sets the duress PIN with a fresh decoy profile key, or (null) replaces it with an unopenable slot of the same
     * shape. Either way any existing decoy profile can no longer be opened, so its file is deleted too: a stale decoy
     * would only tell someone that a duress PIN was once used.
     */
    fun setDuress(pin: CharArray?) {
        val salt = Rand.bytes(16)
        val inner = if (pin != null) {
            val kek = secretKek(pin, salt)
            val decoyKey = Rand.bytes(32)
            val payload = DURESS_MARKER + decoyKey
            Aead.seal(kek, payload, AAD_DURESS).also {
                kek.wipe()
                decoyKey.wipe()
                payload.wipe()
            }
        } else {
            Aead.seal(Rand.bytes(32), Rand.bytes(DURESS_PAYLOAD), AAD_DURESS)
        }
        sealDuressSlot(inner, salt)
        inner.wipe()
        app.goldfishsend.db.Db.deleteFiles(context, app.goldfishsend.db.Db.DECOY_NAME)
    }

    private fun sealDuressSlot(inner: ByteArray, salt: ByteArray) {
        val blob = if (keyStore.containsAlias(deviceAlias)) keystoreSeal(deviceAlias, inner) else Rand.bytes(inner.size + 28)
        prefs.edit().putString(P_DURESS, B64.enc(blob)).putString(P_DURESS_SALT, B64.enc(salt)).commit()
    }

    /** What the duress PIN does. Sealed under the device key, so a copy of the files doesn't say whether a decoy exists. */
    var duressAction: DuressAction
        get() = cachedAction ?: readDuressAction().also { cachedAction = it }
        set(v) {
            sealDuressAction(byteArrayOf(v.ordinal.toByte()) + Rand.bytes(15))
        }

    /** Settings read it on every redraw: one Keystore call per process (or per change) is enough. */
    @Volatile
    private var cachedAction: DuressAction? = null

    private fun readDuressAction(): DuressAction {
        val blob = prefs.getString(P_DURESS_ACTION, null)?.let { B64.dec(it) } ?: return DuressAction.WIPE_ALL
        val v = runCatching { keystoreOpen(deviceAlias, blob) }.getOrNull() ?: return DuressAction.WIPE_ALL
        val i = v.firstOrNull()?.toInt() ?: 0
        v.wipe()
        return DuressAction.entries.getOrElse(i) { DuressAction.WIPE_ALL }
    }

    private fun sealDuressAction(plain: ByteArray) {
        val blob = if (keyStore.containsAlias(deviceAlias)) keystoreSeal(deviceAlias, plain) else Rand.bytes(plain.size + 28)
        prefs.edit().putString(P_DURESS_ACTION, B64.enc(blob)).commit()
        cachedAction = null
        plain.wipe()
    }

    /**
     * The hidden-chats slot holds `hiddenKey(HiddenSlot(secretKek(pin, salt), secret))`: the PIN goes through the same
     * Keystore HMAC and Argon2 as the app secret, and the result is sealed under a Keystore key of its own ("gf_hidden",
     * unlocked-device-required). So a copy of the files can't be tested offline, and whether the slot is filler or real
     * can't be told. Its own key, not the device key: it must outlive changes of the unlock method, including to the
     * phone's screen lock, which has no device key. Returns the hidden-chats secret (the caller wipes it) or null, always
     * after the same single Argon2 run.
     */
    fun openHidden(pin: CharArray): ByteArray? {
        val blob = prefs.getString(P_HIDDEN, null)?.let { B64.dec(it) }
        val salt = prefs.getString(P_HIDDEN_SALT, null)?.let { B64.dec(it) } ?: Rand.bytes(16)
        val kek = runCatching { secretKek(pin, salt) }.getOrNull() ?: return null
        try {
            val inner = blob?.let { runCatching { keystoreOpen(ALIAS_HIDDEN, it) }.getOrNull() } ?: return null
            try {
                return HiddenSlot.open(kek, inner)
            } finally {
                inner.wipe()
            }
        } finally {
            kek.wipe()
        }
    }

    /** Seals [secret] under [pin], or (both null) replaces the slot with filler that no PIN opens. */
    fun setHidden(pin: CharArray?, secret: ByteArray?) {
        val salt = Rand.bytes(16)
        ensureHiddenKey()
        val inner = if (pin != null && secret != null) {
            ensurePinKey()
            val kek = secretKek(pin, salt)
            HiddenSlot.seal(kek, secret).also { kek.wipe() }
        } else {
            HiddenSlot.filler()
        }
        val blob = if (keyStore.containsAlias(ALIAS_HIDDEN)) keystoreSeal(ALIAS_HIDDEN, inner) else Rand.bytes(inner.size + 28)
        inner.wipe()
        prefs.edit().putString(P_HIDDEN, B64.enc(blob)).putString(P_HIDDEN_SALT, B64.enc(salt)).commit()
    }

    private fun ensureHiddenKey() {
        if (!keyStore.containsAlias(ALIAS_HIDDEN)) {
            createKey(ALIAS_HIDDEN, preferStrongBox = false, biometric = false)
        }
    }

    /** Fills the slots with decoy data, if they're empty (setup, upgrade). */
    fun ensureDecoySlots() {
        // The hidden-chats PIN can be set with any unlock method: its KDF key must exist even without an app secret.
        runCatching { ensurePinKey() }
        if (!prefs.contains(P_DURESS) || !prefs.contains(P_DURESS_SALT)) {
            setDuress(null)
        }
        if (!prefs.contains(P_DURESS_ACTION)) {
            duressAction = DuressAction.WIPE_ALL
        }
        if (!prefs.contains(P_HIDDEN) || !prefs.contains(P_HIDDEN_SALT) || !keyStore.containsAlias(ALIAS_HIDDEN)) {
            setHidden(null, null)
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
            setDuress(null)
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
        setDuress(null)
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

    // --- master-key rotation (unlock-method or secret changes) ---
    //
    // Changing how GoldfishSend is unlocked also changes *what* is protected: a brand-new MK, a rekeyed database and a
    // fresh device-key alias. The old wrapping (perhaps a weak PIN, or none at all) may survive in flash remnants of the
    // preference file, but it only ever opens the old MK, which no longer opens anything, under a Keystore alias that's
    // been deleted.
    //
    // Crash safety, in three steps (Graph.changeUnlock):
    //   1. stageRotation: the new MK is wrapped for the target method under a fresh alias (P_NEXT_*), and a link
    //      AEAD(oldMk → newMk) is written. The old wrapping still works.
    //   2. The database is rekeyed to the new MK (SQLCipher does this atomically).
    //   3. promoteRotation: NEXT becomes current, and the old alias, link and biometric copy are deleted.
    // If the app dies before 2, the old method still opens the old DB and the stage is discarded (Graph.openSession).
    // If it dies between 2 and 3, the old method opens the old MK, which fails on the DB, and the link recovers the new
    // MK to finish step 3.

    sealed class Target {
        data object None : Target()

        class Secret(val secret: CharArray, val isPin: Boolean) : Target()

        /** [cipher] is a screen-lock cipher (from [screenLockEncryptCipher]) already authenticated by the system prompt. */
        class ScreenLock(val cipher: Cipher) : Target()
    }

    val hasPendingRotation: Boolean
        get() = prefs.contains(P_NEXT_WRAPPED)

    fun stageRotation(oldMk: ByteArray, newMk: ByteArray, target: Target) {
        abortRotation()
        val edit = prefs.edit()
        when (target) {
            is Target.ScreenLock -> {
                edit.putString(P_NEXT_WRAPPED, B64.enc(target.cipher.iv + target.cipher.doFinal(newMk)))
                    .putString(P_NEXT_METHOD, NEXT_SCREENLOCK)
            }
            is Target.None, is Target.Secret -> {
                val alias = ALIAS_DEVICE + "_" + B64.enc(Rand.bytes(9)).replace('-', 'x').replace('_', 'y')
                createKey(alias, preferStrongBox = true, biometric = false)
                edit.putString(P_NEXT_ALIAS, alias)
                if (target is Target.Secret) {
                    val salt = Rand.bytes(16)
                    ensurePinKey()
                    val kek = secretKek(target.secret, salt)
                    val inner = Aead.seal(kek, newMk, AAD_MK)
                    edit.putString(P_NEXT_WRAPPED, B64.enc(keystoreSeal(alias, inner)))
                        .putString(P_NEXT_METHOD, if (target.isPin) NEXT_PIN else NEXT_PASSPHRASE)
                        .putString(P_NEXT_SALT, B64.enc(salt))
                    kek.wipe()
                    inner.wipe()
                } else {
                    edit.putString(P_NEXT_WRAPPED, B64.enc(keystoreSeal(alias, newMk)))
                        .putString(P_NEXT_METHOD, NEXT_NONE)
                }
            }
        }
        val link = linkKey(oldMk)
        edit.putString(P_ROTATE_LINK, B64.enc(Aead.seal(link, newMk, AAD_LINK)))
        link.wipe()
        edit.commit()
    }

    /** After a crash between the rekey and [promoteRotation]: recovers the new MK from the old one. */
    fun recoverRotation(oldMk: ByteArray): ByteArray? {
        val blob = prefs.getString(P_ROTATE_LINK, null)?.let { B64.dec(it) } ?: return null
        val link = linkKey(oldMk)
        return try {
            Aead.open(link, blob, AAD_LINK)
        } catch (e: Exception) {
            null
        } finally {
            link.wipe()
        }
    }

    /**
     * Makes the staged wrapping current. The duress verifier doesn't contain MK, but it's sealed under the device key,
     * so it moves to the new alias (or becomes a decoy slot when there's no app secret). The biometric shortcut wraps
     * the old MK, so it's switched off.
     */
    fun promoteRotation() {
        val method = prefs.getString(P_NEXT_METHOD, null) ?: return
        val wrapped = prefs.getString(P_NEXT_WRAPPED, null) ?: return
        val oldAlias = deviceAlias
        val newAlias = prefs.getString(P_NEXT_ALIAS, null)
        val duressInner = runCatching { keystoreOpen(oldAlias, B64.dec(prefs.getString(P_DURESS, null)!!)) }.getOrNull()
        val duressSalt = prefs.getString(P_DURESS_SALT, null)?.let { B64.dec(it) }
        val action = runCatching { keystoreOpen(oldAlias, B64.dec(prefs.getString(P_DURESS_ACTION, null)!!)) }.getOrNull()
        val edit = prefs.edit()
            .putString(P_WRAPPED, wrapped)
            .putBoolean(P_SCREENLOCK, method == NEXT_SCREENLOCK)
            .putBoolean(P_HAS_PASS, method == NEXT_PIN || method == NEXT_PASSPHRASE)
        when (method) {
            NEXT_PIN, NEXT_PASSPHRASE -> edit.putString(P_SECRET_KIND, if (method == NEXT_PIN) KIND_PIN else KIND_PASSPHRASE)
                .putString(P_SALT, prefs.getString(P_NEXT_SALT, null))
            else -> edit.remove(P_SECRET_KIND).remove(P_SALT)
        }
        if (newAlias != null) {
            edit.putString(P_DEVICE_ALIAS, newAlias)
        } else {
            // Screen lock: no device-key-wrapped copy of MK may remain.
            edit.remove(P_DEVICE_ALIAS)
        }
        edit.remove(P_NEXT_WRAPPED).remove(P_NEXT_METHOD).remove(P_NEXT_SALT).remove(P_NEXT_ALIAS).remove(P_ROTATE_LINK)
        edit.commit()
        if (oldAlias != newAlias) {
            runCatching { keyStore.deleteEntry(oldAlias) }
        }
        if (method != NEXT_SCREENLOCK) {
            runCatching { keyStore.deleteEntry(ALIAS_SYSLOCK) }
        }
        disableBiometric()
        if (duressInner != null && duressSalt != null && (method == NEXT_PIN || method == NEXT_PASSPHRASE)) {
            sealDuressSlot(duressInner, duressSalt)
        } else {
            setDuress(null)
        }
        duressInner?.wipe()
        sealDuressAction(action ?: (byteArrayOf(DuressAction.WIPE_ALL.ordinal.toByte()) + Rand.bytes(15)))
    }

    /** Discards a staged rotation (the rekey never happened). */
    fun abortRotation() {
        val alias = prefs.getString(P_NEXT_ALIAS, null)
        if (alias != null && alias != deviceAlias) {
            runCatching { keyStore.deleteEntry(alias) }
        }
        prefs.edit().remove(P_NEXT_WRAPPED).remove(P_NEXT_METHOD).remove(P_NEXT_SALT).remove(P_NEXT_ALIAS).remove(P_ROTATE_LINK).commit()
    }

    private fun linkKey(mk: ByteArray): ByteArray = app.goldfishsend.proto.Hash.hmacSha256(mk, "gf/rotate-link/v1".toByteArray())

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

    /** A message root key wrapped by the Keystore key [alias]. Both are stored in the database. */
    class WrappedRoot(val alias: String, val blob: ByteArray)

    /**
     * Wraps [mrk] under a brand-new Keystore key, each root under its own. The keys of earlier roots stay until
     * [keepOnlyMessageKey], so a rotation that doesn't commit loses nothing.
     */
    fun wrapMessageRoot(mrk: ByteArray): WrappedRoot {
        val alias = ALIAS_MSG + "_" + Rand.bytes(8).joinToString("") { "%02x".format(it) }
        createKey(alias, preferStrongBox = false, biometric = false)
        try {
            return WrappedRoot(alias, keystoreSeal(alias, mrk))
        } catch (e: Exception) {
            deleteMessageKey(alias)
            throw e
        }
    }

    /** Null if the message key was destroyed (reboot/panic wipe) or the blob is invalid. [alias] null: the original key. */
    fun unwrapMessageRoot(blob: ByteArray, alias: String?): ByteArray? {
        val a = alias ?: ALIAS_MSG
        if (!isMessageAlias(a) || !keyStore.containsAlias(a)) {
            return null
        }
        return try {
            keystoreOpen(a, blob)
        } catch (e: Exception) {
            null
        }
    }

    /** Deletes one message-root key: a rotation that failed, so its root was never stored. */
    fun deleteMessageKey(alias: String) {
        if (isMessageAlias(alias)) {
            runCatching { keyStore.deleteEntry(alias) }
        }
    }

    /**
     * Deletes every message-root key but [alias] (null: the original key): once a rotation has committed, the old
     * root's wrapper goes, and with it the only way to open stale copies of what was wrapped under it.
     */
    fun keepOnlyMessageKey(alias: String?) {
        val keep = alias ?: ALIAS_MSG
        for (a in messageAliases()) {
            if (a != keep) {
                runCatching { keyStore.deleteEntry(a) }
            }
        }
    }

    /** Instantly makes every stored message unreadable. Works while the app is locked. */
    fun destroyMessageKey() {
        for (a in messageAliases()) {
            runCatching { keyStore.deleteEntry(a) }
        }
    }

    private fun isMessageAlias(a: String) = a == ALIAS_MSG || a.startsWith(ALIAS_MSG + "_")

    private fun messageAliases(): List<String> =
        runCatching { keyStore.aliases().toList().filter(::isMessageAlias) }.getOrDefault(listOf(ALIAS_MSG))

    /** Destroys every key: everything encrypted becomes unrecoverable. */
    fun destroyAll() {
        val extra = listOfNotNull(prefs.getString(P_DEVICE_ALIAS, null), prefs.getString(P_NEXT_ALIAS, null))
        for (alias in listOf(ALIAS_DEVICE, ALIAS_BIO, ALIAS_SYSLOCK, ALIAS_PIN, ALIAS_HIDDEN) + extra) {
            runCatching { keyStore.deleteEntry(alias) }
        }
        destroyMessageKey()
        // Rotated device aliases from interrupted rotations.
        runCatching {
            for (alias in keyStore.aliases().toList().filter { it.startsWith("${ALIAS_DEVICE}_") }) {
                keyStore.deleteEntry(alias)
            }
        }
        prefs.edit().clear().commit()
        cachedAction = null
    }

    // --- internals ---

    private fun writeWrapped(mk: ByteArray, passphrase: CharArray?, isPin: Boolean = false) {
        if (!keyStore.containsAlias(deviceAlias)) {
            createKey(deviceAlias, preferStrongBox = true, biometric = false)
        }
        val edit = prefs.edit().putBoolean(P_SCREENLOCK, false)
        if (passphrase == null || passphrase.isEmpty()) {
            edit.putString(P_WRAPPED, B64.enc(keystoreSeal(deviceAlias, mk)))
                .putBoolean(P_HAS_PASS, false)
                .remove(P_SALT)
                .remove(P_SECRET_KIND)
        } else {
            edit.putString(P_SECRET_KIND, if (isPin) KIND_PIN else KIND_PASSPHRASE)
            val salt = Rand.bytes(16)
            ensurePinKey()
            val kek = secretKek(passphrase, salt)
            val inner = Aead.seal(kek, mk, AAD_MK)
            edit.putString(P_WRAPPED, B64.enc(keystoreSeal(deviceAlias, inner)))
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
        private const val ALIAS_PIN = "gf_pin"
        private const val ALIAS_HIDDEN = "gf_hidden"
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
        private val AAD_DURESS = "gf/duress/v3".toByteArray()
        private const val P_DURESS_ACTION = "duress_cfg"

        /** What the duress slot encrypts first. A constant: it proves the PIN, and unlocks nothing real. */
        private val DURESS_MARKER = "gf/duress-verifier/v3/0000000000".toByteArray().copyOf(32)

        /** MARKER ‖ decoy database key. */
        private const val DURESS_PAYLOAD = 64

        /** The decoy session's own check of the duress PIN: `HMAC(secretKek(pin, duressSalt), label)`. */
        fun decoySecretTag(kek: ByteArray): ByteArray = app.goldfishsend.proto.Hash.hmacSha256(kek, "gf/decoy-secret/v1".toByteArray())
        private const val P_STRONGBOX = "strongbox"
        private const val P_DEVICE_ALIAS = "device_alias"
        private const val P_NEXT_WRAPPED = "next_wrapped"
        private const val P_NEXT_METHOD = "next_method"
        private const val P_NEXT_SALT = "next_salt"
        private const val P_NEXT_ALIAS = "next_alias"
        private const val P_ROTATE_LINK = "rotate_link"
        private const val NEXT_NONE = "none"
        private const val NEXT_PIN = "pin"
        private const val NEXT_PASSPHRASE = "passphrase"
        private const val NEXT_SCREENLOCK = "screenlock"
        private val AAD_LINK = "gf/rotate-link/v1".toByteArray()
        private val AAD_MK = "gf/mk/v1".toByteArray()

        /** Argon2id, m = 64 MiB, t = 3, p = 1. */
        fun argon2(passphrase: CharArray, salt: ByteArray): ByteArray {
            val bytes = utf8(passphrase)
            try {
                return argon2(bytes, salt)
            } finally {
                bytes.wipe()
            }
        }

        fun argon2(input: ByteArray, salt: ByteArray): ByteArray {
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
            gen.generateBytes(input, out)
            return out
        }

        /** Encoded to UTF-8 by hand so the copy can be wiped (BouncyCastle's CharArray overload leaves one behind). */
        private fun utf8(chars: CharArray): ByteArray {
            val buf = java.nio.charset.StandardCharsets.UTF_8.encode(java.nio.CharBuffer.wrap(chars))
            val bytes = ByteArray(buf.remaining())
            buf.get(bytes)
            if (buf.hasArray()) {
                java.util.Arrays.fill(buf.array(), 0.toByte())
            }
            return bytes
        }
    }
}
