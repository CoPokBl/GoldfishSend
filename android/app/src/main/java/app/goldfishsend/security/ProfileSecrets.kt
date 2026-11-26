package app.goldfishsend.security

import app.goldfishsend.core.DuressAction
import app.goldfishsend.core.Graph
import app.goldfishsend.core.KvStore
import app.goldfishsend.crypto.HiddenSlot
import app.goldfishsend.crypto.KeyVault
import app.goldfishsend.proto.Rand
import app.goldfishsend.proto.wipe
import java.security.MessageDigest

/**
 * The checks and settings behind a profile's PINs: its app secret, duress PIN, hidden-chats PIN and what the duress PIN
 * does. The real profile uses the vault. A decoy profile has its own ([DecoySecrets]), so nothing done in a decoy session
 * tests a guess against a real secret or changes a real slot, and each check costs the same Argon2 run either way.
 */
interface ProfileSecrets {
    /** Is [secret] the app secret this profile was opened with? Throws if the phone's secure storage is unavailable. */
    fun checkSecret(secret: CharArray): Boolean

    fun isDuress(pin: CharArray): Boolean

    fun setDuress(pin: CharArray?)

    /**
     * The hidden-chats secret [pin] opens (core/HiddenChats), or null. Always one KDF run, whether a hidden-chats PIN is
     * set or not. The caller wipes it.
     */
    fun openHidden(pin: CharArray): ByteArray?

    /** Seals the hidden-chats [secret] under [pin], or (both null) replaces the slot with filler that no PIN opens. */
    fun setHidden(pin: CharArray?, secret: ByteArray?)

    var duressAction: DuressAction
}

/** Convenience for checks that only need a yes or no (a new PIN mustn't be the hidden-chats PIN). */
fun ProfileSecrets.isHiddenPin(pin: CharArray): Boolean = openHidden(pin)?.also { it.wipe() } != null

/** The real profile: everything lives in the vault. */
object VaultSecrets : ProfileSecrets {
    private val vault: KeyVault
        get() = Graph.vault

    override fun checkSecret(secret: CharArray): Boolean = vault.unlockWithPassphrase(secret)?.also { it.wipe() } != null

    override fun isDuress(pin: CharArray): Boolean = vault.isDuress(pin)

    override fun setDuress(pin: CharArray?) = vault.setDuress(pin)

    override fun openHidden(pin: CharArray): ByteArray? = vault.openHidden(pin)

    override fun setHidden(pin: CharArray?, secret: ByteArray?) = vault.setHidden(pin, secret)

    override var duressAction: DuressAction
        get() = vault.duressAction
        set(v) {
            vault.duressAction = v
        }
}

/**
 * A decoy profile's own secrets, in its encrypted database. Its app secret is the duress PIN that opened it, recognised
 * by the tag [KeyVault.openDuress] produced ([secretKdf] is the same derivation, [KeyVault.secretKek]: nothing is
 * checked against a real slot). Its duress and hidden-chats PINs are its own: setting them in the decoy works there and
 * nowhere else. Every slot always exists (random filler when off), so a check costs one Argon2 run whatever is set, just
 * like the real vault.
 */
class DecoySecrets(
    private val kv: KvStore,
    private val argon2: (CharArray, ByteArray) -> ByteArray = KeyVault::argon2,
    private val secretKdf: (CharArray, ByteArray) -> ByteArray = argon2,
) : ProfileSecrets {
    /** Records how to recognise the PIN that opened this decoy (salt ‖ tag). Called on every duress unlock. */
    fun rememberSecret(salt: ByteArray, tag: ByteArray) {
        kv.put(K_SECRET, salt + tag)
    }

    override fun checkSecret(secret: CharArray): Boolean {
        val (salt, tag) = slot(K_SECRET)
        val k = secretKdf(secret, salt)
        val t = KeyVault.decoySecretTag(k)
        k.wipe()
        return MessageDigest.isEqual(t, tag).also { t.wipe() }
    }

    override fun isDuress(pin: CharArray): Boolean = matches(K_DURESS, pin)

    override fun setDuress(pin: CharArray?) = set(K_DURESS, pin)

    /**
     * The decoy's hidden-chats slot: salt ‖ [HiddenSlot], under the same KDF as its app secret ([secretKdf], the real
     * vault's Keystore HMAC and Argon2), so a copy of the decoy database can't be tested offline either.
     */
    override fun openHidden(pin: CharArray): ByteArray? {
        val v = kv.get(K_HIDDEN)?.takeIf { it.size == HIDDEN_SLOT } ?: fillHidden()
        val kek = secretKdf(pin, v.copyOfRange(0, 16))
        try {
            return HiddenSlot.open(kek, v.copyOfRange(16, v.size))
        } finally {
            kek.wipe()
        }
    }

    override fun setHidden(pin: CharArray?, secret: ByteArray?) {
        if (pin == null || secret == null) {
            fillHidden()
            return
        }
        val salt = Rand.bytes(16)
        val kek = secretKdf(pin, salt)
        kv.put(K_HIDDEN, salt + HiddenSlot.seal(kek, secret))
        kek.wipe()
    }

    private fun fillHidden(): ByteArray = (Rand.bytes(16) + HiddenSlot.filler()).also { kv.put(K_HIDDEN, it) }

    override var duressAction: DuressAction
        get() = kv.get(K_ACTION)?.firstOrNull()?.toInt()?.let { DuressAction.entries.getOrNull(it) } ?: DuressAction.WIPE_ALL
        set(v) {
            kv.put(K_ACTION, byteArrayOf(v.ordinal.toByte()))
        }

    private fun matches(k: String, pin: CharArray): Boolean {
        val (salt, stored) = slot(k)
        val h = argon2(pin, salt)
        return MessageDigest.isEqual(h, stored).also { h.wipe() }
    }

    private fun set(k: String, pin: CharArray?) {
        val salt = Rand.bytes(16)
        val h = if (pin != null) argon2(pin, salt) else Rand.bytes(32)
        kv.put(k, salt + h)
        h.wipe()
    }

    /** salt ‖ value, created as unopenable filler the first time it's needed. */
    private fun slot(k: String): Pair<ByteArray, ByteArray> {
        val v = kv.get(k)?.takeIf { it.size == 48 } ?: (Rand.bytes(16) + Rand.bytes(32)).also { kv.put(k, it) }
        return v.copyOfRange(0, 16) to v.copyOfRange(16, 48)
    }

    private companion object {
        const val K_SECRET = "decoy_secret"
        const val K_DURESS = "decoy_duress"
        const val K_HIDDEN = "decoy_hidden"
        const val K_ACTION = "decoy_duress_action"

        /** salt ‖ nonce ‖ (marker ‖ secret) ‖ tag. */
        const val HIDDEN_SLOT = 16 + 12 + 64 + 16
    }
}
