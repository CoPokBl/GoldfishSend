package app.goldfishsend.crypto

import app.goldfishsend.proto.Aead
import app.goldfishsend.proto.Hash
import app.goldfishsend.proto.Rand
import app.goldfishsend.proto.utf8
import app.goldfishsend.proto.wipe
import java.nio.ByteBuffer
import java.security.MessageDigest
import javax.crypto.AEADBadTagException
import org.signal.libsignal.protocol.ecc.ECKeyPair
import org.signal.libsignal.protocol.ecc.ECPrivateKey
import org.signal.libsignal.protocol.ecc.ECPublicKey

/**
 * The hidden-chats PIN's slot: `AEAD(secretKek(pin, salt), MARKER ‖ secret)`. The real profile seals it once more under
 * a Keystore key ([KeyVault.openHidden]); a decoy keeps it in its own database. With the feature off, the slot holds
 * [filler] of the same size, which no PIN opens. The secret is random, made when the PIN is set, and is the only way to
 * the hidden chats ([HiddenKey]).
 */
object HiddenSlot {
    const val SECRET = 32
    private val MARKER = "gf/hidden-verifier/v1/0000000000".utf8().copyOf(32)
    private val AAD = "gf/hidden/v1".utf8()

    fun seal(kek: ByteArray, secret: ByteArray): ByteArray {
        require(secret.size == SECRET)
        val payload = MARKER + secret
        try {
            return Aead.seal(kek, payload, AAD)
        } finally {
            payload.wipe()
        }
    }

    /** Same size and shape as a sealed slot, under a key nobody has. */
    fun filler(): ByteArray = Aead.seal(Rand.bytes(32), Rand.bytes(MARKER.size + SECRET), AAD)

    /** The secret, or null if [kek] (the PIN) doesn't open the slot. The caller wipes it. */
    fun open(kek: ByteArray, slot: ByteArray): ByteArray? {
        val pt = try {
            Aead.open(kek, slot, AAD)
        } catch (e: AEADBadTagException) {
            return null
        } catch (e: IllegalArgumentException) {
            return null
        }
        try {
            if (pt.size != MARKER.size + SECRET || !MessageDigest.isEqual(pt.copyOfRange(0, MARKER.size), MARKER)) {
                return null
            }
            return pt.copyOfRange(MARKER.size, pt.size)
        } finally {
            pt.wipe()
        }
    }
}

/**
 * What the hidden-chats secret opens: the private key the hidden chats are sealed to ([HiddenBoxes]). Its public key is
 * kept in the profile's database, so the app can seal to it without the PIN (when a message arrives for a hidden chat,
 * or to put hidden chats away again after a crash), but only the PIN gets the private key back.
 */
class HiddenKey(secret: ByteArray) {
    /** A copy: re-sealing the slot under a new PIN needs it. */
    val secret: ByteArray = secret.copyOf()

    val privateKey: ECPrivateKey = derive(secret)

    val publicKey: ECPublicKey
        get() = privateKey.publicKey()

    fun wipe() {
        secret.wipe()
    }

    companion object {
        fun derive(secret: ByteArray): ECPrivateKey {
            val raw = Hash.hmacSha256(secret, "gf/hidden/store-key/v1".utf8())
            try {
                return ECPrivateKey(raw)
            } finally {
                raw.wipe()
            }
        }

        fun newSecret(): ByteArray = Rand.bytes(HiddenSlot.SECRET)

        /** A public key whose private key is thrown away: what the store is sealed to while the feature is off. */
        fun fillerPublicKey(): ECPublicKey = ECKeyPair.generate().publicKey
    }
}

/**
 * The sealed forms the hidden chats take in the profile's database (docs/threat-model.md, "Hidden chats"). Both are HPKE
 * (through libsignal) to [HiddenKey.publicKey], padded so their size says little:
 *  - the snapshot (every hidden chat, see app.goldfishsend.db.HiddenTransfer), padded to a power of two of at least
 *    [SNAPSHOT_MIN];
 *  - a parked push: one that arrived for a mailbox the open profile doesn't know, which may be a hidden chat's. It's
 *    padded to one fixed size, and also sealed under the hidden message root, so erasing messages destroys it as it does
 *    every other message.
 */
object HiddenBoxes {
    private const val INFO = "gf/hidden/v1"
    private val AAD_SNAPSHOT = "gf/hidden/snapshot".utf8()
    private val AAD_PUSH = "gf/hidden/push".utf8()
    const val SNAPSHOT_MIN = 16 * 1024

    /** A push (a Web Push payload is at most 4096 bytes) with its tag and lengths. */
    const val PUSH_PLAIN = 4096 + 64

    fun paddedSize(len: Int): Int {
        var n = SNAPSHOT_MIN
        while (n < len + 4) {
            n *= 2
        }
        return n
    }

    private fun pad(data: ByteArray, size: Int): ByteArray =
        ByteBuffer.allocate(size).putInt(data.size).put(data).array()

    private fun unpad(padded: ByteArray): ByteArray? {
        if (padded.size < 4) {
            return null
        }
        val len = ByteBuffer.wrap(padded).int
        if (len < 0 || len > padded.size - 4) {
            return null
        }
        return padded.copyOfRange(4, 4 + len)
    }

    fun sealSnapshot(to: ECPublicKey, data: ByteArray): ByteArray {
        val padded = pad(data, paddedSize(data.size))
        try {
            return to.seal(padded, INFO, AAD_SNAPSHOT)
        } finally {
            padded.wipe()
        }
    }

    /** Null if it isn't sealed to [key] (filler, or a slot from before the PIN was set). */
    fun openSnapshot(key: ECPrivateKey, blob: ByteArray): ByteArray? {
        val padded = runCatching { key.open(blob, INFO, AAD_SNAPSHOT) }.getOrNull() ?: return null
        try {
            return unpad(padded)
        } finally {
            padded.wipe()
        }
    }

    /** A snapshot nobody can open, the same size as [like] (or the smallest size). */
    fun fillerSnapshot(like: ByteArray? = null): ByteArray {
        val overhead = fillerOverhead
        val size = like?.let { maxOf(SNAPSHOT_MIN, it.size - overhead) } ?: SNAPSHOT_MIN
        return HiddenKey.fillerPublicKey().seal(ByteArray(size), INFO, AAD_SNAPSHOT)
    }

    /** What HPKE adds to a payload: the same for every key and size. */
    private val fillerOverhead: Int by lazy { HiddenKey.fillerPublicKey().seal(ByteArray(0), INFO, AAD_SNAPSHOT).size }

    /** Null if [raw] is too big to park (no Web Push payload is). */
    fun sealPush(to: ECPublicKey, root: ByteArray, tag: ByteArray, raw: ByteArray): ByteArray? {
        if (tag.size > 255 || 1 + tag.size + 4 + raw.size > PUSH_PLAIN) {
            return null
        }
        val plain = ByteBuffer.allocate(PUSH_PLAIN).put(tag.size.toByte()).put(tag).putInt(raw.size).put(raw).array()
        val inner = Aead.seal(root, plain, AAD_PUSH)
        plain.wipe()
        try {
            return to.seal(inner, INFO, AAD_PUSH)
        } finally {
            inner.wipe()
        }
    }

    /** (tag, raw), or null if it isn't ours or its root was destroyed (messages were erased since). */
    fun openPush(key: ECPrivateKey, root: ByteArray, blob: ByteArray): Pair<ByteArray, ByteArray>? {
        val inner = runCatching { key.open(blob, INFO, AAD_PUSH) }.getOrNull() ?: return null
        val plain = runCatching { Aead.open(root, inner, AAD_PUSH) }.getOrNull() ?: return null
        inner.wipe()
        try {
            val b = ByteBuffer.wrap(plain)
            val tag = ByteArray(b.get().toInt() and 0xff).also { b.get(it) }
            val len = b.int
            if (len < 0 || len > b.remaining()) {
                return null
            }
            return tag to ByteArray(len).also { b.get(it) }
        } catch (e: RuntimeException) {
            return null
        } finally {
            plain.wipe()
        }
    }
}
