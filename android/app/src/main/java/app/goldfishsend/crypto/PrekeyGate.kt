package app.goldfishsend.crypto

import app.goldfishsend.group.ScratchStore
import org.signal.libsignal.protocol.InvalidKeyIdException
import org.signal.libsignal.protocol.SessionCipher
import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.message.PreKeySignalMessage
import org.signal.libsignal.protocol.state.KyberPreKeyRecord
import org.signal.libsignal.protocol.state.PreKeyRecord
import org.signal.libsignal.protocol.state.SignalProtocolStore
import org.signal.libsignal.protocol.state.SignedPreKeyRecord

/**
 * A view of [base] that lends libsignal only the signed and Kyber prekeys in [signed] and [kyber]: the ones a 1:1 chat's
 * own invite advertised. Every prekey lives in one store, so without this a PreKey message on one chat's mailbox could
 * start a session from another invite's prekeys, or from a group card's last-resort ones (which anyone in the group
 * has), and take the chat over. A message that names any other prekey fails as if the prekey didn't exist.
 */
class BoundPrekeys(private val base: SignalProtocolStore, private val signed: Set<Int>, private val kyber: Set<Int>) :
    SignalProtocolStore by base {
    override fun loadSignedPreKey(signedPreKeyId: Int): SignedPreKeyRecord {
        if (signedPreKeyId !in signed) {
            throw InvalidKeyIdException("not this chat's prekey")
        }
        return base.loadSignedPreKey(signedPreKeyId)
    }

    override fun loadSignedPreKeys(): List<SignedPreKeyRecord> = base.loadSignedPreKeys().filter { it.id in signed }

    override fun containsSignedPreKey(signedPreKeyId: Int): Boolean = signedPreKeyId in signed && base.containsSignedPreKey(signedPreKeyId)

    override fun loadKyberPreKey(kyberPreKeyId: Int): KyberPreKeyRecord {
        if (kyberPreKeyId !in kyber) {
            throw InvalidKeyIdException("not this chat's prekey")
        }
        return base.loadKyberPreKey(kyberPreKeyId)
    }

    override fun loadKyberPreKeys(): List<KyberPreKeyRecord> = base.loadKyberPreKeys().filter { it.id in kyber }

    override fun containsKyberPreKey(kyberPreKeyId: Int): Boolean = kyberPreKeyId in kyber && base.containsKyberPreKey(kyberPreKeyId)

    // One-time EC prekeys are never published, so none may be used.
    override fun loadPreKey(preKeyId: Int): PreKeyRecord = throw InvalidKeyIdException("no one-time prekeys")

    override fun containsPreKey(preKeyId: Int): Boolean = false
}

object IdentityCheck {
    /**
     * Proves that [m], which carries an identity key [store] doesn't trust for [remote], is authentic: it's decrypted as
     * if that key were trusted, in a scratch copy of the store, and thrown away. Throws if it doesn't decrypt. Nothing
     * reaches [store]: no identity, session or used prekey, so a forged message can't record a change or break the chat.
     */
    fun authenticate(store: SignalProtocolStore, local: SignalProtocolAddress, remote: SignalProtocolAddress, m: PreKeySignalMessage) {
        val scratch = ScratchStore(store)
        scratch.saveIdentity(remote, m.identityKey)
        SessionCipher(scratch, local, remote).decrypt(m)
    }
}
