package app.goldfishsend.group

import app.goldfishsend.crypto.LastResortLog
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.ReusedBaseKeyException
import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.ecc.ECPublicKey
import org.signal.libsignal.protocol.state.IdentityKeyStore
import org.signal.libsignal.protocol.state.SessionRecord
import org.signal.libsignal.protocol.state.SignalProtocolStore

/**
 * A view of [base] that reads from it and writes nothing back: sessions and identities stay in memory, and prekeys are
 * never removed. A message from someone our roster doesn't list yet is decrypted with it, so whoever holds our group
 * inbox's hint key can't make us store sessions or identities (docs/groups.md, "Senders our roster doesn't list").
 *
 * A PreKey message that would start a session again from last-resort prekeys ([LastResortLog]) is refused here too,
 * without recording anything. [commit] writes what one decryption did back to [base], once it has succeeded: libsignal
 * stores the session before it asks whether the prekeys were used already, so decrypting with [base] itself would
 * leave a replay's session behind even though the message was refused.
 */
class ScratchStore(private val base: SignalProtocolStore) : SignalProtocolStore by base {
    private fun key(a: SignalProtocolAddress) = "${a.name}.${a.deviceId}"
    private val sessions = HashMap<String, Pair<SignalProtocolAddress, ByteArray>>()
    private val identities = HashMap<String, Pair<SignalProtocolAddress, IdentityKey>>()
    private val used = mutableListOf<Triple<Int, Int, ECPublicKey>>()

    override fun loadSession(address: SignalProtocolAddress): SessionRecord? =
        sessions[key(address)]?.let { SessionRecord(it.second) } ?: base.loadSession(address)

    override fun loadExistingSessions(addresses: List<SignalProtocolAddress>): List<SessionRecord> =
        addresses.map { loadSession(it) ?: throw org.signal.libsignal.protocol.NoSessionException("no session") }

    override fun storeSession(address: SignalProtocolAddress, record: SessionRecord) {
        sessions[key(address)] = address to record.serialize()
    }

    override fun containsSession(address: SignalProtocolAddress): Boolean = key(address) in sessions || base.containsSession(address)

    override fun deleteSession(address: SignalProtocolAddress) {
        sessions.remove(key(address))
    }

    override fun deleteAllSessions(name: String) {
        sessions.keys.removeAll { it.startsWith("$name.") }
    }

    override fun getIdentity(address: SignalProtocolAddress): IdentityKey? = identities[key(address)]?.second ?: base.getIdentity(address)

    override fun saveIdentity(address: SignalProtocolAddress, identityKey: IdentityKey): IdentityKeyStore.IdentityChange {
        val existing = getIdentity(address)
        identities[key(address)] = address to identityKey
        return if (existing == null || existing == identityKey) {
            IdentityKeyStore.IdentityChange.NEW_OR_UNCHANGED
        } else {
            IdentityKeyStore.IdentityChange.REPLACED_EXISTING
        }
    }

    override fun isTrustedIdentity(address: SignalProtocolAddress, identityKey: IdentityKey, direction: IdentityKeyStore.Direction): Boolean =
        identities[key(address)]?.let { it.second == identityKey } ?: base.isTrustedIdentity(address, identityKey, direction)

    // Decrypting only reads prekeys, and marks or removes the ones it used: none of that reaches the real store until
    // [commit].
    override fun removePreKey(preKeyId: Int) = Unit

    override fun markKyberPreKeyUsed(kyberPreKeyId: Int, signedPreKeyId: Int, baseKey: ECPublicKey) {
        if ((base as? LastResortLog)?.baseKeySeen(kyberPreKeyId, signedPreKeyId, baseKey) == true) {
            throw ReusedBaseKeyException("PreKey message replayed")
        }
        used += Triple(kyberPreKeyId, signedPreKeyId, baseKey)
    }

    override fun storePreKey(preKeyId: Int, record: org.signal.libsignal.protocol.state.PreKeyRecord) = Unit

    override fun storeSignedPreKey(signedPreKeyId: Int, record: org.signal.libsignal.protocol.state.SignedPreKeyRecord) = Unit

    override fun removeSignedPreKey(signedPreKeyId: Int) = Unit

    override fun storeKyberPreKey(kyberPreKeyId: Int, record: org.signal.libsignal.protocol.state.KyberPreKeyRecord) = Unit

    override fun storeSenderKey(sender: SignalProtocolAddress, distributionId: java.util.UUID, record: org.signal.libsignal.protocol.groups.state.SenderKeyRecord) = Unit

    /**
     * Writes the sessions and identities stored here, and the prekeys used, to [base], then forgets them. The prekeys
     * go first: [base] refuses a replay there too, before anything else is written.
     */
    fun commit() {
        for ((k, s, b) in used) {
            base.markKyberPreKeyUsed(k, s, b)
        }
        for ((address, record) in sessions.values) {
            base.storeSession(address, SessionRecord(record))
        }
        for ((address, key) in identities.values) {
            base.saveIdentity(address, key)
        }
        used.clear()
        sessions.clear()
        identities.clear()
    }
}
