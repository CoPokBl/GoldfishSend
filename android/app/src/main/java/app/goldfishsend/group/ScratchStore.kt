package app.goldfishsend.group

import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.ecc.ECPublicKey
import org.signal.libsignal.protocol.state.IdentityKeyStore
import org.signal.libsignal.protocol.state.SessionRecord
import org.signal.libsignal.protocol.state.SignalProtocolStore

/**
 * A view of [base] that reads from it and writes nothing back: sessions and identities stay in memory, and prekeys are
 * never removed. A message from someone our roster doesn't list yet is decrypted with it, so whoever holds our group
 * inbox's hint key can't make us store sessions or identities (docs/groups.md, "Senders our roster doesn't list").
 */
class ScratchStore(private val base: SignalProtocolStore) : SignalProtocolStore by base {
    private fun key(a: SignalProtocolAddress) = "${a.name}.${a.deviceId}"
    private val sessions = HashMap<String, ByteArray>()
    private val identities = HashMap<String, IdentityKey>()

    override fun loadSession(address: SignalProtocolAddress): SessionRecord? =
        sessions[key(address)]?.let { SessionRecord(it) } ?: base.loadSession(address)

    override fun loadExistingSessions(addresses: List<SignalProtocolAddress>): List<SessionRecord> =
        addresses.map { loadSession(it) ?: throw org.signal.libsignal.protocol.NoSessionException("no session") }

    override fun storeSession(address: SignalProtocolAddress, record: SessionRecord) {
        sessions[key(address)] = record.serialize()
    }

    override fun containsSession(address: SignalProtocolAddress): Boolean = key(address) in sessions || base.containsSession(address)

    override fun deleteSession(address: SignalProtocolAddress) {
        sessions.remove(key(address))
    }

    override fun deleteAllSessions(name: String) {
        sessions.keys.removeAll { it.startsWith("$name.") }
    }

    override fun getIdentity(address: SignalProtocolAddress): IdentityKey? = identities[key(address)] ?: base.getIdentity(address)

    override fun saveIdentity(address: SignalProtocolAddress, identityKey: IdentityKey): IdentityKeyStore.IdentityChange {
        val existing = getIdentity(address)
        identities[key(address)] = identityKey
        return if (existing == null || existing == identityKey) {
            IdentityKeyStore.IdentityChange.NEW_OR_UNCHANGED
        } else {
            IdentityKeyStore.IdentityChange.REPLACED_EXISTING
        }
    }

    override fun isTrustedIdentity(address: SignalProtocolAddress, identityKey: IdentityKey, direction: IdentityKeyStore.Direction): Boolean =
        identities[key(address)]?.let { it == identityKey } ?: base.isTrustedIdentity(address, identityKey, direction)

    // Decrypting only reads prekeys, and marks or removes the ones it used: none of that reaches the real store.
    override fun removePreKey(preKeyId: Int) = Unit

    override fun markKyberPreKeyUsed(kyberPreKeyId: Int, signedPreKeyId: Int, baseKey: ECPublicKey) = Unit

    override fun storePreKey(preKeyId: Int, record: org.signal.libsignal.protocol.state.PreKeyRecord) = Unit

    override fun storeSignedPreKey(signedPreKeyId: Int, record: org.signal.libsignal.protocol.state.SignedPreKeyRecord) = Unit

    override fun removeSignedPreKey(signedPreKeyId: Int) = Unit

    override fun storeKyberPreKey(kyberPreKeyId: Int, record: org.signal.libsignal.protocol.state.KyberPreKeyRecord) = Unit

    override fun storeSenderKey(sender: SignalProtocolAddress, distributionId: java.util.UUID, record: org.signal.libsignal.protocol.groups.state.SenderKeyRecord) = Unit
}
