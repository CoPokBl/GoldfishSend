package app.goldfishsend.crypto

import app.goldfishsend.db.Db
import java.util.UUID
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.IdentityKeyPair
import org.signal.libsignal.protocol.InvalidKeyIdException
import org.signal.libsignal.protocol.NoSessionException
import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.ecc.ECPublicKey
import org.signal.libsignal.protocol.groups.state.SenderKeyRecord
import org.signal.libsignal.protocol.state.IdentityKeyStore
import org.signal.libsignal.protocol.state.KyberPreKeyRecord
import org.signal.libsignal.protocol.state.PreKeyRecord
import org.signal.libsignal.protocol.state.SessionRecord
import org.signal.libsignal.protocol.state.SignalProtocolStore
import org.signal.libsignal.protocol.state.SignedPreKeyRecord

/** libsignal protocol store backed by the SQLCipher database. */
class SignalStore(private val db: Db) : SignalProtocolStore {
    private fun key(a: SignalProtocolAddress): String = "${a.name}.${a.deviceId}"

    private val identity: IdentityKeyPair by lazy {
        val raw = db.queryOne("SELECT v FROM kv WHERE k = 'identity'") { it.getBlob(0) }
        if (raw != null) {
            IdentityKeyPair(raw)
        } else {
            val kp = IdentityKeyPair.generate()
            db.exec("INSERT INTO kv (k, v) VALUES ('identity', ?)", kp.serialize())
            kp
        }
    }

    private val registrationId: Int by lazy {
        val raw = db.queryOne("SELECT v FROM kv WHERE k = 'registration_id'") { it.getBlob(0) }
        if (raw != null) {
            String(raw).toInt()
        } else {
            // 14-bit registration id, as in Signal.
            val id = 1 + app.goldfishsend.proto.Rand.int(16380)
            db.exec("INSERT INTO kv (k, v) VALUES ('registration_id', ?)", id.toString().toByteArray())
            id
        }
    }

    // --- IdentityKeyStore ---

    override fun getIdentityKeyPair(): IdentityKeyPair = identity

    override fun getLocalRegistrationId(): Int = registrationId

    override fun saveIdentity(address: SignalProtocolAddress, identityKey: IdentityKey): IdentityKeyStore.IdentityChange {
        val existing = getIdentity(address)
        db.exec("INSERT OR REPLACE INTO sig_identity (address, key) VALUES (?, ?)", key(address), identityKey.serialize())
        return if (existing == null || existing == identityKey) {
            IdentityKeyStore.IdentityChange.NEW_OR_UNCHANGED
        } else {
            IdentityKeyStore.IdentityChange.REPLACED_EXISTING
        }
    }

    /** Trust on first use. A changed identity for an existing contact is never trusted automatically. */
    override fun isTrustedIdentity(
        address: SignalProtocolAddress,
        identityKey: IdentityKey,
        direction: IdentityKeyStore.Direction,
    ): Boolean {
        val existing = getIdentity(address) ?: return true
        return existing == identityKey
    }

    override fun getIdentity(address: SignalProtocolAddress): IdentityKey? =
        db.queryOne("SELECT key FROM sig_identity WHERE address = ?", key(address)) { IdentityKey(it.getBlob(0)) }

    // --- PreKeyStore (one-time EC prekeys are not used, but the interface must work) ---

    override fun loadPreKey(preKeyId: Int): PreKeyRecord =
        db.queryOne("SELECT record FROM sig_prekey WHERE id = ?", preKeyId) { PreKeyRecord(it.getBlob(0)) }
            ?: throw InvalidKeyIdException("no prekey $preKeyId")

    override fun storePreKey(preKeyId: Int, record: PreKeyRecord) {
        db.exec("INSERT OR REPLACE INTO sig_prekey (id, record) VALUES (?, ?)", preKeyId, record.serialize())
    }

    override fun containsPreKey(preKeyId: Int): Boolean =
        db.long("SELECT COUNT(*) FROM sig_prekey WHERE id = ?", preKeyId) > 0

    override fun removePreKey(preKeyId: Int) {
        db.exec("DELETE FROM sig_prekey WHERE id = ?", preKeyId)
    }

    // --- SignedPreKeyStore ---

    override fun loadSignedPreKey(signedPreKeyId: Int): SignedPreKeyRecord =
        db.queryOne("SELECT record FROM sig_signed_prekey WHERE id = ?", signedPreKeyId) { SignedPreKeyRecord(it.getBlob(0)) }
            ?: throw InvalidKeyIdException("no signed prekey $signedPreKeyId")

    override fun loadSignedPreKeys(): List<SignedPreKeyRecord> =
        db.query("SELECT record FROM sig_signed_prekey") { SignedPreKeyRecord(it.getBlob(0)) }

    override fun storeSignedPreKey(signedPreKeyId: Int, record: SignedPreKeyRecord) {
        db.exec(
            "INSERT OR REPLACE INTO sig_signed_prekey (id, record, created_at) VALUES (?, ?, ?)",
            signedPreKeyId, record.serialize(), System.currentTimeMillis(),
        )
    }

    override fun containsSignedPreKey(signedPreKeyId: Int): Boolean =
        db.long("SELECT COUNT(*) FROM sig_signed_prekey WHERE id = ?", signedPreKeyId) > 0

    override fun removeSignedPreKey(signedPreKeyId: Int) {
        db.exec("DELETE FROM sig_signed_prekey WHERE id = ?", signedPreKeyId)
    }

    // --- KyberPreKeyStore (each invite gets its own one-time Kyber prekey) ---

    override fun loadKyberPreKey(kyberPreKeyId: Int): KyberPreKeyRecord =
        db.queryOne("SELECT record FROM sig_kyber_prekey WHERE id = ?", kyberPreKeyId) { KyberPreKeyRecord(it.getBlob(0)) }
            ?: throw InvalidKeyIdException("no kyber prekey $kyberPreKeyId")

    override fun loadKyberPreKeys(): List<KyberPreKeyRecord> =
        db.query("SELECT record FROM sig_kyber_prekey") { KyberPreKeyRecord(it.getBlob(0)) }

    override fun storeKyberPreKey(kyberPreKeyId: Int, record: KyberPreKeyRecord) {
        db.exec(
            "INSERT OR REPLACE INTO sig_kyber_prekey (id, record, created_at) VALUES (?, ?, ?)",
            kyberPreKeyId, record.serialize(), System.currentTimeMillis(),
        )
    }

    override fun containsKyberPreKey(kyberPreKeyId: Int): Boolean =
        db.long("SELECT COUNT(*) FROM sig_kyber_prekey WHERE id = ?", kyberPreKeyId) > 0

    /** Deletes an unused Kyber prekey (its invite expired or was abandoned). */
    fun removeKyberPreKey(kyberPreKeyId: Int) {
        db.exec("DELETE FROM sig_kyber_prekey WHERE id = ?", kyberPreKeyId)
    }

    /**
     * One-time Kyber prekeys are deleted on use (forward secrecy). The signed prekey goes with it. A group's last-resort
     * prekeys (published in its card, used by every member who starts a session) stay until we leave or replace the card.
     */
    override fun markKyberPreKeyUsed(kyberPreKeyId: Int, signedPreKeyId: Int, baseKey: ECPublicKey) {
        if (db.long("SELECT COUNT(*) FROM sig_kyber_prekey WHERE id = ? AND last_resort = 1", kyberPreKeyId) > 0) {
            return
        }
        db.exec("DELETE FROM sig_kyber_prekey WHERE id = ?", kyberPreKeyId)
        db.exec("DELETE FROM sig_signed_prekey WHERE id = ?", signedPreKeyId)
    }

    /** Marks a Kyber prekey as last-resort (a group card's), so using it doesn't delete it. */
    fun markLastResort(kyberPreKeyId: Int) {
        db.exec("UPDATE sig_kyber_prekey SET last_resort = 1 WHERE id = ?", kyberPreKeyId)
    }

    // --- SessionStore ---

    override fun loadSession(address: SignalProtocolAddress): SessionRecord? =
        db.queryOne("SELECT record FROM sig_session WHERE address = ?", key(address)) { SessionRecord(it.getBlob(0)) }

    override fun loadExistingSessions(addresses: List<SignalProtocolAddress>): List<SessionRecord> =
        addresses.map { loadSession(it) ?: throw NoSessionException("no session for $it") }

    override fun getSubDeviceSessions(name: String): List<Int> =
        db.query("SELECT address FROM sig_session WHERE address LIKE ?", "$name.%") {
            it.getString(0).substringAfterLast('.').toInt()
        }.filter { it != 1 }

    override fun storeSession(address: SignalProtocolAddress, record: SessionRecord) {
        db.exec("INSERT OR REPLACE INTO sig_session (address, record) VALUES (?, ?)", key(address), record.serialize())
    }

    override fun containsSession(address: SignalProtocolAddress): Boolean =
        db.long("SELECT COUNT(*) FROM sig_session WHERE address = ?", key(address)) > 0

    override fun deleteSession(address: SignalProtocolAddress) {
        db.exec("DELETE FROM sig_session WHERE address = ?", key(address))
    }

    override fun deleteAllSessions(name: String) {
        db.exec("DELETE FROM sig_session WHERE address LIKE ?", "$name.%")
        db.exec("DELETE FROM sig_identity WHERE address LIKE ?", "$name.%")
    }

    // --- SenderKeyStore (groups; unused in v1) ---

    override fun storeSenderKey(sender: SignalProtocolAddress, distributionId: UUID, record: SenderKeyRecord) {
        db.exec(
            "INSERT OR REPLACE INTO sig_sender_key (address, dist, record) VALUES (?, ?, ?)",
            key(sender), distributionId.toString(), record.serialize(),
        )
    }

    override fun loadSenderKey(sender: SignalProtocolAddress, distributionId: UUID): SenderKeyRecord? =
        db.queryOne(
            "SELECT record FROM sig_sender_key WHERE address = ? AND dist = ?",
            key(sender), distributionId.toString(),
        ) { SenderKeyRecord(it.getBlob(0)) }
}
