package app.goldfishsend.core

import app.goldfishsend.db.Mailbox
import app.goldfishsend.db.OutboxKind
import app.goldfishsend.net.ApiException
import app.goldfishsend.net.ServerApi
import app.goldfishsend.proto.B64
import app.goldfishsend.proto.Content
import app.goldfishsend.proto.InviteBundle
import app.goldfishsend.proto.InviteCrypto
import app.goldfishsend.proto.InviteLink
import app.goldfishsend.proto.Rand
import app.goldfishsend.proto.Sanitize
import kotlinx.coroutines.sync.withLock
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.SessionBuilder
import org.signal.libsignal.protocol.ecc.ECKeyPair
import org.signal.libsignal.protocol.ecc.ECPublicKey
import org.signal.libsignal.protocol.kem.KEMKeyPair
import org.signal.libsignal.protocol.kem.KEMKeyType
import org.signal.libsignal.protocol.kem.KEMPublicKey
import org.signal.libsignal.protocol.state.KyberPreKeyRecord
import org.signal.libsignal.protocol.state.PreKeyBundle
import org.signal.libsignal.protocol.state.SignedPreKeyRecord

class InviteException(val human: String) : Exception(human)

/** Contact exchange through one-time invite blobs (protocol.md "Invite QR / link"). */
object Invites {
    const val QR_TTL_SECS = 15 * 60L
    const val LINK_TTL_SECS = 24 * 3600L
    const val DEFAULT_NAME = "New contact"

    data class Created(val link: InviteLink, val mailboxId: Long, val expiresAt: Long)

    private fun nextKeyId(s: Session): Int {
        val cur = s.repo.kvString("next_key_id")?.toInt() ?: (1 + Rand.int(1 shl 20))
        val next = if (cur >= 0xFFFFFF) 1 else cur + 1
        s.repo.kvPutString("next_key_id", next.toString())
        return cur
    }

    @Volatile
    private var cachedQr: Created? = null

    /** Creates an invite backed by a ready mailbox. It's instant when the background pool is warm. */
    suspend fun create(s: Session, purpose: Int): Created {
        if (purpose == Mailbox.PURPOSE_QR) {
            cachedQr?.let { c ->
                // Re-show the same still-valid QR code instead of burning a new mailbox each time the screen opens.
                if (c.expiresAt - System.currentTimeMillis() > 60_000 && s.repo.mailbox(c.mailboxId)?.contactId == null) {
                    return c
                }
            }
        }
        val mb = Mailboxes.take(s, purpose)
            ?: throw InviteException("Still getting things ready. This only takes a moment the first time.")
        val ttl = if (purpose == Mailbox.PURPOSE_LINK) LINK_TTL_SECS else QR_TTL_SECS
        var issued: Pair<Int, Int>? = null
        val bundle = s.lock.withLock {
            s.db.tx {
                val identity = s.signal.identityKeyPair
                val spkId = nextKeyId(s)
                val spk = ECKeyPair.generate()
                val spkSig = identity.privateKey.calculateSignature(spk.publicKey.serialize())
                s.signal.storeSignedPreKey(spkId, SignedPreKeyRecord(spkId, System.currentTimeMillis(), spk, spkSig))
                val kyberId = nextKeyId(s)
                val kyber = KEMKeyPair.generate(KEMKeyType.KYBER_1024)
                val kyberSig = identity.privateKey.calculateSignature(kyber.publicKey.serialize())
                s.signal.storeKyberPreKey(kyberId, KyberPreKeyRecord(kyberId, System.currentTimeMillis(), kyber, kyberSig))
                // Bind the invite to this mailbox: a first hello is only accepted here, and only with this prekey.
                s.repo.setInvitePrekeys(mb.id, spkId, kyberId)
                issued = spkId to kyberId
                InviteBundle(
                    server = Graph.prefs.serverUrl,
                    sendSecret = B64.enc(mb.sendSecret),
                    registrationId = s.signal.localRegistrationId,
                    deviceId = 1,
                    identityKey = B64.enc(identity.publicKey.serialize()),
                    signedPreKeyId = spkId,
                    signedPreKey = B64.enc(spk.publicKey.serialize()),
                    signedPreKeySig = B64.enc(spkSig),
                    kyberPreKeyId = kyberId,
                    kyberPreKey = B64.enc(kyber.publicKey.serialize()),
                    kyberPreKeySig = B64.enc(kyberSig),
                    name = s.repo.displayName,
                )
            }
        }
        val key = Rand.bytes(32)
        val id = try {
            Graph.api().uploadInvite(InviteCrypto.encrypt(key, bundle), ttl)
        } catch (e: ApiException) {
            // 429 (for example scope "global": the server's live-invite cap is full) or any other failure: the mailbox
            // stays unadvertised, so the next attempt can reuse it.
            s.lock.withLock {
                s.db.tx {
                    issued?.let { (spk, kyber) ->
                        s.signal.removeSignedPreKey(spk)
                        s.signal.removeKyberPreKey(kyber)
                    }
                    s.repo.releasePoolMailbox(mb.id)
                }
            }
            throw InviteException(
                if (e.status == 429) "The server is busy right now. Try again in a minute." else e.human,
            )
        }
        val expiresAt = System.currentTimeMillis() + ttl * 1000
        s.repo.markInviteUsed(mb.id, expiresAt)
        Graph.scope.launchSafe { Mailboxes.ensurePool(s) }
        val created = Created(InviteLink(Graph.prefs.serverUrl, id, key), mb.id, expiresAt)
        if (purpose == Mailbox.PURPOSE_QR) {
            cachedQr = created
        }
        return created
    }

    /**
     * Accepts an invite (scanned QR or pasted link). It builds the session, queues `hello` and returns the new contact id
     * right away. The chat can open and the user can type at once, because everything is queued in the outbox.
     */
    suspend fun accept(s: Session, link: InviteLink, viaQr: Boolean): Long {
        if (!ServerApi.isValidContactServer(link.server)) {
            throw InviteException("This invite points to a server that isn't secure.")
        }
        val blob = try {
            Graph.api(link.server).fetchInvite(link.id)
        } catch (e: ApiException) {
            throw InviteException(if (e.code == "network") "Couldn't reach the server. Check your connection and try again." else e.human)
        } ?: throw InviteException("This code was already used or has expired. Ask for a new one.")
        val bundle = try {
            InviteCrypto.decrypt(link.key, blob)
        } catch (e: Exception) {
            throw InviteException("This code doesn't look right. Ask for a new one.")
        }
        if (!ServerApi.isValidContactServer(bundle.server)) {
            throw InviteException("This invite points to a server that isn't secure.")
        }
        val contactId = s.lock.withLock {
            s.db.tx {
                val timer = Graph.prefs.defaultTimerSecs
                val cid = s.repo.createContact(
                    name = Sanitize.name(bundle.name) ?: DEFAULT_NAME,
                    verified = viaQr,
                    timerSecs = timer,
                    outServer = bundle.server,
                    outSecret = B64.dec(bundle.sendSecret),
                )
                val identity = IdentityKey(B64.dec(bundle.identityKey))
                val pk = PreKeyBundle(
                    bundle.registrationId,
                    bundle.deviceId,
                    PreKeyBundle.NULL_PRE_KEY_ID,
                    null,
                    bundle.signedPreKeyId,
                    ECPublicKey(B64.dec(bundle.signedPreKey)),
                    B64.dec(bundle.signedPreKeySig),
                    identity,
                    bundle.kyberPreKeyId,
                    KEMPublicKey(B64.dec(bundle.kyberPreKey)),
                    B64.dec(bundle.kyberPreKeySig),
                )
                SessionBuilder(s.signal, Messenger.remote(cid), Messenger.LOCAL).process(pk)
                s.repo.setContactIdentity(cid, identity.serialize())
                s.repo.enqueue(cid, null, OutboxKind.HELLO, null)
                if (timer > 0) {
                    s.repo.enqueue(cid, null, OutboxKind.CONTENT, Content.Timer(timer).encode())
                }
                cid
            }
        }
        Messenger.systemMessage(s, contactId, "Messages are end-to-end encrypted.")
        if (Graph.prefs.defaultTimerSecs > 0) {
            Messenger.systemMessage(s, contactId, "Disappearing messages: ${timerLabel(Graph.prefs.defaultTimerSecs)}")
        }
        s.db.notifyChanged()
        Outbox.kick()
        return contactId
    }
}
