package app.goldfishsend

import app.goldfishsend.core.Graph
import app.goldfishsend.core.Groups
import app.goldfishsend.core.Session
import app.goldfishsend.crypto.BucketKeys
import app.goldfishsend.crypto.MessageVault
import app.goldfishsend.db.Db
import app.goldfishsend.db.Mailbox
import app.goldfishsend.db.MsgStatus
import app.goldfishsend.db.groupRef
import app.goldfishsend.db.memberRoutes
import app.goldfishsend.group.GroupEngine
import app.goldfishsend.proto.B64
import app.goldfishsend.proto.CardBundle
import app.goldfishsend.proto.CardInbox
import app.goldfishsend.proto.Content
import app.goldfishsend.proto.GroupCard
import app.goldfishsend.proto.MailboxCrypto
import app.goldfishsend.proto.Rand
import app.goldfishsend.proto.SignedCard
import org.signal.libsignal.protocol.ecc.ECKeyPair
import org.signal.libsignal.protocol.kem.KEMKeyPair
import org.signal.libsignal.protocol.kem.KEMKeyType
import org.signal.libsignal.protocol.state.KyberPreKeyRecord
import org.signal.libsignal.protocol.state.SignedPreKeyRecord

/**
 * Several profiles on the device's real SQLCipher and libsignal stores, each in its own database, with the test carrying
 * outbox rows between them in place of a server.
 */
internal object GroupKit {
    fun profile(name: String, opened: MutableList<Pair<Session, String>>, keys: MutableMap<String, ByteArray>? = null): Session {
        val mk = Rand.bytes(32)
        keys?.put(name, mk.copyOf())
        val db = Db.open(Graph.app, mk, name)
        return Session(db, mk, MessageVault(Rand.bytes(32), BucketKeys.DbStore(db))).also { opened += it to name }
    }

    fun id(s: Session) = Groups.me(s)

    fun befriend(a: Session, b: Session, nameOfB: String, server: String = "https://$nameOfB.example"): Long =
        a.repo.createContact(nameOfB, true, 0, server, Rand.bytes(32), B64.enc(ByteArray(32) { 5 })).also {
            a.repo.setContactIdentity(it, B64.dec(id(b)))
            a.repo.setReceivedAny(it)
        }

    /** A group inbox row and a card for it, as Groups.create/join make them (without the server round trip). */
    fun inboxAndCard(s: Session, gid: String, name: String, server: String = "https://$name.example"): Triple<Mailbox, ByteArray, SignedCard> {
        val secret = MailboxCrypto.newSecret()
        val mbId = s.repo.insertMailbox(Mailbox.PURPOSE_GROUP, secret, MailboxCrypto.newSecret(), MailboxCrypto.tag(secret))
        s.repo.setMailboxState(mbId, Mailbox.STATE_ACTIVE)
        val hint = Rand.bytes(32)
        val identity = s.signal.identityKeyPair
        val spkId = 1000 + Rand.int(100000)
        val spk = ECKeyPair.generate()
        val spkSig = identity.privateKey.calculateSignature(spk.publicKey.serialize())
        s.signal.storeSignedPreKey(spkId, SignedPreKeyRecord(spkId, 0, spk, spkSig))
        val kyberId = spkId + 1
        val kyber = KEMKeyPair.generate(KEMKeyType.KYBER_1024)
        val kyberSig = identity.privateKey.calculateSignature(kyber.publicKey.serialize())
        s.signal.storeKyberPreKey(kyberId, KyberPreKeyRecord(kyberId, 0, kyber, kyberSig))
        s.signal.markLastResort(kyberId)
        val card = GroupCard(
            g = gid, id = id(s), name = name,
            inbox = CardInbox(server, B64.enc(ByteArray(32) { 5 }), B64.enc(secret)),
            hintKey = B64.enc(hint),
            bundle = CardBundle(
                s.signal.localRegistrationId, 1, spkId, B64.enc(spk.publicKey.serialize()), B64.enc(spkSig),
                kyberId, B64.enc(kyber.publicKey.serialize()), B64.enc(kyberSig),
            ),
            seq = 1,
        )
        return Triple(s.repo.mailbox(mbId)!!, hint, GroupEngine.makeCard(identity, card))
    }

    /** [owner] creates group [gid] with [member], who joins. Returns the group's chat id at the owner and at the member. */
    suspend fun createAndJoin(owner: Session, member: Session, gid: String, groupName: String, server: (String) -> String): Pair<Long, Long> {
        val (ownerInbox, ownerHint, ownerCard) = inboxAndCard(owner, gid, "owner", server("owner"))
        owner.lock.lock()
        try {
            owner.db.tx {
                Groups.engine(owner).create(gid, groupName, listOf(id(member)), ownerCard, 0)
                owner.repo.bindGroupInbox(ownerInbox.id, owner.repo.groupRef(Groups.store(owner).cidOf(gid)!!)!!.cid, ownerHint)
            }
        } finally {
            owner.lock.unlock()
        }
        route(listOf(owner, member))
        val memberCid = Groups.store(member).cidOf(gid)!!
        val (memberInbox, memberHint, memberCard) = inboxAndCard(member, gid, "member", server("member"))
        member.lock.lock()
        try {
            member.db.tx {
                member.repo.bindGroupInbox(memberInbox.id, memberCid, memberHint)
                check(Groups.engine(member).join(Groups.model(member, memberCid)!!, memberCard))
            }
        } finally {
            member.lock.unlock()
        }
        route(listOf(owner, member))
        return Groups.store(owner).cidOf(gid)!! to memberCid
    }

    /**
     * Stands in for the servers: moves every queued outbox row to the other profile. 1:1 rows go through the contact
     * channel; group rows are encrypted by the sender's engine and land on the recipient's group inbox.
     */
    suspend fun route(profiles: List<Session>) {
        repeat(20) {
            var moved = false
            for (from in profiles) {
                val chunks = HashMap<String, MutableMap<Int, String>>()
                for (row in from.repo.outboxAll()) {
                    val content = from.repo.openOutboxContent(row)?.let { Content.decode(it) }
                    from.repo.outboxDelete(row.seq)
                    // As the outbox does once the server accepted the last row of a message.
                    row.messageId?.let { mid ->
                        if (from.repo.outboxRemaining(mid) == 0L && from.repo.message(mid)?.status == MsgStatus.QUEUED) {
                            from.repo.setStatus(mid, MsgStatus.SENT)
                        }
                    }
                    moved = true
                    val member = row.memberKey
                    if (member == null) {
                        val c = content ?: continue
                        val whole = if (c is Content.Chunk) {
                            val parts = chunks.getOrPut(c.id) { HashMap() }
                            parts[c.part] = c.data
                            if (parts.size < c.parts) continue
                            Content.decode(B64.dec((0 until c.parts).joinToString("") { parts[it]!! }))
                        } else {
                            c
                        }
                        val peerKey = B64.enc(from.repo.contact(row.contactId)!!.identityKey!!)
                        val to = profiles.first { id(it) == peerKey }
                        val sender = to.repo.personByIdentity(B64.dec(id(from)))!!
                        if (whole.groupId != null) {
                            to.lock.lock()
                            try {
                                to.db.tx { Groups.onDirect(to, sender.id, whole) }
                            } finally {
                                to.lock.unlock()
                            }
                        }
                    } else {
                        val to = profiles.first { id(it) == member }
                        val card = from.repo.memberRoutes(row.contactId)[member]!!.card
                        val blob = row.blob ?: Groups.engine(from).encryptTo(member, card, from.repo.openOutboxContent(row)!!)
                        val mb = to.repo.mailboxByTag(MailboxCrypto.tag(B64.dec(card.inbox.sendSecret)))!!
                        Groups.receive(to, mb, blob)
                    }
                }
            }
            if (!moved) {
                return
            }
        }
    }
}
