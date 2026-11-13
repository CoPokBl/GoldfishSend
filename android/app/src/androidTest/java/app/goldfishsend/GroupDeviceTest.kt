package app.goldfishsend

import androidx.test.ext.junit.runners.AndroidJUnit4
import app.goldfishsend.core.Graph
import app.goldfishsend.core.Groups
import app.goldfishsend.core.LockedInbox
import app.goldfishsend.core.Messenger

import app.goldfishsend.core.Session
import app.goldfishsend.crypto.BucketKeys
import app.goldfishsend.crypto.MessageVault
import app.goldfishsend.db.Db
import app.goldfishsend.db.Mailbox
import app.goldfishsend.db.MsgKind
import app.goldfishsend.db.MsgStatus
import app.goldfishsend.db.OutboxKind
import app.goldfishsend.db.groupRef
import app.goldfishsend.db.memberRoutes
import app.goldfishsend.db.pruneGoneCards
import app.goldfishsend.group.GroupEngine
import app.goldfishsend.group.GroupModel
import app.goldfishsend.proto.B64
import app.goldfishsend.proto.CardBundle
import app.goldfishsend.proto.CardInbox
import app.goldfishsend.proto.Content
import app.goldfishsend.proto.GroupCard
import app.goldfishsend.proto.MailboxCrypto
import app.goldfishsend.proto.Rand
import app.goldfishsend.proto.Role
import app.goldfishsend.proto.RosterOp
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.signal.libsignal.protocol.ecc.ECKeyPair
import org.signal.libsignal.protocol.kem.KEMKeyPair
import org.signal.libsignal.protocol.kem.KEMKeyType
import org.signal.libsignal.protocol.state.KyberPreKeyRecord
import org.signal.libsignal.protocol.state.SignedPreKeyRecord

/** Turns a current database back into schema v4 (no group tables or columns), for upgrade tests. */
internal fun downgradeToV4(db: Db) {
    for (t in listOf("groups", "group_cards", "group_rosters", "group_held", "group_receipts")) {
        db.exec("DROP TABLE IF EXISTS $t")
    }
    db.exec("ALTER TABLE contacts DROP COLUMN is_group")
    db.exec("ALTER TABLE mailboxes DROP COLUMN hint_key")
    db.exec("ALTER TABLE outbox DROP COLUMN member_key")
    db.exec("ALTER TABLE messages DROP COLUMN sender_key")
    db.exec("ALTER TABLE messages DROP COLUMN recipients")
    db.exec("ALTER TABLE sig_kyber_prekey DROP COLUMN last_resort")
    db.exec("PRAGMA user_version = 4")
}

/**
 * Group chats on the device's real SQLCipher store and libsignal store (docs/groups.md): two profiles in two databases,
 * with the real engine and app wiring, and the test carrying outbox rows between them in place of a server.
 */
@RunWith(AndroidJUnit4::class)
class GroupDeviceTest {
    private val ctx get() = Graph.app
    private val opened = mutableListOf<Pair<Session, String>>()

    @Before
    fun clean() {
        Graph.lock()
        Graph.vault.destroyAll()
        BucketKeys.destroyAll()
        Db.deleteFiles(ctx)
        for (n in listOf("ga.db", "gb.db", "gc.db")) {
            Db.deleteFiles(ctx, n)
        }
        LockedInbox.clear()
        Graph.prefs.clear()
    }

    @After
    fun tearDown() {
        for ((s, _) in opened) {
            s.db.close()
        }
        clean()
    }

    private fun profile(name: String): Session {
        val mk = Rand.bytes(32)
        val db = Db.open(ctx, mk, name)
        return Session(db, mk, MessageVault(Rand.bytes(32), BucketKeys.DbStore(db))).also { opened += it to name }
    }

    private fun id(s: Session) = Groups.me(s)

    private fun befriend(a: Session, b: Session, nameOfB: String): Long =
        a.repo.createContact(nameOfB, true, 0, "https://$nameOfB.example", Rand.bytes(32), B64.enc(ByteArray(32) { 5 })).also {
            a.repo.setContactIdentity(it, B64.dec(id(b)))
            a.repo.setReceivedAny(it)
        }

    /** A group inbox row and a card for it, as Groups.create/join make them (without the server round trip). */
    private fun inboxAndCard(s: Session, gid: String, name: String): Triple<Mailbox, ByteArray, app.goldfishsend.proto.SignedCard> {
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
            inbox = CardInbox("https://$name.example", B64.enc(ByteArray(32) { 5 }), B64.enc(secret)),
            hintKey = B64.enc(hint),
            bundle = CardBundle(
                s.signal.localRegistrationId, 1, spkId, B64.enc(spk.publicKey.serialize()), B64.enc(spkSig),
                kyberId, B64.enc(kyber.publicKey.serialize()), B64.enc(kyberSig),
            ),
            seq = 1,
        )
        return Triple(s.repo.mailbox(mbId)!!, hint, GroupEngine.makeCard(identity, card))
    }

    /**
     * Stands in for the servers: moves every queued outbox row to the other profile. 1:1 rows go through the contact
     * channel; group rows are encrypted by the sender's engine and land on the recipient's group inbox.
     */
    private suspend fun route(profiles: List<Session>) {
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

    @Test
    fun schemaV4UpgradesToV5KeepingData() = runBlocking<Unit> {
        val mk = Graph.vault.setup(null)
        val keep = mk.copyOf()
        var s = Graph.openSession(mk)
        val cid = s.repo.createContact("Bob", true, 0, "https://bob.example", ByteArray(32) { 9 })
        Messenger.systemMessage(s, cid, "hello")
        s.repo.enqueue(cid, null, OutboxKind.CONTENT, "x".toByteArray())
        downgradeToV4(s.db)
        Graph.lock()
        s = Graph.openSession(keep)
        assertEquals(app.goldfishsend.db.Schema.VERSION.toLong(), s.db.long("PRAGMA user_version"))
        val c = s.repo.contact(cid)!!
        assertFalse(c.isGroup)
        assertEquals("hello", s.repo.messages(cid, System.currentTimeMillis()).single().body)
        assertNull(s.repo.outboxAll().single().memberKey)
        assertEquals(0L, s.db.long("SELECT COUNT(*) FROM groups"))
    }

    @Test
    fun lastResortPrekeysSurviveUseButOneTimeOnesDont() {
        val s = profile("ga.db")
        val kp = KEMKeyPair.generate(KEMKeyType.KYBER_1024)
        val sig = s.signal.identityKeyPair.privateKey.calculateSignature(kp.publicKey.serialize())
        s.signal.storeKyberPreKey(7, KyberPreKeyRecord(7, 0, kp, sig))
        s.signal.storeKyberPreKey(8, KyberPreKeyRecord(8, 0, kp, sig))
        s.signal.markLastResort(7)
        val base = ECKeyPair.generate().publicKey
        s.signal.markKyberPreKeyUsed(7, 70, base)
        s.signal.markKyberPreKeyUsed(8, 80, base)
        assertTrue(s.signal.containsKyberPreKey(7))
        assertFalse(s.signal.containsKyberPreKey(8))
    }

    @Test
    fun twoProfilesCreateJoinAndChatOnTheRealStore() = runBlocking<Unit> {
        Graph.prefs.readReceipts = true
        val alice = profile("ga.db")
        val bob = profile("gb.db")
        val bobAtAlice = befriend(alice, bob, "bob")
        befriend(bob, alice, "alice")
        val gid = B64.enc(Rand.bytes(32))

        // Alice creates the group (as Groups.create does, minus the server).
        val (aliceInbox, aliceHint, aliceCard) = inboxAndCard(alice, gid, "alice")
        alice.lock.lock()
        try {
            alice.db.tx {
                Groups.engine(alice).create(gid, "Picnic", listOf(id(bob)), aliceCard, 0)
                alice.repo.bindGroupInbox(aliceInbox.id, alice.repo.groupRef(Groups.store(alice).cidOf(gid)!!)!!.cid, aliceHint)
            }
        } finally {
            alice.lock.unlock()
        }
        val aliceCid = Groups.store(alice).cidOf(gid)!!
        assertTrue(alice.repo.contact(aliceCid)!!.isGroup)
        assertEquals("Picnic", alice.repo.contact(aliceCid)!!.name)

        route(listOf(alice, bob))
        val bobCid = Groups.store(bob).cidOf(gid)!!
        assertEquals(GroupModel.INVITED, Groups.model(bob, bobCid)!!.state)
        assertTrue(bob.repo.messages(bobCid, System.currentTimeMillis()).any { it.kind == MsgKind.SYSTEM && it.body.contains("invited you") })
        assertNotNull(Groups.model(bob, bobCid)!!.cards[id(alice)])

        // Bob joins.
        val (bobInbox, bobHint, bobCard) = inboxAndCard(bob, gid, "bob")
        bob.lock.lock()
        try {
            bob.db.tx {
                bob.repo.bindGroupInbox(bobInbox.id, bobCid, bobHint)
                assertTrue(Groups.engine(bob).join(Groups.model(bob, bobCid)!!, bobCard))
            }
        } finally {
            bob.lock.unlock()
        }
        route(listOf(alice, bob))
        assertEquals(Role.MEMBER, Groups.model(alice, aliceCid)!!.roster!!.roster.role(id(bob)))
        assertEquals(Groups.model(alice, aliceCid)!!.roster!!.hashB64, Groups.model(bob, bobCid)!!.roster!!.hashB64)

        // Messages both ways, stored per sender, crypto-shredded like any other.
        Groups.sendText(bob, bobCid, "hi alice")
        route(listOf(alice, bob))
        val got = alice.repo.messages(aliceCid, System.currentTimeMillis()).first { it.kind == MsgKind.TEXT }
        assertEquals("hi alice", got.body)
        assertEquals(id(bob), got.senderKey)
        assertEquals("bob", Groups.memberName(alice, Groups.model(alice, aliceCid), id(bob)).name)
        assertEquals(id(bob), alice.repo.chatSummaries(System.currentTimeMillis()).first { it.contact.id == aliceCid }.lastSender)

        Groups.sendText(alice, aliceCid, "hi bob")
        val sent = alice.repo.messages(aliceCid, System.currentTimeMillis()).first { it.outgoing }
        assertEquals(1, sent.recipients)
        route(listOf(alice, bob))
        assertEquals(MsgStatus.SENT, alice.repo.message(sent.id)!!.status)
        assertTrue(bob.repo.messages(bobCid, System.currentTimeMillis()).any { it.body == "hi bob" && !it.outgoing })
        // Bob reads it: Alice sees "read".
        Messenger.markChatRead(bob, bobCid)
        route(listOf(alice, bob))
        assertEquals(MsgStatus.READ, alice.repo.message(sent.id)!!.status)

        // Alice renames; Bob's chat row follows.
        alice.lock.lock()
        try {
            alice.db.tx { assertNotNull(Groups.engine(alice).publish(Groups.model(alice, aliceCid)!!, RosterOp.Meta(name = "Picnic 2"))) }
        } finally {
            alice.lock.unlock()
        }
        route(listOf(alice, bob))
        assertEquals("Picnic 2", bob.repo.contact(bobCid)!!.name)

        // Bob leaves: Alice's roster drops him and his card is kept only for what was queued, then pruned.
        Groups.leave(bob, bobCid)
        route(listOf(alice, bob))
        assertEquals(GroupModel.LEFT, Groups.model(bob, bobCid)!!.state)
        assertNull(Groups.model(alice, aliceCid)!!.roster!!.roster.role(id(bob)))
        assertTrue(alice.repo.memberRoutes(aliceCid)[id(bob)]!!.gone)
        assertEquals(listOf(id(bob)), alice.repo.pruneGoneCards())
        assertTrue(alice.repo.memberRoutes(aliceCid).isEmpty())
        // Bob's inbox went with him.
        assertTrue(bob.repo.mailboxesForContact(bobCid).isEmpty())

        // Wipes and deletion cover groups like chats.
        alice.repo.wipeAllMessages()
        assertTrue(alice.repo.messages(aliceCid, System.currentTimeMillis()).isEmpty())
        alice.repo.deleteContact(aliceCid)
        assertNull(Groups.model(alice, aliceCid))
        assertEquals(0L, alice.db.long("SELECT COUNT(*) FROM group_rosters"))
        assertTrue(alice.repo.contact(bobAtAlice) != null)
    }
}
