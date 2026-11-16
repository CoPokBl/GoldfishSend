package app.goldfishsend

import androidx.test.ext.junit.runners.AndroidJUnit4
import app.goldfishsend.core.Graph
import app.goldfishsend.core.Groups
import app.goldfishsend.core.LockedInbox
import app.goldfishsend.core.Messenger

import app.goldfishsend.core.Session
import app.goldfishsend.crypto.BucketKeys
import app.goldfishsend.db.Db
import app.goldfishsend.db.MsgKind
import app.goldfishsend.db.MsgStatus
import app.goldfishsend.db.OutboxKind
import app.goldfishsend.db.groupRef
import app.goldfishsend.db.memberRoutes
import app.goldfishsend.db.pruneGoneCards
import app.goldfishsend.group.GroupModel
import app.goldfishsend.proto.B64
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

    private fun profile(name: String): Session = GroupKit.profile(name, opened)

    private fun id(s: Session) = GroupKit.id(s)

    private fun befriend(a: Session, b: Session, nameOfB: String): Long = GroupKit.befriend(a, b, nameOfB)

    private fun inboxAndCard(s: Session, gid: String, name: String) = GroupKit.inboxAndCard(s, gid, name)

    private suspend fun route(profiles: List<Session>) = GroupKit.route(profiles)

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
        // The invitation is the roster alone: Bob gets Alice's card once she lets him in.
        assertNull(Groups.model(bob, bobCid)!!.cards[id(alice)])

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
        assertEquals(Role.MEMBER, Groups.model(alice, aliceCid)!!.view()!!.role(id(bob)))
        assertEquals(Groups.model(alice, aliceCid)!!.roster!!.hashB64, Groups.model(bob, bobCid)!!.roster!!.hashB64)
        assertNotNull(Groups.model(bob, bobCid)!!.cards[id(alice)])

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
