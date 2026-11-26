package app.goldfishsend

import app.goldfishsend.group.GroupEngine
import app.goldfishsend.group.GroupEvent
import app.goldfishsend.group.GroupIo
import app.goldfishsend.group.GroupModel
import app.goldfishsend.group.GroupStore
import app.goldfishsend.proto.B64
import app.goldfishsend.proto.Content
import app.goldfishsend.proto.Fact
import app.goldfishsend.proto.FactKind
import app.goldfishsend.proto.GroupCrypto
import app.goldfishsend.proto.Rand
import app.goldfishsend.proto.Role
import app.goldfishsend.proto.Roster
import app.goldfishsend.proto.RosterMember
import app.goldfishsend.proto.RosterOp
import app.goldfishsend.proto.RosterRules
import app.goldfishsend.proto.SignedRoster
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.signal.libsignal.protocol.IdentityKeyPair

/** What members who are out, or contacts who aren't the owner, or the server, can and can't get the group engine to do. */
class GroupHardeningTest {
    private val net = GroupNet()
    private val alice = net.peer("alice")
    private val bob = net.peer("bob")
    private val carol = net.peer("carol")
    private val mallory = net.peer("mallory")
    private val gid = B64.enc(Rand.bytes(32))
    private var now = 1_700_000_000_000L

    init {
        net.clock = { now }
        alice.befriend(bob)
        alice.befriend(carol)
        alice.befriend(mallory)
        bob.befriend(mallory)
    }

    private fun texts(p: Peer) = p.texts.filter { it.first == gid }.map { it.third }

    /** Everything queued to [p] (not delivered), and what it is. */
    private fun queuedTo(p: Peer) = net.queue.filter {
        when (it) {
            is GroupNet.Envelope.Direct -> it.to == p
            is GroupNet.Envelope.ToInbox -> it.to == p
        }
    }

    /** The rosters in state messages queued to [p] over 1:1. */
    private fun rostersTo(p: Peer): List<Roster> = queuedTo(p).filterIsInstance<GroupNet.Envelope.Direct>()
        .mapNotNull { it.content as? Content.GState }.flatMap { s -> s.rosters.mapNotNull { GroupCrypto.openRoster(it)?.roster } }

    /** Alice owns the group; Bob and Mallory join, then Mallory is removed and Carol comes in after her. */
    private fun malloryRemovedThenCarolJoins(): Long {
        alice.create(gid, "Trip", bob, mallory)
        net.deliverAll()
        bob.join(gid)
        mallory.join(gid)
        net.deliverAll()
        alice.publish(gid, RosterOp.Remove(listOf(mallory.id)))
        net.deliverAll()
        val removedAt = alice.roster(gid).roster.ver
        assertEquals(GroupModel.REMOVED, mallory.model(gid).state)
        alice.publish(gid, RosterOp.Add(listOf(carol.id)))
        net.deliverAll()
        carol.join(gid)
        net.deliverAll()
        assertEquals(Role.MEMBER, bob.view(gid).role(carol.id))
        return removedAt
    }

    private fun acceptance(p: Peer, since: Long) =
        GroupCrypto.signFact(p.identity.privateKey, Fact(g = gid, kind = FactKind.ACCEPT, id = p.id, since = since, ts = now / 1000))

    /**
     * Mallory, removed, sends an acceptance for her old stint to a member who has her as a contact. She's told how her
     * stint ended, and nothing after it: not who came in since, nor their cards.
     */
    @Test
    fun aRemovedMemberCantPullLaterRosters() {
        val removedAt = malloryRemovedThenCarolJoins()
        for (p in listOf(bob, alice)) {
            now += GroupEngine.SEND_AGAIN_AFTER
            p.engine.onDirect(mallory.id, factState(acceptance(mallory, 1)))
            val got = rostersTo(mallory)
            assertTrue("${p.name} sent v${got.map { it.ver }}", got.all { it.ver <= removedAt })
            assertTrue(got.none { r -> r.member(carol.id) != null })
            net.queue.clear()
        }
    }

    /** Someone who left knows how their stint ended: an acceptance for it gets nothing at all. */
    @Test
    fun aMemberWhoLeftGetsNothingForAnOldAcceptance() {
        alice.create(gid, "Trip", bob, mallory)
        net.deliverAll()
        bob.join(gid)
        mallory.join(gid)
        net.deliverAll()
        mallory.leave(gid)
        net.deliverAll()
        alice.publish(gid, RosterOp.Add(listOf(carol.id)))
        net.deliverAll()
        now += GroupEngine.SEND_AGAIN_AFTER
        bob.engine.onDirect(mallory.id, factState(acceptance(mallory, 1)))
        assertTrue(queuedTo(mallory).isEmpty())
    }

    /**
     * Mallory, removed, keeps writing to the group through Alice's old card: Alice sends again the rosters that say she's
     * out, up to the one that took her out, never those after it.
     */
    @Test
    fun theRemovedAreOwedNothingPastTheirRemoval() {
        alice.create(gid, "Trip", bob, mallory)
        net.deliverAll()
        bob.join(gid)
        mallory.join(gid)
        net.deliverAll()
        val oldCard = mallory.model(gid).cards[alice.id]!!.card
        alice.publish(gid, RosterOp.Remove(listOf(mallory.id)))
        // Mallory never hears.
        net.queue.removeAll { it.receiver() == mallory }
        net.deliverAll()
        val removedAt = alice.roster(gid).roster.ver
        alice.publish(gid, RosterOp.Add(listOf(carol.id)))
        net.deliverAll()
        carol.join(gid)
        net.deliverAll()
        now += GroupEngine.RESEND_AFTER
        mallory.sendWithCard(oldCard, Content.GText(gid, "x", "anyone?", now, h = mallory.engine.head(mallory.model(gid))))
        net.deliver(net.queue.removeFirst())
        val got = rostersTo(mallory)
        assertTrue("resent v${got.map { it.ver }}", got.isNotEmpty() && got.all { it.ver <= removedAt })
    }

    /** A gstate full of copies of one stale acceptance, and of acceptances for stints never had, costs one history walk. */
    @Test
    fun oneStateCausesBoundedWork() {
        malloryRemovedThenCarolJoins()
        repeat(30) { alice.publish(gid, RosterOp.Meta(name = "Trip $it")) }
        net.deliverAll()
        val counting = CountingStore(bob.store)
        val engine = GroupEngine(counting, bob.signal, bob.identity, NullIo)
        val one = acceptance(mallory, 1)
        val facts = List(100) { one.wire() } + (1L..100L).map { since -> acceptance(mallory, since).wire() }
        now += GroupEngine.SEND_AGAIN_AFTER
        engine.onDirect(mallory.id, Content.GState(gid, NO_HEAD, facts = facts))
        assertTrue("${counting.loads} loads", counting.loads <= 5)
        // One walk back through the chain, not one per fact.
        assertTrue("${counting.history} history lookups", counting.history <= bob.roster(gid).roster.ver + 2)
    }

    /** A contact relays an invitation signed by a stranger: it isn't one, whatever name the stranger's card carries. */
    @Test
    fun anInvitationMustComeFromItsOwner() {
        val stranger = IdentityKeyPair.generate()
        val strangerId = B64.enc(stranger.publicKey.serialize())
        val r = Roster(
            g = gid, ver = 1, name = "Trip",
            members = listOf(RosterMember(strangerId, Role.OWNER, 1), RosterMember(bob.id, Role.INVITED, 1)), by = strangerId, ts = 1,
        )
        bob.engine.onDirect(mallory.id, rosterState(GroupCrypto.signRoster(stranger.privateKey, r)))
        assertNull(bob.store.load(gid))
        // From its owner, over 1:1, it is.
        alice.create(gid, "Trip", bob)
        net.deliverAll()
        assertEquals(alice.id, bob.model(gid).invitedBy)
    }

    /**
     * Bob's invitation from Alice is pending; Mallory, who knows the group, signs a roster further on that makes her the
     * owner and invites Bob again. It isn't taken: only the owner Bob knows can invite him again.
     */
    @Test
    fun aContactCantTakeOverAPendingInvitation() {
        alice.create(gid, "Trip", bob, mallory)
        net.deliverAll()
        val before = bob.roster(gid)
        val takeover = takeover(before)
        bob.engine.onDirect(mallory.id, rosterState(takeover))
        net.deliverAll()
        assertEquals(before.hashB64, bob.roster(gid).hashB64)
        assertEquals(alice.id, bob.model(gid).invitedBy)
        assertEquals(GroupModel.INVITED, bob.model(gid).state)
        // The same once he's left: it's still not an invitation.
        bob.leave(gid)
        net.deliverAll()
        bob.engine.onDirect(mallory.id, rosterState(takeover))
        assertEquals(GroupModel.LEFT, bob.model(gid).state)
        assertEquals(before.hashB64, bob.roster(gid).hashB64)
    }

    /** The real owner's re-invitation, past a gap, still is one. */
    @Test
    fun theOwnersReinvitationPastAGapStands() {
        alice.create(gid, "Trip", bob, carol)
        net.deliverAll()
        bob.join(gid)
        carol.join(gid)
        net.deliverAll()
        bob.leave(gid)
        net.deliverAll()
        alice.publish(gid, RosterOp.Meta(name = "Trip 2"))
        alice.publish(gid, RosterOp.Add(listOf(bob.id)))
        net.queue.clear()
        bob.engine.onDirect(alice.id, rosterState(alice.roster(gid)))
        assertEquals(GroupModel.INVITED, bob.model(gid).state)
        assertEquals(alice.roster(gid).hashB64, bob.roster(gid).hashB64)
    }

    /** A roster at [base]'s version + 2 signed by Mallory, who makes herself its owner and invites Bob again. */
    private fun takeover(base: SignedRoster): SignedRoster {
        val r = base.roster
        val members = r.members.map {
            when (it.id) {
                mallory.id -> it.copy(role = Role.OWNER)
                alice.id -> it.copy(role = Role.MEMBER)
                bob.id -> it.copy(since = r.ver + 2)
                else -> it
            }
        }
        val forged = r.copy(ver = r.ver + 2, prev = B64.enc(Rand.bytes(32)), members = members, by = mallory.id, ts = 2)
        assertTrue(RosterRules.wellFormed(forged, gid))
        return GroupCrypto.signRoster(mallory.identity.privateKey, forged)
    }

    /** Bob leaves after the one who invited him was removed: what he sends on leaving doesn't go to her. */
    @Test
    fun leavingTellsNobodyWhoIsOut() {
        alice.create(gid, "Trip", bob, carol)
        net.deliverAll()
        bob.join(gid)
        carol.join(gid)
        net.deliverAll()
        alice.publish(gid, RosterOp.MakeOwner(carol.id))
        net.deliverAll()
        carol.publish(gid, RosterOp.Remove(listOf(alice.id)))
        net.deliverAll()
        assertEquals(GroupModel.REMOVED, alice.model(gid).state)
        bob.leave(gid)
        assertTrue(queuedTo(alice).isEmpty())
        assertTrue(queuedTo(carol).isNotEmpty())
    }

    /**
     * Carol rotates her card a few times, leaves, and is invited back; her new stint's card has a lower seq. Mallory sends
     * Bob Carol's last card from before: it's for a stint that's over, and doesn't replace the new one.
     */
    @Test
    fun aCardFromAnEarlierStintDoesNotReplaceTheNewOne() {
        alice.create(gid, "Trip", bob, carol, mallory)
        net.deliverAll()
        bob.join(gid)
        carol.join(gid)
        mallory.join(gid)
        net.deliverAll()
        repeat(3) {
            val prev = carol.model(gid).myCard!!.card
            carol.engine.updateCard(carol.model(gid), carol.card(gid, prev.seq + 1, prev.bundle))
            net.deliverAll()
        }
        val old = carol.model(gid).myCard!!
        assertEquals(old.card.seq, bob.model(gid).cards[carol.id]!!.card.seq)
        carol.leave(gid)
        net.deliverAll()
        alice.publish(gid, RosterOp.Add(listOf(carol.id)))
        net.deliverAll()
        assertTrue(carol.engine.join(carol.model(gid), carol.card(gid, 1)))
        net.deliverAll()
        val fresh = bob.model(gid).cards[carol.id]!!
        assertEquals(carol.model(gid).since, fresh.card.since)
        bob.engine.onDirect(mallory.id, cardState(old))
        mallory.sendWithCard(mallory.model(gid).cards[bob.id]!!.card, cardState(old))
        net.deliverAll()
        assertTrue(bob.model(gid).cards[carol.id]!!.bytes.contentEquals(fresh.bytes))
        bob.say(gid, "still there?")
        net.deliverAll()
        assertTrue(texts(carol).contains("still there?"))
    }

    /** A card for a stint other than the one it's used in is refused when joining. */
    @Test
    fun joiningTakesACardForThisStintOnly() {
        alice.create(gid, "Trip", bob)
        net.deliverAll()
        assertFalse(bob.engine.join(bob.model(gid), bob.card(gid, 1, since = 7)))
        assertTrue(bob.engine.join(bob.model(gid), bob.card(gid, 1)))
    }

    /**
     * Carol, a newcomer, writes before Bob has the roster that lists her: Bob reads it without a session and holds it.
     * Once she's listed it's delivered, and the server delivering her blob again later shows nothing twice.
     */
    @Test
    fun aMessageReadBeforeItsSenderWasListedCantBeReplayed() {
        alice.create(gid, "Trip", bob)
        net.deliverAll()
        bob.join(gid)
        net.deliverAll()
        alice.publish(gid, RosterOp.Add(listOf(carol.id)))
        // Bob misses what Alice sends him from here on, for now.
        val toBob = mutableListOf<GroupNet.Envelope>()
        net.filter = { e -> !(e.sender() == alice && e.receiver() == bob).also { if (it) toBob += e } }
        net.deliverAll()
        carol.join(gid)
        net.deliverAll()
        assertEquals(Role.MEMBER, carol.view(gid).role(carol.id))
        carol.say(gid, "first")
        val blobs = net.queue.filter { it.sender() == carol && it.receiver() == bob }
        net.deliverAll()
        assertTrue(texts(bob).isEmpty())
        net.filter = { true }
        net.queue.addAll(toBob)
        net.deliverAll()
        assertEquals(listOf("first"), texts(bob))
        // Bob replies, so his own session with Carol exists too; then the server sends her first blob again.
        bob.say(gid, "hi carol")
        net.deliverAll()
        for (e in blobs) {
            net.deliver(e)
        }
        assertEquals(listOf("first"), texts(bob))
        // And Carol's later messages still arrive.
        carol.say(gid, "second")
        net.deliverAll()
        assertEquals(listOf("first", "second"), texts(bob))
    }

    private fun GroupNet.Envelope.sender(): Peer = when (this) {
        is GroupNet.Envelope.ToInbox -> from
        is GroupNet.Envelope.Direct -> from
    }

    private fun GroupNet.Envelope.receiver(): Peer = when (this) {
        is GroupNet.Envelope.ToInbox -> to
        is GroupNet.Envelope.Direct -> to
    }

    /** Counts what the engine asks of the store. */
    private class CountingStore(private val inner: GroupStore) : GroupStore by inner {
        var loads = 0
        var history = 0

        override fun load(gid: String): GroupModel? {
            loads++
            return inner.load(gid)
        }

        override fun history(gid: String, hashB64: String) = inner.history(gid, hashB64).also { history++ }

        override fun historySince(gid: String, since: Long) = inner.historySince(gid, since).also { history += it.size }
    }

    private object NullIo : GroupIo {
        override fun sendGroup(gid: String, to: String, content: Content) = Unit
        override fun sendDirect(gid: String, to: String, content: Content): Boolean = true
        override fun onEvents(m: GroupModel, events: List<GroupEvent>) = Unit
        override fun onText(m: GroupModel, from: String, t: Content.GText) = Unit
        override fun onReceipt(m: GroupModel, from: String, r: Content.GReceipt) = Unit
        override fun onDelete(m: GroupModel, from: String, d: Content.GDelete) = Unit
        override fun rotateInbox(m: GroupModel) = Unit
        override fun validServer(url: String): Boolean = true
        override fun nowMillis(): Long = 1_800_000_000_000L
    }
}
