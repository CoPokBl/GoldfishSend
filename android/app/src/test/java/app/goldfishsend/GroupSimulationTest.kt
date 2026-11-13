package app.goldfishsend

import app.goldfishsend.group.GroupEvent
import app.goldfishsend.group.GroupModel
import app.goldfishsend.proto.B64
import app.goldfishsend.proto.Content
import app.goldfishsend.proto.Rand
import app.goldfishsend.proto.Role
import app.goldfishsend.proto.RosterOp
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Multi-party runs of the real group engine with real libsignal sessions and an in-memory server (docs/groups.md).
 * Alice knows Bob, Carol and Dave; Bob, Carol and Dave don't know each other.
 */
class GroupSimulationTest {
    private val net = GroupNet()
    private val alice = net.peer("alice")
    private val bob = net.peer("bob")
    private val carol = net.peer("carol")
    private val dave = net.peer("dave")
    private val gid = B64.enc(Rand.bytes(32))

    init {
        alice.befriend(bob)
        alice.befriend(carol)
        alice.befriend(dave)
    }

    private fun texts(p: Peer) = p.texts.filter { it.first == gid }.map { it.third }

    /** Alice creates the group with Bob and Carol, and both join. */
    private fun threeMembers() {
        alice.create(gid, "Trip", bob, carol)
        net.deliverAll()
        assertEquals(GroupModel.INVITED, bob.model(gid).state)
        assertEquals(GroupModel.INVITED, carol.model(gid).state)
        bob.join(gid)
        net.deliverAll()
        carol.join(gid)
        net.deliverAll()
    }

    private fun assertConverged(vararg peers: Peer) {
        val hashes = peers.map { it.roster(gid).hashB64 }.toSet()
        assertEquals("rosters differ: ${peers.map { it.name to it.roster(gid).roster.ver }}", 1, hashes.size)
    }

    @Test
    fun createInviteJoinAndMessageBetweenNonContacts() {
        threeMembers()
        assertConverged(alice, bob, carol)
        val r = alice.roster(gid).roster
        assertEquals(listOf(Role.ADMIN, Role.MEMBER, Role.MEMBER), listOf(alice.id, bob.id, carol.id).map { r.role(it) })
        // Everyone has everyone else's card.
        assertEquals(setOf(alice.id, carol.id), bob.model(gid).cards.keys)
        assertEquals(setOf(alice.id, bob.id), carol.model(gid).cards.keys)
        assertEquals(setOf(bob.id, carol.id), alice.model(gid).cards.keys)

        // Bob and Carol aren't contacts, yet they talk both ways (PQXDH sessions from each other's cards).
        bob.say(gid, "hi from bob")
        net.deliverAll()
        carol.say(gid, "hi from carol")
        net.deliverAll()
        alice.say(gid, "hi from alice")
        net.deliverAll()
        assertEquals(listOf("hi from bob", "hi from alice"), texts(carol))
        assertEquals(listOf("hi from carol", "hi from alice"), texts(bob))
        assertEquals(listOf("hi from bob", "hi from carol"), texts(alice))
        assertTrue(bob.events.any { it.second == GroupEvent.Invited(alice.id) })
        assertTrue(alice.events.any { it.second == GroupEvent.Joined(carol.id) })
    }

    @Test
    fun longMessagesAreChunkedAndReassembled() {
        threeMembers()
        val long = "x".repeat(9000)
        bob.say(gid, long)
        net.deliverAll()
        assertEquals(listOf(long), texts(carol))
    }

    @Test
    fun concurrentAdminChangesConvergeAndBothSurvive() {
        threeMembers()
        alice.publish(gid, RosterOp.SetRole(bob.id, Role.ADMIN))
        net.deliverAll()
        assertTrue(bob.roster(gid).roster.isAdmin(bob.id))
        // Both admins change the roster before seeing each other's change.
        assertNotNull(alice.publish(gid, RosterOp.Meta(name = "Road trip")))
        assertNotNull(bob.publish(gid, RosterOp.Meta(timer = 3600)))
        net.deliverAll()
        assertConverged(alice, bob, carol)
        val r = carol.roster(gid).roster
        // The loser re-applied its change on top of the winner, so both are in.
        assertEquals("Road trip", r.name)
        assertEquals(3600L, r.timer)
        assertTrue(r.ver >= 4)
    }

    @Test
    fun removalRotatesInboxesAndDropsTheRemovedMembersMessages() {
        threeMembers()
        bob.say(gid, "before")
        net.deliverAll()
        val bobsOldCard = carol.model(gid).cards[bob.id]!!.card
        val alicesOldCard = carol.model(gid).cards[alice.id]!!.card
        alice.publish(gid, RosterOp.Remove(listOf(carol.id)))
        net.deliverAll()
        assertEquals(GroupModel.REMOVED, carol.model(gid).state)
        assertTrue(carol.events.any { it.second == GroupEvent.YouWereRemoved(alice.id) })
        assertConverged(alice, bob)
        assertEquals(listOf(alice.id, bob.id), bob.roster(gid).roster.ids())
        // The remaining members moved to new inboxes (new cards) and told each other.
        assertEquals(2L, alice.model(gid).cards[bob.id]!!.card.seq)
        assertEquals(2L, bob.model(gid).cards[alice.id]!!.card.seq)
        assertTrue(bob.model(gid).cards[alice.id]!!.card.inbox.sendSecret != alicesOldCard.inbox.sendSecret)

        // Carol keeps sending to the old (still draining) inboxes: it's dropped, she's not a member.
        val before = texts(bob).size
        carol.sendWithCard(bobsOldCard, Content.GText(gid, "z", "still here?", 0))
        carol.sendWithCard(alicesOldCard, Content.GText(gid, "z", "still here?", 0))
        net.deliverAll()
        assertEquals(before, texts(bob).size)
        assertFalse(texts(alice).contains("still here?"))

        // The others carry on.
        alice.say(gid, "after")
        net.deliverAll()
        assertEquals("after", texts(bob).last())
    }

    @Test
    fun leaveStopsTrafficAndUpdatesEveryone() {
        threeMembers()
        bob.engine.leave(bob.model(gid))
        net.deliverAll()
        assertEquals(GroupModel.LEFT, bob.model(gid).state)
        assertTrue(alice.events.any { it.second == GroupEvent.Left(bob.id) })
        assertEquals(listOf(alice.id, carol.id), carol.roster(gid).roster.ids())
        assertFalse(carol.model(gid).cards.containsKey(bob.id))
        alice.say(gid, "bye bob")
        net.deliverAll()
        assertFalse(texts(bob).contains("bye bob"))
        assertTrue(texts(carol).contains("bye bob"))
    }

    @Test
    fun lastAdminMustPromoteBeforeLeaving() {
        threeMembers()
        assertFalse(alice.engine.leave(alice.model(gid)))
        alice.publish(gid, RosterOp.SetRole(carol.id, Role.ADMIN))
        net.deliverAll()
        assertTrue(alice.engine.leave(alice.model(gid)))
        net.deliverAll()
        assertTrue(carol.roster(gid).roster.isAdmin(carol.id))
        assertEquals(listOf(bob.id, carol.id), bob.roster(gid).roster.ids())
    }

    @Test
    fun declineRemovesTheInvitee() {
        alice.create(gid, "Trip", bob, carol)
        net.deliverAll()
        bob.join(gid)
        net.deliverAll()
        carol.engine.leave(carol.model(gid))
        net.deliverAll()
        assertConverged(alice, bob)
        assertEquals(listOf(alice.id, bob.id), alice.roster(gid).roster.ids())
    }

    @Test
    fun missedRostersAreRecoveredWithSync() {
        threeMembers()
        // Bob misses everything Alice sends for a while: Dave's invitation and Carol's promotion.
        net.filter = { e -> !(e is GroupNet.Envelope.ToInbox && e.to == bob && e.from == alice) }
        alice.publish(gid, RosterOp.Add(listOf(dave.id)))
        net.deliverAll()
        dave.join(gid)
        net.filter = { e -> !(e is GroupNet.Envelope.ToInbox && e.to == bob && e.from == alice) && !(e.to() == bob && e.from() == dave) }
        net.deliverAll()
        alice.publish(gid, RosterOp.SetRole(carol.id, Role.ADMIN))
        net.deliverAll()
        assertTrue(net.dropped > 0)
        assertTrue(bob.roster(gid).roster.ver < alice.roster(gid).roster.ver)
        // Connectivity is back: Alice's next change skips versions for Bob, who asks for the history.
        net.filter = { true }
        alice.publish(gid, RosterOp.Meta(name = "Trip 2"))
        net.deliverAll()
        assertConverged(alice, bob, carol, dave)
        assertTrue(bob.model(gid).cards.containsKey(dave.id))
        dave.say(gid, "hello all")
        net.deliverAll()
        assertTrue(texts(bob).contains("hello all"))
        bob.say(gid, "hi dave")
        net.deliverAll()
        assertTrue(texts(dave).contains("hi dave"))
    }

    /**
     * Found on the emulator: Bob joins (v2) while Carol, still invited, never hears about it. Carol then joins on top of v1,
     * so her acceptance is a concurrent v2 that may lose the tie. Whichever wins, everyone must end up agreeing that Bob
     * and Carol are both members, and Bob and Carol must be able to talk, even when the first thing Carol hears afterwards is
     * a later roster from Alice. Repeated so both tie outcomes are covered.
     */
    @Test
    fun aLateJoinOnAStaleRosterStillLands() {
        repeat(8) { run ->
            val net = GroupNet()
            val a = net.peer("alice")
            val b = net.peer("bob")
            val c = net.peer("carol")
            a.befriend(b)
            a.befriend(c)
            val g = B64.enc(Rand.bytes(32))
            a.create(g, "Trip", b, c)
            net.deliverAll()
            // Carol hears nothing from Alice while Bob joins.
            net.filter = { e -> !(e.to() == c && e.from() == a) }
            b.join(g)
            net.deliverAll()
            assertEquals(1L, c.roster(g).roster.ver)
            // Carol joins, but Alice's replies (including the sync answer) are lost too.
            c.join(g)
            net.deliverAll()
            // Connectivity is back. Alice's next change is the first thing Carol hears from her.
            net.filter = { true }
            a.publish(g, RosterOp.Meta(name = "Trip $run"))
            net.deliverAll()
            val hashes = listOf(a, b, c).map { it.roster(g).hashB64 }.toSet()
            assertEquals("run $run: rosters differ: ${listOf(a, b, c).map { it.roster(g).roster.ver }}", 1, hashes.size)
            val r = a.roster(g).roster
            assertEquals("run $run", listOf(Role.ADMIN, Role.MEMBER, Role.MEMBER), listOf(a.id, b.id, c.id).map { r.role(it) })
            b.say(g, "hi carol")
            c.say(g, "hi bob")
            net.deliverAll()
            assertTrue("run $run", c.texts.any { it.first == g && it.third == "hi carol" })
            assertTrue("run $run", b.texts.any { it.first == g && it.third == "hi bob" })
        }
    }

    /** A new member's first message can overtake their acceptance (pushes aren't ordered). It must wait, not be dropped. */
    @Test
    fun aMessageThatOvertakesTheSendersJoinIsKept() {
        alice.create(gid, "Trip", bob, carol)
        net.deliverAll()
        bob.join(gid)
        net.deliverAll()
        // Carol joins and speaks at once, but Bob gets her text before anything telling him she joined.
        carol.join(gid)
        carol.say(gid, "first words")
        net.reorder = { batch -> batch.sortedBy { e -> if (e.to() == bob && e.from() == carol) 0 else 1 } }
        net.deliverAll()
        net.reorder = null
        net.deliverAll()
        assertConverged(alice, bob, carol)
        assertTrue(texts(bob).contains("first words"))
        assertTrue(texts(alice).contains("first words"))
    }

    @Test
    fun nonAdminsCantChangeMembership() {
        threeMembers()
        // Carol's client is modified: it signs a roster removing Bob and sends it to everyone.
        assertEquals(null, carol.publish(gid, RosterOp.Remove(listOf(bob.id))))
        val base = carol.roster(gid)
        val forged = app.goldfishsend.proto.RosterRules.successor(
            base, base.roster.copy(members = base.roster.members.filter { it.id != bob.id }), carol.id, 0,
        )
        val signed = app.goldfishsend.proto.GroupCrypto.signRoster(carol.identity.privateKey, forged)
        for (to in listOf(alice, bob)) {
            carol.sendGroup(gid, to.id, app.goldfishsend.group.GroupEngine.rosterContent(signed))
        }
        net.deliverAll()
        assertEquals(3, alice.roster(gid).roster.members.size)
        assertEquals(3, bob.roster(gid).roster.members.size)
        assertEquals(GroupModel.JOINED, bob.model(gid).state)
    }

    private fun GroupNet.Envelope.to(): Peer = when (this) {
        is GroupNet.Envelope.ToInbox -> to
        is GroupNet.Envelope.Direct -> to
    }

    private fun GroupNet.Envelope.from(): Peer = when (this) {
        is GroupNet.Envelope.ToInbox -> from
        is GroupNet.Envelope.Direct -> from
    }
}
