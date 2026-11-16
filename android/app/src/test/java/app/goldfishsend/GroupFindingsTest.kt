package app.goldfishsend

import app.goldfishsend.group.GroupEngine
import app.goldfishsend.group.GroupModel
import app.goldfishsend.proto.B64
import app.goldfishsend.proto.FactKind
import app.goldfishsend.proto.GroupCrypto
import app.goldfishsend.proto.Rand
import app.goldfishsend.proto.Role
import app.goldfishsend.proto.RosterOp
import app.goldfishsend.proto.SignedFact
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Bugs the group fuzzers found (fuzz/), written out as plain scenarios. */
class GroupFindingsTest {
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

    /** [p]'s own fact of [kind] (they hold it until it's folded into a roster). */
    private fun factOf(p: Peer, kind: String): SignedFact = p.model(gid).facts.last { it.fact.id == p.id && it.fact.kind == kind }

    private fun everyone(vararg ps: Peer, check: (Peer) -> Unit) = ps.forEach(check)

    /**
     * Bob (an admin then, the owner now) never saw Dave's first stint, so an old acceptance replayed to him looked
     * current. Facts name their stint: an old one does nothing.
     */
    @Test
    fun aReplayedOldAcceptanceDoesNotAdmitAnInvitee() {
        alice.create(gid, "Trip", bob, dave)
        net.deliverAll()
        bob.join(gid)
        dave.join(gid)
        val oldAcceptance = factOf(dave, FactKind.ACCEPT)
        net.deliverAll()
        alice.publish(gid, RosterOp.Remove(listOf(dave.id)))
        net.deliverAll()
        alice.publish(gid, RosterOp.Add(listOf(dave.id)))
        alice.publish(gid, RosterOp.MakeOwner(bob.id))
        net.deliverAll()
        // Anyone who kept it (a member, a removed member) sends it to Bob again.
        bob.engine.onDirect(alice.id, GroupEngine.factContent(oldAcceptance))
        net.deliverAll()
        everyone(alice, bob) { assertEquals(it.name, Role.INVITED, it.view(gid).role(dave.id)) }
        assertEquals(GroupModel.INVITED, dave.model(gid).state)
        // And Dave can still join.
        dave.join(gid)
        net.deliverAll()
        everyone(alice, bob) { assertEquals(Role.MEMBER, it.view(gid).role(dave.id)) }
    }

    @Test
    fun aReplayedOldDepartureDoesNotRemoveAReturningMember() {
        alice.create(gid, "Trip", bob, carol)
        net.deliverAll()
        bob.join(gid)
        carol.join(gid)
        net.deliverAll()
        carol.engine.leave(carol.model(gid))
        val oldDeparture = factOf(carol, FactKind.LEAVE)
        net.deliverAll()
        alice.publish(gid, RosterOp.Add(listOf(carol.id)))
        alice.publish(gid, RosterOp.MakeOwner(bob.id))
        net.deliverAll()
        carol.join(gid)
        net.deliverAll()
        bob.engine.onDirect(alice.id, GroupEngine.factContent(oldDeparture))
        net.deliverAll()
        everyone(alice, bob, carol) { assertEquals(it.name, Role.MEMBER, it.view(gid).role(carol.id)) }
    }

    /** Signed, so it passed every check, but no one could start a session from it. */
    @Test
    fun aCardWithSignedGarbagePrekeysIsRejected() {
        val good = bob.card(gid).card
        val junk = Rand.bytes(33)
        val bad = good.copy(bundle = good.bundle.copy(signedPreKey = B64.enc(junk), signedPreKeySig = B64.enc(bob.identity.privateKey.calculateSignature(junk))))
        val signed = GroupCrypto.signCard(bob.identity.privateKey, bad)
        assertNull(GroupCrypto.openCard(signed.bytes, signed.sig) { true })
        val ok = GroupCrypto.signCard(bob.identity.privateKey, good)
        assertTrue(GroupCrypto.openCard(ok.bytes, ok.sig) { true } != null)
    }

    /** 1:1 messages aren't ordered: the invitation can come before the inviter's card. Bob's card then went to no one. */
    @Test
    fun anInviteeWhoJoinsBeforeTheInvitersCardArrivesIsReachable() {
        alice.create(gid, "Trip", bob)
        // Bob has the invitation but not Alice's card yet when he joins.
        val late = mutableListOf<GroupNet.Envelope>()
        net.filter = { e -> !(e is GroupNet.Envelope.Direct && e.content is app.goldfishsend.proto.Content.GCard).also { if (it) late += e } }
        net.deliverAll()
        assertTrue(bob.model(gid).cards.isEmpty())
        bob.join(gid)
        net.filter = { true }
        net.queue.addAll(late)
        net.deliverAll()
        assertTrue(alice.model(gid).cards.containsKey(bob.id))
        alice.say(gid, "hi bob")
        net.deliverAll()
        assertTrue(bob.texts.any { it.third == "hi bob" })
    }

    /**
     * Alice invites Bob and takes it back at once, and the withdrawal reaches Bob first (1:1 messages aren't ordered). Bob
     * saw an invitation to a group he wasn't in; joining it, he was "in" for good: nobody told him otherwise, and his
     * messages were dropped.
     */
    @Test
    fun aWithdrawalThatOvertakesTheInvitationVoidsIt() {
        alice.create(gid, "Trip", bob, carol)
        alice.publish(gid, RosterOp.Remove(listOf(bob.id)))
        net.reorder = { batch -> batch.reversed() }
        net.deliverAll()
        assertNull(bob.store.load(gid))
    }

    /**
     * The same, when the withdrawal never reaches Bob (Carol, the owner now and not his contact, removed him). He joins,
     * and the inviter's answer to his sync tells him.
     */
    @Test
    fun joiningAWithdrawnInvitationEndsInRemoved() {
        repeat(2) {
            val net = GroupNet()
            val alice = net.peer("alice")
            val bob = net.peer("bob")
            val carol = net.peer("carol")
            alice.befriend(bob)
            alice.befriend(carol)
            alice.create(gid, "Trip", bob, carol)
            net.deliverAll()
            carol.join(gid)
            net.deliverAll()
            alice.publish(gid, RosterOp.MakeOwner(carol.id))
            net.deliverAll()
            carol.publish(gid, RosterOp.Remove(listOf(bob.id)))
            net.deliverAll()
            assertEquals(GroupModel.INVITED, bob.model(gid).state)
            bob.join(gid)
            net.deliverAll()
            assertEquals(GroupModel.REMOVED, bob.model(gid).state)
            everyone(alice, carol) { p -> assertEquals(null, p.view(gid).role(bob.id)) }
        }
    }

    /**
     * Once a fork rule's case: Bob's change raced Alice's, and his had to be re-signed on top of hers. Now only the owner
     * signs rosters (Bob can't), and what Bob and Carol do concurrently (leave, accept) are facts that stand on any roster.
     */
    @Test
    fun concurrentFactsAndTheOwnersChangesAllStand() {
        alice.create(gid, "Trip", bob, carol, dave)
        net.deliverAll()
        bob.join(gid)
        net.deliverAll()
        assertNull(bob.publish(gid, RosterOp.Meta(name = "Bob's")))
        // Nobody hears anyone else before they've all acted.
        val held = mutableListOf<GroupNet.Envelope>()
        net.filter = { e -> false.also { held += e } }
        alice.publish(gid, RosterOp.Meta(timer = 3600))
        alice.publish(gid, RosterOp.Remove(listOf(dave.id)))
        bob.leave(gid)
        carol.join(gid)
        net.deliverAll()
        net.filter = { true }
        net.queue.addAll(held.reversed())
        net.deliverAll()
        everyone(alice, carol) { p ->
            assertEquals(p.name, alice.roster(gid).hashB64, p.roster(gid).hashB64)
            assertEquals(3600L, p.view(gid).timer)
            assertEquals(listOf(alice.id, carol.id), p.view(gid).ids())
            assertEquals(Role.MEMBER, p.view(gid).role(carol.id))
        }
        assertEquals(GroupModel.LEFT, bob.model(gid).state)
        assertEquals(GroupModel.REMOVED, dave.model(gid).state)
    }

    /**
     * Mallory, removed, forks from the roster before her removal: a long chain of renames she signs herself. Only the
     * owner signs rosters, so none of it counts; the removal stands, and it costs little traffic.
     */
    @Test
    fun aRemovedMembersForkCantUndoTheRemoval() {
        val mallory = net.peer("mallory")
        alice.befriend(mallory)
        alice.create(gid, "Trip", bob, mallory)
        net.deliverAll()
        bob.join(gid)
        mallory.join(gid)
        net.deliverAll()
        val before = mallory.roster(gid)
        val routes = mallory.store.routes[gid].orEmpty().filterKeys { it != mallory.id }
        alice.publish(gid, RosterOp.Remove(listOf(mallory.id)))
        net.deliverAll()
        var tip = before
        val chain = (1..6).map { i ->
            val change = tip.roster.copy(name = "Mine $i")
            GroupCrypto.signRoster(mallory.identity.privateKey, app.goldfishsend.proto.RosterRules.successor(tip, change, mallory.id, 99L, emptyList()))
                .also { tip = it }
        }
        val sent = net.delivered
        for (r in chain) {
            for ((_, card) in routes) {
                mallory.sendWithCard(card.card, GroupEngine.rosterContent(r))
            }
        }
        net.deliverAll()
        everyone(alice, bob) { p ->
            assertNull(p.name, p.view(gid).role(mallory.id))
            assertEquals(alice.roster(gid).hashB64, p.roster(gid).hashB64)
        }
        // Mallory's own sends, and nothing much in reply.
        assertTrue("${net.delivered - sent} deliveries", net.delivered - sent <= chain.size * routes.size + 10)
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
