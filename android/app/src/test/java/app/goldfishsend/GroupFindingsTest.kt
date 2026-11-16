package app.goldfishsend

import app.goldfishsend.group.GroupEngine
import app.goldfishsend.group.GroupModel
import app.goldfishsend.proto.B64
import app.goldfishsend.proto.GroupCrypto
import app.goldfishsend.proto.Rand
import app.goldfishsend.proto.Role
import app.goldfishsend.proto.RosterOp
import app.goldfishsend.proto.SignedRoster
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

    private fun mine(p: Peer, by: Peer): SignedRoster = p.store.historySince(gid, 0).last { it.roster.by == by.id }

    private fun everyone(vararg ps: Peer, check: (Peer) -> Unit) = ps.forEach(check)

    /** Bob is an admin who never saw Dave's first stint, so an old acceptance replayed to him looked current. */
    @Test
    fun aReplayedOldAcceptanceDoesNotAdmitAnInvitee() {
        alice.create(gid, "Trip", bob, dave)
        net.deliverAll()
        bob.join(gid)
        dave.join(gid)
        net.deliverAll()
        val oldAcceptance = mine(alice, dave)
        alice.publish(gid, RosterOp.Remove(listOf(dave.id)))
        net.deliverAll()
        alice.publish(gid, RosterOp.Add(listOf(dave.id)))
        alice.publish(gid, RosterOp.SetRole(bob.id, Role.ADMIN))
        net.deliverAll()
        // Anyone who kept it (a member, a removed member) sends it to Bob again.
        bob.engine.onDirect(alice.id, GroupEngine.rosterContent(oldAcceptance))
        net.deliverAll()
        everyone(alice, bob) { assertEquals(it.name, Role.INVITED, it.roster(gid).roster.role(dave.id)) }
        assertEquals(GroupModel.INVITED, dave.model(gid).state)
        // And Dave can still join.
        dave.join(gid)
        net.deliverAll()
        everyone(alice, bob) { assertEquals(Role.MEMBER, it.roster(gid).roster.role(dave.id)) }
    }

    @Test
    fun aReplayedOldDepartureDoesNotRemoveAReturningMember() {
        alice.create(gid, "Trip", bob, carol)
        net.deliverAll()
        bob.join(gid)
        carol.join(gid)
        net.deliverAll()
        carol.engine.leave(carol.model(gid))
        net.deliverAll()
        val oldDeparture = mine(alice, carol)
        alice.publish(gid, RosterOp.Add(listOf(carol.id)))
        alice.publish(gid, RosterOp.SetRole(bob.id, Role.ADMIN))
        net.deliverAll()
        carol.join(gid)
        net.deliverAll()
        bob.engine.onDirect(alice.id, GroupEngine.rosterContent(oldDeparture))
        net.deliverAll()
        everyone(alice, bob, carol) { assertEquals(it.name, Role.MEMBER, it.roster(gid).roster.role(carol.id)) }
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
     * The same, when the withdrawal never reaches Bob (Carol, an admin who isn't his contact, removed him). He joins, and
     * the inviter's answer to his sync tells him. (Repeated: his acceptance and the removal are concurrent, and either can
     * have the larger hash.)
     */
    @Test
    fun joiningAWithdrawnInvitationEndsInRemoved() {
        repeat(8) {
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
            alice.publish(gid, RosterOp.SetRole(carol.id, Role.ADMIN))
            net.deliverAll()
            carol.publish(gid, RosterOp.Remove(listOf(bob.id)))
            net.deliverAll()
            assertEquals(GroupModel.INVITED, bob.model(gid).state)
            bob.join(gid)
            net.deliverAll()
            assertEquals(GroupModel.REMOVED, bob.model(gid).state)
            everyone(alice, carol) { p -> assertEquals(null, p.roster(gid).roster.role(bob.id)) }
        }
    }
}
