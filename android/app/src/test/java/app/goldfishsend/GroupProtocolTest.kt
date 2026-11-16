package app.goldfishsend

import app.goldfishsend.net.BatchItem
import app.goldfishsend.net.MessageBatch
import app.goldfishsend.proto.B64
import app.goldfishsend.proto.Chunker
import app.goldfishsend.proto.Content
import app.goldfishsend.proto.Fact
import app.goldfishsend.proto.FactKind
import app.goldfishsend.proto.GroupBlob
import app.goldfishsend.proto.GroupCrypto
import app.goldfishsend.proto.GroupJson
import app.goldfishsend.proto.Membership
import app.goldfishsend.proto.Padding
import app.goldfishsend.proto.Rand
import app.goldfishsend.proto.Role
import app.goldfishsend.proto.Roster
import app.goldfishsend.proto.RosterMember
import app.goldfishsend.proto.RosterOp
import app.goldfishsend.proto.RosterRules
import app.goldfishsend.proto.Signed
import app.goldfishsend.proto.SignedFact
import app.goldfishsend.proto.SignedRoster
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.signal.libsignal.protocol.IdentityKeyPair

/** Group wire formats, roster rules and facts (docs/groups.md). */
class GroupProtocolTest {
    private val a = IdentityKeyPair.generate()
    private val b = IdentityKeyPair.generate()
    private val c = IdentityKeyPair.generate()
    private val ida = B64.enc(a.publicKey.serialize())
    private val idb = B64.enc(b.publicKey.serialize())
    private val idc = B64.enc(c.publicKey.serialize())
    private val g = B64.enc(Rand.bytes(32))

    private fun roster(
        ver: Long = 1,
        prev: String = "",
        by: String = ida,
        members: List<RosterMember> = listOf(RosterMember(ida, Role.OWNER, 1), RosterMember(idb, Role.MEMBER, 1), RosterMember(idc, Role.INVITED, 1)),
        name: String = "Group",
        timer: Long = 0,
    ) = Roster(g = g, ver = ver, prev = prev, name = name, timer = timer, members = members, by = by, ts = 1)

    private fun keyOf(id: String) = when (id) {
        ida -> a
        idb -> b
        else -> c
    }

    private fun signed(r: Roster) = GroupCrypto.signRoster(keyOf(r.by).privateKey, r)

    private fun next(base: SignedRoster, change: (Roster) -> Roster, by: String = ida, proof: List<SignedFact> = emptyList()): SignedRoster =
        signed(RosterRules.successor(base, change(base.roster), by, 2, proof.map { it.wire() }))

    private fun fact(id: String, kind: String, since: Long = 1, last: SignedRoster? = null) =
        GroupCrypto.signFact(keyOf(id).privateKey, Fact(g = g, kind = kind, id = id, since = since, ts = 1, last = last?.wire()))

    // --- signatures ---

    @Test
    fun rosterSignatureIsCheckedOnTheExactBytes() {
        val s = signed(roster())
        val opened = GroupCrypto.openRoster(s.bytes, s.sig)
        assertNotNull(opened)
        assertEquals(s.hashB64, opened!!.hashB64)
        val tampered = s.bytes.toString(Charsets.UTF_8).replace("\"Group\"", "\"Evil\"").toByteArray()
        assertNull(GroupCrypto.openRoster(tampered, s.sig))
        // Signed by someone other than `by`.
        val forged = GroupCrypto.signRoster(b.privateKey, roster(by = ida))
        assertNull(GroupCrypto.openRoster(forged.bytes, forged.sig))
    }

    @Test
    fun factSignatureAndFormAreChecked() {
        val f = fact(idb, FactKind.LEAVE)
        assertNotNull(GroupCrypto.openFact(f.bytes, f.sig))
        // Signed by someone other than its member.
        val forged = GroupCrypto.signFact(a.privateKey, f.fact)
        assertNull(GroupCrypto.openFact(forged.bytes, forged.sig))
        // A kind we don't know, a stint before the first roster, a roster on an acceptance, an unreadable roster.
        for (bad in listOf(f.fact.copy(kind = "own"), f.fact.copy(since = 0), f.fact.copy(kind = FactKind.ACCEPT, last = signed(roster()).wire()),
            f.fact.copy(last = Signed("AAAA", "AAAA")))) {
            val x = GroupCrypto.signFact(b.privateKey, bad)
            assertNull(GroupCrypto.openFact(x.bytes, x.sig))
        }
    }

    @Test
    fun cardSignatureBundleAndFieldsAreChecked() {
        val alice = Peer("alice", GroupNet())
        val card = alice.card(g)
        assertNotNull(GroupCrypto.openCard(card.bytes, card.sig) { it.startsWith("https://") })
        // Server rule applied.
        assertNull(GroupCrypto.openCard(card.bytes, card.sig) { false })
        // Tampered card.
        val tampered = card.bytes.toString(Charsets.UTF_8).replace("\"seq\":1", "\"seq\":9").toByteArray()
        assertNull(GroupCrypto.openCard(tampered, card.sig) { true })
        // A validly signed card whose prekey signature is bad.
        val bad = card.card.copy(bundle = card.card.bundle.copy(kyberPreKeySig = card.card.bundle.signedPreKeySig))
        val resigned = GroupCrypto.signCard(alice.identity.privateKey, bad)
        assertNull(GroupCrypto.openCard(resigned.bytes, resigned.sig) { true })
        // A card signed by someone else than its `id`.
        val stolen = GroupCrypto.signCard(b.privateKey, card.card)
        assertNull(GroupCrypto.openCard(stolen.bytes, stolen.sig) { true })
    }

    @Test
    fun hintIdentifiesTheSenderOnly() {
        val key = Rand.bytes(32)
        val nonce = Rand.bytes(16)
        val h = GroupCrypto.hint(key, nonce, a.publicKey.serialize())
        assertEquals(16, h.size)
        assertArrayEquals(h, GroupCrypto.hint(key, nonce, a.publicKey.serialize()))
        assertFalse(h.contentEquals(GroupCrypto.hint(key, nonce, b.publicKey.serialize())))
        assertFalse(h.contentEquals(GroupCrypto.hint(key, Rand.bytes(16), a.publicKey.serialize())))
        assertFalse(h.contentEquals(GroupCrypto.hint(Rand.bytes(32), nonce, a.publicKey.serialize())))
    }

    @Test
    fun blobFormat() {
        val body = Rand.bytes(100)
        val blob = GroupBlob(3, Rand.bytes(16), Rand.bytes(16), body).encode()
        assertEquals(0x13.toByte(), blob[0])
        assertTrue(GroupBlob.isGroup(blob))
        val back = GroupBlob.decode(blob)!!
        assertEquals(3, back.type)
        assertArrayEquals(body, back.body)
        assertNull(GroupBlob.decode(byteArrayOf(0x03) + Rand.bytes(60)))
        assertNull(GroupBlob.decode(byteArrayOf(0x12) + Rand.bytes(32)))
        assertEquals(0x12.toByte(), GroupBlob(2, Rand.bytes(16), Rand.bytes(16), body).encode()[0])
    }

    @Test
    fun addressesNeverCollideWithContacts() {
        val addr = GroupCrypto.address(ida)
        assertTrue(addr.name.startsWith("m"))
        assertEquals(1, addr.deviceId)
        assertFalse(addr.name == GroupCrypto.address(idb).name)
    }

    // --- structure ---

    @Test
    fun wellFormed() {
        assertTrue(RosterRules.wellFormed(roster(), g))
        assertFalse(RosterRules.wellFormed(roster(), B64.enc(Rand.bytes(32))))
        // Exactly one owner.
        assertFalse(RosterRules.wellFormed(roster(members = listOf(RosterMember(ida, Role.MEMBER, 1))), g))
        assertFalse(RosterRules.wellFormed(roster(members = listOf(RosterMember(ida, Role.OWNER, 1), RosterMember(idb, Role.OWNER, 1))), g))
        assertFalse(RosterRules.wellFormed(roster(members = listOf(RosterMember(ida, Role.OWNER, 1), RosterMember(ida, Role.MEMBER, 1))), g))
        assertFalse(RosterRules.wellFormed(roster(members = listOf(RosterMember(ida, "admin", 1))), g))
        assertFalse(RosterRules.wellFormed(roster(members = listOf(RosterMember(ida, Role.OWNER, 1), RosterMember("junk", Role.MEMBER, 1))), g))
        // A stint can't start after the roster, or before the first.
        assertFalse(RosterRules.wellFormed(roster(members = listOf(RosterMember(ida, Role.OWNER, 2))), g))
        assertFalse(RosterRules.wellFormed(roster(members = listOf(RosterMember(ida, Role.OWNER, 0))), g))
        assertFalse(RosterRules.wellFormed(roster(name = "   "), g))
        assertFalse(RosterRules.wellFormed(roster(timer = -1), g))
        assertFalse(RosterRules.wellFormed(roster(ver = 2, prev = ""), g))
        // The first roster is its owner's own.
        assertFalse(RosterRules.wellFormed(roster(by = idb), g))
        val many = listOf(RosterMember(ida, Role.OWNER, 1)) + (1..100).map { RosterMember(B64.enc(IdentityKeyPair.generate().publicKey.serialize()), Role.MEMBER, 1) }
        assertFalse(RosterRules.wellFormed(roster(members = many), g))
        assertTrue(RosterRules.wellFormed(roster(members = many.take(100)), g))
    }

    // --- authority and succession ---

    @Test
    fun onlyTheOwnerSignsTheNextRoster() {
        val v1 = signed(roster())
        val v2 = next(v1, { it.copy(name = "Renamed") })
        assertTrue(RosterRules.validChild(v1.roster, v2.roster, emptyList()))
        assertFalse(RosterRules.validChild(v2.roster, v1.roster, emptyList()))
        // Skipping versions isn't a child.
        assertFalse(RosterRules.validChild(v1.roster, v2.roster.copy(ver = 5), emptyList()))
        // A member can't sign one, not even to leave or rename; an invitee can't either.
        assertFalse(RosterRules.validChild(v1.roster, next(v1, { it.copy(name = "Mine") }, by = idb).roster, emptyList()))
        assertFalse(RosterRules.validChild(v1.roster, next(v1, { r -> r.copy(members = r.members.filter { it.id != idc }) }, by = idc).roster, emptyList()))
        // Stints carry over; a new one starts at the roster's version, as an invitation.
        assertFalse(RosterRules.validChild(v1.roster, next(v1, { r -> r.copy(members = r.members.map { if (it.id == idb) it.copy(since = 2) else it }) }).roster, emptyList()))
        val stranger = B64.enc(IdentityKeyPair.generate().publicKey.serialize())
        assertTrue(RosterRules.validChild(v1.roster, next(v1, { r -> r.copy(members = r.members + RosterMember(stranger, Role.INVITED, 2)) }).roster, emptyList()))
        assertFalse(RosterRules.validChild(v1.roster, next(v1, { r -> r.copy(members = r.members + RosterMember(stranger, Role.MEMBER, 2)) }).roster, emptyList()))
    }

    @Test
    fun theNextMemberTakesOverFromAnOwnerWhoLeft() {
        val v1 = signed(roster())
        val aLeft = fact(ida, FactKind.LEAVE)
        // Bob is next: with Alice's departure as proof, his roster follows.
        val takeover = next(v1, { r -> r.copy(members = r.members.filter { it.id != ida }.map { if (it.id == idb) it.copy(role = Role.OWNER) else it }) }, by = idb, proof = listOf(aLeft))
        assertTrue(RosterRules.validChild(v1.roster, takeover.roster, listOf(aLeft.fact)))
        // Not without the proof, and not with a proof that still lists her.
        assertFalse(RosterRules.validChild(v1.roster, takeover.roster, emptyList()))
        val keeps = next(v1, { r -> r.copy(members = r.members.map { if (it.id == idb) it.copy(role = Role.OWNER) else if (it.id == ida) it.copy(role = Role.MEMBER) else it }) }, by = idb, proof = listOf(aLeft))
        assertFalse(RosterRules.validChild(v1.roster, keeps.roster, listOf(aLeft.fact)))
        // Carol (invited) is never next, even if she accepted: only departures decide who is.
        val cTakes = next(v1, { r -> r.copy(members = r.members.filter { it.id != ida }) }, by = idc, proof = listOf(aLeft))
        assertFalse(RosterRules.validChild(v1.roster, cTakes.roster, listOf(aLeft.fact)))
        assertEquals(idb, Membership.owner(v1.roster, listOf(aLeft.fact, fact(idc, FactKind.ACCEPT).fact)))
        // Bob's departure as well: nobody's next (Carol is still invited).
        assertNull(Membership.owner(v1.roster, listOf(aLeft.fact, fact(idb, FactKind.LEAVE).fact)))
        // Someone's own departure is no proof they're next.
        val bLeft = fact(idb, FactKind.LEAVE)
        assertFalse(RosterRules.validChild(v1.roster, next(v1, { it.copy(name = "x") }, by = idb, proof = listOf(bLeft)).roster, listOf(bLeft.fact)))
    }

    @Test
    fun factsApplyToTheirStintOnly() {
        val v1 = roster()
        val v = Membership.view(v1, listOf(fact(idb, FactKind.LEAVE).fact, fact(idc, FactKind.ACCEPT).fact))
        assertNull(v.role(idb))
        assertEquals(Role.MEMBER, v.role(idc))
        assertEquals(ida, v.owner)
        // A fact about another stint (an old one, replayed) doesn't apply; nor does accepting as a member.
        val later = v1.copy(ver = 5, members = v1.members.map { if (it.id == idb) it.copy(since = 4) else it })
        assertFalse(Membership.applies(later, fact(idb, FactKind.LEAVE).fact))
        assertTrue(Membership.stale(later, fact(idb, FactKind.LEAVE).fact))
        assertFalse(Membership.applies(v1, fact(idb, FactKind.ACCEPT).fact))
        // One about a stint our roster doesn't reach yet isn't stale: it waits.
        assertFalse(Membership.stale(v1, fact(idb, FactKind.LEAVE, since = 3).fact))
        // A departure carrying a roster newer than ours waits for ours to catch up.
        val v3 = signed(roster(ver = 3, prev = "x"))
        assertFalse(Membership.applies(v1, fact(idb, FactKind.LEAVE, last = v3).fact))
        assertFalse(Membership.stale(v1, fact(idb, FactKind.LEAVE, last = v3).fact))
        assertTrue(Membership.applies(v1.copy(ver = 3), fact(idb, FactKind.LEAVE, last = v3).fact))
    }

    @Test
    fun foldingTakesTheFactsIn() {
        val v1 = roster()
        val facts = listOf(fact(ida, FactKind.LEAVE).fact, fact(idc, FactKind.ACCEPT).fact)
        val folded = Membership.fold(v1, facts, idb)
        assertEquals(listOf(RosterMember(idb, Role.OWNER, 1), RosterMember(idc, Role.MEMBER, 1)), folded.members)
        assertEquals(listOf(ida), Membership.departures(v1, facts).map { it.id })
    }

    @Test
    fun opsApply() {
        val r = roster()
        val stranger = B64.enc(IdentityKeyPair.generate().publicKey.serialize())
        assertEquals(RosterMember(stranger, Role.INVITED, 2), RosterOp.Add(listOf(stranger)).apply(r, ida, 2)!!.members.last())
        assertNull(RosterOp.Add(listOf(idb)).apply(r, ida, 2))
        assertNull(RosterOp.Remove(listOf(ida)).apply(r, ida, 2))
        assertEquals(2, RosterOp.Remove(listOf(idb)).apply(r, ida, 2)!!.members.size)
        // Ownership goes to a member, not an invitee; the old owner stays on as a member.
        assertNull(RosterOp.MakeOwner(idc).apply(r, ida, 2))
        val handed = RosterOp.MakeOwner(idb).apply(r, ida, 2)!!
        assertEquals(idb, handed.owner)
        assertEquals(Role.MEMBER, handed.role(ida))
        assertNull(RosterOp.MakeOwner(idc).apply(handed, idb, 3))
        assertNull(RosterOp.MakeOwner(idc).apply(handed, ida, 3))
        assertNull(RosterOp.Meta(name = "Group").apply(r, ida, 2))
        assertEquals(60L, RosterOp.Meta(timer = 60).apply(r, ida, 2)!!.timer)
    }

    @Test
    fun rosterJsonIsCanonical() {
        val r = roster()
        val json = GroupJson.encodeToString(Roster.serializer(), r)
        assertTrue(json.contains("\"v\":2"))
        assertTrue(json.contains("\"proof\":[]"))
        assertTrue(json.contains("\"since\":1"))
    }

    // --- chunking and batches ---

    @Test
    fun anyContentChunksAndReassembles() {
        val big = Content.GCard(g, B64.enc(Rand.bytes(5000)), B64.enc(Rand.bytes(64)))
        val parts = Chunker.splitContent(big, Padding.MAX_PREKEY_PLAINTEXT)
        assertTrue(parts.size > 1)
        for (p in parts) {
            assertTrue(p is Content.Chunk)
            assertTrue(Padding.paddedSize(p.encode().size) <= Padding.MAX_PREKEY_PLAINTEXT)
        }
        val joined = parts.joinToString("") { (it as Content.Chunk).data }
        assertEquals(big, Content.decode(B64.dec(joined)))
        val small = Content.GLeave(g)
        assertEquals(listOf(small), Chunker.splitContent(small, Padding.MAX_PREKEY_PLAINTEXT))
    }

    @Test
    fun batchEncoding() {
        val items = (1..3).map { BatchItem(Rand.bytes(32), Rand.bytes(16), if (it == 2) 3600L else null, Rand.bytes(100 * it)) }
        val body = MessageBatch.encode(items)
        assertEquals(MessageBatch.size(items.map { it.blob.size }), body.size)
        assertEquals(3, body[0].toInt())
        val back = MessageBatch.decode(body)!!
        assertEquals(3, back.size)
        for ((x, y) in items.zip(back)) {
            assertArrayEquals(x.sendSecret, y.sendSecret)
            assertArrayEquals(x.idempotencyKey, y.idempotencyKey)
            assertEquals(x.ttlSeconds, y.ttlSeconds)
            assertArrayEquals(x.blob, y.blob)
        }
        // Strict: count 0 or 33, truncated, trailing bytes, empty blob.
        assertNull(MessageBatch.decode(byteArrayOf(0)))
        assertNull(MessageBatch.decode(byteArrayOf(33) + body.copyOfRange(1, body.size)))
        assertNull(MessageBatch.decode(body.copyOf(body.size - 1)))
        assertNull(MessageBatch.decode(body + byteArrayOf(0)))
        val emptyBlob = byteArrayOf(1) + Rand.bytes(32 + 16 + 4) + byteArrayOf(0, 0)
        assertNull(MessageBatch.decode(emptyBlob))
        assertNull(MessageBatch.decode(ByteArray(0)))
    }
}
