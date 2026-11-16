package app.goldfishsend

import app.goldfishsend.net.BatchItem
import app.goldfishsend.net.MessageBatch
import app.goldfishsend.proto.B64
import app.goldfishsend.proto.Chunker
import app.goldfishsend.proto.Content
import app.goldfishsend.proto.GroupBlob
import app.goldfishsend.proto.GroupCrypto
import app.goldfishsend.proto.GroupJson
import app.goldfishsend.proto.Padding
import app.goldfishsend.proto.Rand
import app.goldfishsend.proto.Role
import app.goldfishsend.proto.Roster
import app.goldfishsend.proto.RosterMember
import app.goldfishsend.proto.RosterOp
import app.goldfishsend.proto.RosterRules
import app.goldfishsend.proto.SignedRoster
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.signal.libsignal.protocol.IdentityKeyPair

/** Group wire formats and roster rules (docs/groups.md). */
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
        members: List<RosterMember> = listOf(RosterMember(ida, Role.ADMIN), RosterMember(idb, Role.MEMBER), RosterMember(idc, Role.INVITED)),
        name: String = "Group",
        timer: Long = 0,
        adminsOnly: Boolean = true,
    ) = Roster(g = g, ver = ver, prev = prev, name = name, timer = timer, adminsOnly = adminsOnly, members = members, by = by, ts = 1)

    private fun keyOf(id: String) = when (id) {
        ida -> a
        idb -> b
        else -> c
    }

    private fun signed(r: Roster) = GroupCrypto.signRoster(keyOf(r.by).privateKey, r)

    private fun next(base: SignedRoster, change: (Roster) -> Roster, by: String = ida): SignedRoster =
        signed(RosterRules.successor(base, change(base.roster), by, 2))

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
        assertFalse(RosterRules.wellFormed(roster(members = listOf(RosterMember(ida, Role.MEMBER))), g))
        assertFalse(RosterRules.wellFormed(roster(members = listOf(RosterMember(ida, Role.ADMIN), RosterMember(ida, Role.MEMBER))), g))
        assertFalse(RosterRules.wellFormed(roster(members = listOf(RosterMember(ida, "owner"))), g))
        assertFalse(RosterRules.wellFormed(roster(members = listOf(RosterMember(ida, Role.ADMIN), RosterMember("junk", Role.MEMBER))), g))
        assertFalse(RosterRules.wellFormed(roster(name = "   "), g))
        assertFalse(RosterRules.wellFormed(roster(timer = -1), g))
        assertFalse(RosterRules.wellFormed(roster(ver = 2, prev = ""), g))
        val many = listOf(RosterMember(ida, Role.ADMIN)) + (1..100).map { RosterMember(B64.enc(IdentityKeyPair.generate().publicKey.serialize()), Role.MEMBER) }
        assertFalse(RosterRules.wellFormed(roster(members = many), g))
        assertTrue(RosterRules.wellFormed(roster(members = many.take(100)), g))
    }

    // --- authority ---

    @Test
    fun authority() {
        val base = roster()
        // An admin may do anything.
        assertTrue(RosterRules.authorized(base, base.copy(members = base.members.filter { it.id != idb }, by = ida)))
        // A member may not remove someone else, promote themselves, or add people.
        assertFalse(RosterRules.authorized(base, base.copy(members = base.members.filter { it.id != idc }, by = idb)))
        assertFalse(
            RosterRules.authorized(base, base.copy(members = base.members.map { if (it.id == idb) it.copy(role = Role.ADMIN) else it }, by = idb)),
        )
        // Anyone may leave.
        assertTrue(RosterRules.authorized(base, base.copy(members = base.members.filter { it.id != idb }, by = idb)))
        // An invitee may accept (to member, not admin) or decline.
        assertTrue(
            RosterRules.authorized(base, base.copy(members = base.members.map { if (it.id == idc) it.copy(role = Role.MEMBER) else it }, by = idc)),
        )
        assertFalse(
            RosterRules.authorized(base, base.copy(members = base.members.map { if (it.id == idc) it.copy(role = Role.ADMIN) else it }, by = idc)),
        )
        assertTrue(RosterRules.authorized(base, base.copy(members = base.members.filter { it.id != idc }, by = idc)))
        // Name and timer: admins only, unless adminsOnly is off; never together with a membership change.
        assertFalse(RosterRules.authorized(base, base.copy(name = "New", by = idb)))
        val open = base.copy(adminsOnly = false)
        assertTrue(RosterRules.authorized(open, open.copy(name = "New", timer = 60, by = idb)))
        assertFalse(RosterRules.authorized(open, open.copy(adminsOnly = true, by = idb)))
        assertFalse(RosterRules.authorized(open, open.copy(name = "New", by = idc)))
        assertFalse(RosterRules.authorized(open, open.copy(name = "New", members = open.members.filter { it.id != idc }, by = idb)))
        // Strangers can't do anything.
        val stranger = B64.enc(IdentityKeyPair.generate().publicKey.serialize())
        assertFalse(RosterRules.authorized(base, base.copy(by = stranger)))
    }

    // --- ordering ---

    @Test
    fun aChildIsOneVersionOnAndAllowed() {
        val v1 = signed(roster())
        val v2 = next(v1, { it.copy(name = "Renamed") })
        assertTrue(RosterRules.validChild(v1.roster, v2.roster))
        assertFalse(RosterRules.validChild(v2.roster, v1.roster))
        // Skipping versions isn't a child.
        assertFalse(RosterRules.validChild(v1.roster, v2.roster.copy(ver = 5)))
        // A member's change to others isn't allowed; their own departure is.
        val kick = next(v2, { r -> r.copy(members = r.members.filter { it.id != idc }) }, by = idb)
        assertFalse(RosterRules.validChild(v2.roster, kick.roster))
        val leave = next(v2, { r -> r.copy(members = r.members.filter { it.id != idb }) }, by = idb)
        assertTrue(RosterRules.validChild(v2.roster, leave.roster))
    }

    @Test
    fun forkChoice() {
        val v1 = signed(roster(members = listOf(RosterMember(ida, Role.ADMIN), RosterMember(idb, Role.ADMIN), RosterMember(idc, Role.MEMBER))))
        val x = next(v1, { it.copy(name = "By A") }, by = ida)
        val y = next(v1, { it.copy(timer = 60) }, by = idb)
        // Two admins: the larger hash, and both sides agree.
        val xWins = RosterRules.beats(v1.roster, listOf(x), listOf(y))
        assertEquals(!xWins, RosterRules.beats(v1.roster, listOf(y), listOf(x)))
        assertEquals(RosterRules.compareUnsigned(x.hash, y.hash) > 0, xWins)
        // A member's branch never outweighs an admin's, however long.
        val open = signed(roster(members = v1.roster.members, adminsOnly = false))
        val byAdmin = next(open, { it.copy(name = "Admin") }, by = ida)
        var byMember = next(open, { it.copy(name = "Member 1") }, by = idc)
        val chain = mutableListOf(byMember)
        repeat(5) { i ->
            byMember = next(byMember, { it.copy(name = "Member ${i + 2}") }, by = idc)
            chain += byMember
        }
        assertTrue(RosterRules.beats(open.roster, listOf(byAdmin), chain))
        assertFalse(RosterRules.beats(open.roster, chain, listOf(byAdmin)))
        // Taking out the other branch's author wins, even against an admin.
        val kickB = next(v1, { r -> r.copy(members = r.members.filter { it.id != idb }) }, by = ida)
        assertTrue(RosterRules.beats(v1.roster, listOf(kickB), listOf(y)))
        assertFalse(RosterRules.beats(v1.roster, listOf(y), listOf(kickB)))
    }

    @Test
    fun opsApply() {
        val r = roster()
        assertEquals(Role.INVITED, RosterOp.Add(listOf(B64.enc(IdentityKeyPair.generate().publicKey.serialize()))).apply(r, ida)!!.members.last().role)
        assertNull(RosterOp.Add(listOf(idb)).apply(r, ida))
        assertNull(RosterOp.Remove(listOf(ida)).apply(r, ida))
        assertEquals(2, RosterOp.Remove(listOf(idb)).apply(r, ida)!!.members.size)
        assertNull(RosterOp.SetRole(idc, Role.ADMIN).apply(r, ida))
        assertEquals(Role.ADMIN, RosterOp.SetRole(idb, Role.ADMIN).apply(r, ida)!!.role(idb))
        assertNull(RosterOp.Meta(name = "Group").apply(r, ida))
        assertEquals(Role.MEMBER, RosterOp.Accept.apply(r, idc)!!.role(idc))
        assertNull(RosterOp.Accept.apply(r, idb))
        assertNull(RosterOp.Leave.apply(r, B64.enc(IdentityKeyPair.generate().publicKey.serialize())))
        for (op in listOf(RosterOp.Add(listOf(idb)), RosterOp.Remove(listOf(idc)), RosterOp.SetRole(idb, Role.ADMIN), RosterOp.Meta("x", 1, false), RosterOp.Leave, RosterOp.Accept)) {
            assertEquals(op, RosterOp.decode(op.encode()))
        }
    }

    @Test
    fun rosterJsonIsCanonical() {
        val r = roster()
        val json = GroupJson.encodeToString(Roster.serializer(), r)
        assertTrue(json.contains("\"v\":1"))
        assertTrue(json.contains("\"adminsOnly\":true"))
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
