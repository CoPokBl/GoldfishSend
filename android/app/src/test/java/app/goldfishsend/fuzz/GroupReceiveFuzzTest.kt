package app.goldfishsend.fuzz

import app.goldfishsend.LastResortStore
import app.goldfishsend.MemoryGroupStore
import app.goldfishsend.fuzz.FuzzKit.content
import app.goldfishsend.fuzz.FuzzKit.str
import app.goldfishsend.group.GroupEngine
import app.goldfishsend.group.GroupEvent
import app.goldfishsend.group.GroupIo
import app.goldfishsend.group.GroupModel
import app.goldfishsend.proto.B64
import app.goldfishsend.proto.CardBundle
import app.goldfishsend.proto.CardInbox
import app.goldfishsend.proto.Chunker
import app.goldfishsend.proto.Content
import app.goldfishsend.proto.GroupBlob
import app.goldfishsend.proto.GroupCard
import app.goldfishsend.proto.GroupCrypto
import app.goldfishsend.proto.Padding
import app.goldfishsend.proto.Role
import app.goldfishsend.proto.Roster
import app.goldfishsend.proto.RosterMember
import app.goldfishsend.proto.RosterRules
import app.goldfishsend.proto.SignedCard
import app.goldfishsend.proto.SignedRoster
import com.code_intelligence.jazzer.api.FuzzedDataProvider
import com.code_intelligence.jazzer.junit.FuzzTest
import org.signal.libsignal.protocol.IdentityKeyPair
import org.signal.libsignal.protocol.ecc.ECKeyPair
import org.signal.libsignal.protocol.ecc.ECPublicKey
import org.signal.libsignal.protocol.kem.KEMKeyPair
import org.signal.libsignal.protocol.kem.KEMKeyType
import org.signal.libsignal.protocol.kem.KEMPublicKey
import org.signal.libsignal.protocol.state.KyberPreKeyRecord
import org.signal.libsignal.protocol.state.SessionRecord
import org.signal.libsignal.protocol.state.SignedPreKeyRecord

/**
 * One honest member (Bob) receives whatever a hostile member (Mallory), an invitee and a stranger whose keys the attacker
 * holds can send: raw blobs on Bob's group inbox, content over Mallory's group session or the 1:1 session, forged and
 * replayed rosters and cards, chunks in any order, and messages claiming another sender. After every input, nothing may
 * have thrown, and the attacker must not have changed anything only the honest members' keys allow.
 */
class GroupReceiveFuzzTest {
    @FuzzTest(maxDuration = "60s")
    fun hostileMember(data: FuzzedDataProvider) {
        if (System.getProperty("gf.fuzz.debug") != null) {
            GroupEngine.debugLog = { println("  " + it) }
        }
        val bob = Bob(admin = data.consumeBoolean())
        repeat(data.consumeInt(1, 6)) {
            val action = data.consumeInt(0, 7)
            GroupEngine.debugLog?.invoke("action $action")
            when (action) {
                0 -> bob.engine.receive(W.gid, W.bobHint, data.consumeBytes(600))
                1 -> bob.fromMallory(content(data))
                2 -> bob.engine.onDirect(W.id(W.mallory), content(data))
                3 -> bob.claimingOther(data, content(data))
                4 -> bob.fromStranger(content(data))
                5 -> bob.chunked(data, content(data))
                6 -> ParserFuzzTest.rejectsOnly(IllegalArgumentException::class.java) { Content.decode(data.consumeBytes(400)) }
                    ?.let { bob.engine.onDirect(W.id(W.mallory), it) }
                else -> bob.fromMallory(W.honest[data.consumeInt(0, W.honest.size - 1)].let { GroupEngine.rosterContent(it) })
            }
            bob.replayHeld()
            bob.check()
        }
    }

    /** Content the attacker can make: anything, but mostly group content for this group, signed with keys it holds. */
    private fun content(data: FuzzedDataProvider): Content = when (data.consumeInt(0, 9)) {
        0 -> data.content()
        1, 2, 3 -> GroupEngine.rosterContent(forgeRoster(data))
        4 -> GroupEngine.rosterContent(W.honest[data.consumeInt(0, W.honest.size - 1)])
        5, 6 -> forgeCard(data)
        7 -> Content.GSync(W.gid, data.consumeLong())
        8 -> Content.GLeave(W.gid)
        else -> Content.GText(W.gid, data.str(20), data.str(40), data.consumeLong(), if (data.consumeBoolean()) data.consumeLong() else null)
    }

    private fun forgeRoster(data: FuzzedDataProvider): SignedRoster {
        val base = W.honest[data.consumeInt(0, W.honest.size - 1)]
        var members = base.roster.members
        repeat(data.consumeInt(0, 3)) {
            members = when (data.consumeInt(0, 3)) {
                0 -> if (members.isEmpty()) members else members - members[data.consumeInt(0, members.size - 1)]
                1 -> members + RosterMember(W.pickId(data), W.pickRole(data))
                2 -> members.map { if (data.consumeBoolean()) it.copy(role = W.pickRole(data)) else it }
                else -> members.shuffled(java.util.Random(data.consumeLong()))
            }
        }
        val signer = W.attackers[data.consumeInt(0, W.attackers.size - 1)]
        val ver = when (data.consumeInt(0, 3)) {
            0 -> base.roster.ver + 1
            1 -> base.roster.ver
            2 -> base.roster.ver + data.consumeInt(-3, 5)
            else -> data.consumeLong()
        }
        val prev = when (data.consumeInt(0, 3)) {
            0 -> base.hashB64
            1 -> W.honest[data.consumeInt(0, W.honest.size - 1)].hashB64
            2 -> ""
            else -> data.str(50)
        }
        val r = base.roster.copy(
            ver = ver, prev = prev, members = members,
            name = if (data.consumeBoolean()) base.roster.name else data.str(70),
            timer = if (data.consumeBoolean()) base.roster.timer else data.consumeLong(),
            adminsOnly = if (data.consumeBoolean()) base.roster.adminsOnly else !base.roster.adminsOnly,
            by = if (data.consumeBoolean()) W.id(signer) else W.pickId(data),
            ts = if (data.consumeBoolean()) base.roster.ts else data.consumeLong(),
            g = if (data.consumeInt(0, 15) == 0) data.str(50) else W.gid,
        )
        return GroupCrypto.signRoster(signer.privateKey, r)
    }

    private fun forgeCard(data: FuzzedDataProvider): Content.GCard {
        val signer = W.attackers[data.consumeInt(0, W.attackers.size - 1)]
        val signerId = W.id(signer)
        val bundle = if (data.consumeBoolean()) W.bundles.getValue(signerId) else {
            val junk = data.consumeBytes(40)
            W.bundles.getValue(signerId).copy(
                signedPreKey = B64.enc(junk), signedPreKeySig = B64.enc(signer.privateKey.calculateSignature(junk)),
                deviceId = if (data.consumeBoolean()) 1 else data.consumeInt(),
            )
        }
        val card = GroupCard(
            g = if (data.consumeInt(0, 7) == 0) data.str(50) else W.gid,
            id = if (data.consumeBoolean()) signerId else W.pickId(data),
            name = if (data.consumeBoolean()) data.str(80) else null,
            inbox = CardInbox(
                if (data.consumeBoolean()) "https://evil.example" else data.str(40),
                if (data.consumeBoolean()) W.fp else data.str(45),
                if (data.consumeBoolean()) B64.enc(ByteArray(32) { 3 }) else data.str(45),
            ),
            hintKey = if (data.consumeBoolean()) B64.enc(ByteArray(32) { 4 }) else data.str(45),
            bundle = bundle,
            seq = data.consumeLong(),
        )
        val signed = GroupCrypto.signCard(signer.privateKey, card)
        return GroupEngine.cardContent(signed)
    }

    /** The attacker's world: fixed identities, the honest history (signed by its real authors) and Bob's starting state. */
    private object W {
        val gid = B64.enc(ByteArray(32) { 1 })
        val alice = FuzzKit.identity(1)
        val bob = FuzzKit.identity(2)
        val mallory = FuzzKit.identity(3)
        val carol = FuzzKit.identity(4)
        val dave = FuzzKit.identity(5)
        val ivan = FuzzKit.identity(6)
        val sam = FuzzKit.identity(7)
        val fp = B64.enc(ByteArray(32) { 9 })

        /** Keys the attacker holds. */
        val attackers = listOf(mallory, ivan, sam)
        val all = listOf(alice, bob, mallory, carol, dave, ivan, sam)
        private val byId = all.associateBy { id(it) }

        fun id(k: IdentityKeyPair): String = B64.enc(k.publicKey.serialize())

        fun pickId(data: FuzzedDataProvider): String = if (data.consumeInt(0, 15) == 0) data.str(50) else id(all[data.consumeInt(0, all.size - 1)])

        fun pickRole(data: FuzzedDataProvider): String =
            listOf(Role.ADMIN, Role.MEMBER, Role.INVITED)[data.consumeInt(0, 3).coerceAtMost(2)].takeIf { data.consumeInt(0, 15) != 0 } ?: data.str(8)

        private class Keys(val spk: ECKeyPair, val spkSig: ByteArray, val kyber: KEMKeyPair, val kyberSig: ByteArray)

        private val keys = all.associate { k ->
            val spk = ECKeyPair.generate()
            val kyber = KEMKeyPair.generate(KEMKeyType.KYBER_1024)
            id(k) to Keys(spk, k.privateKey.calculateSignature(spk.publicKey.serialize()), kyber, k.privateKey.calculateSignature(kyber.publicKey.serialize()))
        }

        val bundles: Map<String, CardBundle> = keys.mapValues { (_, k) ->
            CardBundle(7, 1, 11, B64.enc(k.spk.publicKey.serialize()), B64.enc(k.spkSig), 12, B64.enc(k.kyber.publicKey.serialize()), B64.enc(k.kyberSig))
        }

        val bobHint = ByteArray(32) { 2 }

        fun card(k: IdentityKeyPair, hint: ByteArray = ByteArray(32) { 5 }): SignedCard = GroupEngine.makeCard(
            k,
            GroupCard(
                g = gid, id = id(k), name = "n", inbox = CardInbox("https://h.example", fp, B64.enc(ByteArray(32) { 6 })),
                hintKey = B64.enc(hint), bundle = bundles.getValue(id(k)), seq = 1,
            ),
        )

        val cards = listOf(alice, mallory, carol, ivan, sam, dave).associate { id(it) to card(it) }
        val bobCard = card(bob, bobHint)

        fun store(k: IdentityKeyPair): LastResortStore = LastResortStore(k, 7).also { s ->
            val kk = keys.getValue(id(k))
            s.storeSignedPreKey(11, SignedPreKeyRecord(11, 0, kk.spk, kk.spkSig))
            s.storeKyberPreKey(12, KyberPreKeyRecord(12, 0, kk.kyber, kk.kyberSig))
        }

        /** The honest history. Carol leaves and is added back, Dave accepts, is removed and is invited again. */
        val honest: List<SignedRoster>

        /** Bob's starting roster: [honest] up to Carol's return (non-admin) or up to his promotion. */
        val startMember: SignedRoster
        val startAdmin: SignedRoster

        init {
            val list = mutableListOf<SignedRoster>()
            fun add(by: IdentityKeyPair, change: (Roster) -> Roster) {
                val base = list.last()
                list += GroupCrypto.signRoster(by.privateKey, RosterRules.successor(base, change(base.roster), id(by), 1000L + list.size))
            }
            fun role(r: Roster, k: IdentityKeyPair, role: String?) = r.copy(
                members = if (role == null) r.members.filter { it.id != id(k) } else if (r.role(id(k)) == null) r.members + RosterMember(id(k), role)
                else r.members.map { if (it.id == id(k)) it.copy(role = role) else it },
            )
            list += GroupCrypto.signRoster(
                alice.privateKey,
                Roster(
                    g = gid, ver = 1, name = "Trip", members = listOf(RosterMember(id(alice), Role.ADMIN)) +
                        listOf(bob, mallory, carol, dave).map { RosterMember(id(it), Role.INVITED) },
                    by = id(alice), ts = 1000,
                ),
            )
            add(bob) { role(it, bob, Role.MEMBER) }
            add(mallory) { role(it, mallory, Role.MEMBER) }
            add(carol) { role(it, carol, Role.MEMBER) }
            add(dave) { role(it, dave, Role.MEMBER) }
            add(carol) { role(it, carol, null) }
            add(alice) { role(it, dave, null) }
            add(alice) { role(role(role(it, carol, Role.INVITED), dave, Role.INVITED), ivan, Role.INVITED) }
            add(carol) { role(it, carol, Role.MEMBER) }
            startMember = list.last()
            add(alice) { role(it, bob, Role.ADMIN) }
            startAdmin = list.last()
            add(alice) { it.copy(name = "Trip 2") }
            honest = list
        }

        val names = honest.map { it.roster.name }.toSet()
        val timers = honest.map { it.roster.timer }.toSet()

        /** Mallory's and Bob's ends of an established group session, so a fresh copy is cheap. */
        val malloryToBob: ByteArray
        val bobFromMallory: ByteArray

        init {
            val m = store(mallory)
            val b = store(bob)
            val me = GroupEngine(MemoryGroupStore(), m, mallory, NullIo)
            val blob = me.encryptTo(id(bob), bobCard.card, Content.GLeave("x").encode())
            val raw = GroupBlob.decode(blob)!!
            org.signal.libsignal.protocol.SessionCipher(b, GroupEngine.LOCAL, GroupCrypto.address(id(mallory)))
                .decrypt(org.signal.libsignal.protocol.message.PreKeySignalMessage(raw.body))
            malloryToBob = m.loadSession(GroupCrypto.address(id(bob))).serialize()
            bobFromMallory = b.loadSession(GroupCrypto.address(id(mallory))).serialize()
        }

        fun roleAllowed(id: String, role: String?): Boolean = when (id) {
            id(alice) -> role == Role.ADMIN
            id(bob) -> role == Role.ADMIN || role == Role.MEMBER
            id(carol) -> role == Role.MEMBER
            id(dave) -> role == Role.INVITED
            // The attacker's own keys may leave, decline or accept, never more.
            id(mallory) -> role == null || role == Role.MEMBER
            id(ivan) -> role == null || role == Role.MEMBER || role == Role.INVITED
            else -> role == null
        }

        fun name(id: String): String = byId[id]?.let { k -> listOf("alice", "bob", "mallory", "carol", "dave", "ivan", "sam")[all.indexOf(k)] } ?: id
    }

    private object NullIo : GroupIo {
        override fun sendGroup(gid: String, to: String, content: Content) = Unit
        override fun sendDirect(gid: String, to: String, content: Content): Boolean = false
        override fun onEvents(m: GroupModel, events: List<GroupEvent>) = Unit
        override fun onText(m: GroupModel, from: String, t: Content.GText) = Unit
        override fun onReceipt(m: GroupModel, from: String, r: Content.GReceipt) = Unit
        override fun onDelete(m: GroupModel, from: String, d: Content.GDelete) = Unit
        override fun rotateInbox(m: GroupModel) = Unit
        override fun validServer(url: String): Boolean = url.startsWith("https://")
        override fun nowMillis(): Long = 2_000_000L
    }

    private class Bob(admin: Boolean) {
        val store = MemoryGroupStore()
        val signal = W.store(W.bob)
        val sent = mutableListOf<Pair<String, Content>>()
        val texts = mutableListOf<String>()
        val start = if (admin) W.startAdmin else W.startMember
        val contacts = setOf(W.id(W.alice), W.id(W.mallory), W.id(W.carol))

        val engine = GroupEngine(store, signal, W.bob, object : GroupIo by NullIo {
            override fun sendGroup(gid: String, to: String, content: Content) {
                check(store.load(gid)?.cards?.containsKey(to) == true || store.routes[gid]?.containsKey(to) == true) { "sent to ${W.name(to)} without a card" }
                sent += to to content
            }

            override fun sendDirect(gid: String, to: String, content: Content): Boolean {
                if (to !in contacts) {
                    return false
                }
                sent += to to content
                return true
            }

            override fun onText(m: GroupModel, from: String, t: Content.GText) {
                check(m.roster!!.roster.isActive(from)) { "text from non-member ${W.name(from)}" }
                check(from == W.id(W.mallory) || from == W.id(W.ivan)) { "text claims to be from ${W.name(from)}" }
                texts += t.body
            }
        })

        init {
            for (r in W.honest.filter { it.roster.ver <= start.roster.ver }) {
                store.addHistory(W.gid, r)
            }
            val cards = listOf(W.alice, W.mallory, W.carol).associate { W.id(it) to W.cards.getValue(W.id(it)) }
            store.save(GroupModel(W.gid, GroupModel.JOINED, start, cards.toMutableMap(), W.bobCard, W.id(W.alice), mutableListOf()))
            signal.storeSession(GroupCrypto.address(W.id(W.mallory)), SessionRecord(W.bobFromMallory))
        }

        private val malloryStore = W.store(W.mallory).also {
            it.storeSession(GroupCrypto.address(W.id(W.bob)), SessionRecord(W.malloryToBob))
        }
        private val malloryEngine = GroupEngine(MemoryGroupStore(), malloryStore, W.mallory, NullIo)

        fun fromMallory(c: Content) {
            for (p in Chunker.splitContent(c, Padding.MAX_PREKEY_PLAINTEXT)) {
                engine.receive(W.gid, W.bobHint, malloryEngine.encryptTo(W.id(W.bob), W.bobCard.card, p.encode()))
            }
        }

        /** Mallory's session, but the sender hint names someone else. */
        fun claimingOther(data: FuzzedDataProvider, c: Content) {
            val blob = GroupBlob.decode(malloryEngine.encryptTo(W.id(W.bob), W.bobCard.card, c.encode().take(1900).toByteArray()))!!
            val other = W.all[data.consumeInt(0, W.all.size - 1)]
            val mac = GroupCrypto.hint(W.bobHint, blob.nonce, other.publicKey.serialize())
            engine.receive(W.gid, W.bobHint, GroupBlob(blob.type, blob.nonce, mac, blob.body).encode())
        }

        /** Sam isn't in the group but has Bob's card. */
        fun fromStranger(c: Content) {
            val sam = GroupEngine(MemoryGroupStore(), W.store(W.sam), W.sam, NullIo)
            for (p in Chunker.splitContent(c, Padding.MAX_PREKEY_PLAINTEXT)) {
                engine.receive(W.gid, W.bobHint, sam.encryptTo(W.id(W.bob), W.bobCard.card, p.encode()))
            }
        }

        /** Chunk parts out of order, duplicated, missing, or mixed with parts that disagree. */
        fun chunked(data: FuzzedDataProvider, c: Content) {
            val big = if (c.encode().size < 2100) Content.GText(W.gid, "big", "x".repeat(data.consumeInt(2100, 9000)), 1) else c
            val parts = Chunker.splitContent(big, Padding.MAX_PREKEY_PLAINTEXT).map { it as? Content.Chunk ?: return fromMallory(it) }
            val sendList = mutableListOf<Content>()
            repeat(data.consumeInt(1, parts.size * 2)) {
                val p = parts[data.consumeInt(0, parts.size - 1)]
                sendList += when (data.consumeInt(0, 5)) {
                    0 -> p.copy(parts = data.consumeInt())
                    1 -> p.copy(part = data.consumeInt(-1, 70))
                    2 -> p.copy(data = data.str(100))
                    3 -> p.copy(id = data.str(40))
                    else -> p
                }
            }
            val direct = data.consumeBoolean()
            for (p in sendList) {
                if (direct) engine.onDirect(W.id(W.mallory), p) else fromMallory(p)
            }
        }

        /** Like Groups.replayHeld, but anything thrown is a finding. */
        fun replayHeld() {
            while (true) {
                val ready = engine.readyHeld()
                if (ready.isEmpty()) {
                    return
                }
                for ((g, h) in ready) {
                    engine.replayHeld(g, h)
                }
            }
        }

        fun check() {
            val m = store.load(W.gid)!!
            check(m.state == GroupModel.JOINED) { "Bob's state changed to ${m.state}" }
            val r = m.roster!!.roster
            check(RosterRules.wellFormed(r, W.gid)) { "roster not well formed" }
            for (k in W.all) {
                check(W.roleAllowed(W.id(k), r.role(W.id(k)))) { "${W.name(W.id(k))} is ${r.role(W.id(k))} (by ${W.name(r.by)}, v${r.ver})" }
            }
            check(r.members.all { mem -> W.all.any { W.id(it) == mem.id } }) { "unknown member" }
            check(r.name in W.names && r.timer in W.timers && r.adminsOnly) { "settings changed by ${W.name(r.by)}" }
            check(m.cards[W.id(W.alice)]?.bytes?.contentEquals(W.cards.getValue(W.id(W.alice)).bytes) == true) { "Alice's card replaced" }
            check(m.cards.keys.all { r.role(it) != null }) { "card of a non-member" }
            for (card in m.cards.values) {
                ECPublicKey(B64.dec(card.card.bundle.signedPreKey))
                KEMPublicKey(B64.dec(card.card.bundle.kyberPreKey))
            }
            check(store.held(W.gid).size <= 200 && store.chunkRows(W.gid) <= 256) { "unbounded storage" }
            check(sent.size < 2000) { "message storm" }
        }
    }
}
