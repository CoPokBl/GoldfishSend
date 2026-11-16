package app.goldfishsend

import app.goldfishsend.group.FactLines
import app.goldfishsend.group.GroupEngine
import app.goldfishsend.group.GroupEvent
import app.goldfishsend.group.GroupIo
import app.goldfishsend.group.GroupModel
import app.goldfishsend.group.GroupStore
import app.goldfishsend.core.ReceiveGuard
import app.goldfishsend.db.MAX_CHUNKS_PER_CONTACT
import app.goldfishsend.group.HeldBlob
import app.goldfishsend.proto.B64
import app.goldfishsend.proto.CardBundle
import app.goldfishsend.proto.CardInbox
import app.goldfishsend.proto.Chunker
import app.goldfishsend.proto.Content
import app.goldfishsend.proto.GroupCard
import app.goldfishsend.proto.GroupCrypto
import app.goldfishsend.proto.Padding
import app.goldfishsend.proto.Rand
import app.goldfishsend.proto.SignedCard
import app.goldfishsend.proto.SignedRoster
import org.signal.libsignal.protocol.IdentityKeyPair
import org.signal.libsignal.protocol.ecc.ECKeyPair
import org.signal.libsignal.protocol.ecc.ECPublicKey
import org.signal.libsignal.protocol.kem.KEMKeyPair
import org.signal.libsignal.protocol.kem.KEMKeyType
import org.signal.libsignal.protocol.state.KyberPreKeyRecord
import org.signal.libsignal.protocol.state.SignedPreKeyRecord
import org.signal.libsignal.protocol.state.impl.InMemorySignalProtocolStore

/** Like the app's SignalStore: group prekeys are last-resort, so using them deletes nothing. */
class LastResortStore(kp: IdentityKeyPair, reg: Int) : InMemorySignalProtocolStore(kp, reg) {
    override fun markKyberPreKeyUsed(kyberPreKeyId: Int, signedPreKeyId: Int, baseKey: ECPublicKey) = Unit
}

/** [GroupStore] in memory, mirroring RepoGroupStore (including departed members' cards kept for routing). */
class MemoryGroupStore : GroupStore {
    private class Row(
        var state: Int,
        var roster: SignedRoster?,
        var cards: Map<String, SignedCard>,
        var myCard: SignedCard?,
        var invitedBy: String?,
        var facts: String?,
        var since: Long,
    )

    private val rows = HashMap<String, Row>()
    private val historyRows = HashMap<String, MutableMap<String, SignedRoster>>()
    private val chunks = LinkedHashMap<String, java.util.TreeMap<Int, String>>()
    private val heldRows = HashMap<String, MutableList<HeldBlob>>()
    private var heldSeq = 0L

    /** Every card ever stored per group (routing for final deliveries to departed members). */
    val routes = HashMap<String, MutableMap<String, SignedCard>>()

    override fun load(gid: String): GroupModel? {
        val r = rows[gid] ?: return null
        return GroupModel(gid, r.state, r.roster, r.cards.toMutableMap(), r.myCard, r.invitedBy, FactLines.decode(r.facts), r.since)
    }

    override fun save(m: GroupModel) {
        rows[m.gid] = Row(m.state, m.roster, m.cards.toMap(), m.myCard, m.invitedBy, FactLines.encode(m.facts), m.since)
        routes.getOrPut(m.gid) { HashMap() }.putAll(m.cards)
    }

    /** Like RepoGroupStore.addHistory: capped per version, nothing kept 200 versions behind the newest. */
    override fun addHistory(gid: String, r: SignedRoster) {
        val rows = historyRows.getOrPut(gid) { LinkedHashMap() }
        if (r.hashB64 !in rows && !GroupEngine.fits(rows.values.filter { it.roster.ver == r.roster.ver }.map { it.roster }, r.roster)) {
            return
        }
        rows.putIfAbsent(r.hashB64, r)
        val newest = rows.values.maxOf { it.roster.ver }
        rows.values.removeAll { it.roster.ver < newest - 200 }
    }

    override fun history(gid: String, hashB64: String): SignedRoster? = historyRows[gid]?.get(hashB64)

    override fun historySince(gid: String, since: Long): List<SignedRoster> =
        historyRows[gid]?.values?.filter { it.roster.ver > since }?.sortedBy { it.roster.ver }.orEmpty()

    /** Like Repo.storeChunk and assembleChunks: bounded per group (oldest dropped), complete once parts 0 until [parts] are there. */
    override fun storeChunk(gid: String, key: String, part: Int, parts: Int, data: String): String? {
        val all = chunks.filterKeys { it.startsWith("$gid/") }
        if (all.values.sumOf { it.size } >= MAX_CHUNKS_PER_CONTACT) {
            all.keys.first().let { chunks.remove(it) }
        }
        val m = chunks.getOrPut("$gid/$key") { java.util.TreeMap() }
        m[part] = data
        if (m.size != parts || m.keys.toList() != (0 until parts).toList()) {
            return null
        }
        chunks.remove("$gid/$key")
        return m.values.joinToString("")
    }

    fun chunkRows(gid: String): Int = chunks.filterKeys { it.startsWith("$gid/") }.values.sumOf { it.size }

    /** Bounded like RepoGroupStore.hold. */
    override fun hold(gid: String, hintKey: ByteArray, blob: ByteArray) {
        val rows = heldRows.getOrPut(gid) { mutableListOf() }
        if (rows.size < 200) {
            rows += HeldBlob(++heldSeq, hintKey, blob)
        }
    }

    override fun held(gid: String): List<HeldBlob> = heldRows[gid].orEmpty().toList()

    override fun dropHeld(id: Long) {
        heldRows.values.forEach { l -> l.removeAll { it.id == id } }
    }

    private val withdrawals = LinkedHashMap<String, Long>()
    private val early = mutableListOf<Content.GFact>()

    override fun addEarlyFact(gid: String, fact: Content.GFact) {
        early += fact
        while (early.size > 16) {
            early.removeAt(0)
        }
    }

    override fun takeEarlyFacts(gid: String): List<Content.GFact> = early.filter { it.g == gid }.also { early.removeAll(it) }

    override fun withdrawn(gid: String, by: String): Long? = withdrawals["$gid $by"]

    override fun addWithdrawn(gid: String, by: String, ver: Long) {
        val v = withdrawals.remove("$gid $by")
        withdrawals["$gid $by"] = maxOf(ver, v ?: ver)
        while (withdrawals.size > 32) {
            withdrawals.remove(withdrawals.keys.first())
        }
    }
}

/**
 * An in-memory network of group members: real libsignal stores and the real [GroupEngine], with a FIFO "server" that
 * carries blobs to inboxes and a 1:1 channel between contacts.
 */
class GroupNet {
    sealed class Envelope {
        /** [what]: the content's type, for tests that pick envelopes (the blob is encrypted). */
        class ToInbox(val to: Peer, val sendSecret: String, val blob: ByteArray, val from: Peer, val what: String = "") : Envelope()
        class Direct(val to: Peer, val from: Peer, val content: Content) : Envelope()
    }

    val queue = ArrayDeque<Envelope>()
    val peers = mutableListOf<Peer>()

    /** Return false to drop an envelope (a lost push). */
    var filter: (Envelope) -> Boolean = { true }

    var dropped = 0

    /** Reorders what's queued at the start of [deliverAll] (pushes aren't ordered). */
    var reorder: ((List<Envelope>) -> List<Envelope>)? = null

    /** The members' clock (roster timestamps). Tests that need reproducible roster hashes set a fixed one. */
    var clock: () -> Long = { System.currentTimeMillis() }

    /** Debug output: who each delivery goes to. */
    var trace: ((String) -> Unit)? = null

    fun peer(name: String, identity: IdentityKeyPair = IdentityKeyPair.generate()): Peer = Peer(name, this, identity).also { peers += it }

    /** Delivers one envelope, then runs what each member does after a call (held messages, inbox rotation, waiting texts). */
    var delivered = 0

    fun deliver(e: Envelope) {
        delivered++
        trace?.invoke(
            when (e) {
                is Envelope.ToInbox -> "  ${e.from.name} -> ${e.to.name} (group)"
                is Envelope.Direct -> "  ${e.from.name} -> ${e.to.name} (1:1) ${e.content.javaClass.simpleName}"
            },
        )
        when (e) {
            is Envelope.ToInbox -> e.to.onInbox(e.sendSecret, e.blob)
            is Envelope.Direct -> e.to.engine.onDirect(e.from.id, e.content)
        }
        for (p in peers) {
            p.runDeferred()
        }
    }

    /** Delivers everything queued (and whatever that causes), in order. */
    fun deliverAll(limit: Int = 100_000) {
        // Local actions since the last delivery (publish, join) can free held messages too.
        for (p in peers) {
            p.runDeferred()
        }
        reorder?.let { r ->
            val batch = r(queue.toList())
            queue.clear()
            queue.addAll(batch)
        }
        var n = 0
        while (queue.isNotEmpty()) {
            check(n++ < limit) { "message storm" }
            val e = queue.removeFirst()
            if (!filter(e)) {
                dropped++
                continue
            }
            deliver(e)
        }
    }
}

class Peer(val name: String, private val net: GroupNet, val identity: IdentityKeyPair = IdentityKeyPair.generate()) {
    val id: String = B64.enc(identity.publicKey.serialize())
    val signal = LastResortStore(identity, 1 + Rand.int(16000))
    val store = MemoryGroupStore()
    val contacts = mutableSetOf<String>()
    val events = mutableListOf<Pair<String, GroupEvent>>()
    val texts = mutableListOf<Triple<String, String, String>>()

    /** A text with this body makes the text handler throw, like a bug or a storage error would. */
    var failOnText: String? = null

    /** gid → our inboxes (newest last): sendSecret → hint key. */
    val inboxes = HashMap<String, LinkedHashMap<String, ByteArray>>()
    private val deferred = ArrayDeque<() -> Unit>()
    private var keyId = 100

    val engine = GroupEngine(store, signal, identity, Io())

    fun model(gid: String): GroupModel = store.load(gid)!!

    fun befriend(other: Peer) {
        contacts += other.id
        other.contacts += id
    }

    fun newInbox(gid: String): Pair<String, ByteArray> {
        val secret = B64.enc(Rand.bytes(32))
        val hint = Rand.bytes(32)
        inboxes.getOrPut(gid) { LinkedHashMap() }[secret] = hint
        return secret to hint
    }

    fun card(gid: String, seq: Long = 1, reuse: CardBundle? = null): SignedCard {
        val (secret, hint) = newInbox(gid)
        val bundle = reuse ?: run {
            val spkId = keyId++
            val spk = ECKeyPair.generate()
            val spkSig = identity.privateKey.calculateSignature(spk.publicKey.serialize())
            signal.storeSignedPreKey(spkId, SignedPreKeyRecord(spkId, 0, spk, spkSig))
            val kyberId = keyId++
            val kyber = KEMKeyPair.generate(KEMKeyType.KYBER_1024)
            val kyberSig = identity.privateKey.calculateSignature(kyber.publicKey.serialize())
            signal.storeKyberPreKey(kyberId, KyberPreKeyRecord(kyberId, 0, kyber, kyberSig))
            CardBundle(
                signal.localRegistrationId, 1, spkId, B64.enc(spk.publicKey.serialize()), B64.enc(spkSig),
                kyberId, B64.enc(kyber.publicKey.serialize()), B64.enc(kyberSig),
            )
        }
        val card = GroupCard(
            g = gid, id = id, name = name,
            inbox = CardInbox("https://$name.example", B64.enc(ByteArray(32) { 7 }), secret),
            hintKey = B64.enc(hint), bundle = bundle, seq = seq,
        )
        return GroupEngine.makeCard(identity, card)
    }

    fun create(gid: String, name: String, vararg invitees: Peer) = engine.create(gid, name, invitees.map { it.id }, card(gid), 0)

    fun join(gid: String) = check(engine.join(model(gid), card(gid))) { "$name couldn't join" }

    fun publish(gid: String, op: app.goldfishsend.proto.RosterOp) = engine.publish(model(gid), op)

    fun leave(gid: String) = engine.leave(model(gid))

    /** Our membership as we see it. */
    fun view(gid: String) = model(gid).view()!!

    /** What the app does for a text: one gtext per member with a card. */
    /** Like the app: every active member gets it, and members whose card we don't have yet get it once it arrives. */
    fun say(gid: String, body: String, wireId: String = Content.newId()): List<String> {
        val m = model(gid)
        check(m.state == GroupModel.JOINED)
        val content = Content.GText(gid, wireId, body, System.currentTimeMillis())
        val r = m.view()!!
        val to = r.members.map { it.id }.filter { it != id && r.isActive(it) }
        for (t in to) {
            if (m.cards[t] != null) {
                sendGroup(gid, t, content)
            } else {
                waiting += Triple(gid, t, content)
            }
        }
        return to
    }

    private val waiting = mutableListOf<Triple<String, String, Content>>()

    private fun flushWaiting() {
        val it = waiting.iterator()
        while (it.hasNext()) {
            val (g, to, content) = it.next()
            if (store.load(g)?.cards?.get(to) != null) {
                it.remove()
                sendGroup(g, to, content)
            }
        }
    }

    /** Sends straight to a member's (possibly stale) card, as a modified or removed client might. */
    fun sendWithCard(card: GroupCard, content: Content) {
        val to = net.peers.first { it.id == card.id }
        for (part in Chunker.splitContent(content, Padding.MAX_PREKEY_PLAINTEXT)) {
            val blob = engine.encryptTo(card.id, card, part.encode())
            net.queue.addLast(GroupNet.Envelope.ToInbox(to, card.inbox.sendSecret, blob, this, content.javaClass.simpleName))
        }
    }

    fun sendGroup(gid: String, to: String, content: Content) {
        val card = store.routes[gid]?.get(to)?.card ?: error("$name has no route to member")
        sendWithCard(card, content)
    }

    fun onInbox(sendSecret: String, blob: ByteArray) {
        val (gid, hint) = inboxes.entries.firstNotNullOfOrNull { (gid, boxes) -> boxes[sendSecret]?.let { gid to it } } ?: return
        engine.receive(gid, hint, blob)
    }

    fun runDeferred() {
        replayHeld()
        while (deferred.isNotEmpty()) {
            deferred.removeFirst()()
        }
        flushWaiting()
    }

    /** Like Groups.replayHeld, after each call: each held message on its own; one that fails is dropped, the rest still go. */
    fun replayHeld() {
        while (true) {
            val ready = engine.readyHeld()
            if (ready.isEmpty()) {
                return
            }
            for ((g, h) in ready) {
                ReceiveGuard.run("held group message") { engine.replayHeld(g, h) } ?: store.dropHeld(h.id)
            }
        }
    }

    fun roster(gid: String) = model(gid).roster!!

    private inner class Io : GroupIo {
        override fun sendGroup(gid: String, to: String, content: Content) = this@Peer.sendGroup(gid, to, content)

        override fun sendDirect(gid: String, to: String, content: Content): Boolean {
            if (to !in contacts) {
                return false
            }
            val peer = net.peers.first { it.id == to }
            // The app splits and reassembles 1:1 content in Messenger; the simulated 1:1 channel carries it whole.
            net.queue.addLast(GroupNet.Envelope.Direct(peer, this@Peer, content))
            return true
        }

        override fun onEvents(m: GroupModel, events: List<GroupEvent>) {
            for (e in events) {
                this@Peer.events += m.gid to e
                // Like Groups.AppIo: what's still queued to someone who left or was removed is dropped.
                when (e) {
                    is GroupEvent.Removed -> waiting.removeAll { it.first == m.gid && it.second in e.ids }
                    is GroupEvent.Left -> waiting.removeAll { it.first == m.gid && it.second == e.id }
                    is GroupEvent.YouWereRemoved, GroupEvent.YouLeft -> {
                        waiting.removeAll { it.first == m.gid }
                        // Like Groups.afterDeparture: our group inbox goes (the engine ignores it once we're out anyway).
                        inboxes.remove(m.gid)
                    }
                    else -> Unit
                }
            }
        }

        override fun onText(m: GroupModel, from: String, t: Content.GText) {
            check(t.body != failOnText) { "handler failed" }
            texts += Triple(m.gid, from, t.body)
        }

        override fun onReceipt(m: GroupModel, from: String, r: Content.GReceipt) = Unit

        override fun onDelete(m: GroupModel, from: String, d: Content.GDelete) = Unit

        override fun rotateInbox(m: GroupModel) {
            // Like Groups.rotatePending: after the current call, a new inbox and card (same prekeys), sent to everyone.
            deferred.addLast {
                val cur = store.load(m.gid) ?: return@addLast
                val prev = cur.myCard?.card ?: return@addLast
                if (cur.state == GroupModel.JOINED) {
                    engine.updateCard(cur, card(m.gid, prev.seq + 1, prev.bundle))
                }
            }
        }

        override fun validServer(url: String): Boolean = url.startsWith("https://")

        override fun nowMillis(): Long = net.clock()
    }
}
