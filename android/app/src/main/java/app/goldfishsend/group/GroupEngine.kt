package app.goldfishsend.group

import app.goldfishsend.proto.B64
import app.goldfishsend.proto.BlobWrap
import app.goldfishsend.proto.Chunker
import app.goldfishsend.proto.Content
import app.goldfishsend.proto.Fact
import app.goldfishsend.proto.FactKind
import app.goldfishsend.proto.GroupBlob
import app.goldfishsend.proto.GroupCard
import app.goldfishsend.proto.GroupCrypto
import app.goldfishsend.proto.GroupJson
import app.goldfishsend.proto.Head
import app.goldfishsend.proto.Membership
import app.goldfishsend.proto.Padding
import app.goldfishsend.proto.Rand
import app.goldfishsend.proto.Role
import app.goldfishsend.proto.Roster
import app.goldfishsend.proto.RosterMember
import app.goldfishsend.proto.RosterOp
import app.goldfishsend.proto.RosterRules
import app.goldfishsend.proto.Signed
import app.goldfishsend.proto.SignedCard
import app.goldfishsend.proto.SignedFact
import app.goldfishsend.proto.SignedRoster
import app.goldfishsend.proto.View
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import org.signal.libsignal.protocol.DuplicateMessageException
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.IdentityKeyPair
import org.signal.libsignal.protocol.ReusedBaseKeyException
import org.signal.libsignal.protocol.SessionBuilder
import org.signal.libsignal.protocol.SessionCipher
import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.ecc.ECPublicKey
import org.signal.libsignal.protocol.kem.KEMPublicKey
import org.signal.libsignal.protocol.message.PreKeySignalMessage
import org.signal.libsignal.protocol.message.SignalMessage
import org.signal.libsignal.protocol.state.PreKeyBundle
import org.signal.libsignal.protocol.state.SignalProtocolStore

/** One group as seen by this member. Who's in it comes from [view]; [cards] holds the other members' latest cards. */
class GroupModel(
    val gid: String,
    var state: Int,
    var roster: SignedRoster?,
    val cards: MutableMap<String, SignedCard>,
    var myCard: SignedCard?,
    /** Who invited us (identity key, b64u). */
    var invitedBy: String?,
    /** Members' accepts and leaves (ours too) for the roster's stints, and a few for stints we can't place yet. */
    val facts: MutableList<SignedFact>,
    /** Our stint: the `since` of our entry in the roster (0 if we never had one). */
    var since: Long,
    /** What we know of each peer's state, and what we've sent them (docs/groups.md, "What's owed"). */
    val peers: MutableMap<String, PeerSync> = mutableMapOf(),
    /** How often our head has changed ([Head.s]), and the last one counted. */
    var headSeq: Long = 0,
    var headKey: String? = null,
) {
    /** Cards of members who just went, in memory only, so the system line can still name them. */
    val departed: MutableMap<String, SignedCard> = mutableMapOf()

    /** The membership everyone acts on: the roster with the facts held applied (docs/groups.md, "The view"). */
    fun view(): View? = roster?.let { Membership.view(it.roster, facts.map { f -> f.fact }) }

    companion object {
        const val INVITED = 0
        const val JOINED = 1
        const val REMOVED = 2
        const val LEFT = 3
    }
}

/**
 * Per peer: [acked], the newest head they showed us (on anything they sent); [sent], the last state or ask we sent them,
 * as "their head > our head", at [sentTs] (our clock); [sentN], how many we sent while our head was [sentAt]. [out]:
 * they were taken out, and we owe them the rosters from version [outFrom] on that say so.
 */
@Serializable
data class PeerSync(
    val acked: Head? = null,
    val sent: String? = null,
    val sentAt: String? = null,
    val sentN: Int = 0,
    val sentTs: Long = 0,
    val out: Boolean = false,
    val outFrom: Long = 0,
) {
    companion object {
        private val serializer = MapSerializer(String.serializer(), serializer())

        fun encode(m: Map<String, PeerSync>): String? = if (m.isEmpty()) null else GroupJson.encodeToString(serializer, m)

        fun decode(s: String?): MutableMap<String, PeerSync> =
            s?.let { runCatching { GroupJson.decodeFromString(serializer, it).toMutableMap() }.getOrNull() } ?: mutableMapOf()
    }
}

/** Facts in the store's text column: `fact sig` (b64u) per line. */
object FactLines {
    fun encode(list: List<SignedFact>): String? = if (list.isEmpty()) null else list.joinToString("\n") { "${B64.enc(it.bytes)} ${B64.enc(it.sig)}" }

    /** Stored facts were checked before they were stored: parsed, not re-verified. */
    fun decode(s: String?): MutableList<SignedFact> = s?.lines()?.mapNotNull { line ->
        val parts = line.split(' ')
        if (parts.size != 2) {
            return@mapNotNull null
        }
        runCatching {
            val bytes = B64.dec(parts[0])
            SignedFact(bytes, B64.dec(parts[1]), GroupJson.decodeFromString(Fact.serializer(), bytes.toString(Charsets.UTF_8)))
        }.getOrNull()
    }?.toMutableList() ?: mutableListOf()
}

/** What changed, for system lines and app state. `by` is who did it (the roster's author, or a fact's). */
sealed class GroupEvent {
    data class Invited(val by: String) : GroupEvent()
    data object Created : GroupEvent()
    data class Added(val by: String, val ids: List<String>) : GroupEvent()
    data class Removed(val by: String, val ids: List<String>) : GroupEvent()
    data class Left(val id: String) : GroupEvent()
    data class Joined(val id: String) : GroupEvent()
    data class OwnerChanged(val by: String, val id: String) : GroupEvent()
    data class Renamed(val by: String, val name: String) : GroupEvent()
    data class TimerChanged(val by: String, val secs: Long) : GroupEvent()
    data class YouWereRemoved(val by: String) : GroupEvent()
    data object YouLeft : GroupEvent()
}

class HeldBlob(val id: Long, val hintKey: ByteArray, val blob: ByteArray)

/** Persistence for [GroupEngine]: the app's SQLCipher tables, or in-memory maps in tests. */
interface GroupStore {
    fun load(gid: String): GroupModel?

    /** Writes the group and replaces its card set with [GroupModel.cards]. */
    fun save(m: GroupModel)

    /** Stores a roster of our chain (the newest 200 versions are kept). */
    fun addHistory(gid: String, r: SignedRoster)

    fun history(gid: String, hashB64: String): SignedRoster?

    /** Rosters with `ver > since`, oldest first. */
    fun historySince(gid: String, since: Long): List<SignedRoster>

    /** Stores one part. Returns the concatenated `data` of all parts, in order, once every part is there. */
    fun storeChunk(gid: String, key: String, part: Int, parts: Int, data: String): String?

    fun hold(gid: String, hintKey: ByteArray, blob: ByteArray)

    fun held(gid: String): List<HeldBlob>

    fun dropHeld(id: Long)

    /** Members of our other groups whose cards we hold (we may share a session with them), not of [gid]. */
    fun membersElsewhere(gid: String): Collection<String>
}

/** Side effects of [GroupEngine]: sending, and telling the app what happened. */
interface GroupIo {
    /** Queues [content] to [to]'s group inbox (their card is known). */
    fun sendGroup(gid: String, to: String, content: Content)

    /** Sends [content] over the existing 1:1 session with [to], if they're a contact. Returns false if they aren't. */
    fun sendDirect(gid: String, to: String, content: Content): Boolean

    fun onEvents(m: GroupModel, events: List<GroupEvent>)

    /** A member's card was stored (their first, or a newer one): their self-chosen name may be new. */
    fun onCard(m: GroupModel, id: String) {}

    fun onText(m: GroupModel, from: String, t: Content.GText)

    fun onReceipt(m: GroupModel, from: String, r: Content.GReceipt)

    fun onDelete(m: GroupModel, from: String, d: Content.GDelete)

    /** Someone went: give the remaining members a fresh inbox (new card) and drain the old one. */
    fun rotateInbox(m: GroupModel)

    fun validServer(url: String): Boolean

    fun nowMillis(): Long
}

class NoCardException(id: String) : Exception("no card for member")

/**
 * The group protocol (docs/groups.md): the owner's roster chain and members' facts (membership), and one idempotent
 * state message with heads on everything (delivery). All calls are synchronous; the app runs them under its libsignal
 * lock inside one DB transaction.
 */
class GroupEngine(
    private val store: GroupStore,
    private val signal: SignalProtocolStore,
    private val identity: IdentityKeyPair,
    private val io: GroupIo,
) {
    val me: String = B64.enc(identity.publicKey.serialize())
    private val meBytes: ByteArray = identity.publicKey.serialize()

    // ---------- local actions ----------

    /** Creates a group with us as its owner and [invitees] (identity keys) invited, and invites them over 1:1. */
    fun create(gid: String, name: String, invitees: List<String>, myCard: SignedCard, timer: Long): GroupModel {
        val others = invitees.distinct().filter { it != me && GroupCrypto.isIdentity(it) }
        require(others.size + 1 <= RosterRules.MAX_MEMBERS) { "too many members" }
        val r = Roster(
            g = gid, ver = 1, prev = "", name = name, timer = timer,
            members = listOf(RosterMember(me, Role.OWNER, 1)) + others.map { RosterMember(it, Role.INVITED, 1) },
            by = me, ts = io.nowMillis() / 1000,
        )
        require(RosterRules.wellFormed(r, gid)) { "bad roster" }
        val signed = GroupCrypto.signRoster(identity.privateKey, r)
        val m = GroupModel(gid, GroupModel.JOINED, signed, mutableMapOf(), myCard, null, mutableListOf(), 1)
        store.addHistory(gid, signed)
        store.save(m)
        io.onEvents(m, listOf(GroupEvent.Created))
        invite(m, signed, others)
        return m
    }

    /**
     * As the owner, publishes [op] as the next roster, with the facts we hold folded in (null: only fold them). Signs it
     * and applies it; what everyone is owed follows from that ([flush]). Returns null if we aren't the owner or the change
     * isn't possible.
     */
    fun publish(m: GroupModel, op: RosterOp?): SignedRoster? {
        val signed = sign(m, op) ?: return null
        flush(m)
        return signed
    }

    private fun sign(m: GroupModel, op: RosterOp?): SignedRoster? {
        val base = m.roster ?: return null
        if (m.state != GroupModel.JOINED) {
            return null
        }
        val facts = m.facts.map { it.fact }
        if (Membership.owner(base.roster, facts) != me) {
            return null
        }
        val ver = base.roster.ver + 1
        val folded = Membership.fold(base.roster, facts, me)
        val changed = (if (op == null) folded.takeIf { Membership.pending(base.roster, facts, me) } else op.apply(folded, me, ver)) ?: return null
        val proof = Membership.departures(base.roster, facts)
        val proofWire = m.facts.filter { sf -> proof.any { it === sf.fact } }.map { it.wire() }
        val next = RosterRules.successor(base, changed, me, io.nowMillis() / 1000, proofWire)
        if (!RosterRules.wellFormed(next, m.gid) || !RosterRules.validChild(base.roster, next, proof)) {
            return null
        }
        val signed = GroupCrypto.signRoster(identity.privateKey, next)
        dbg { "publish v${next.ver} ${op?.javaClass?.simpleName ?: "fold"}" }
        take(m, signed)
        // Whoever this takes out is owed the rosters that say so; whoever it invites gets the invitation over 1:1.
        for (id in base.roster.ids() - next.ids().toSet() - me) {
            if (facts.none { it.kind == FactKind.LEAVE && it.id == id }) {
                val since = base.roster.member(id)!!.since
                m.peers[id] = (m.peers[id] ?: PeerSync()).copy(out = true, outFrom = since)
            }
        }
        invite(m, signed, next.members.filter { it.role == Role.INVITED && it.since == next.ver }.map { it.id })
        store.save(m)
        return signed
    }

    /** An invitation: the roster that invites them, over 1:1 (they're the owner's contacts, and have no inbox yet). */
    private fun invite(m: GroupModel, signed: SignedRoster, ids: List<String>) {
        val h = head(m) ?: return
        for (id in ids) {
            // Invited again: whatever we owed them from before is over.
            m.peers.remove(id)
            io.sendDirect(m.gid, id, Content.GState(m.gid, h, rosters = listOf(signed.wire())))
        }
    }

    /**
     * Joins a group we were invited to: our acceptance, carrying our card, goes to the owner (over 1:1, or through their
     * card if we have it); the owner admits us in its next roster and then sends us the group's state.
     */
    fun join(m: GroupModel, myCard: SignedCard): Boolean {
        val mine = m.roster?.roster?.member(me)
        if (m.state != GroupModel.INVITED || mine?.role != Role.INVITED || mine.since != m.since || m.view()?.owner == null) {
            return false
        }
        // Members take a card only for the stint it names.
        if (myCard.card.since != m.since || myCard.card.g != m.gid) {
            return false
        }
        val before = m.view()
        val fact = GroupCrypto.signFact(
            identity.privateKey,
            Fact(g = m.gid, kind = FactKind.ACCEPT, id = me, since = m.since, ts = io.nowMillis() / 1000, card = Signed(B64.enc(myCard.bytes), B64.enc(myCard.sig))),
        )
        m.myCard = myCard
        m.state = GroupModel.JOINED
        m.facts += fact
        settle(m, before, me)
        flush(m)
        return true
    }

    /**
     * The user's "Send again", while waiting to be let in: our acceptance, with our card, goes once more to whoever owns
     * the group as far as we know, over 1:1 if they're a contact (else through their card). Our acceptance, or the owner's
     * answer to it, may have been lost, and nothing else sends it again. The owner treats it like the first one: it takes
     * it in, or answers with its state if it already has, or if the invitation is over. At most once per
     * [SEND_AGAIN_AFTER] ([sendAgainAt]). Returns whether it went.
     */
    fun sendAgain(m: GroupModel): Boolean {
        val at = sendAgainAt(m, me) ?: return false
        if (io.nowMillis() < at) {
            return false
        }
        val owner = m.view()?.owner ?: return false
        val mine = head(m) ?: return false
        val ps = m.peers[owner] ?: PeerSync()
        val from = ps.acked?.v?.coerceAtMost(m.roster!!.roster.ver) ?: (m.since - 1).coerceAtLeast(0)
        val ok = states(m, mine, from, withCards = true).all { s ->
            io.sendDirect(m.gid, owner, s) || (m.cards[owner] != null).also { if (it) io.sendGroup(m.gid, owner, s) }
        }
        dbg { "${who(me)} sends its acceptance again to ${who(owner)}: $ok" }
        if (ok) {
            m.peers[owner] = ps.copy(sent = "accept>${mine.key}", sentAt = mine.key, sentN = 1, sentTs = io.nowMillis())
            store.save(m)
        }
        return ok
    }

    /**
     * Leaves (or declines): our departure (a fact) goes at once to everyone we can reach, the owner (or, declining, the
     * inviter) included, and takes us out of their view. Leaving as the owner hands the group to the next member.
     */
    fun leave(m: GroupModel): Boolean {
        if (m.state == GroupModel.LEFT || m.state == GroupModel.REMOVED) {
            return true
        }
        // As the owner: first take in the acceptances we hold, so whoever joined can take over.
        sign(m, null)
        val fact = GroupCrypto.signFact(
            identity.privateKey,
            Fact(
                g = m.gid, kind = FactKind.LEAVE, id = me, since = m.since, ts = io.nowMillis() / 1000,
                // Whoever takes over from us builds on the newest rosters we know, which may be ones we just signed and that
                // reached nobody yet.
                last = if (m.state == GroupModel.JOINED) m.roster?.roster?.ver ?: 0 else 0,
            ),
        )
        m.facts += fact
        val h = head(m)
        if (h != null) {
            val run = if (m.state == GroupModel.JOINED) ownRun(m).map { it.wire() } else emptyList()
            val content = Content.GState(m.gid, h, rosters = run, facts = listOf(fact.wire()))
            val v = m.view()!!
            // Whoever is still in, and the owner. The one who invited us only while they're in too (or while we're only
            // declining): someone who has gone since isn't told who's in now.
            val inviter = m.invitedBy?.takeIf { m.state == GroupModel.INVITED || v.isActive(it) }
            val targets = (if (m.state == GroupModel.JOINED) v.ids().filter { v.isActive(it) } else emptyList()) + listOfNotNull(inviter, v.owner)
            for (id in targets.toSet() - me) {
                send(m, id, content)
            }
            if (m.state == GroupModel.INVITED) {
                v.owner?.let { m.peers[it] = PeerSync(sent = DECLINED, sentTs = io.nowMillis()) }
            }
        }
        m.state = GroupModel.LEFT
        // The cards stay until what's queued above is delivered; nothing new is sent once we've left.
        store.save(m)
        io.onEvents(m, listOf(GroupEvent.YouLeft))
        return true
    }

    /** The newest roster, and before it the run of rosters we signed ending there, oldest first (sent with a departure). */
    private fun ownRun(m: GroupModel): List<SignedRoster> {
        val out = ArrayList<SignedRoster>()
        var x = m.roster
        while (x != null && out.size < GroupCrypto.MAX_LAST && (out.isEmpty() || x.roster.by == me)) {
            out += x
            x = store.history(m.gid, x.roster.prev)?.takeIf { it.roster.ver == x!!.roster.ver - 1 }
        }
        return out.reversed()
    }

    /** Replaces our card (new inbox or keys). Who needs it follows from our head ([flush]). */
    fun updateCard(m: GroupModel, card: SignedCard) {
        m.myCard = card
        store.save(m)
        flush(m)
    }

    // ---------- heads and state ----------

    /** Our head (docs/groups.md, "Heads"), to put on everything we send to the group. Null without a roster. */
    fun head(m: GroupModel): Head? = headOf(m, me)

    /** The cards half of a head's digest, to tell whether cards differ. */
    private fun cardsPart(h: Head) = h.d.drop(16)

    /**
     * What we owe each peer, from our state and what they last showed us (docs/groups.md, "What's owed"), sent where we
     * have a route. The owner owes every member its state; a member owes the owner, and anyone whose head shows them
     * behind. A peer ahead of us is asked. Each (their head, our head) pair gets one message (an ask: each head of theirs),
     * and at most [MAX_STATES] go to a peer per head of ours, whatever heads they show; an ordinary message or an ask from
     * them renews that, [RESEND_AFTER] after we last sent them one ([observe]). What can't be sent yet stays owed.
     */
    private fun flush(m: GroupModel) {
        val v = m.view() ?: return
        val mine = head(m) ?: return
        if (mine.key != m.headKey) {
            m.headSeq++
            m.headKey = mine.key
            store.save(m)
            return flush(m)
        }
        if (m.state == GroupModel.JOINED && m.roster!!.roster.role(me) == Role.INVITED) {
            oweAcceptance(m, v, mine)
            store.save(m)
            return
        }
        if (m.state == GroupModel.LEFT && m.roster!!.roster.role(me) == Role.INVITED) {
            oweDecline(m, v, mine)
            return
        }
        if (m.state != GroupModel.JOINED) {
            return
        }
        for (mem in v.members) {
            val id = mem.id
            if (id == me || !v.isActive(id)) {
                continue
            }
            val ps = m.peers[id] ?: PeerSync()
            val theirs = ps.acked
            val cmp = theirs?.let { Head.compare(mine, it) }
            if (cmp == 0 || (theirs != null && cmp == null)) {
                continue
            }
            if (!(v.owner == me || id == v.owner || theirs != null)) {
                continue
            }
            // Once per pair of heads; an ask (we're behind) once per head of theirs and version of ours, whatever else
            // changes on our side.
            val key = if (cmp == -1) "ask ${theirs!!.key}<${mine.v}" else "${theirs?.key}>${mine.key}"
            val n = if (ps.sentAt == mine.key) ps.sentN else 0
            dbg { "${who(me)} owes ${who(id)}: cmp $cmp, $n sent for this head" }
            if (ps.sent == key || n >= MAX_STATES) {
                continue
            }
            val ok = if (cmp == -1) {
                send(m, id, Content.GState(m.gid, mine))
            } else {
                val withCards = theirs == null || cardsPart(theirs) != cardsPart(mine)
                states(m, mine, theirs?.v ?: (mem.since - 1).coerceAtLeast(0), withCards).all { send(m, id, it) }
            }
            if (ok) {
                m.peers[id] = ps.copy(sent = key, sentAt = mine.key, sentN = n + 1, sentTs = io.nowMillis())
            }
        }
        // Who was taken out is owed the rosters that say so (through their old card, or over 1:1), again if they still
        // write to the group ([receive]): up to the one that took them out, and none after it.
        for ((id, ps) in m.peers.filter { it.value.out && it.value.sent == null }) {
            val from = ps.acked?.v ?: (ps.outFrom - 1)
            // Nothing to tell them if we no longer hold the roster that took them out.
            val until = stintRun(m, id, ps.outFrom)?.last()?.roster?.ver
            val ok = until == null || states(m, mine, from, withCards = false, withFacts = false, newest = true, until = until).all { s ->
                io.sendDirect(m.gid, id, s) || sendGroupTo(m, id, s)
            }
            if (ok) {
                m.peers[id] = ps.copy(sent = OUT, sentTs = io.nowMillis())
            }
        }
        store.save(m)
    }

    /**
     * Joined, not admitted yet: our state, with our acceptance in it, is owed to the owner, through their card if we have
     * it, else over 1:1. It may tell them more than that we accepted: that they're the owner now, say, when the one who
     * invited us left and only we heard.
     */
    private fun oweAcceptance(m: GroupModel, v: View, mine: Head) {
        val owner = v.owner?.takeIf { it != me } ?: return
        if (m.facts.none { it.fact.id == me && it.fact.kind == FactKind.ACCEPT && it.fact.since == m.since }) {
            return
        }
        val ps = m.peers[owner] ?: PeerSync()
        // Once the owner shows a head ahead of ours, it has taken us in: what we lack is what it sends us, so we ask.
        val ahead = ps.acked?.let { Head.compare(mine, it) == -1 } == true
        val key = if (ahead) "ask ${ps.acked!!.key}<${mine.v}" else "accept>${mine.key}"
        if (ps.sent == key) {
            return
        }
        val ok = if (ahead) {
            send(m, owner, Content.GState(m.gid, mine))
        } else {
            states(m, mine, ps.acked?.v ?: (m.since - 1).coerceAtLeast(0), withCards = true).all { send(m, owner, it) }
        }
        if (ok) {
            m.peers[owner] = ps.copy(sent = key, sentAt = mine.key, sentN = 1, sentTs = io.nowMillis())
        }
    }

    /**
     * Declined: our departure is owed to the owner. It went to the one we knew when we declined; if they had left, their
     * answer ([redirect]) names the one after them, with their card. That may be out of date too (they may not have heard
     * of every departure), so then it goes to every member we can reach, once each: whoever holds it passes it on.
     */
    private fun oweDecline(m: GroupModel, v: View, mine: Head) {
        val owner = v.owner?.takeIf { it != me } ?: return
        val dep = m.facts.lastOrNull { it.fact.id == me && it.fact.kind == FactKind.LEAVE && it.fact.since == m.since } ?: return
        if (m.peers[owner]?.sent == DECLINED) {
            return
        }
        val content = Content.GState(m.gid, mine, facts = listOf(dep.wire()))
        for (id in listOf(owner) + v.ids().filter { it != me && it != owner && v.isActive(it) }) {
            if (m.peers[id]?.sent == DECLINED) {
                continue
            }
            val sent = when {
                io.sendDirect(m.gid, id, content) -> true
                m.cards[id] != null -> {
                    io.sendGroup(m.gid, id, content)
                    true
                }
                else -> false
            }
            if (sent) {
                m.peers[id] = PeerSync(sent = DECLINED, sentTs = io.nowMillis())
            }
        }
        store.save(m)
    }

    /**
     * Our state for someone at version [from]: our chain after it, up to [until] (the first [SYNC_ROSTERS]: they ask again
     * from where they got to; or with [newest], the last ones, for someone out, who can take the newest past a gap), the
     * facts our roster doesn't show yet, and (if [withCards]) every card we hold, in as many messages as it takes to keep
     * each small.
     */
    private fun states(
        m: GroupModel,
        h: Head,
        from: Long,
        withCards: Boolean,
        withFacts: Boolean = true,
        newest: Boolean = false,
        until: Long = Long.MAX_VALUE,
    ): List<Content.GState> {
        val after = chain(m, from + 1).filter { it.roster.ver <= until }
        val r = m.roster!!.roster
        val facts = if (withFacts) m.facts.filter { Membership.applies(r, it.fact) }.map { it.wire() } else emptyList()
        val cards = if (withCards) (m.cards.values + listOfNotNull(m.myCard)).map { Signed(B64.enc(it.bytes), B64.enc(it.sig)) } else emptyList()
        return pack(m, h, if (newest) after.takeLast(SYNC_ROSTERS) else after.take(SYNC_ROSTERS), facts, cards)
    }

    /** [rosters], [facts] and [cards] in as many state messages as it takes to keep each small. */
    private fun pack(m: GroupModel, h: Head, list: List<SignedRoster>, facts: List<Signed>, cards: List<Signed>): List<Content.GState> {
        val rosters = list.map { it.wire() }
        val out = mutableListOf<Content.GState>()
        var cur = Content.GState(m.gid, h, facts = facts)
        var size = facts.sumOf { it.data.length }
        fun add(w: Signed, roster: Boolean) {
            if (size + w.data.length > STATE_BYTES && (cur.rosters.isNotEmpty() || cur.cards.isNotEmpty() || cur.facts.isNotEmpty())) {
                out += cur
                cur = Content.GState(m.gid, h)
                size = 0
            }
            cur = if (roster) cur.copy(rosters = cur.rosters + w) else cur.copy(cards = cur.cards + w)
            size += w.data.length
        }
        rosters.forEach { add(it, true) }
        cards.forEach { add(it, false) }
        out += cur
        return out
    }

    /** Through their card if we have it (and we're in), else over 1:1. */
    private fun send(m: GroupModel, id: String, content: Content): Boolean {
        if (m.cards[id] != null && m.state == GroupModel.JOINED) {
            io.sendGroup(m.gid, id, content)
            return true
        }
        return io.sendDirect(m.gid, id, content)
    }

    /** To someone just taken out: their card is kept (as departed) until what's queued to them is delivered. */
    private fun sendGroupTo(m: GroupModel, id: String, content: Content): Boolean {
        if (m.departed[id] == null && m.cards[id] == null) {
            return false
        }
        io.sendGroup(m.gid, id, content)
        return true
    }

    /**
     * [id]'s stint [since] as our chain tells it: the rosters from the one that invited them up to and including the one
     * that ended it, oldest first. Null if we hold no roster of it, or it hasn't ended.
     */
    private fun stintRun(m: GroupModel, id: String, since: Long): List<SignedRoster>? {
        val run = chain(m, since)
        val end = run.indexOfFirst { it.roster.member(id)?.since != since }
        return if (end > 0) run.subList(0, end + 1) else null
    }

    /** Our chain from version [from] (inclusive) to the current roster, oldest first, as far back as we hold it. */
    private fun chain(m: GroupModel, from: Long): List<SignedRoster> {
        val out = ArrayList<SignedRoster>()
        var x = m.roster
        while (x != null && x.roster.ver >= from && out.size < 200) {
            out += x
            x = store.history(m.gid, x.roster.prev)?.takeIf { it.roster.ver == x!!.roster.ver - 1 }
        }
        return out.reversed()
    }

    // ---------- crypto ----------

    /**
     * Encrypts [plaintext] (a Content encoding) to member [to] with their [card], starting a PQXDH session from it if
     * needed, and wraps it for their inbox ([BlobWrap.groupKey] of the card's hint key): what comes back is what the
     * server relays. The card may belong to a member who just left or was removed: the roster telling them still goes out.
     */
    fun encryptTo(to: String, card: GroupCard, plaintext: ByteArray): ByteArray {
        if (card.id != to) {
            throw NoCardException(to)
        }
        val addr = GroupCrypto.address(to)
        // A stored session can have no current state to send with (its last one archived): start a new one then too,
        // or every message to this member would fail from now on.
        if (!signal.containsSession(addr) || !signal.loadSession(addr).hasSenderChain()) {
            val b = card.bundle
            val bundle = PreKeyBundle(
                b.registrationId,
                b.deviceId,
                PreKeyBundle.NULL_PRE_KEY_ID,
                null,
                b.signedPreKeyId,
                ECPublicKey(B64.dec(b.signedPreKey)),
                B64.dec(b.signedPreKeySig),
                IdentityKey(B64.dec(to)),
                b.kyberPreKeyId,
                KEMPublicKey(B64.dec(b.kyberPreKey)),
                B64.dec(b.kyberPreKeySig),
            )
            SessionBuilder(signal, addr, LOCAL).process(bundle)
        }
        val msg = SessionCipher(signal, LOCAL, addr).encrypt(Padding.pad(plaintext))
        val nonce = Rand.bytes(GroupCrypto.HINT_NONCE)
        val hintKey = B64.dec(card.hintKey)
        val mac = GroupCrypto.hint(hintKey, nonce, meBytes)
        return BlobWrap.seal(BlobWrap.groupKey(hintKey), GroupBlob(msg.type, nonce, mac, msg.serialize()).encode())
    }

    /**
     * A blob that arrived on our inbox for [gid], whose hint key is [inboxHintKey]: unwrapped with the key derived from it,
     * then the sender is found by hint.
     */
    fun receive(gid: String, inboxHintKey: ByteArray, raw: ByteArray) {
        val inner = BlobWrap.open(BlobWrap.groupKey(inboxHintKey), raw) ?: return
        val blob = GroupBlob.decode(inner) ?: return
        val m = store.load(gid) ?: return
        val r = m.roster?.roster ?: return
        if (m.state != GroupModel.JOINED) {
            return
        }
        val sender = r.ids().firstOrNull { id ->
            id != me && GroupCrypto.hint(inboxHintKey, blob.nonce, B64.dec(id)).contentEquals(blob.mac)
        }
        dbg { "${who(me)} receives g=${gid.take(6)} type=${blob.type} sender=${sender?.let(::who)}" }
        if (sender == null) {
            // Someone we took out, still writing to the group: they didn't hear (it was lost). Their message isn't
            // read; the rosters that say so are owed again, at most once per [RESEND_AFTER].
            val out = m.peers.entries.firstOrNull { (id, ps) ->
                ps.out && GroupCrypto.hint(inboxHintKey, blob.nonce, B64.dec(id)).contentEquals(blob.mac)
            }
            if (out != null) {
                if (io.nowMillis() - out.value.sentTs >= RESEND_AFTER) {
                    m.peers[out.key] = out.value.copy(sent = null)
                    store.save(m)
                    flush(m)
                }
                return
            }
            fromUnlisted(m, inboxHintKey, blob)
            return
        }
        val content = decrypt(sender, blob) ?: return
        onContent(m.gid, sender, content, direct = false)
    }

    /**
     * Someone our roster doesn't list yet (a newcomer, or an owner who came after it). We've never written to them in
     * this group, so their messages are PreKey messages, each saying who it's from, unless we share a session through
     * another group: then the hint names someone we know from there. Either way it's decrypted without storing anything
     * ([ScratchStore]): no session or identity is kept, nor an existing one moved on, for someone who may never be a
     * member. What they send counts only if it comes from further on than our roster, where a roster could list them
     * ([onContent]). The blob goes along with what's held from it, so the real session consumes it before that's
     * delivered ([consume]).
     */
    private fun fromUnlisted(m: GroupModel, inboxHintKey: ByteArray, blob: GroupBlob) {
        val from = if (blob.type == PREKEY) {
            val id = runCatching { PreKeySignalMessage(blob.body).identityKey.serialize() }.getOrNull() ?: return
            if (!GroupCrypto.hint(inboxHintKey, blob.nonce, id).contentEquals(blob.mac)) {
                return
            }
            B64.enc(id)
        } else {
            store.membersElsewhere(m.gid).firstOrNull { id ->
                GroupCrypto.isIdentity(id) && GroupCrypto.hint(inboxHintKey, blob.nonce, B64.dec(id)).contentEquals(blob.mac)
            } ?: return
        }
        if (from == me) {
            return
        }
        val content = decrypt(from, blob, ScratchStore(signal)) ?: return
        onContent(m.gid, from, content, direct = false, unlisted = true, raw = blob)
    }

    /**
     * Before content read with a [ScratchStore] counts ([raw], the blob it came in, or the last part of it), the blob is
     * decrypted again with the real store, now that its sender is a member: the session moves past it, so the server
     * delivering it again later gets nowhere (libsignal rejects it as a duplicate). Without that, nothing would have
     * recorded that it was read: the group's last-resort prekeys would decrypt it again, and a view-once, disappearing
     * or deleted message would come back. Returns false if the real session had already had it (it was delivered).
     */
    private fun consume(sender: String, raw: GroupBlob?): Boolean {
        raw ?: return true
        return try {
            open(sender, raw, signal)
            true
        } catch (e: DuplicateMessageException) {
            dbg { "already had what ${who(sender)} sent before they were listed" }
            false
        } catch (e: ReusedBaseKeyException) {
            // Its PreKey message started a session from our last-resort prekeys before: a replay.
            dbg { "replayed PreKey message from ${who(sender)}" }
            false
        } catch (e: Exception) {
            // It was read once, and the real session can't move past it: nothing can decrypt it again either.
            true
        }
    }

    /**
     * The padded plaintext of [blob] from [sender], or null if the PreKey message names someone else. Throws if it fails.
     * A PreKey message for the real store is decrypted in a [ScratchStore] first and only then written to it: libsignal
     * stores the session before it refuses a replayed one ([app.goldfishsend.crypto.LastResortLog]).
     */
    private fun open(sender: String, blob: GroupBlob, keys: SignalProtocolStore): ByteArray? {
        val addr = GroupCrypto.address(sender)
        val key = IdentityKey(B64.dec(sender))
        // libsignal stores the sender's identity itself, once the message has decrypted.
        return if (blob.type == PREKEY) {
            val msg = PreKeySignalMessage(blob.body)
            if (msg.identityKey != key) {
                null
            } else if (keys === signal) {
                val staged = ScratchStore(signal)
                SessionCipher(staged, LOCAL, addr).decrypt(msg).also { staged.commit() }
            } else {
                SessionCipher(keys, LOCAL, addr).decrypt(msg)
            }
        } else {
            SessionCipher(keys, LOCAL, addr).decrypt(SignalMessage(blob.body))
        }
    }

    private fun decrypt(sender: String, blob: GroupBlob, keys: SignalProtocolStore = signal): Content? = try {
        val padded = open(sender, blob, keys)
        if (padded == null) dbg { "identity mismatch from ${who(sender)}" }
        padded?.let { Content.decode(Padding.unpad(it)) }
    } catch (e: DuplicateMessageException) {
        dbg { "duplicate from ${who(sender)}" }
        null
    } catch (e: Exception) {
        dbg { "decrypt from ${who(sender)} failed: ${e.javaClass.simpleName}" }
        null
    }

    // ---------- incoming content ----------

    /**
     * Group content that arrived over a 1:1 session with contact [from] (identity key, b64u). About a group we know, only
     * from someone it concerns ([mayWriteDirect]); about one we don't, only an invitation from its owner ([invitation]).
     */
    fun onDirect(from: String, content: Content) {
        val gid = content.groupId ?: return
        val m = store.load(gid)
        if (m != null && !mayWriteDirect(m, from)) {
            dbg { "${who(me)} ignores 1:1 group content from ${who(from)}, who isn't in g=${gid.take(6)}" }
            return
        }
        onContent(gid, from, content, direct = true)
    }

    /**
     * Whether [from] may tell us anything over 1:1 about [m]: someone our roster lists (owner, member or invitee), the one
     * who invited us, or a peer we're in touch with about it (one we answer, or took out). Any other contact who knows
     * the group's id has nothing for us: their rosters, facts and cards would check themselves, but merging them is work
     * (and held facts) a stranger shouldn't be able to cause.
     */
    private fun mayWriteDirect(m: GroupModel, from: String): Boolean {
        val r = m.roster?.roster ?: return false
        return r.member(from) != null || from == m.invitedBy || from in m.peers
    }

    /**
     * [unlisted]: from someone our roster didn't list when it arrived, read by [fromUnlisted]; [raw], the blob it was read
     * from then (see [consume]).
     */
    private fun onContent(gid: String, from: String, content: Content, direct: Boolean, unlisted: Boolean = false, raw: GroupBlob? = null) {
        if (content is Content.Chunk) {
            if (content.parts !in 2..Chunker.MAX_PARTS || content.part !in 0 until content.parts || content.data.length > 4096) {
                return
            }
            val key = "k:" + GroupCrypto.tag(from) + ":" + content.id.take(32)
            val joined = store.storeChunk(gid, key, content.part, content.parts, content.data) ?: return
            val inner = runCatching { Content.decode(B64.dec(joined)) }.getOrNull() ?: return
            if (inner !is Content.Chunk) {
                // Its last part's blob: once the real session has that one, the server can't make the whole again.
                onContent(gid, from, inner, direct, unlisted, raw)
            }
            return
        }
        if (content.groupId != gid) {
            return
        }
        if (unlisted && !fromFurtherOn(gid, from, content)) {
            return
        }
        dbg { "${who(me)} content ${content.javaClass.simpleName} g=${gid.take(6)} from=${who(from)} direct=$direct unlisted=$unlisted" }
        when (content) {
            is Content.GState -> onState(from, content, direct)
            is Content.GText -> active(gid, from, content.h)?.let { m -> if (consume(from, raw)) io.onText(m, from, content) }
                ?: holdFromInvitee(gid, from, content, unlisted, raw)
            is Content.GReceipt -> active(gid, from, content.h)?.let { m -> if (consume(from, raw)) io.onReceipt(m, from, content) }
                ?: holdFromInvitee(gid, from, content, unlisted, raw)
            is Content.GDelete -> active(gid, from, content.h)?.let { m -> if (consume(from, raw)) io.onDelete(m, from, content) }
                ?: holdFromInvitee(gid, from, content, unlisted, raw)
            else -> Unit
        }
        store.load(gid)?.let { flush(it) }
    }

    /**
     * Whether content from [from], whom our roster didn't list, may count: they're listed by now, or it comes from further
     * on than our roster (only a newer roster can list them). Someone who was in the group once and isn't now, writing from
     * where we are or before, has nothing for us.
     */
    private fun fromFurtherOn(gid: String, from: String, content: Content): Boolean {
        val r = store.load(gid)?.roster?.roster ?: return false
        return r.member(from) != null || (content.head?.v ?: 0) > r.ver
    }

    /**
     * A message from someone still invited as far as we know: their admission hasn't reached us yet (pushes arrive out of
     * order). Keep it until it does, bounded like other held blobs. It's already decrypted (the session has moved on), so
     * it's kept as content, then replayed by [replayHeld]. With [unlisted], from someone our roster doesn't list at all
     * (a newcomer from a roster we haven't got); [raw] is kept with it (see [consume]).
     */
    private fun holdFromInvitee(gid: String, from: String, content: Content, unlisted: Boolean, raw: GroupBlob?) {
        val m = store.load(gid) ?: return
        val role = m.view()?.role(from)
        if (m.state != GroupModel.JOINED || (role != Role.INVITED && !(role == null && unlisted))) {
            return
        }
        if (role == null && (content.head?.v ?: 0) > (m.roster?.roster?.ver ?: 0) + 1) {
            // Someone our roster doesn't list, writing from further on: we missed what lists them.
            behindAGap(m)
        }
        dbg { "holding ${content.javaClass.simpleName} from invitee ${who(from)}" }
        val blob = raw?.encode() ?: ByteArray(0)
        store.hold(gid, if (role == null) HELD_UNLISTED else HELD_CONTENT, B64.dec(from) + u32(blob.size) + blob + content.encode())
    }

    /** The group, if we're in it and [from] is a current member (not just invited); their head is noted. */
    private fun active(gid: String, from: String, h: Head?): GroupModel? {
        val m = store.load(gid) ?: return null
        if (m.state != GroupModel.JOINED || m.view()?.isActive(from) != true) {
            return null
        }
        if (h != null) {
            observe(m, from, h, renew = true)
            store.save(m)
        }
        return m
    }

    /**
     * [from]'s head, which acknowledges everything up to it (unless a newer one of theirs came first). With [renew] (an
     * ordinary message, or an ask), once [RESEND_AFTER] has passed since we last sent them anything, what we sent may
     * have been lost (retention expiry), so it's owed again. Before that it's likely still on its way: answering every
     * message, or any state, would have two members answer each other's messages in flight.
     */
    private fun observe(m: GroupModel, from: String, h: Head, renew: Boolean) {
        val ps0 = m.peers[from] ?: PeerSync()
        val ps = if (renew && io.nowMillis() - ps0.sentTs >= RESEND_AFTER) ps0.copy(sent = null, sentN = 0) else ps0
        m.peers[from] = if (ps.acked == null || h.s >= ps.acked.s) ps.copy(acked = h) else ps
    }

    /**
     * State from a peer, merged: rosters extend our chain, facts join the set, the higher card `seq` wins. Merging the
     * same state again changes nothing. Then whatever it changed is owed on ([flush], by [onContent]).
     *
     * The work one state can cause is bounded: the group is loaded once and every step works on that model, a fact
     * repeated in it (the same bytes, or the same stint and kind) is looked at once, and only one stale acceptance per
     * state is answered ([answerStale]).
     */
    private fun onState(from: String, c: Content.GState, direct: Boolean) {
        val rosters = c.rosters.take(SYNC_ROSTERS).mapNotNull { w -> GroupCrypto.openRoster(w)?.takeIf { RosterRules.wellFormed(it.roster, c.g) } }
        val m = store.load(c.g) ?: invitation(from, rosters.firstOrNull() ?: return, direct) ?: return
        val was = m.roster?.roster?.ver ?: return
        for (sr in rosters) {
            onSignedRoster(m, sr)
        }
        if (m.roster?.roster?.ver == was && rosters.any { it.roster.ver > was + 1 }) {
            behindAGap(m)
        }
        val before = m.view() ?: return
        var changed = false
        var by = from
        var answered = false
        val seen = HashSet<String>()
        for (w in c.facts.distinctBy { it.data }.take(MAX_FACTS)) {
            val sf = GroupCrypto.openFact(w) ?: continue
            if (!seen.add(sf.key)) {
                continue
            }
            val counts = onFact(m, from, sf, direct) { stale ->
                if (!answered) {
                    answered = answerStale(m, from, stale, c.h)
                }
            }
            if (counts) {
                changed = true
                by = sf.fact.id
            }
        }
        if (changed && m.state != GroupModel.LEFT && m.state != GroupModel.REMOVED) {
            settle(m, before, by)
        }
        for (w in c.cards.take(RosterRules.MAX_MEMBERS + 1)) {
            val card = runCatching { GroupCrypto.openCard(B64.dec(w.data), B64.dec(w.sig), io::validServer) }.getOrNull() ?: continue
            addCard(m, card)
        }
        if (m.roster?.roster?.role(from) != null) {
            observe(m, from, c.h, renew = c.rosters.isEmpty() && c.facts.isEmpty() && c.cards.isEmpty())
        }
        store.save(m)
    }

    /**
     * Someone sent us rosters further on than ours that don't connect: their chain starts after ours ends (they came
     * later). Only an owner of ours can fill that, and what it sent us may have been lost: what we owe it is owed again
     * (at most once per [RESEND_AFTER]). If it has left since, its answer names who owns the group now.
     */
    private fun behindAGap(m: GroupModel) {
        if (m.state != GroupModel.JOINED) {
            return
        }
        val owner = m.view()?.owner?.takeIf { it != me } ?: return
        val ps = m.peers[owner] ?: return
        if (io.nowMillis() - ps.sentTs >= RESEND_AFTER) {
            m.peers[owner] = ps.copy(sent = null, sentN = 0)
            store.save(m)
        }
    }

    /**
     * A roster for a group we don't know: an invitation if it came over 1:1 from its owner, who signed it, listing us
     * invited. The 1:1 session says who it's from, so no contact can invite us in someone else's name (nor relay a roster
     * a stranger signed, who would then be the owner).
     */
    private fun invitation(from: String, signed: SignedRoster, direct: Boolean): GroupModel? {
        val r = signed.roster
        val mine = r.member(me)
        if (!direct || from != r.by || r.by != r.owner || mine?.role != Role.INVITED) {
            return null
        }
        val fresh = GroupModel(r.g, GroupModel.INVITED, signed, mutableMapOf(), null, r.by, mutableListOf(), mine.since)
        store.save(fresh)
        store.addHistory(r.g, signed)
        io.onEvents(fresh, listOf(GroupEvent.Invited(r.by)))
        return fresh
    }

    /**
     * A roster for a group we know. The chain is linear: the next one (signed by the owner of ours) is taken; an older one
     * is old news; one further on can't be checked, except as an invitation (we're out) or as the owner of ours taking us
     * out. Otherwise it's left: whoever sent it sees our head and sends what's in between.
     */
    private fun onSignedRoster(m: GroupModel, signed: SignedRoster) {
        val cur = m.roster ?: return
        val r = signed.roster
        if (r.ver <= cur.roster.ver) {
            return
        }
        if (r.ver == cur.roster.ver + 1 && r.prev == cur.hashB64 && validNext(cur, signed)) {
            take(m, signed)
            return
        }
        if (r.ver > cur.roster.ver + 1) {
            if (invitesAgain(m, signed)) {
                jump(m, signed)
            } else if (m.state != GroupModel.LEFT && m.state != GroupModel.REMOVED && r.by == m.view()?.owner && r.member(me)?.since != m.since) {
                // Our owner, signing a roster without our stint: we were taken out (what's in between isn't ours to know).
                jump(m, signed)
            }
        }
    }

    /**
     * Out of the group (or only invited, and taken out meanwhile), [r] lists us as invited in a newer stint, signed by the
     * owner as far as we know (our view's), who is its owner too. Like a first invitation, it's taken on its owner's word,
     * gap or not. (Not while we're in: then the chain is ours to follow.) Only the owner we know: anyone else who knows
     * the group could sign a roster further on that makes themselves its owner, and with it take over our invitation, or
     * our place in a group we left, and keep the real owner's later rosters out (ours would be further on).
     */
    private fun invitesAgain(m: GroupModel, r: SignedRoster): Boolean {
        val mine = r.roster.member(me) ?: return false
        val owner = m.view()?.owner ?: return false
        return m.state != GroupModel.JOINED && r.roster.by == owner && r.roster.owner == owner && mine.role == Role.INVITED && mine.since > m.since
    }

    /** Moves to [signed] past a gap (see [onSignedRoster]). */
    private fun jump(m: GroupModel, signed: SignedRoster) {
        m.roster = signed
        store.addHistory(m.gid, signed)
        settle(m, null, signed.roster.by)
    }

    private fun validNext(cur: SignedRoster, next: SignedRoster): Boolean {
        val proof = next.roster.proof.map { GroupCrypto.openFact(it)?.fact ?: return false }
        return RosterRules.validChild(cur.roster, next.roster, proof)
    }

    /**
     * A member's accept or leave. It counts if it's about a stint our roster lists; one about a newer stint (we're behind)
     * is kept for when our roster catches up; one about a stint that's over is ignored, so replays do nothing, but for
     * [stale], which may answer its author ([answerStale]). Returns whether it's new and counts.
     */
    private fun onFact(m: GroupModel, from: String, sf: SignedFact, direct: Boolean, stale: (SignedFact) -> Unit): Boolean {
        val f = sf.fact
        if (f.g != m.gid || f.id == me) {
            return false
        }
        val r = m.roster?.roster ?: return false
        val out = m.state == GroupModel.LEFT || m.state == GroupModel.REMOVED
        if (out) {
            // Out of the group: an invitee's acceptance or decline that reached us, the inviter, is answered from our
            // records, and so is one we took in before we left (what we sent them since may have been lost).
            redirect(m, from, sf, direct)
        }
        if (Membership.stale(r, f)) {
            if (!out) {
                stale(sf)
            }
            return false
        }
        if (m.facts.any { it.key == sf.key }) {
            return false
        }
        val applies = Membership.applies(r, f)
        if (!applies) {
            // Kept for when our roster catches up: a few per member, and a few in all, since anyone can sign facts about
            // new identities of their own. When full, the ones nearest our roster are kept: they're the likeliest to count.
            val ahead = m.facts.filter { it.fact.id != me && !Membership.applies(r, it.fact) }
            if (ahead.count { it.fact.id == f.id } >= MAX_AHEAD) {
                return false
            }
            if (ahead.size >= MAX_AHEAD_ALL) {
                val furthest = ahead.maxBy { reach(it.fact) }
                if (reach(furthest.fact) <= reach(f)) {
                    return false
                }
                m.facts.remove(furthest)
            }
        }
        if (out) {
            m.facts += sf
            store.save(m)
            return false
        }
        m.facts += sf
        store.save(m)
        if (applies && f.kind == FactKind.ACCEPT) {
            f.card?.let { w -> runCatching { GroupCrypto.openCard(B64.dec(w.data), B64.dec(w.sig), io::validServer) }.getOrNull() }
                ?.takeIf { it.card.id == f.id && it.card.g == m.gid }?.let { addCard(m, it) }
        }
        return applies
    }

    /**
     * An acceptance, from its author, that our roster doesn't take: they're waiting to be let in, and what we sent them
     * was lost, or they sent it again ([sendAgain]). Taking it again changes nothing; they're answered instead.
     * - **Already let in:** what we owe them is owed again, so they get our state.
     * - **Taken out by us:** the rosters that say so are owed again ([flush]).
     * - **The stint is over otherwise** (the invitation withdrawn, or they were taken out): our chain from where they are
     *   (their head [h], or that invitation) up to the roster that ended it, which says how it ended, over 1:1. Never the
     *   rosters after it: who came in since is none of their business. Nothing if they left: they know how it ended.
     *
     * Once per our head, and at most once per [SEND_AGAIN_AFTER]. Returns whether it looked for the stint in our chain,
     * the costly part, which [onState] does for one acceptance per state.
     */
    private fun answerStale(m: GroupModel, from: String, sf: SignedFact, h: Head): Boolean {
        val f = sf.fact
        if (from != f.id || f.kind != FactKind.ACCEPT || m.state != GroupModel.JOINED) {
            return false
        }
        val ps = m.peers[from] ?: PeerSync()
        if (m.roster?.roster?.member(f.id)?.since == f.since) {
            if (m.view()?.isActive(f.id) == true && io.nowMillis() - ps.sentTs >= SEND_AGAIN_AFTER) {
                dbg { "${who(me)} answers ${who(from)}'s acceptance again: already in" }
                m.peers[from] = ps.copy(sent = null, sentN = 0)
                store.save(m)
            }
            return false
        }
        if (ps.out && ps.outFrom == f.since) {
            if (ps.sent != null && io.nowMillis() - ps.sentTs >= SEND_AGAIN_AFTER) {
                m.peers[from] = ps.copy(sent = null)
                store.save(m)
            }
            return false
        }
        val mine = head(m) ?: return false
        val key = "stale>${mine.key}"
        if (ps.sent == key && io.nowMillis() - ps.sentTs < SEND_AGAIN_AFTER) {
            return false
        }
        val run = stintRun(m, f.id, f.since) ?: return true
        val left = run.last().roster.proof.any { w ->
            GroupCrypto.openFact(w)?.fact?.let { it.kind == FactKind.LEAVE && it.id == f.id && it.since == f.since } == true
        }
        if (left) {
            return true
        }
        // From where they say they are, if that's inside the stint: each "Send again" gets them further.
        val rest = run.dropWhile { it.roster.ver <= h.v }.ifEmpty { run.takeLast(1) }.take(SYNC_ROSTERS)
        dbg { "${who(me)} answers ${who(from)}'s stale acceptance: v${rest.first().roster.ver} to v${rest.last().roster.ver}" }
        if (pack(m, mine, rest, emptyList(), emptyList()).all { io.sendDirect(m.gid, from, it) }) {
            m.peers[from] = ps.copy(sent = key, sentTs = io.nowMillis())
            store.save(m)
        }
        return true
    }

    /**
     * We invited them, then left: their acceptance (or decline) reached only us. They get, over 1:1, our chain from the invitation, the
     * facts we hold (which say who owns the group now) and that owner's card, and can send it on themselves.
     */
    private fun redirect(m: GroupModel, from: String, sf: SignedFact, direct: Boolean) {
        val f = sf.fact
        val r = m.roster?.roster ?: return
        val mem = r.member(f.id)
        if (!direct || from != f.id || mem?.since != f.since || (f.kind != FactKind.ACCEPT && mem.role != Role.INVITED)) {
            return
        }
        val v = m.view() ?: return
        // Nobody left to own it, maybe: then what we send says so.
        val owner = v.owner?.takeIf { it != me }
        val mine = head(m) ?: return
        val ps = m.peers[from] ?: PeerSync()
        val key = "redirect>${mine.key}"
        if (ps.sent == key && io.nowMillis() - ps.sentTs < SEND_AGAIN_AFTER) {
            return
        }
        val base = states(m, mine, f.since - 1, withCards = false).first()
        val ownerCard = owner?.let { m.cards[it] ?: m.departed[it] }
        val content = base.copy(cards = listOfNotNull(ownerCard?.let { Signed(B64.enc(it.bytes), B64.enc(it.sig)) }))
        if (io.sendDirect(m.gid, from, content)) {
            m.peers[from] = ps.copy(sent = key, sentTs = io.nowMillis())
            store.save(m)
        }
    }

    /** A card for someone in our roster, if it's newer than the one we hold. */
    private fun addCard(m: GroupModel, card: SignedCard) {
        val id = card.card.id
        // Out of the group, we keep no cards, but for one: having declined, the owner's, to send them the decline.
        val declined = m.state == GroupModel.LEFT && m.roster?.roster?.role(me) == Role.INVITED
        val out = (m.state == GroupModel.LEFT && !declined) || m.state == GroupModel.REMOVED
        // A card names the stint it's for: one kept from an earlier stint (whose inbox and keys are gone) never stands in
        // for this one's, whatever its seq.
        val since = m.roster?.roster?.member(id)?.since
        if (card.card.g != m.gid || id == me || since == null || card.card.since != since || out || (declined && id != m.view()?.owner)) {
            return
        }
        val existing = m.cards[id]
        if (existing != null && existing.card.since == since && existing.card.seq >= card.card.seq) {
            return
        }
        m.cards[id] = card
        store.save(m)
        io.onCard(m, id)
    }

    // ---------- applying changes ----------

    /**
     * Moves to [signed] (already checked) as our roster. The departures in its proof count as held facts, and the card of
     * anyone it admits is taken.
     */
    private fun take(m: GroupModel, signed: SignedRoster) {
        val before = m.view()
        m.roster = signed
        store.addHistory(m.gid, signed)
        for (w in signed.roster.proof) {
            val sf = GroupCrypto.openFact(w) ?: continue
            if (sf.fact.id != me && m.facts.none { it.key == sf.key }) {
                m.facts += sf
            }
        }
        settle(m, before, signed.roster.by)
        for (mem in signed.roster.members) {
            val w = mem.card ?: continue
            val card = runCatching { GroupCrypto.openCard(B64.dec(w.data), B64.dec(w.sig), io::validServer) }.getOrNull() ?: continue
            if (card.card.id == mem.id) {
                addCard(m, card)
            }
        }
    }

    /**
     * After the roster or the facts changed: drop facts that no longer matter, update our state, tell the app, and, if
     * we're the owner now, fold what's pending into a roster of ours.
     */
    private fun settle(m: GroupModel, before: View?, by: String) {
        val r = m.roster?.roster ?: return
        // Who left (rather than was removed), from the departures held and the roster's proof, before they're dropped.
        val leavers = (m.facts.map { it.fact } + r.proof.mapNotNull { GroupCrypto.openFact(it)?.fact })
            .filter { it.kind == FactKind.LEAVE }.map { it.id }.toSet()
        m.facts.removeAll { Membership.stale(r, it.fact) }
        val after = m.view()!!
        val events = mutableListOf<GroupEvent>()
        val mine = r.member(me)
        val again = mine != null && mine.role == Role.INVITED && mine.since > m.since
        if (again) {
            invitedAgain(m, mine!!, r.by, events)
        } else if ((m.state == GroupModel.JOINED || m.state == GroupModel.INVITED) && (mine?.since != m.since || after.role(me) == null)) {
            m.state = GroupModel.REMOVED
            events += GroupEvent.YouWereRemoved(r.by)
        }
        if (before != null) {
            events += changes(before, after, by, leavers)
        }
        val ids = after.ids().toSet()
        m.departed.clear()
        m.cards.filterKeys { it !in ids }.let { m.departed.putAll(it) }
        m.cards.keys.retainAll(ids)
        // A card from someone's earlier stint is no use for this one (its inbox is gone): theirs comes with their admission.
        m.cards.entries.removeAll { (id, c) -> after.member(id)?.since != c.card.since }
        m.peers.keys.retainAll { it in ids || m.peers[it]?.out == true }
        store.save(m)
        if (events.isNotEmpty()) {
            io.onEvents(m, events)
        }
        if (before != null && (before.ids().toSet() - ids - me).isNotEmpty() && m.state == GroupModel.JOINED && after.isActive(me)) {
            io.rotateInbox(m)
        }
        heldReady += m.gid
        if (m.state == GroupModel.JOINED && Membership.pending(r, m.facts.map { it.fact }, me)) {
            sign(m, null)
        }
    }

    /** Out (or in a stint that's over), and [mine] is a newer invitation. */
    private fun invitedAgain(m: GroupModel, mine: RosterMember, by: String, events: MutableList<GroupEvent>) {
        m.state = GroupModel.INVITED
        m.since = mine.since
        m.invitedBy = by
        m.facts.removeAll { it.fact.id == me }
        m.peers.clear()
        events += GroupEvent.Invited(by)
    }

    /** What changed for others, from [before] to [after]; [by] did it, unless it was someone's own departure or acceptance. */
    private fun changes(before: View, after: View, by: String, leavers: Set<String>): List<GroupEvent> {
        val events = mutableListOf<GroupEvent>()
        val gone = before.ids().filter { it != me && after.role(it) == null }
        val left = gone.filter { it in leavers }
        for (id in left) {
            events += GroupEvent.Left(id)
        }
        val kicked = gone - left.toSet()
        if (kicked.isNotEmpty()) {
            events += GroupEvent.Removed(by, kicked)
        }
        val added = after.ids().filter { it != me && before.role(it) == null }
        if (added.isNotEmpty()) {
            events += GroupEvent.Added(by, added)
        }
        for (id in after.ids()) {
            if (before.role(id) == Role.INVITED && after.isActive(id)) {
                events += GroupEvent.Joined(id)
            }
        }
        val owner = after.owner
        if (owner != null && owner != before.owner) {
            events += GroupEvent.OwnerChanged(by, owner)
        }
        if (before.name != after.name) {
            events += GroupEvent.Renamed(by, after.name)
        }
        if (before.timer != after.timer) {
            events += GroupEvent.TimerChanged(by, after.timer)
        }
        return events
    }

    /** Groups whose membership changed in this engine's calls, so their held messages may be deliverable now. */
    private val heldReady = LinkedHashSet<String>()

    /**
     * The held messages that may be deliverable now (their group's membership changed since the last call). The caller
     * replays each with [replayHeld] in its own transaction, once the change that freed them is stored: a held message
     * that fails then only drops itself, instead of undoing that change (and wedging the group) every time it's retried.
     */
    fun readyHeld(): List<Pair<String, HeldBlob>> {
        val gids = heldReady.toList()
        heldReady.clear()
        return gids.flatMap { g -> store.held(g).map { g to it } }
    }

    /** Delivers one held message, or holds it again if it still can't be. */
    fun replayHeld(gid: String, h: HeldBlob) {
        store.dropHeld(h.id)
        if (h.hintKey.contentEquals(HELD_CONTENT) || h.hintKey.contentEquals(HELD_UNLISTED)) {
            // The sender, the blob it was read from (if that was without a session: see [consume]), then the content.
            val held = runCatching {
                val from = B64.enc(h.blob.copyOfRange(0, IDENTITY_LEN))
                val n = java.nio.ByteBuffer.wrap(h.blob, IDENTITY_LEN, 4).int
                val at = IDENTITY_LEN + 4
                val raw = if (n == 0) null else GroupBlob.decode(h.blob.copyOfRange(at, at + n)) ?: error("bad blob")
                Triple(from, raw, Content.decode(h.blob.copyOfRange(at + n, h.blob.size)))
            }.getOrNull() ?: return
            onContent(gid, held.first, held.third, direct = false, unlisted = h.hintKey.contentEquals(HELD_UNLISTED), raw = held.second)
        } else {
            receive(gid, h.hintKey, h.blob)
        }
    }

    companion object {
        val LOCAL = SignalProtocolAddress("self", 1)
        private const val PREKEY = 3

        /** Rosters per state message; whoever is still behind shows it in their head, and gets the next ones. */
        const val SYNC_ROSTERS = 50

        /** Facts kept per member for stints our roster doesn't reach yet. */
        const val MAX_AHEAD = 2

        /** Facts kept in all for stints our roster doesn't reach yet. */
        const val MAX_AHEAD_ALL = 40

        /** How far on a roster must be before [f] can count. */
        private fun reach(f: Fact): Long = maxOf(f.since, f.last)

        /** Facts looked at per state message (two per member is all there can be). */
        private const val MAX_FACTS = 2 * RosterRules.MAX_MEMBERS

        /** State messages sent to one peer per head of ours, whatever heads they show (inventing heads gets no more). */
        const val MAX_STATES = 3

        /** [PeerSync.sent] for someone taken out, once the rosters that say so went to them. */
        private const val OUT = "out"

        /** [PeerSync.sent] for an owner our decline went to. */
        private const val DECLINED = "declined"

        /** How long what we sent a peer counts as on its way: after that, a message showing they still lack it renews it. */
        const val RESEND_AFTER = 60 * 60 * 1000L

        /**
         * An invitee's "Send again" ([sendAgain]) is allowed this long after they last sent the owner anything, and the
         * owner (or an inviter who left) answers the same invitee's acceptance at most this often.
         */
        const val SEND_AGAIN_AFTER = 10 * 60 * 1000L

        /** Payload per state message (b64u characters of rosters and cards), so each stays well within the chunk limit. */
        private const val STATE_BYTES = 40_000

        /** Marks a held row as already-decrypted content from an invitee (a real hint key is 32 bytes). */
        private val HELD_CONTENT = byteArrayOf(0x43)

        /** The same, from someone our roster didn't list ([fromUnlisted]). */
        private val HELD_UNLISTED = byteArrayOf(0x55)
        private const val IDENTITY_LEN = 33

        private fun u32(n: Int): ByteArray = java.nio.ByteBuffer.allocate(4).putInt(n).array()

        /** Protocol decisions, for debugging. The app routes this to logcat in debug builds only; it never carries content. */
        @Volatile
        var debugLog: ((String) -> Unit)? = null

        private fun dbg(msg: () -> String) {
            debugLog?.invoke(msg())
        }

        /** A short, stable label for a member in debug output. */
        private fun who(id: String): String = id.takeLast(6)

        /**
         * Joined and taken in: the roster lists [me] as a member. Until then (our acceptance on its way to the owner) we
         * don't know who else is in, so we can't send to the group.
         */
        fun admitted(m: GroupModel, me: String): Boolean =
            m.state == GroupModel.JOINED && m.roster?.roster?.role(me).let { it != null && it != Role.INVITED }

        /**
         * Joined, waiting to be let in: from when (our clock) the user may send our acceptance again ([sendAgain]), which
         * is [SEND_AGAIN_AFTER] after we last sent the owner anything. Null if there's nothing to send again: we're in,
         * not waiting, or nobody is left to own the group.
         */
        fun sendAgainAt(m: GroupModel, me: String): Long? {
            if (m.state != GroupModel.JOINED || m.roster?.roster?.role(me) != Role.INVITED || m.view()?.owner.let { it == null || it == me }) {
                return null
            }
            if (m.facts.none { it.fact.id == me && it.fact.kind == FactKind.ACCEPT && it.fact.since == m.since }) {
                return null
            }
            return (m.peers.values.maxOfOrNull { it.sentTs } ?: 0) + SEND_AGAIN_AFTER
        }

        /** [me]'s head in [m] (see [head]); for the app, which adds it to messages outside the engine. */
        fun headOf(m: GroupModel, me: String): Head? {
            val sr = m.roster ?: return null
            val v = m.view() ?: return null
            val f = Membership.factDigest(sr.roster, m.facts.map { it.fact to it.bytes })
            val c = Membership.cardDigest(v) { id -> if (id == me) m.myCard?.card?.seq ?: 0 else m.cards[id]?.card?.seq ?: 0 }
            return Head(sr.roster.ver, B64.enc(sr.hash.copyOf(12)), B64.enc(f) + B64.enc(c), m.headSeq)
        }

        /** Builds and signs this member's card. */
        fun makeCard(identity: IdentityKeyPair, card: GroupCard): SignedCard = GroupCrypto.signCard(identity.privateKey, card)
    }
}
