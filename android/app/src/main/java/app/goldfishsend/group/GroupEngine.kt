package app.goldfishsend.group

import app.goldfishsend.proto.B64
import app.goldfishsend.proto.Chunker
import app.goldfishsend.proto.Content
import app.goldfishsend.proto.Fact
import app.goldfishsend.proto.FactKind
import app.goldfishsend.proto.GroupBlob
import app.goldfishsend.proto.GroupCard
import app.goldfishsend.proto.GroupCrypto
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
import org.signal.libsignal.protocol.DuplicateMessageException
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.IdentityKeyPair
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
            SignedFact(bytes, B64.dec(parts[1]), app.goldfishsend.proto.GroupJson.decodeFromString(Fact.serializer(), bytes.toString(Charsets.UTF_8)))
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

    /**
     * Stores a roster: one we took, or one further on that we can't take yet (a gap). Capped per version and per author
     * ([GroupEngine.fits]): anyone can sign rosters that will never be valid, and they mustn't crowd out the real one.
     */
    fun addHistory(gid: String, r: SignedRoster)

    fun history(gid: String, hashB64: String): SignedRoster?

    /** Rosters with `ver > since`, oldest first. */
    fun historySince(gid: String, since: Long): List<SignedRoster>

    /** Stores one part. Returns the concatenated `data` of all parts, in order, once every part is there. */
    fun storeChunk(gid: String, key: String, part: Int, parts: Int, data: String): String?

    fun hold(gid: String, hintKey: ByteArray, blob: ByteArray)

    /** The newest roster version from [by] that left us out of [gid] while we had no invitation to it, or null. */
    fun withdrawn(gid: String, by: String): Long?

    /** Records one for [withdrawn]. Only the newest few (any group) are kept. */
    fun addWithdrawn(gid: String, by: String, ver: Long)

    /** Keeps a fact for a group we don't know yet (it overtook our invitation). Only the newest few (any group) are kept. */
    fun addEarlyFact(gid: String, fact: Content.GFact)

    /** The facts kept by [addEarlyFact] for [gid], and forgets them. */
    fun takeEarlyFacts(gid: String): List<Content.GFact>

    fun held(gid: String): List<HeldBlob>

    fun dropHeld(id: Long)
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
 * The group protocol (docs/groups.md): the owner's roster chain, members' facts, cards, sync, and the per-member
 * encryption with sender hints. All calls are synchronous; the app runs them under its libsignal lock inside one DB
 * transaction.
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
        for (id in others) {
            io.sendDirect(gid, id, rosterContent(signed))
            io.sendDirect(gid, id, cardContent(myCard))
        }
        return m
    }

    /**
     * As the owner, publishes [op] as the next roster, with the facts we hold folded in (null: only fold them). Signs it,
     * applies it locally and sends it to everyone in the old and new roster; new invitees also get every card over 1:1.
     * Returns null if we aren't the owner or the change isn't possible.
     */
    fun publish(m: GroupModel, op: RosterOp?): SignedRoster? {
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
        val changed = (if (op == null) folded.takeIf { it != base.roster } else op.apply(folded, me, ver)) ?: return null
        val proof = Membership.departures(base.roster, facts)
        val proofWire = m.facts.filter { sf -> proof.any { it === sf.fact } }.map { it.wire() }
        val next = RosterRules.successor(base, changed, me, io.nowMillis() / 1000, proofWire)
        if (!RosterRules.wellFormed(next, m.gid) || !RosterRules.validChild(base.roster, next, proof)) {
            return null
        }
        val signed = GroupCrypto.signRoster(identity.privateKey, next)
        dbg { "publish v${next.ver} ${op?.javaClass?.simpleName ?: "fold"}" }
        val cardsBefore = m.cards.toMap()
        take(m, signed)
        broadcast(m, base.roster, signed, cardsBefore)
        return signed
    }

    /**
     * Joins a group we were invited to: our acceptance and card go to every member we can reach (the inviter and the
     * owner over 1:1 too), then we ask the inviter for anything we missed.
     */
    fun join(m: GroupModel, myCard: SignedCard): Boolean {
        val mine = m.roster?.roster?.member(me)
        if (m.state != GroupModel.INVITED || mine?.role != Role.INVITED || mine.since != m.since || m.view()?.owner == null) {
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
        tellEveryone(m, factContent(fact))
        for (id in m.cards.keys) {
            io.sendGroup(m.gid, id, cardContent(myCard))
        }
        // Over 1:1 where possible: if the invitation was withdrawn meanwhile, the inviter can still tell us (see onSync).
        m.invitedBy?.let {
            io.sendDirect(m.gid, it, cardContent(myCard))
            if (!io.sendDirect(m.gid, it, Content.GSync(m.gid, 0))) {
                requestSync(m, it, 0)
            }
        }
        return true
    }

    /**
     * Leaves (or declines). Members stop sending to us at once (`gleave`), and our departure (a fact) takes us out of
     * everyone's view. Leaving as the owner hands the group to the next member in the roster. Always possible.
     */
    fun leave(m: GroupModel): Boolean {
        if (m.state == GroupModel.LEFT || m.state == GroupModel.REMOVED) {
            return true
        }
        // As the owner: first take in the acceptances we hold, so whoever joined can take over.
        publish(m, null)
        val head = m.roster
        val fact = GroupCrypto.signFact(
            identity.privateKey,
            Fact(
                g = m.gid, kind = FactKind.LEAVE, id = me, since = m.since, ts = io.nowMillis() / 1000,
                // Whoever takes over from us builds on the newest roster we know, which may be one we just signed.
                last = head?.takeIf { m.state == GroupModel.JOINED }?.wire(),
            ),
        )
        if (m.state == GroupModel.JOINED) {
            for (id in m.cards.keys) {
                io.sendGroup(m.gid, id, Content.GLeave(m.gid))
            }
        }
        // Declining: the inviter (the owner, and our contact) hears it over 1:1 too, which survives deleting the chat.
        tellEveryone(m, factContent(fact))
        m.facts += fact
        m.state = GroupModel.LEFT
        // The cards stay until the goodbyes above are delivered; nothing new is sent once we've left.
        store.save(m)
        io.onEvents(m, listOf(GroupEvent.YouLeft))
        return true
    }

    /** Replaces our card (new inbox or keys) and sends it to every member. */
    fun updateCard(m: GroupModel, card: SignedCard) {
        m.myCard = card
        store.save(m)
        if (m.state == GroupModel.JOINED) {
            for (id in m.cards.keys) {
                io.sendGroup(m.gid, id, cardContent(card))
            }
        }
    }

    /**
     * A fact of ours, to everyone in the roster: through their card if we have it, else over 1:1 (invitees have no
     * inbox yet, and the owner invited them, so they're the owner's contacts). And to our inviter over 1:1.
     */
    private fun tellEveryone(m: GroupModel, content: Content) {
        val ids = m.roster?.roster?.ids().orEmpty() - me
        for (id in ids) {
            if (m.cards[id] != null) {
                io.sendGroup(m.gid, id, content)
            } else {
                io.sendDirect(m.gid, id, content)
            }
        }
        m.invitedBy?.takeIf { it != me }?.let { io.sendDirect(m.gid, it, content) }
    }

    // ---------- crypto ----------

    /**
     * Encrypts [plaintext] (a Content encoding) to member [to] with their [card], starting a PQXDH session from it if
     * needed. The card may belong to a member who just left or was removed: the roster telling them still goes out.
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
        val mac = GroupCrypto.hint(B64.dec(card.hintKey), nonce, meBytes)
        return GroupBlob(msg.type, nonce, mac, msg.serialize()).encode()
    }

    /** A blob that arrived on our inbox for [gid], whose hint key is [inboxHintKey]. Finds the sender by hint. */
    fun receive(gid: String, inboxHintKey: ByteArray, raw: ByteArray) {
        val blob = GroupBlob.decode(raw) ?: return
        val m = store.load(gid) ?: return
        val r = m.roster?.roster ?: return
        if (m.state != GroupModel.JOINED) {
            return
        }
        val sender = r.ids().firstOrNull { id ->
            id != me && GroupCrypto.hint(inboxHintKey, blob.nonce, B64.dec(id)).contentEquals(blob.mac)
        }
        dbg { "receive g=${gid.take(6)} type=${blob.type} sender=${sender?.let(::who)}" }
        if (sender == null) {
            // A newcomer whose roster hasn't reached us yet: keep it (bounded, 7 days) if the hint really is theirs.
            if (blob.type == PREKEY) {
                val id = runCatching { PreKeySignalMessage(blob.body).identityKey.serialize() }.getOrNull() ?: return
                if (GroupCrypto.hint(inboxHintKey, blob.nonce, id).contentEquals(blob.mac)) {
                    store.hold(gid, inboxHintKey, raw)
                }
            }
            return
        }
        val content = decrypt(sender, blob) ?: return
        onContent(m.gid, sender, content, direct = false)
    }

    private fun decrypt(sender: String, blob: GroupBlob): Content? = try {
        val addr = GroupCrypto.address(sender)
        val key = IdentityKey(B64.dec(sender))
        val cipher = SessionCipher(signal, LOCAL, addr)
        val padded = if (blob.type == PREKEY) {
            val msg = PreKeySignalMessage(blob.body)
            if (msg.identityKey != key) {
                null
            } else {
                if (signal.getIdentity(addr) == null) {
                    signal.saveIdentity(addr, key)
                }
                cipher.decrypt(msg)
            }
        } else {
            cipher.decrypt(SignalMessage(blob.body))
        }
        padded?.let { Content.decode(Padding.unpad(it)) }
    } catch (e: DuplicateMessageException) {
        null
    } catch (e: Exception) {
        dbg { "decrypt from ${who(sender)} failed: ${e.javaClass.simpleName}" }
        null
    }

    // ---------- incoming content ----------

    /** Group content that arrived over a 1:1 session with contact [from] (identity key, b64u). */
    fun onDirect(from: String, content: Content) {
        val gid = content.groupId ?: return
        onContent(gid, from, content, direct = true)
    }

    private fun onContent(gid: String, from: String, content: Content, direct: Boolean) {
        if (content is Content.Chunk) {
            if (content.parts !in 2..Chunker.MAX_PARTS || content.part !in 0 until content.parts || content.data.length > 4096) {
                return
            }
            val key = "k:" + GroupCrypto.tag(from) + ":" + content.id.take(32)
            val joined = store.storeChunk(gid, key, content.part, content.parts, content.data) ?: return
            val inner = runCatching { Content.decode(B64.dec(joined)) }.getOrNull() ?: return
            if (inner !is Content.Chunk) {
                onContent(gid, from, inner, direct)
            }
            return
        }
        if (content.groupId != gid) {
            return
        }
        dbg { "content ${content.javaClass.simpleName} g=${gid.take(6)} from=${who(from)} direct=$direct" }
        when (content) {
            is Content.GRoster -> onRoster(from, content, direct)
            is Content.GFact -> onFact(from, content, direct)
            is Content.GCard -> onCard(content)
            is Content.GSync -> onSync(from, content)
            is Content.GLeave -> onLeave(from, content)
            is Content.GText -> active(gid, from)?.let { io.onText(it, from, content) } ?: holdFromInvitee(gid, from, content)
            is Content.GReceipt -> active(gid, from)?.let { io.onReceipt(it, from, content) } ?: holdFromInvitee(gid, from, content)
            is Content.GDelete -> active(gid, from)?.let { io.onDelete(it, from, content) } ?: holdFromInvitee(gid, from, content)
            else -> Unit
        }
    }

    /**
     * A message from someone still invited as far as we know: their acceptance hasn't reached us yet (pushes arrive out of
     * order). Keep it until it does, bounded like other held blobs. It's already decrypted (the session has moved on), so
     * it's kept as content, then replayed by [replayHeld].
     */
    private fun holdFromInvitee(gid: String, from: String, content: Content) {
        val m = store.load(gid) ?: return
        if (m.state != GroupModel.JOINED || m.view()?.role(from) != Role.INVITED) {
            return
        }
        dbg { "holding ${content.javaClass.simpleName} from invitee ${who(from)}" }
        store.hold(gid, HELD_CONTENT, B64.dec(from) + content.encode())
    }

    /** The group, if we're in it and [from] is a current member (not just invited). */
    private fun active(gid: String, from: String): GroupModel? {
        val m = store.load(gid) ?: return null
        if (m.state != GroupModel.JOINED || m.view()?.isActive(from) != true) {
            return null
        }
        return m
    }

    private fun onRoster(from: String, c: Content.GRoster, direct: Boolean) {
        val signed = runCatching { GroupCrypto.openRoster(B64.dec(c.roster), B64.dec(c.sig)) }.getOrNull() ?: return
        val r = signed.roster
        if (!RosterRules.wellFormed(r, c.g)) {
            return
        }
        val m = store.load(c.g)
        if (m == null) {
            invitation(from, signed, direct)
            return
        }
        onSignedRoster(m, signed, from, direct)
    }

    /** A roster for a group we don't know: an invitation if it came over 1:1 from the owner who signed it, listing us. */
    private fun invitation(from: String, signed: SignedRoster, direct: Boolean) {
        val r = signed.roster
        if (!direct || r.by != from || r.owner != from) {
            return
        }
        val mine = r.member(me)
        if (mine == null) {
            // 1:1 messages aren't ordered: this may be the invitation being withdrawn, ahead of the invitation.
            store.addWithdrawn(r.g, from, r.ver)
            return
        }
        if (mine.role != Role.INVITED || (store.withdrawn(r.g, from) ?: 0) > r.ver) {
            return
        }
        val fresh = GroupModel(r.g, GroupModel.INVITED, signed, mutableMapOf(), null, from, mutableListOf(), mine.since)
        store.save(fresh)
        store.addHistory(r.g, signed)
        io.onEvents(fresh, listOf(GroupEvent.Invited(from)))
        for (f in store.takeEarlyFacts(r.g)) {
            onFact(from, f, direct = true)
        }
    }

    /**
     * A roster for a group we know. The chain is linear: the next one (signed by the owner of ours) is taken; an older one
     * is old news; one further on means we missed some, so it's kept and we ask for what's in between.
     */
    private fun onSignedRoster(m: GroupModel, signed: SignedRoster, from: String, direct: Boolean) {
        val cur = m.roster ?: return
        val r = signed.roster
        // (One we kept from beyond a gap may come again, now as something we can use: it's looked at again.)
        if (r.ver <= cur.roster.ver) {
            return
        }
        val mine = r.member(me)
        if ((m.state == GroupModel.LEFT || m.state == GroupModel.REMOVED) && direct && r.by == from && r.owner == from &&
            mine?.role == Role.INVITED && mine.since > m.since && r.ver > cur.roster.ver + 1
        ) {
            // Out of the group and invited again: like a first invitation, it's taken on its owner's word, gap or not (what
            // we missed meanwhile isn't ours to know).
            m.roster = signed
            m.facts.clear()
            store.addHistory(m.gid, signed)
            settle(m, null, r.by)
            return
        }
        if (r.ver == cur.roster.ver + 1) {
            if (r.prev == cur.hashB64 && validNext(cur, signed)) {
                take(m, signed)
                followHeld(m)
            }
            return
        }
        store.addHistory(m.gid, signed)
        dbg { "gap: v${r.ver} on v${cur.roster.ver}" }
        // Whoever sent it, and the owner: the sender may only be passing on a departure, from a leaver who's gone. Once
        // per gap and member an hour.
        for (id in setOfNotNull(from, m.view()?.owner) - me) {
            if (askOnce("$me ${m.gid} ${cur.hashB64} $id", io.nowMillis())) {
                requestSync(m, id, cur.roster.ver)
            }
        }
    }

    private fun validNext(cur: SignedRoster, next: SignedRoster): Boolean {
        val proof = next.roster.proof.map { GroupCrypto.openFact(it)?.fact ?: return false }
        return RosterRules.validChild(cur.roster, next.roster, proof)
    }

    /** Rosters we kept from beyond a gap that follow on now. */
    private fun followHeld(m: GroupModel) {
        while (true) {
            val cur = m.roster ?: return
            val next = store.historySince(m.gid, cur.roster.ver).firstOrNull {
                it.roster.ver == cur.roster.ver + 1 && it.roster.prev == cur.hashB64 && validNext(cur, it)
            } ?: return
            take(m, next)
        }
    }

    /**
     * A member's accept or leave. It counts if it's about a stint our roster lists; one about a newer stint (we're behind)
     * is kept for when our roster catches up; one about a stint that's over is ignored, so replays do nothing.
     */
    private fun onFact(from: String, c: Content.GFact, direct: Boolean) {
        val sf = runCatching { GroupCrypto.openFact(B64.dec(c.fact), B64.dec(c.sig)) }.getOrNull() ?: return
        val f = sf.fact
        if (f.g != c.g || f.id == me) {
            return
        }
        val loaded = store.load(c.g)
        if (loaded == null) {
            // 1:1 messages aren't ordered: this may have overtaken our invitation (the owner left right after inviting us).
            if (direct) {
                store.addEarlyFact(c.g, c)
            }
            return
        }
        if (loaded.state != GroupModel.JOINED && loaded.state != GroupModel.INVITED) {
            // Out of the group, we may still be the only link between its author and the members who are our contacts
            // (people we invited): it goes on to them over 1:1, once.
            if (direct && askOnce("$me pass ${sf.key}", io.nowMillis())) {
                for (id in loaded.roster?.roster?.ids().orEmpty() - me - f.id - from) {
                    io.sendDirect(c.g, id, c)
                }
            }
            return
        }
        // A departure carries the newest roster the leaver had: it may be one we haven't seen (they signed it just before).
        f.last?.let { w ->
            GroupCrypto.openRoster(w)?.takeIf { RosterRules.wellFormed(it.roster, c.g) }?.let { onSignedRoster(loaded, it, from, direct = false) }
        }
        val m = store.load(c.g) ?: return
        val r = m.roster?.roster ?: return
        val applies = Membership.applies(r, f)
        if (Membership.stale(r, f) || m.facts.any { it.key == sf.key }) {
            return
        }
        if (!applies && m.facts.count { it.fact.id == f.id && !Membership.applies(r, it.fact) } >= MAX_AHEAD) {
            return
        }
        val before = m.view()
        m.facts += sf
        if (!applies) {
            store.save(m)
            return
        }
        settle(m, before, f.id)
        // An acceptance carries the newcomer's card: whoever learns they're in can reach them.
        f.card?.let { onCard(Content.GCard(c.g, it.data, it.sig)) }
        // The owner takes facts in, and may not be reachable by their author (no card, not a contact): whoever got it
        // from the author passes it on. (If it made someone else the owner, settle has passed it on already.)
        val after = store.load(c.g) ?: return
        val owner = after.view()?.owner
        if (owner != null && owner == before?.owner && owner != me && owner != from && owner != f.id && from == f.id) {
            toOwner(after, owner, c)
        }
    }

    private fun toOwner(m: GroupModel, owner: String, c: Content) {
        if (m.cards[owner] != null && m.state == GroupModel.JOINED) {
            io.sendGroup(m.gid, owner, c)
        } else {
            io.sendDirect(m.gid, owner, c)
        }
    }

    private fun onCard(c: Content.GCard) {
        val m = store.load(c.g) ?: return
        val card = runCatching { GroupCrypto.openCard(B64.dec(c.card), B64.dec(c.sig), io::validServer) }.getOrNull() ?: return
        val id = card.card.id
        if (card.card.g != c.g || id == me || m.view()?.role(id) == null || m.state == GroupModel.LEFT || m.state == GroupModel.REMOVED) {
            return
        }
        val existing = m.cards[id]
        if (existing != null && existing.card.seq >= card.card.seq) {
            return
        }
        m.cards[id] = card
        store.save(m)
        io.onCard(m, id)
        val mine = m.myCard
        if (existing != null || m.state != GroupModel.JOINED || mine == null) {
            return
        }
        // A newcomer has only the cards that existed when they were sent some: ours may be missing (we joined at about the
        // same time) or old (we moved inbox since). Ours goes to them now.
        io.sendGroup(m.gid, id, cardContent(mine))
        if (m.view()?.isOwner(me) == true) {
            // The owner closes the gaps: the current roster (sent before they could be reached), every card to them, and
            // theirs to everyone else.
            m.roster?.let { io.sendGroup(m.gid, id, rosterContent(it)) }
            val content = cardContent(card)
            for ((other, theirs) in m.cards) {
                if (other != id) {
                    io.sendGroup(m.gid, other, content)
                    io.sendGroup(m.gid, id, cardContent(theirs))
                }
            }
            // Invitees too (over 1:1): they'll need it to answer, or to reach the group once they're in.
            for (other in m.view()?.members.orEmpty()) {
                if (other.role == Role.INVITED && other.id != id && m.cards[other.id] == null) {
                    io.sendDirect(m.gid, other.id, content)
                }
            }
        }
    }

    private fun onSync(from: String, c: Content.GSync) {
        val m = store.load(c.g) ?: return
        val cur = m.roster ?: return
        if (m.state != GroupModel.JOINED) {
            return
        }
        if (cur.roster.role(from) == null) {
            // Someone who's out but doesn't know it (the roster taking them out never reached them): they get that
            // roster, and nothing newer.
            removalOf(m, from)?.let { io.sendDirect(c.g, from, rosterContent(it)) }
            return
        }
        val rosters = chain(m, c.have).takeLast(SYNC_ROSTERS)
        dbg { "sync from ${who(from)} have=${c.have}: ${rosters.size} rosters" }
        // Someone still invited (or invited again) may not read their group inbox: 1:1 for them.
        val send: (Content) -> Unit = if (m.cards[from] != null && m.view()?.isActive(from) == true) {
            { content -> io.sendGroup(c.g, from, content) }
        } else {
            { content -> if (!io.sendDirect(c.g, from, content) && m.cards[from] != null) io.sendGroup(c.g, from, content) }
        }
        for (r in rosters) {
            send(rosterContent(r))
        }
        for (f in m.facts) {
            if (Membership.applies(cur.roster, f.fact) && f.fact.id != from) {
                send(factContent(f))
            }
        }
        m.myCard?.let { send(cardContent(it)) }
        for ((id, card) in m.cards) {
            if (id != from) {
                send(cardContent(card))
            }
        }
    }

    /** Our chain from version [have] (inclusive) to the current roster, oldest first, as far back as we hold it. */
    private fun chain(m: GroupModel, have: Long): List<SignedRoster> {
        val out = ArrayList<SignedRoster>()
        var x = m.roster
        while (x != null && x.roster.ver >= have && out.size < 200) {
            out += x
            x = store.history(m.gid, x.roster.prev)?.takeIf { it.roster.ver == x!!.roster.ver - 1 }
        }
        return out.reversed()
    }

    /** The roster in our chain that took [id] out: the oldest one back from the current roster that doesn't list them. */
    private fun removalOf(m: GroupModel, id: String): SignedRoster? {
        var cur = m.roster ?: return null
        while (true) {
            val parent = store.history(m.gid, cur.roster.prev)?.takeIf { it.roster.ver < cur.roster.ver } ?: return null
            if (parent.roster.role(id) != null) {
                return cur
            }
            cur = parent
        }
    }

    private fun onLeave(from: String, c: Content.GLeave) {
        val m = store.load(c.g) ?: return
        // Stop sending to them at once. Their departure (a fact) does the rest.
        if (m.cards.remove(from) != null) {
            store.save(m)
        }
    }

    // ---------- applying changes ----------

    /** Moves to [signed] (already checked) as our roster. The departures in its proof count as held facts. */
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
        store.save(m)
        if (events.isNotEmpty()) {
            io.onEvents(m, events)
        }
        if (before != null && (before.ids().toSet() - ids - me).isNotEmpty() && m.state == GroupModel.JOINED && after.isActive(me)) {
            io.rotateInbox(m)
        }
        heldReady += m.gid
        val owner = after.owner
        if (before != null && owner != before.owner && owner != null && owner != me && (m.state == GroupModel.JOINED || m.state == GroupModel.INVITED)) {
            // Someone else is the owner now: they take the facts in, and may not have heard the ones we hold.
            for (f in m.facts) {
                if (f.fact.id != owner && Membership.applies(r, f.fact)) {
                    toOwner(m, owner, factContent(f))
                }
            }
        }
        if (m.state == GroupModel.JOINED && after.owner == me && Membership.fold(r, m.facts.map { it.fact }, me) != r) {
            publish(m, null)
        }
    }

    /** Out (or in a stint that's over), and [mine] is a newer invitation. */
    private fun invitedAgain(m: GroupModel, mine: RosterMember, by: String, events: MutableList<GroupEvent>) {
        m.state = GroupModel.INVITED
        m.since = mine.since
        m.invitedBy = by
        m.facts.removeAll { it.fact.id == me }
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

    private fun broadcast(m: GroupModel, old: Roster, signed: SignedRoster, cardsBefore: Map<String, SignedCard>) {
        val content = rosterContent(signed)
        val targets = (old.ids() + signed.roster.ids()).toSet() - me
        val newcomers = signed.roster.members.filter { it.role == Role.INVITED && it.since == signed.roster.ver }.map { it.id }.toSet()
        dbg { "broadcast v${signed.roster.ver} to ${targets.map { who(it) + (if (cardsBefore[it] != null) "/g" else "/d") }}" }
        for (id in targets) {
            if (cardsBefore[id] != null && id !in newcomers) {
                io.sendGroup(m.gid, id, content)
            } else {
                io.sendDirect(m.gid, id, content)
            }
        }
        // Newcomers need every card to reach the members.
        for (id in newcomers) {
            m.myCard?.let { io.sendDirect(m.gid, id, cardContent(it)) }
            for (card in m.cards.values) {
                io.sendDirect(m.gid, id, cardContent(card))
            }
        }
    }

    private fun requestSync(m: GroupModel, to: String, have: Long) {
        val content = Content.GSync(m.gid, have)
        if (m.cards[to] != null && m.state == GroupModel.JOINED) {
            io.sendGroup(m.gid, to, content)
        } else {
            io.sendDirect(m.gid, to, content)
        }
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
        if (h.hintKey.contentEquals(HELD_CONTENT)) {
            val from = B64.enc(h.blob.copyOfRange(0, IDENTITY_LEN))
            val content = runCatching { Content.decode(h.blob.copyOfRange(IDENTITY_LEN, h.blob.size)) }.getOrNull()
            content?.let { onContent(gid, from, it, direct = false) }
        } else {
            receive(gid, h.hintKey, h.blob)
        }
    }

    companion object {
        val LOCAL = SignalProtocolAddress("self", 1)
        private const val PREKEY = 3

        /** Rosters per `gsync` answer; the asker asks again from where it got to. */
        const val SYNC_ROSTERS = 50

        /** Facts kept per member for stints our roster doesn't reach yet. */
        const val MAX_AHEAD = 2

        /** Rosters kept per version (see [GroupStore.addHistory]): the chain has one, the rest is room for junk, capped per author. */
        const val MAX_PER_VERSION = 16
        const val MAX_PER_AUTHOR = 2

        /** Whether [r] may join [held], the rosters already kept at its version. */
        fun fits(held: List<Roster>, r: Roster): Boolean = held.size < MAX_PER_VERSION && held.count { it.by == r.by } < MAX_PER_AUTHOR

        /** Marks a held row as already-decrypted content from an invitee (a real hint key is 32 bytes). */
        private val HELD_CONTENT = byteArrayOf(0x43)
        private const val IDENTITY_LEN = 33

        /** Syncs we asked for, by what about, and when; newest last. Per process: enough to stop a loop. */
        private val asked = LinkedHashMap<String, Long>()

        /** A sync whose answer didn't help may be asked for again after this long (the answer may have been lost). */
        private const val ASK_AGAIN_MS = 3600_000L

        /** True if [key] wasn't asked about in the last hour (of the last 256 keys). */
        @Synchronized
        private fun askOnce(key: String, now: Long): Boolean {
            val last = asked[key]
            if (last != null && now - last in 0 until ASK_AGAIN_MS) {
                return false
            }
            asked.remove(key)
            asked[key] = now
            if (asked.size > 256) {
                asked.remove(asked.keys.first())
            }
            return true
        }

        /** For tests: each scenario starts with a fresh process, as far as this goes. */
        @Synchronized
        fun forgetAsked() = asked.clear()

        /** Protocol decisions, for debugging. The app routes this to logcat in debug builds only; it never carries content. */
        @Volatile
        var debugLog: ((String) -> Unit)? = null

        private fun dbg(msg: () -> String) {
            debugLog?.invoke(msg())
        }

        /** A short, stable label for a member in debug output. */
        private fun who(id: String): String = id.takeLast(6)

        fun rosterContent(r: SignedRoster) = Content.GRoster(r.roster.g, B64.enc(r.bytes), B64.enc(r.sig))

        fun factContent(f: SignedFact) = Content.GFact(f.fact.g, B64.enc(f.bytes), B64.enc(f.sig))

        fun cardContent(c: SignedCard) = Content.GCard(c.card.g, B64.enc(c.bytes), B64.enc(c.sig))

        /** Builds and signs this member's card. */
        fun makeCard(identity: IdentityKeyPair, card: GroupCard): SignedCard = GroupCrypto.signCard(identity.privateKey, card)
    }
}
