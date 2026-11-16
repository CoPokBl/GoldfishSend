package app.goldfishsend.group

import app.goldfishsend.proto.B64
import app.goldfishsend.proto.Chunker
import app.goldfishsend.proto.Content
import app.goldfishsend.proto.GroupBlob
import app.goldfishsend.proto.GroupCard
import app.goldfishsend.proto.GroupCrypto
import app.goldfishsend.proto.Padding
import app.goldfishsend.proto.Rand
import app.goldfishsend.proto.Role
import app.goldfishsend.proto.Roster
import app.goldfishsend.proto.RosterMember
import app.goldfishsend.proto.RosterOp
import app.goldfishsend.proto.RosterRules
import app.goldfishsend.proto.SignedCard
import app.goldfishsend.proto.SignedRoster
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

/** One group as seen by this member. Roles come from [roster]; [cards] holds the other members' latest cards. */
class GroupModel(
    val gid: String,
    var state: Int,
    var roster: SignedRoster?,
    val cards: MutableMap<String, SignedCard>,
    var myCard: SignedCard?,
    /** Who invited us (identity key, b64u). */
    var invitedBy: String?,
    /** Our recent changes, kept to re-apply them if a concurrent roster wins (rule 3). Oldest first. */
    val pending: MutableList<Pending>,
) {
    /** Cards of members the last accepted roster removed, in memory only, so the system line can still name them. */
    val departed: MutableMap<String, SignedCard> = mutableMapOf()

    companion object {
        const val INVITED = 0
        const val JOINED = 1
        const val REMOVED = 2
        const val LEFT = 3
    }
}

/** A roster change of ours, and the roster (b64u hash) we published it in. */
class Pending(val op: RosterOp, val hash: String) {
    companion object {
        /** At most this many are kept. An admin's own change and the ones it makes for others (admit, remove) can overlap. */
        const val MAX = 8

        /** In the store's two text columns, one per line. */
        fun encode(list: List<Pending>): Pair<String?, String?> =
            if (list.isEmpty()) null to null else list.joinToString("\n") { it.op.encode() } to list.joinToString("\n") { it.hash }

        fun decode(ops: String?, hashes: String?): MutableList<Pending> {
            if (ops == null || hashes == null) {
                return mutableListOf()
            }
            return ops.lines().zip(hashes.lines()).mapNotNull { (o, h) -> RosterOp.decode(o)?.let { Pending(it, h) } }.toMutableList()
        }
    }
}

/** What changed when a roster was accepted, for system lines and app state. `by` is the roster's author. */
sealed class GroupEvent {
    data class Invited(val by: String) : GroupEvent()
    data object Created : GroupEvent()
    data class Added(val by: String, val ids: List<String>) : GroupEvent()
    data class Removed(val by: String, val ids: List<String>) : GroupEvent()
    data class Left(val id: String) : GroupEvent()
    data class Joined(val id: String) : GroupEvent()
    data class RoleChanged(val by: String, val id: String, val role: String) : GroupEvent()
    data class Renamed(val by: String, val name: String) : GroupEvent()
    data class TimerChanged(val by: String, val secs: Long) : GroupEvent()
    data class AdminsOnlyChanged(val by: String, val on: Boolean) : GroupEvent()
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
     * Stores a roster we accepted, or (with [sibling]) a valid one we didn't take, so that rosters built on it can be
     * checked. Siblings are capped per version, and per author ([GroupEngine.siblingFits]): any member can sign as many
     * as they like, but an honest one signs at most a couple per version (a change, and its re-application).
     */
    fun addHistory(gid: String, r: SignedRoster, sibling: Boolean = false)

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

    /** Someone was removed: give the remaining members a fresh inbox (new card) and drain the old one. */
    fun rotateInbox(m: GroupModel)

    fun validServer(url: String): Boolean

    fun nowMillis(): Long
}

class NoCardException(id: String) : Exception("no card for member")

/**
 * The group protocol (docs/groups.md): rosters, cards, sync, leave, membership checks, and the per-member encryption with
 * sender hints. All calls are synchronous; the app runs them under its libsignal lock inside one DB transaction.
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

    /** Creates a group with us as its only admin and [invitees] (identity keys) invited, and invites them over 1:1. */
    fun create(gid: String, name: String, invitees: List<String>, myCard: SignedCard, timer: Long): GroupModel {
        val others = invitees.distinct().filter { it != me && GroupCrypto.isIdentity(it) }
        require(others.size + 1 <= RosterRules.MAX_MEMBERS) { "too many members" }
        val r = Roster(
            g = gid, ver = 1, prev = "", name = name, timer = timer, adminsOnly = true,
            members = listOf(RosterMember(me, Role.ADMIN)) + others.map { RosterMember(it, Role.INVITED) },
            by = me, ts = io.nowMillis() / 1000,
        )
        require(RosterRules.wellFormed(r, gid)) { "bad roster" }
        val signed = GroupCrypto.signRoster(identity.privateKey, r)
        val m = GroupModel(gid, GroupModel.JOINED, signed, mutableMapOf(), myCard, null, mutableListOf())
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
     * Publishes a change as the next roster: signs it, applies it locally and sends it to everyone in the old and new roster.
     * Newly invited members also get every card over 1:1. Returns null if the change isn't possible or allowed.
     */
    fun publish(m: GroupModel, op: RosterOp): SignedRoster? {
        val base = m.roster ?: return null
        val changed = op.apply(base.roster, me) ?: return null
        val next = RosterRules.successor(base, changed, me, io.nowMillis() / 1000)
        if (!RosterRules.wellFormed(next, m.gid) || !RosterRules.authorized(base.roster, next)) {
            return null
        }
        val signed = GroupCrypto.signRoster(identity.privateKey, next)
        dbg { "publish v${next.ver} op=${op.javaClass.simpleName}" }
        m.pending += Pending(op, signed.hashB64)
        while (m.pending.size > Pending.MAX) {
            m.pending.removeAt(0)
        }
        val cardsBefore = m.cards.toMap()
        accept(m, signed)
        broadcast(m, base.roster, signed, cardsBefore)
        return signed
    }

    /** Joins a group we were invited to: our card goes to every member, then we ask the inviter for anything we missed. */
    fun join(m: GroupModel, myCard: SignedCard): Boolean {
        if (m.state != GroupModel.INVITED || m.roster?.roster?.role(me) != Role.INVITED) {
            return false
        }
        m.myCard = myCard
        m.state = GroupModel.JOINED
        store.save(m)
        publish(m, RosterOp.Accept) ?: return false
        for (id in m.cards.keys) {
            io.sendGroup(m.gid, id, cardContent(myCard))
        }
        // Over 1:1 where possible: if the invitation was withdrawn meanwhile, the inviter can still tell us (see onSync).
        m.invitedBy?.let { if (!io.sendDirect(m.gid, it, Content.GSync(m.gid, 0))) requestSync(m, it, 0) }
        return true
    }

    /**
     * Leaves (or declines). Members stop sending to us at once (`gleave`), and our self-removal roster updates everyone.
     * Returns false if we're the last admin and others remain: promote someone first.
     */
    fun leave(m: GroupModel): Boolean {
        val r = m.roster?.roster
        if (r != null && r.isAdmin(me) && r.members.count { it.role == Role.ADMIN } == 1 && r.members.size > 1) {
            return false
        }
        if (m.state == GroupModel.JOINED) {
            for (id in m.cards.keys) {
                io.sendGroup(m.gid, id, Content.GLeave(m.gid))
            }
        }
        val wasInvited = m.state == GroupModel.INVITED
        if (r != null && r.members.size > 1) {
            val signed = publish(m, RosterOp.Leave)
            // Declining: the inviter (an admin and our contact) hears it over 1:1 too, which survives deleting the chat.
            val inviter = m.invitedBy
            if (signed != null && wasInvited && inviter != null) {
                io.sendDirect(m.gid, inviter, rosterContent(signed))
            }
        }
        if (m.state != GroupModel.LEFT) {
            m.state = GroupModel.LEFT
            io.onEvents(m, listOf(GroupEvent.YouLeft))
        }
        // The cards stay until the goodbyes above are delivered; nothing new is sent once we've left.
        m.pending.clear()
        store.save(m)
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
        if (!signal.containsSession(addr)) {
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
     * A message from someone our roster still lists as invited: their acceptance hasn't reached us yet (pushes arrive out of
     * order, and concurrent joins can need a round of re-applying). Keep it until it does, bounded like other held blobs.
     * It's already decrypted (the session has moved on), so it's kept as content, then replayed by [replayHeld].
     */
    private fun holdFromInvitee(gid: String, from: String, content: Content) {
        val m = store.load(gid) ?: return
        if (m.state != GroupModel.JOINED || m.roster?.roster?.role(from) != Role.INVITED) {
            return
        }
        dbg { "holding ${content.javaClass.simpleName} from invitee ${who(from)}" }
        store.hold(gid, HELD_CONTENT, B64.dec(from) + content.encode())
    }

    /** The group, if we're in it and [from] is a current member (not just invited). */
    private fun active(gid: String, from: String): GroupModel? {
        val m = store.load(gid) ?: return null
        if (m.state != GroupModel.JOINED || m.roster?.roster?.isActive(from) != true) {
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
            // An invitation: over 1:1, from its author, who is an admin in it and lists us as invited.
            if (!direct || r.by != from || !r.isAdmin(from)) {
                return
            }
            if (r.role(me) == null) {
                // 1:1 messages aren't ordered: this may be the invitation being withdrawn, ahead of the invitation.
                store.addWithdrawn(c.g, from, r.ver)
                return
            }
            if (r.role(me) != Role.INVITED || (store.withdrawn(c.g, from) ?: 0) > r.ver) {
                return
            }
            val fresh = GroupModel(c.g, GroupModel.INVITED, signed, mutableMapOf(), null, from, mutableListOf())
            store.addHistory(c.g, signed)
            store.save(fresh)
            io.onEvents(fresh, listOf(GroupEvent.Invited(from)))
            return
        }
        val cur = m.roster ?: return
        if (signed.hashB64 == cur.hashB64) {
            return
        }
        val parent = store.history(c.g, r.prev)
        if (parent == null) {
            onOrphan(m, cur, signed, from)
            return
        }
        val valid = RosterRules.validChild(parent.roster, r)
        if (valid) {
            store.addHistory(c.g, signed, sibling = true)
        }
        val head = if (valid) chooseHead(m) else cur
        dbg { "roster v${r.ver} by=${who(r.by)} on cur v${cur.roster.ver} by=${who(cur.roster.by)}: valid=$valid head=v${head.roster.ver} by=${who(head.roster.by)}" }
        if (head.hashB64 == cur.hashB64) {
            // Not taken (it lost a fork, is too old, or isn't allowed): what it says about its author, or us, still counts.
            enforceOwnRemoval(m, signed)
            enforceDeparture(m, r)
            enforceAcceptance(m, r)
            if (valid) {
                enforceAll(m)
            }
            recheckInvitation(m)
            return
        }
        val cardsBefore = m.cards.toMap()
        val extends = descends(m, head, cur)
        val won = if (extends) listOf(head) else lostBranch(m, head, cur)
        accept(m, head)
        // Members' rosters on the branch we take may not have reached everyone (relay() only passes them on once).
        for (x in won.reversed()) {
            relay(m, x, cardsBefore)
        }
        if (!extends) {
            // We were on a branch that lost. accept() re-applies our own changes from it on top of the winner; if it
            // removed us, that stands (enforceAll covers others' departures and acceptances on it).
            for (lost in lostBranch(m, cur, head)) {
                enforceOwnRemoval(m, lost)
            }
        }
        enforceAll(m)
        recheckInvitation(m)
    }

    /** A roster whose parent we don't have: we missed versions, or it builds on a branch we never saw. */
    private fun onOrphan(m: GroupModel, cur: SignedRoster, signed: SignedRoster, from: String) {
        val r = signed.roster
        if (r.ver > cur.roster.ver && cur.roster.isAdmin(r.by)) {
            // An admin of ours moved on: take it, and ask that admin for what's in between.
            dbg { "orphan v${r.ver} by=${who(r.by)} on cur v${cur.roster.ver}: taken" }
            val cardsBefore = m.cards.toMap()
            store.addHistory(m.gid, signed)
            accept(m, signed)
            relay(m, signed, cardsBefore)
            requestSync(m, r.by, cur.roster.ver)
            recheckInvitation(m)
            return
        }
        // Otherwise it can only be placed once we have its parent. Ask an admin who sent or signed it, once per roster:
        // if the answer doesn't place it, asking again won't.
        val admin = listOf(from, r.by).firstOrNull { it != me && cur.roster.isAdmin(it) }
        // Kept: once its parent comes, it's part of the picture (chooseHead, enforceAll).
        store.addHistory(m.gid, signed, sibling = true)
        if (admin != null && m.state == GroupModel.JOINED && askOnce("$me ${signed.hashB64}", io.nowMillis())) {
            // From as far back as forks are decided: what it builds on may be a branch we never saw.
            requestSync(m, admin, (cur.roster.ver - FORK_DEPTH).coerceAtLeast(0))
        }
        enforceOwnRemoval(m, signed)
        enforceDeparture(m, r)
        enforceAcceptance(m, r)
    }

    /**
     * Fork choice (docs/groups.md, rule 3): the roster to be on, given every roster we hold from [FORK_DEPTH] versions
     * below ours. From there, at each fork, the branch that [RosterRules.beats] the other; the tip of that branch is it.
     * Depends only on the rosters held, not on the order they came in, so members who hold the same ones agree.
     */
    private fun chooseHead(m: GroupModel, t: Tree = tree(m)): SignedRoster {
        val path = HashMap<String, List<SignedRoster>>()
        // The branch from n down to its tip, n first.
        fun branch(n: SignedRoster): List<SignedRoster> = path.getOrPut(n.hashB64) {
            val cs = t.kids[n.hashB64]?.distinctBy { it.hashB64 }?.sortedWith { a, b -> RosterRules.compareUnsigned(a.hash, b.hash) }
            if (cs.isNullOrEmpty()) {
                listOf(n)
            } else {
                val best = cs.reduce { a, b ->
                    val aWins = RosterRules.beats(n.roster, branch(a), branch(b))
                    dbg { "fork at v${n.roster.ver}: ${who(a.roster.by)} (${branch(a).size}) vs ${who(b.roster.by)} (${branch(b).size}): ${if (aWins) "first" else "second"}" }
                    if (aWins) a else b
                }
                listOf(n) + branch(best)
            }
        }
        return branch(t.root).last()
    }

    /** The rosters we hold that connect, by valid steps, to ours from [FORK_DEPTH] versions below it. */
    private class Tree(val root: SignedRoster, val nodes: Map<String, SignedRoster>, val kids: Map<String, List<SignedRoster>>)

    private fun tree(m: GroupModel): Tree {
        val cur = m.roster!!
        val ours = mutableListOf(cur)
        while (ours.size <= FORK_DEPTH) {
            val last = ours.last()
            ours += store.history(m.gid, last.roster.prev)?.takeIf { it.roster.ver == last.roster.ver - 1 } ?: break
        }
        val root = ours.last()
        // Our own line counts as valid as it is: we took each of its rosters.
        val nodes = HashMap<String, SignedRoster>()
        ours.forEach { nodes[it.hashB64] = it }
        val kids = HashMap<String, MutableList<SignedRoster>>()
        for (r in store.historySince(m.gid, root.roster.ver)) {
            val p = nodes[r.roster.prev] ?: continue
            if (r.hashB64 !in nodes) {
                if (!RosterRules.validChild(p.roster, r.roster)) {
                    continue
                }
                nodes[r.hashB64] = r
            }
            kids.getOrPut(p.hashB64) { mutableListOf() } += r
        }
        return Tree(root, nodes, kids)
    }

    /**
     * Departures and acceptances anywhere in the rosters we hold that ours doesn't reflect (rule 3). A roster can connect
     * long after it arrived (its parent came later), or sit on a branch that lost: it's still its author's decision.
     */
    private fun enforceAll(m: GroupModel) {
        if (m.state != GroupModel.JOINED || m.roster?.roster?.isAdmin(me) != true) {
            return
        }
        for (r in tree(m).nodes.values.sortedBy { it.roster.ver }) {
            enforceDeparture(m, r.roster)
            enforceAcceptance(m, r.roster)
        }
    }

    /**
     * The mirror of [enforceDeparture]: a roster signed by an invitee that makes them a member is their acceptance. If it
     * lost a tie or arrived late, an admin records it, so the join isn't lost if the invitee's app doesn't retry.
     */
    private fun enforceAcceptance(m: GroupModel, r: Roster) {
        val cur = m.roster?.roster ?: return
        if (r.role(r.by) == Role.MEMBER && cur.role(r.by) == Role.INVITED && r.by != me && m.state == GroupModel.JOINED && cur.isAdmin(me) &&
            madeSince(m, r) { it.role(r.by) == Role.INVITED }
        ) {
            publish(m, RosterOp.Admit(r.by))
        }
    }

    /** The rosters from [old] back to where it and [winner] meet, newest first (a few at most). */
    private fun lostBranch(m: GroupModel, old: SignedRoster, winner: SignedRoster): List<SignedRoster> {
        val theirs = HashSet<String>()
        var w: SignedRoster? = winner
        repeat(BRANCH) {
            w = w?.also { theirs += it.hashB64 }?.let { store.history(m.gid, it.roster.prev) }
        }
        val lost = mutableListOf<SignedRoster>()
        var o: SignedRoster? = old
        while (o != null && o.hashB64 !in theirs && lost.size < BRANCH) {
            lost += o
            o = store.history(m.gid, o.roster.prev)
        }
        return lost
    }

    /**
     * An admin's roster that leaves us out, but that we can't take: it lost a tie here, or we had moved on. Whatever the
     * others took after it, nobody sends it to us, since we're not in it: so if it's from our current stint, we're out.
     */
    private fun enforceOwnRemoval(m: GroupModel, signed: SignedRoster) {
        val r = signed.roster
        val cur = m.roster?.roster ?: return
        if (r.role(me) != null || cur.role(me) == null || r.by == me || (m.state != GroupModel.JOINED && m.state != GroupModel.INVITED)) {
            return
        }
        val parent = store.history(m.gid, r.prev)?.roster ?: cur
        if (parent.isAdmin(r.by) && madeSince(m, r) { it.role(me) != null }) {
            accept(m, signed)
        }
    }

    /**
     * Whether [r] was made during its author's current stint, the run of our rosters back from the current one in which
     * [listed] holds for them. Anyone holding an older acceptance or departure (from before they were removed and added
     * again) could otherwise replay it to make an admin admit or remove them. Where our history has a gap (skipped
     * versions, not synced yet), only a roster newer than the gap counts; the sync brings the rest.
     */
    private fun madeSince(m: GroupModel, r: Roster, listed: (Roster) -> Boolean): Boolean {
        var cur = m.roster ?: return false
        while (listed(cur.roster)) {
            cur = store.history(m.gid, cur.roster.prev)?.takeIf { it.roster.ver < cur.roster.ver } ?: return r.ver > cur.roster.ver
        }
        // cur is the last roster before the stint; the stint's first roster is its successor, which r must build on or after.
        return r.ver > cur.roster.ver + 1
    }

    /**
     * A roster signed by someone that leaves them out means "I'm leaving" (or declining), whatever its version. If it lost
     * a tie or arrived too late to apply, the leaver won't try again, so an admin removes them (docs/groups.md, rule 3).
     */
    private fun enforceDeparture(m: GroupModel, r: Roster) {
        val cur = m.roster?.roster ?: return
        if (r.role(r.by) == null && cur.role(r.by) != null && r.by != me && m.state == GroupModel.JOINED && cur.isAdmin(me) &&
            madeSince(m, r) { it.role(r.by) != null }
        ) {
            publish(m, RosterOp.Remove(listOf(r.by)))
        }
    }

    /**
     * A member without admin rights (joining, leaving, or renaming when `adminsOnly` is off) may not have everyone's card,
     * so admins relay their rosters to the members they can reach (docs/groups.md, "Relaying").
     */
    private fun relay(m: GroupModel, signed: SignedRoster, cardsBefore: Map<String, SignedCard>) {
        val r = signed.roster
        if (r.by == me || r.isAdmin(r.by) || m.state != GroupModel.JOINED || !r.isAdmin(me)) {
            return
        }
        val content = rosterContent(signed)
        for (id in (cardsBefore.keys + r.ids()).toSet() - me - r.by) {
            when {
                cardsBefore[id] != null -> io.sendGroup(m.gid, id, content)
                // Invitees have no group inbox yet. Without this they'd build their acceptance on a stale roster.
                r.role(id) == Role.INVITED -> io.sendDirect(m.gid, id, content)
            }
        }
    }

    private fun onCard(c: Content.GCard) {
        val m = store.load(c.g) ?: return
        val card = runCatching { GroupCrypto.openCard(B64.dec(c.card), B64.dec(c.sig), io::validServer) }.getOrNull() ?: return
        val id = card.card.id
        if (card.card.g != c.g || id == me || m.roster?.roster?.role(id) == null || m.state == GroupModel.LEFT) {
            return
        }
        val existing = m.cards[id]
        if (existing != null && existing.card.seq >= card.card.seq) {
            return
        }
        m.cards[id] = card
        store.save(m)
        io.onCard(m, id)
        // A newcomer has only the cards that existed when they were sent some: ours may be missing (we joined at about the
        // same time, and the admin passed theirs on before ours arrived) or old (we moved inbox since). Ours goes to them now.
        val mine = m.myCard
        if (existing == null && m.state == GroupModel.JOINED && mine != null) {
            io.sendGroup(m.gid, id, cardContent(mine))
            // Rosters relayed before we could reach them (no card yet) didn't reach them either.
            if (m.roster?.roster?.isAdmin(me) == true) {
                m.roster?.let { io.sendGroup(m.gid, id, rosterContent(it)) }
            }
        }
        // A newcomer's first card only reaches the members they already knew: admins pass it on to everyone else.
        if (existing == null && m.state == GroupModel.JOINED && m.roster?.roster?.isAdmin(me) == true) {
            val content = cardContent(card)
            for (other in m.cards.keys) {
                if (other != id) {
                    io.sendGroup(m.gid, other, content)
                }
            }
        }
    }

    private fun onSync(from: String, c: Content.GSync) {
        val m = store.load(c.g) ?: return
        val cur = m.roster ?: return
        if (m.state != GroupModel.JOINED || !cur.roster.isAdmin(me)) {
            return
        }
        if (cur.roster.role(from) == null) {
            // Someone who's out but doesn't know it (the roster removing them never reached them, for example it came
            // before the invitation, and they joined): they get that roster, and nothing newer.
            removalOf(m, from)?.let { io.sendDirect(c.g, from, rosterContent(it)) }
            return
        }
        // From the version before theirs: their copy of `have` may be a concurrent sibling that lost, and they need the winner.
        val rosters = store.historySince(c.g, (c.have - 1).coerceAtLeast(0)).takeLast(50).toMutableList()
        dbg { "sync from ${who(from)} have=${c.have}: ${rosters.size} rosters, via ${if (m.cards[from] != null) "group" else "direct"}" }
        if (rosters.none { it.hashB64 == cur.hashB64 }) {
            rosters += cur
        }
        // Someone still invited (or invited again) may not take what comes to their group inbox: 1:1 for them.
        val send: (Content) -> Unit = if (m.cards[from] != null && cur.roster.isActive(from)) {
            { content -> io.sendGroup(c.g, from, content) }
        } else {
            { content -> if (!io.sendDirect(c.g, from, content) && m.cards[from] != null) io.sendGroup(c.g, from, content) }
        }
        for (r in rosters) {
            send(rosterContent(r))
        }
        m.myCard?.let { send(cardContent(it)) }
        for ((id, card) in m.cards) {
            if (id != from) {
                send(cardContent(card))
            }
        }
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
        // Stop sending to them at once. Their self-removal roster does the rest.
        if (m.cards.remove(from) != null) {
            store.save(m)
        }
    }

    // ---------- roster application ----------

    private fun accept(m: GroupModel, signed: SignedRoster) {
        val prior = m.roster
        val old = prior?.roster
        m.roster = signed
        store.addHistory(m.gid, signed)
        val events = diff(m, old, signed.roster) { prior == null || reinvited(m, signed) }
        store.save(m)
        if (events.isNotEmpty()) {
            io.onEvents(m, events)
        }
        reapplyLost(m, signed)
        // We joined, but this roster still has us invited (our acceptance was on a stint that's over, or got lost): again.
        if (m.state == GroupModel.JOINED && signed.roster.role(me) == Role.INVITED && signed.roster.by != me) {
            publish(m, RosterOp.Accept)
            // If we were taken out and invited again meanwhile, the others dropped our card.
            m.myCard?.let { card -> m.cards.keys.forEach { io.sendGroup(m.gid, it, cardContent(card)) } }
        }
        heldReady += m.gid
    }

    /**
     * We accepted someone else's roster while changes of ours were still pending, and that roster neither contains one nor
     * builds on it (our change was on a sibling that lost, possibly one we never learned about). Publish it again on top.
     * A roster that builds on our change and lacks it was changed back on purpose. A change stays pending even once it's
     * in: the roster that took it in can itself lose to a sibling later.
     */
    private fun reapplyLost(m: GroupModel, signed: SignedRoster) {
        if (m.pending.isEmpty() || signed.roster.by == me || m.state != GroupModel.JOINED) {
            return
        }
        val redo = mutableListOf<RosterOp>()
        val before = m.pending.size
        m.pending.removeAll { p ->
            val mine = store.history(m.gid, p.hash)
            when {
                // Long built on (or forgotten): settled.
                mine == null || signed.roster.ver > mine.roster.ver + SETTLED -> true
                p.op.apply(signed.roster, me) != null && !descends(m, signed, mine) -> redo.add(p.op)
                else -> false
            }
        }
        if (m.pending.size != before) {
            store.save(m)
        }
        if (redo.isNotEmpty()) {
            // All in one roster, so a member who keeps losing forks signs one per version, not one per change.
            dbg { "re-applying ${redo.size} lost on v${m.roster?.roster?.ver}" }
            publish(m, redo.singleOrNull() ?: RosterOp.Batch(redo))
        }
    }

    /**
     * Out of the group, whether [r] (which lists us) invites us again: somewhere down its line we were taken out (a step
     * from a roster listing us to one that doesn't). A branch on which that never happened (it lost to our departure or
     * removal elsewhere) isn't an invitation.
     */
    private fun reinvited(m: GroupModel, r: SignedRoster): Boolean = reinviter(m, r).by != null

    /** [reinviter]'s answer: who invited us again, or null; [gap]: our history of the line stopped before an answer. */
    private class Reinvite(val by: String?, val gap: Boolean)

    /** For [reinvited]: who invited us again (the author of the first roster listing us after we were out), if anyone. */
    private fun reinviter(m: GroupModel, r: SignedRoster): Reinvite {
        var x = r
        var listing = r
        while (true) {
            if (x.roster.role(me) != null) {
                listing = x
            }
            // Where our history of the line stops we can't tell (yet): recheckInvitation looks again as it fills.
            val parent = store.history(m.gid, x.roster.prev)?.takeIf { it.roster.ver < x.roster.ver }
                ?: return Reinvite(null, x.roster.prev.isNotEmpty())
            if (x.roster.role(me) == null && parent.roster.role(me) != null) {
                return Reinvite(listing.roster.by, false)
            }
            x = parent
        }
    }

    /**
     * Out of the group, with our roster listing us as invited but not counted as an invitation (see [reinvited]): what we
     * were missing to tell may have come since.
     */
    private fun recheckInvitation(m: GroupModel) {
        val cur = m.roster ?: return
        if ((m.state != GroupModel.LEFT && m.state != GroupModel.REMOVED) || cur.roster.role(me) != Role.INVITED) {
            return
        }
        val line = reinviter(m, cur)
        val by = line.by
        if (by == null) {
            // Out of the group, nobody sends us the history: ask the admin who signed it, once per roster.
            if (line.gap && cur.roster.isAdmin(cur.roster.by) && cur.roster.by != me && askOnce("$me line ${cur.hashB64}", io.nowMillis())) {
                requestSync(m, cur.roster.by, (cur.roster.ver - FORK_DEPTH).coerceAtLeast(0))
            }
            return
        }
        m.state = GroupModel.INVITED
        m.invitedBy = by
        store.save(m)
        io.onEvents(m, listOf(GroupEvent.Invited(by)))
    }

    /** Whether [r] is [base] or built on it, as far as our history tells. A gap in it counts as yes. */
    private fun descends(m: GroupModel, r: SignedRoster, base: SignedRoster): Boolean {
        var cur = r
        while (cur.roster.ver > base.roster.ver) {
            cur = store.history(m.gid, cur.roster.prev)?.takeIf { it.roster.ver < cur.roster.ver } ?: return true
        }
        return cur.hashB64 == base.hashB64
    }

    private fun diff(m: GroupModel, old: Roster?, new: Roster, reinvite: () -> Boolean): List<GroupEvent> {
        val by = new.by
        val events = mutableListOf<GroupEvent>()
        val oldIds = old?.ids().orEmpty().toSet()
        val newIds = new.ids().toSet()
        val removed = oldIds - newIds
        val added = newIds - oldIds
        m.departed.clear()
        m.cards.filterKeys { it !in newIds }.let { m.departed.putAll(it) }
        m.cards.keys.retainAll(newIds)
        if (me in removed) {
            if (by == me) {
                if (m.state != GroupModel.LEFT) {
                    events += GroupEvent.YouLeft
                }
                m.state = GroupModel.LEFT
            } else {
                m.state = GroupModel.REMOVED
                events += GroupEvent.YouWereRemoved(by)
            }
        } else if (new.role(me) == Role.INVITED && (m.state == GroupModel.REMOVED || m.state == GroupModel.LEFT) && reinvite()) {
            m.state = GroupModel.INVITED
            m.invitedBy = by
            events += GroupEvent.Invited(by)
        }
        val othersRemoved = (removed - me).toList()
        val selfRemoved = othersRemoved.filter { it == by }
        val kicked = othersRemoved - selfRemoved.toSet()
        for (id in selfRemoved) {
            events += GroupEvent.Left(id)
        }
        if (kicked.isNotEmpty()) {
            events += GroupEvent.Removed(by, kicked)
        }
        val addedOthers = (added - me).toList()
        if (old != null && addedOthers.isNotEmpty()) {
            events += GroupEvent.Added(by, addedOthers)
        }
        if (old != null) {
            for (id in newIds.intersect(oldIds)) {
                val before = old.role(id)
                val after = new.role(id)
                // A step back to "invited" only happens while concurrent rosters settle (it isn't a real role change).
                if (before == after || after == null || after == Role.INVITED || before == Role.INVITED && after != Role.MEMBER) {
                    continue
                }
                events += if (before == Role.INVITED && after == Role.MEMBER) GroupEvent.Joined(id) else GroupEvent.RoleChanged(by, id, after)
            }
            if (old.name != new.name) {
                events += GroupEvent.Renamed(by, new.name)
            }
            if (old.timer != new.timer) {
                events += GroupEvent.TimerChanged(by, new.timer)
            }
            if (old.adminsOnly != new.adminsOnly) {
                events += GroupEvent.AdminsOnlyChanged(by, new.adminsOnly)
            }
        }
        if (othersRemoved.isNotEmpty() && m.state == GroupModel.JOINED && new.isActive(me)) {
            io.rotateInbox(m)
        }
        return events
    }

    private fun broadcast(m: GroupModel, old: Roster, signed: SignedRoster, cardsBefore: Map<String, SignedCard>) {
        val content = rosterContent(signed)
        val targets = (old.ids() + signed.roster.ids()).toSet() - me
        val addedInvitees = signed.roster.members.filter { it.role == Role.INVITED && old.role(it.id) == null }.map { it.id }.toSet()
        dbg { "broadcast v${signed.roster.ver} to ${targets.map { who(it) + (if (cardsBefore[it] != null) "/g" else "/d") }}" }
        for (id in targets) {
            if (cardsBefore[id] != null) {
                io.sendGroup(m.gid, id, content)
            } else {
                io.sendDirect(m.gid, id, content)
            }
        }
        // Newcomers need every card to reach the members.
        for (id in addedInvitees) {
            m.myCard?.let { io.sendDirect(m.gid, id, cardContent(it)) }
            for (card in m.cards.values) {
                io.sendDirect(m.gid, id, cardContent(card))
            }
        }
    }

    private fun requestSync(m: GroupModel, admin: String, have: Long) {
        val content = Content.GSync(m.gid, have)
        if (m.cards[admin] != null) {
            io.sendGroup(m.gid, admin, content)
        } else {
            io.sendDirect(m.gid, admin, content)
        }
    }

    /** Groups whose roster changed in this engine's calls, so their held messages may be deliverable now. */
    private val heldReady = LinkedHashSet<String>()

    /**
     * The held messages that may be deliverable now (their group's roster changed since the last call). The caller replays
     * each with [replayHeld] in its own transaction, once the change that freed them is stored: a held message that fails
     * then only drops itself, instead of undoing that change (and wedging the group) every time it's retried.
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

        /** Forks at most this many versions below ours are decided (rule 3); older ones are final. */
        const val FORK_DEPTH = 16

        /** Versions after which our own change, built on by others, no longer needs watching. */
        private const val SETTLED = FORK_DEPTH

        /** How far back a lost branch is checked for departures and acceptances. */
        private const val BRANCH = 16

        /** Rosters we didn't take, kept per version (see [GroupStore.addHistory]). */
        const val MAX_SIBLINGS = 64
        const val MAX_SIBLINGS_PER_AUTHOR = 8

        /** Whether [r] may join [held], the rosters already kept at its version. */
        fun siblingFits(held: List<Roster>, r: Roster): Boolean =
            held.size < MAX_SIBLINGS && held.count { it.by == r.by } < MAX_SIBLINGS_PER_AUTHOR

        /** Marks a held row as already-decrypted content from an invitee (a real hint key is 32 bytes). */
        private val HELD_CONTENT = byteArrayOf(0x43)
        private const val IDENTITY_LEN = 33

        /** Syncs we asked for (see onRoster), by what about, and when; newest last. Per process: enough to stop a loop. */
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

        fun cardContent(c: SignedCard) = Content.GCard(c.card.g, B64.enc(c.bytes), B64.enc(c.sig))

        /** Builds and signs this member's card. */
        fun makeCard(identity: IdentityKeyPair, card: GroupCard): SignedCard = GroupCrypto.signCard(identity.privateKey, card)
    }
}
