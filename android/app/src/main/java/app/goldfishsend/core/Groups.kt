package app.goldfishsend.core

import android.util.Log
import app.goldfishsend.db.Mailbox
import app.goldfishsend.db.MsgKind
import app.goldfishsend.db.MsgStatus
import app.goldfishsend.db.OutboxKind
import app.goldfishsend.db.RepoGroupStore
import app.goldfishsend.db.addGroupRead
import app.goldfishsend.db.groupRef
import app.goldfishsend.db.groupRefs
import app.goldfishsend.db.groupWire
import app.goldfishsend.db.groupsNeedingRotation
import app.goldfishsend.db.groupsWithMember
import app.goldfishsend.db.messageIdByWire
import app.goldfishsend.db.pruneGoneCards
import app.goldfishsend.db.pruneGroupHeld
import app.goldfishsend.db.setRotateNeeded
import app.goldfishsend.group.GroupEngine
import app.goldfishsend.group.GroupEvent
import app.goldfishsend.group.GroupIo
import app.goldfishsend.group.GroupModel
import app.goldfishsend.net.ApiException
import app.goldfishsend.net.ServerApi
import app.goldfishsend.proto.B64
import app.goldfishsend.proto.CardBundle
import app.goldfishsend.proto.CardInbox
import app.goldfishsend.proto.Chunker
import app.goldfishsend.proto.Content
import app.goldfishsend.proto.GroupCard
import app.goldfishsend.proto.GroupCrypto
import app.goldfishsend.proto.Padding
import app.goldfishsend.proto.Rand
import app.goldfishsend.proto.Role
import app.goldfishsend.proto.RosterOp
import app.goldfishsend.proto.RosterRules
import app.goldfishsend.proto.Sanitize
import app.goldfishsend.proto.SignedCard
import kotlinx.coroutines.sync.withLock
import org.signal.libsignal.protocol.ecc.ECKeyPair
import org.signal.libsignal.protocol.kem.KEMKeyPair
import org.signal.libsignal.protocol.kem.KEMKeyType
import org.signal.libsignal.protocol.state.KyberPreKeyRecord
import org.signal.libsignal.protocol.state.SignedPreKeyRecord

class GroupException(val human: String) : Exception(human)

/**
 * Group chats in the app (docs/groups.md): the [GroupEngine] over the SQLCipher store, the outbox and the 1:1 sessions.
 * A group is a `contacts` row with is_group = 1, so the chat list, timers, hidden chats and wipes all cover it.
 */
object Groups {
    init {
        if (app.goldfishsend.BuildConfig.DEBUG) {
            app.goldfishsend.group.GroupEngine.debugLog = { Log.d("GoldfishGroup", it) }
        }
    }

    /** Group content is chunked for the worst case (a first, PreKey message to a member). */
    const val MAX_PLAINTEXT = Padding.MAX_PREKEY_PLAINTEXT

    /** A rotated group inbox keeps receiving for the server's max TTL (14 days) plus a day. */
    private const val DRAIN_MS = 15 * 86_400_000L

    private const val HELD_MS = 7 * 86_400_000L

    fun engine(s: Session): GroupEngine = GroupEngine(RepoGroupStore(s.repo), s.signal, s.signal.identityKeyPair, AppIo(s))

    fun store(s: Session) = RepoGroupStore(s.repo)

    fun me(s: Session): String = B64.enc(s.signal.identityKeyPair.publicKey.serialize())

    fun model(s: Session, cid: Long): GroupModel? = s.repo.groupRef(cid)?.let { store(s).load(it.gid) }

    private suspend fun <T> locked(s: Session, block: () -> T): T = s.lock.withLock { s.db.tx { block() } }

    /** Runs [block] on an engine under the lock in one transaction, then delivers the held messages it freed. */
    private suspend fun <T> withEngine(s: Session, block: (GroupEngine) -> T): T {
        val e = engine(s)
        val r = locked(s) { block(e) }
        replayHeld(s, e)
        return r
    }

    /** Each held message in a transaction of its own: one that fails is dropped, and the rest still go. */
    private suspend fun replayHeld(s: Session, e: GroupEngine) {
        while (true) {
            val ready = locked(s) { e.readyHeld() }
            if (ready.isEmpty()) {
                return
            }
            for ((gid, h) in ready) {
                ReceiveGuard.runSuspend("held group message") { locked(s) { e.replayHeld(gid, h) } }
                    ?: locked(s) { store(s).dropHeld(h.id) }
            }
        }
    }

    // ---------- create, join, leave ----------

    /** Creates a group with [contactIds] invited. Returns the group's chat id. */
    suspend fun create(s: Session, name: String, contactIds: List<Long>): Long {
        if (s.decoy) {
            throw GroupException("Groups aren't available right now.")
        }
        val clean = Sanitize.name(name) ?: throw GroupException("Give the group a name.")
        val invitees = contactIds.mapNotNull { s.repo.contact(it) }
            .filter { !it.isGroup && it.identityKey != null && it.pendingIdentity == null }
            .map { B64.enc(it.identityKey!!) }
        if (invitees.size + 1 > RosterRules.MAX_MEMBERS) {
            throw GroupException("A group can have at most ${RosterRules.MAX_MEMBERS} members.")
        }
        val gid = B64.enc(Rand.bytes(32))
        val (mb, serverKey) = inbox(s)
        val hintKey = Rand.bytes(GroupCrypto.HINT_KEY)
        val cid = locked(s) {
            val card = newCard(s, gid, mb, hintKey, serverKey, seq = 1, bundle = null)
            engine(s).create(gid, clean, invitees, card, Graph.prefs.defaultTimerSecs)
            val cid = store(s).cidOf(gid)!!
            s.repo.bindGroupInbox(mb.id, cid, hintKey)
            cid
        }
        s.db.notifyChanged()
        Outbox.kick()
        return cid
    }

    /** Accepts an invitation: our inbox, keys and card go to every member. */
    suspend fun join(s: Session, cid: Long) {
        val m = model(s, cid) ?: return
        if (m.state != GroupModel.INVITED) {
            return
        }
        val (mb, serverKey) = inbox(s)
        val hintKey = Rand.bytes(GroupCrypto.HINT_KEY)
        val ok = withEngine(s) { e ->
            val fresh = model(s, cid) ?: return@withEngine false
            val card = newCard(s, fresh.gid, mb, hintKey, serverKey, seq = 1, bundle = null)
            s.repo.bindGroupInbox(mb.id, cid, hintKey)
            e.join(fresh, card)
        }
        if (!ok) {
            throw GroupException("Couldn't join. The invitation may have changed; try again.")
        }
        s.db.notifyChanged()
        Outbox.kick()
    }

    /** Declines an invitation, or leaves. An owner who leaves hands the group to the next member ([heir]). */
    suspend fun leave(s: Session, cid: Long) {
        withEngine(s) { e ->
            val m = model(s, cid) ?: return@withEngine true
            if (m.state == GroupModel.LEFT || m.state == GroupModel.REMOVED) {
                return@withEngine true
            }
            e.leave(m)
        }
        s.db.notifyChanged()
        Outbox.kick()
    }

    /** If we own the group: who becomes the owner when we leave (the first other member in the roster), or null. */
    fun heir(m: GroupModel, me: String): String? {
        val v = m.view() ?: return null
        if (!v.isOwner(me)) {
            return null
        }
        // Like Membership.owner: the roster's members, in order, who haven't left.
        return m.roster!!.roster.members.firstOrNull { it.id != me && it.role == Role.MEMBER && v.role(it.id) != null }?.id
    }

    private suspend fun change(s: Session, cid: Long, op: RosterOp): Boolean {
        val done = withEngine(s) { e ->
            val m = model(s, cid) ?: return@withEngine false
            if (m.state != GroupModel.JOINED) {
                return@withEngine false
            }
            e.publish(m, op) != null
        }
        s.db.notifyChanged()
        Outbox.kick()
        return done
    }

    suspend fun addMembers(s: Session, cid: Long, contactIds: List<Long>): Boolean {
        val ids = contactIds.mapNotNull { s.repo.contact(it) }
            .filter { !it.isGroup && it.identityKey != null && it.pendingIdentity == null }
            .map { B64.enc(it.identityKey!!) }
        if (ids.isEmpty()) {
            return false
        }
        val size = model(s, cid)?.view()?.members?.size ?: 0
        if (size + ids.size > RosterRules.MAX_MEMBERS) {
            throw GroupException("A group can have at most ${RosterRules.MAX_MEMBERS} members.")
        }
        return change(s, cid, RosterOp.Add(ids))
    }

    suspend fun removeMember(s: Session, cid: Long, member: String) = change(s, cid, RosterOp.Remove(listOf(member)))

    /** Hands ownership to [member]; we stay on as a member. */
    suspend fun makeOwner(s: Session, cid: Long, member: String) = change(s, cid, RosterOp.MakeOwner(member))

    suspend fun rename(s: Session, cid: Long, name: String): Boolean {
        val clean = Sanitize.name(name) ?: return false
        return change(s, cid, RosterOp.Meta(name = clean))
    }

    suspend fun setTimer(s: Session, cid: Long, secs: Long) =
        change(s, cid, RosterOp.Meta(timer = secs.coerceIn(0, Sanitize.MAX_TIMER_SECS)))

    /** Whether we may change the group: only its owner can. */
    fun canEditInfo(m: GroupModel, me: String): Boolean = m.state == GroupModel.JOINED && m.view()?.isOwner(me) == true

    // ---------- messages ----------

    /** Sends a text to every member we can reach (one outbox row per member and part). */
    fun sendText(s: Session, cid: Long, body: String, viewOnce: Boolean = false) {
        val m = model(s, cid) ?: return
        if (m.state != GroupModel.JOINED) {
            return
        }
        val contact = s.repo.contact(cid) ?: return
        val targets = recipients(s, m)
        val wire = Content.newId()
        val now = System.currentTimeMillis()
        val exp = contact.timerSecs
        val localId = s.repo.insertMessage(
            cid, wire, true, MsgKind.TEXT, body, now, null, exp, viewOnce,
            if (exp > 0) now + exp * 1000 else null,
            if (targets.isEmpty()) MsgStatus.SENT else MsgStatus.QUEUED,
            recipients = targets.size,
        ) ?: return
        val parts = Chunker.splitContent(
            Content.GText(m.gid, wire, body, now, exp.takeIf { it > 0 }, viewOnce.takeIf { it }),
            MAX_PLAINTEXT,
        )
        s.db.tx {
            for (to in targets) {
                for (p in parts) {
                    s.repo.enqueue(cid, localId, OutboxKind.CONTENT, p.encode(), memberKey = to)
                }
            }
        }
        s.repo.touchContact(cid, false)
        s.db.notifyChanged()
        Sweeper.schedule(s)
        Outbox.kick()
    }

    /**
     * Who a group message goes to: every active member but us, including members whose card hasn't reached us yet (a
     * newcomer's card can arrive after their roster). Their rows wait in the outbox until the card does.
     */
    private fun recipients(s: Session, m: GroupModel): List<String> {
        val me = B64.enc(s.signal.identityKeyPair.publicKey.serialize())
        val v = m.view() ?: return emptyList()
        return v.members.filter { it.id != me && v.isActive(it.id) }.map { it.id }
    }

    /** Group fan-out of control content (rosters, cards, receipts). */
    private fun enqueueGroup(s: Session, cid: Long, to: String, content: Content, messageId: String? = null) {
        for (p in Chunker.splitContent(content, MAX_PLAINTEXT)) {
            s.repo.enqueue(cid, messageId, OutboxKind.CONTENT, p.encode(), memberKey = to)
        }
        Outbox.kick()
    }

    fun deleteForEveryone(s: Session, cid: Long, wireId: String) {
        val m = model(s, cid) ?: return
        if (m.state != GroupModel.JOINED) {
            return
        }
        for (to in recipients(s, m)) {
            enqueueGroup(s, cid, to, Content.GDelete(m.gid, listOf(wireId)))
        }
    }

    /** Read receipts go only to each message's author, and only if read receipts are on. */
    fun sendReadReceipts(s: Session, cid: Long, wireIds: List<String>) {
        if (!Graph.prefs.readReceipts || wireIds.isEmpty()) {
            return
        }
        val m = model(s, cid) ?: return
        if (m.state != GroupModel.JOINED) {
            return
        }
        val byTag = m.cards.keys.associateBy { GroupCrypto.tag(it) }
        wireIds.mapNotNull { w ->
            val i = w.indexOf(':')
            if (i <= 0) null else byTag[w.substring(0, i)]?.let { it to w.substring(i + 1) }
        }.groupBy({ it.first }, { it.second }).forEach { (author, ids) ->
            enqueueGroup(s, cid, author, Content.GReceipt(m.gid, ids.take(500), Content.Receipt.READ))
        }
    }

    // ---------- receive ----------

    /** A push on one of our group inboxes. */
    suspend fun receive(s: Session, mb: Mailbox, raw: ByteArray) {
        val cid = mb.contactId ?: return
        val hintKey = mb.hintKey ?: return
        val gid = s.repo.groupRef(cid)?.gid ?: return
        ReceiveGuard.runSuspend("group message") { withEngine(s) { it.receive(gid, hintKey, raw) } } ?: return
        Mailboxes.onMessageOnMailbox(s, s.repo.mailbox(mb.id) ?: mb)
        s.db.notifyChanged()
        // A member's card may just have arrived, unblocking rows that were waiting for it.
        Outbox.kick()
    }

    /** Group content over a 1:1 session (invitations, forwarded cards, rosters for invitees). */
    suspend fun onDirect(s: Session, contactId: Long, content: Content) {
        val key = s.repo.contact(contactId)?.identityKey ?: return
        ReceiveGuard.runSuspend("group content") { withEngine(s) { it.onDirect(B64.enc(key), content) } }
        s.db.notifyChanged()
        Outbox.kick()
    }

    /** Retries a failed group message: queued again to every member (a member who has it already drops the copy). */
    fun resend(s: Session, msg: app.goldfishsend.db.Message) {
        val m = model(s, msg.contactId) ?: return
        if (m.state != GroupModel.JOINED) {
            s.repo.setStatus(msg.id, MsgStatus.FAILED)
            return
        }
        val parts = Chunker.splitContent(
            Content.GText(m.gid, msg.wireId, msg.body, msg.ts, msg.expSecs.takeIf { it > 0 }, msg.viewOnce.takeIf { it }),
            MAX_PLAINTEXT,
        )
        s.db.tx {
            for (to in m.cards.keys) {
                for (p in parts) {
                    s.repo.enqueue(msg.contactId, msg.id, OutboxKind.CONTENT, p.encode(), memberKey = to)
                }
            }
        }
        if (m.cards.isEmpty()) {
            s.repo.setStatus(msg.id, MsgStatus.SENT)
        }
        Outbox.kick()
    }

    /** Drops the shared session with each of [members] that isn't in any group any more. Call under the session lock. */
    fun forgetSessions(s: Session, members: Collection<String>) {
        for (member in members.toSet()) {
            if (s.repo.groupsWithMember(member) == 0L) {
                s.signal.deleteSession(GroupCrypto.address(member))
            }
        }
    }

    // ---------- maintenance ----------

    /** Rotates inboxes that need it, drops stale held messages and departed members' delivered cards. */
    suspend fun maintain(s: Session) {
        if (s.decoy) {
            return
        }
        s.repo.pruneGroupHeld(System.currentTimeMillis() - HELD_MS)
        locked(s) { forgetSessions(s, s.repo.pruneGoneCards()) }
        // Mailbox rotation (Prefs.mailboxRotationDays) covers group inboxes too.
        val days = Graph.prefs.mailboxRotationDays
        if (days > 0) {
            val before = System.currentTimeMillis() - days * 86_400_000L
            for (ref in s.repo.groupRefs().filter { it.state == GroupModel.JOINED }) {
                val mb = s.repo.mailboxForContact(ref.cid)
                if (mb != null && mb.createdAt < before) {
                    s.repo.setRotateNeeded(ref.cid, true)
                }
            }
        }
        rotatePending(s)
    }

    /** Gives every group that lost a member a fresh inbox and card (docs/groups.md, "Accepting a roster", step 4). */
    suspend fun rotatePending(s: Session) {
        for (cid in s.repo.groupsNeedingRotation()) {
            val m = model(s, cid)
            if (m == null || m.state != GroupModel.JOINED || m.myCard == null) {
                s.repo.setRotateNeeded(cid, false)
                continue
            }
            val (mb, serverKey) = try {
                inbox(s)
            } catch (e: GroupException) {
                return
            }
            val hintKey = Rand.bytes(GroupCrypto.HINT_KEY)
            locked(s) {
                val cur = model(s, cid) ?: return@locked
                val old = s.repo.mailboxForContact(cid)
                val now = System.currentTimeMillis()
                old?.let { s.repo.retireGroupInbox(it.id, now, now + DRAIN_MS) }
                s.repo.bindGroupInbox(mb.id, cid, hintKey)
                val prev = cur.myCard!!.card
                val card = newCard(s, cur.gid, mb, hintKey, serverKey, seq = prev.seq + 1, bundle = prev.bundle)
                engine(s).updateCard(cur, card)
                s.repo.setRotateNeeded(cid, false)
            }
            Outbox.kick()
        }
    }

    /** Our own server's key changed (the user trusted it): every group gets a card with the new key. */
    suspend fun announceServerKey(s: Session) {
        for (ref in s.repo.groupRefs().filter { it.state == GroupModel.JOINED }) {
            s.repo.setRotateNeeded(ref.cid, true)
        }
        rotatePending(s)
    }

    // ---------- helpers ----------

    /** A fresh inbox mailbox (from the pool when it's warm) and our server's identity fingerprint. */
    private suspend fun inbox(s: Session): Pair<Mailbox, String> {
        val mb = try {
            Mailboxes.take(s, Mailbox.PURPOSE_GROUP)
        } catch (e: ApiException) {
            throw GroupException(
                if (e.status == 429) {
                    val mins = ((e.retryAfterSeconds ?: 60) + 59) / 60
                    "Your server is limiting new chats from your network right now. Try again in ${if (mins <= 1) "a minute" else "$mins minutes"}."
                } else {
                    "Couldn't reach your server. Check your connection and try again."
                },
            )
        } ?: throw GroupException("Still getting things ready. This only takes a moment the first time.")
        val serverKey = try {
            Graph.ownServerKey()
        } catch (e: Exception) {
            s.repo.releasePoolMailbox(mb.id)
            throw GroupException("Couldn't reach your server. Check your connection and try again.")
        }
        Graph.scope.launchSafe { Mailboxes.ensurePool(s) }
        return mb to serverKey
    }

    /** Our card for a group. New prekeys (last-resort, kept while we're in the group) unless [bundle] is reused. */
    private fun newCard(
        s: Session,
        gid: String,
        mb: Mailbox,
        hintKey: ByteArray,
        serverKey: String,
        seq: Long,
        bundle: CardBundle?,
    ): SignedCard {
        val identity = s.signal.identityKeyPair
        val b = bundle ?: run {
            val spkId = Invites.nextKeyId(s)
            val spk = ECKeyPair.generate()
            val spkSig = identity.privateKey.calculateSignature(spk.publicKey.serialize())
            s.signal.storeSignedPreKey(spkId, SignedPreKeyRecord(spkId, System.currentTimeMillis(), spk, spkSig))
            val kyberId = Invites.nextKeyId(s)
            val kyber = KEMKeyPair.generate(KEMKeyType.KYBER_1024)
            val kyberSig = identity.privateKey.calculateSignature(kyber.publicKey.serialize())
            s.signal.storeKyberPreKey(kyberId, KyberPreKeyRecord(kyberId, System.currentTimeMillis(), kyber, kyberSig))
            s.signal.markLastResort(kyberId)
            CardBundle(
                registrationId = s.signal.localRegistrationId,
                signedPreKeyId = spkId,
                signedPreKey = B64.enc(spk.publicKey.serialize()),
                signedPreKeySig = B64.enc(spkSig),
                kyberPreKeyId = kyberId,
                kyberPreKey = B64.enc(kyber.publicKey.serialize()),
                kyberPreKeySig = B64.enc(kyberSig),
            )
        }
        val card = GroupCard(
            g = gid,
            id = B64.enc(identity.publicKey.serialize()),
            name = s.repo.displayName,
            inbox = CardInbox(Graph.prefs.serverUrl, serverKey, B64.enc(mb.sendSecret)),
            hintKey = B64.enc(hintKey),
            bundle = b,
            seq = seq,
        )
        return GroupEngine.makeCard(identity, card)
    }

    /** How a member appears: your own name for them if they're your contact, otherwise their self-chosen name. */
    data class MemberName(val name: String, val isContact: Boolean, val verified: Boolean, val known: Boolean = true)

    /** Self-chosen names seen in a group's cards, kept after the card goes (removed members, old messages). */
    private fun nameKey(cid: Long, member: String) = "gname/$cid/${GroupCrypto.tag(member)}"

    /** Members whose join line was written before we knew their name: the line naming them follows their card. */
    private fun pendingNameKey(cid: Long, member: String) = "gjoin/$cid/${GroupCrypto.tag(member)}"

    fun memberName(s: Session, m: GroupModel?, member: String): MemberName {
        if (member == me(s)) {
            return MemberName("You", true, true)
        }
        val contact = runCatching { s.repo.personByIdentity(B64.dec(member)) }.getOrNull()
        if (contact != null) {
            return MemberName(contact.name, true, contact.verified)
        }
        val own = (m?.cards?.get(member) ?: m?.departed?.get(member))?.card?.name?.let { Sanitize.name(it) }
            ?: m?.let { g -> RepoGroupStore(s.repo).cidOf(g.gid) }?.let { cid -> s.repo.kvString(nameKey(cid, member)) }
        return if (own != null) MemberName(own, false, false) else MemberName("Someone new", false, false, known = false)
    }

    private fun names(s: Session, m: GroupModel, ids: List<String>): String =
        ids.map { memberName(s, m, it).name }.let { list ->
            when (list.size) {
                0 -> ""
                1 -> list[0]
                2 -> "${list[0]} and ${list[1]}"
                else -> list.dropLast(1).joinToString(", ") + " and " + list.last()
            }
        }

    /** The engine's side effects, applied to the database, outbox and notifications. Runs inside the engine's transaction. */
    private class AppIo(private val s: Session) : GroupIo {
        private fun cid(gid: String): Long? = RepoGroupStore(s.repo).cidOf(gid)

        override fun sendGroup(gid: String, to: String, content: Content) {
            val cid = cid(gid) ?: return
            enqueueGroup(s, cid, to, content)
        }

        override fun sendDirect(gid: String, to: String, content: Content): Boolean {
            val contact = runCatching { s.repo.personByIdentity(B64.dec(to)) }.getOrNull() ?: return false
            Messenger.sendControlChunked(s, contact.id, content)
            return true
        }

        override fun onEvents(m: GroupModel, events: List<GroupEvent>) {
            val cid = cid(m.gid) ?: return
            val r = m.roster?.roster
            // The chat row mirrors the roster's name and timer.
            if (r != null) {
                Sanitize.name(r.name)?.let { s.repo.renameContact(cid, it) }
                s.repo.setTimer(cid, r.timer)
            }
            for (e in events) {
                val text = when (e) {
                    GroupEvent.Created -> "You created the group. Messages are end-to-end encrypted."
                    is GroupEvent.Invited -> "${memberName(s, m, e.by).name} invited you to this group."
                    is GroupEvent.Added -> {
                        val unknown = e.ids.filter { !memberName(s, m, it).known }
                        unknown.forEach { s.repo.kvPutString(pendingNameKey(cid, it), "1") }
                        val known = names(s, m, e.ids - unknown.toSet())
                        val by = memberName(s, m, e.by).name
                        when {
                            unknown.isEmpty() -> "$by added $known."
                            known.isEmpty() -> "$by added ${if (unknown.size == 1) "someone new" else "${unknown.size} new people"}."
                            else -> "$by added $known and ${if (unknown.size == 1) "someone new" else "${unknown.size} new people"}."
                        }
                    }
                    is GroupEvent.Removed -> {
                        for (id in e.ids) {
                            s.repo.outboxDropMember(cid, id).forEach { settleStatus(s, it) }
                        }
                        "${memberName(s, m, e.by).name} removed ${names(s, m, e.ids)}."
                    }
                    is GroupEvent.Left -> {
                        s.repo.outboxDropMember(cid, e.id).forEach { settleStatus(s, it) }
                        "${memberName(s, m, e.id).name} left."
                    }
                    is GroupEvent.Joined -> when {
                        e.id == me(s) -> "You joined the group."
                        memberName(s, m, e.id).known -> "${memberName(s, m, e.id).name} joined."
                        else -> {
                            s.repo.kvPutString(pendingNameKey(cid, e.id), "1")
                            "Someone new joined."
                        }
                    }
                    is GroupEvent.OwnerChanged ->
                        if (e.id == me(s)) "You're the owner of the group now." else "${memberName(s, m, e.id).name} is the owner of the group now."
                    is GroupEvent.Renamed -> "${memberName(s, m, e.by).name} renamed the group to “${Sanitize.name(e.name) ?: ""}”."
                    is GroupEvent.TimerChanged ->
                        "${memberName(s, m, e.by).name} set disappearing messages to ${timerLabel(e.secs).lowercase()}."
                    is GroupEvent.YouWereRemoved -> {
                        dropOutbox(cid)
                        afterDeparture(cid, m)
                        "${memberName(s, m, e.by).name} removed you from the group."
                    }
                    GroupEvent.YouLeft -> {
                        afterDeparture(cid, m)
                        "You left the group."
                    }
                }
                Messenger.systemMessage(s, cid, text)
                when (e) {
                    is GroupEvent.Invited -> {
                        s.repo.touchContact(cid, incrementUnread = true)
                        Messenger.notify(s, cid, "Invitation to join")
                    }
                    is GroupEvent.YouWereRemoved -> s.repo.touchContact(cid, false)
                    else -> Unit
                }
            }
        }

        override fun onCard(m: GroupModel, id: String) {
            val cid = cid(m.gid) ?: return
            val name = m.cards[id]?.card?.name?.let { Sanitize.name(it) } ?: return
            s.repo.kvPutString(nameKey(cid, id), name)
            // A join line said "someone new": now we can say who it was (contacts show your own name for them).
            if (s.repo.kvString(pendingNameKey(cid, id)) != null) {
                s.repo.kvPutString(pendingNameKey(cid, id), null)
                Messenger.systemMessage(s, cid, "${memberName(s, m, id).name} is in the group.")
            }
        }

        /** We're out: our inbox goes (server-side, best effort) and so do this group's prekeys (forward secrecy). */
        /** Nothing queued to this group goes out any more. */
        private fun dropOutbox(cid: Long) {
            s.repo.db.query("SELECT DISTINCT message_id FROM outbox WHERE contact_id = ? AND message_id IS NOT NULL", cid) {
                it.getString(0)
            }.let { ids ->
                s.repo.db.exec("DELETE FROM outbox WHERE contact_id = ?", cid)
                ids.forEach { settleStatus(s, it) }
            }
        }

        private fun afterDeparture(cid: Long, m: GroupModel) {
            m.myCard?.card?.bundle?.let { b ->
                s.signal.removeSignedPreKey(b.signedPreKeyId)
                s.signal.removeKyberPreKey(b.kyberPreKeyId)
            }
            val boxes = s.repo.mailboxesForContact(cid)
            for (b in boxes) {
                s.repo.deleteMailboxRow(b.id)
            }
            if (boxes.isNotEmpty()) {
                Graph.scope.launchSafe { Mailboxes.deleteRemote(boxes.map(Mailboxes::item)) }
            }
        }

        override fun onText(m: GroupModel, from: String, t: Content.GText) {
            val cid = cid(m.gid) ?: return
            val now = System.currentTimeMillis()
            val exp = Sanitize.effectiveTimer(s.repo.contact(cid)?.timerSecs ?: 0, t.exp)
            val expiresAt = if (exp > 0 && !Graph.prefs.timerStartsOnRead) now + exp * 1000 else null
            s.repo.insertMessage(
                contactId = cid,
                wireId = groupWire(from, t.id),
                outgoing = false,
                kind = MsgKind.TEXT,
                body = t.body,
                ts = Sanitize.timestamp(t.ts, now),
                receivedAt = now,
                expSecs = exp,
                viewOnce = t.once == true,
                expiresAt = expiresAt,
                status = MsgStatus.DELIVERED,
                senderKey = from,
            ) ?: return
            val visible = Messenger.openChat.value == cid && AppVisibility.foreground
            s.repo.touchContact(cid, incrementUnread = !visible)
            if (visible) {
                // Read receipts go out from markChatRead once the transaction is done.
                Graph.scope.launchSafe { Messenger.markChatRead(s, cid) }
            } else {
                val who = memberName(s, m, from).name
                Messenger.notify(s, cid, if (t.once == true) "$who: View-once message" else "$who: ${t.body}")
            }
            Sweeper.schedule(s)
        }

        override fun onReceipt(m: GroupModel, from: String, r: Content.GReceipt) {
            val cid = cid(m.gid) ?: return
            if (r.kind != Content.Receipt.READ) {
                return
            }
            for (w in r.ids.take(500)) {
                val id = s.repo.messageIdByWire(cid, w, outgoing = true) ?: continue
                val msg = s.repo.message(id) ?: continue
                val readers = s.repo.addGroupRead(id, from)
                val st = if (msg.recipients > 0 && readers >= msg.recipients) MsgStatus.READ else MsgStatus.DELIVERED
                s.repo.raiseStatus(cid, listOf(w), st)
            }
        }

        override fun onDelete(m: GroupModel, from: String, d: Content.GDelete) {
            val cid = cid(m.gid) ?: return
            s.repo.deleteIncomingByWire(cid, d.ids.take(500).map { groupWire(from, it) })
            Notifier.cancel(Graph.app)
        }

        override fun rotateInbox(m: GroupModel) {
            val cid = cid(m.gid) ?: return
            s.repo.setRotateNeeded(cid, true)
            Graph.scope.launchSafe { rotatePending(s) }
        }

        override fun validServer(url: String): Boolean = ServerApi.isValidContactServer(url)

        override fun nowMillis(): Long = System.currentTimeMillis()
    }

    /** After rows to a member were dropped, an outgoing message with nothing left queued counts as sent. */
    private fun settleStatus(s: Session, messageId: String) {
        if (s.repo.outboxRemaining(messageId) == 0L) {
            val msg = s.repo.message(messageId) ?: return
            if (msg.status == MsgStatus.QUEUED) {
                s.repo.setStatus(messageId, MsgStatus.SENT)
            }
        }
    }
}
