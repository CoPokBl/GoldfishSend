package app.goldfishsend.proto

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.ecc.ECPrivateKey
import org.signal.libsignal.protocol.ecc.ECPublicKey
import org.signal.libsignal.protocol.kem.KEMPublicKey

/** Group wire formats (docs/groups.md). Android-free, so the JVM tests use exactly this code. */

@Serializable
data class CardInbox(val server: String, val serverKey: String, val sendSecret: String)

@Serializable
data class CardBundle(
    val registrationId: Int,
    val deviceId: Int = 1,
    val signedPreKeyId: Int,
    val signedPreKey: String,
    val signedPreKeySig: String,
    val kyberPreKeyId: Int,
    val kyberPreKey: String,
    val kyberPreKeySig: String,
)

/**
 * A member's card. [since] names the stint it's for (their roster entry's): members take it only for that stint, so a
 * card from an earlier one, whose inbox and keys are gone, can't stand in for a newer one, whatever its [seq]. [seq]
 * grows with each new card in a stint, and the highest wins.
 */
@Serializable
data class GroupCard(
    val v: Int = 1,
    val g: String,
    val id: String,
    val name: String? = null,
    val inbox: CardInbox,
    val hintKey: String,
    val bundle: CardBundle,
    val seq: Long,
    val since: Long,
)

/** Signed bytes as they travel inside another document: b64u bytes and b64u signature. */
@Serializable
data class Signed(val data: String, val sig: String)

/**
 * [since]: the version of the roster that invited them, which names this stint of theirs in the group. [card]: only in
 * the roster that admits them (taken from their acceptance), so whoever holds it can reach them.
 */
@Serializable
data class RosterMember(val id: String, val role: String, val since: Long, val card: Signed? = null)

/**
 * Where a member is (docs/groups.md, "Heads"): their roster's version, its hash (first 12 bytes) and a digest (12 bytes
 * for facts, 12 for cards) of the facts it doesn't show yet and the card `seq` of every active member. Two members with
 * equal heads hold the same state; otherwise one of them is behind, or each has something the other lacks. [s] counts
 * the sender's head changes, so an older head arriving late doesn't replace a newer one.
 */
@Serializable
data class Head(val v: Long, val r: String, val d: String, val s: Long = 0) {
    val key: String get() = "$v:$r:$d"

    companion object {
        /** 1: [a] is ahead of [b]; -1: behind; 0: equal; 2: same roster, each may have facts or cards the other lacks. */
        fun compare(a: Head, b: Head): Int? = when {
            a.v > b.v -> 1
            a.v < b.v -> -1
            a.r != b.r -> null
            a.d == b.d -> 0
            else -> 2
        }
    }
}

/**
 * The member list, signed by its owner. [proof]: when the owner of the roster before this one has left, the departures
 * (signed facts) that make [by] their successor.
 */
@Serializable
data class Roster(
    val v: Int = 2,
    val g: String,
    val ver: Long,
    val prev: String = "",
    val name: String,
    val timer: Long = 0,
    val members: List<RosterMember>,
    val by: String,
    val ts: Long,
    val proof: List<Signed> = emptyList(),
) {
    fun member(id: String): RosterMember? = members.firstOrNull { it.id == id }

    fun role(id: String): String? = member(id)?.role

    val owner: String? get() = members.firstOrNull { it.role == Role.OWNER }?.id

    fun ids(): List<String> = members.map { it.id }
}

object Role {
    const val OWNER = "owner"
    const val MEMBER = "member"
    const val INVITED = "invited"

    val ALL = setOf(OWNER, MEMBER, INVITED)
}

/** A member's signed statement about their own stint ([since]): they accepted the invitation, or left (or declined). */
@Serializable
data class Fact(
    val v: Int = 2,
    val g: String,
    val kind: String,
    val id: String,
    val since: Long,
    val ts: Long,
    /**
     * On a departure: the version of the newest roster the leaver held. It only counts once our roster has caught up,
     * so whoever takes over from them builds on it (the rosters themselves travel next to the fact, in the state).
     */
    val last: Long = 0,
    /** On an acceptance: the member's card, so whoever learns they're in can reach them. */
    val card: Signed? = null,
) {
}

object FactKind {
    const val ACCEPT = "accept"
    const val LEAVE = "leave"
}

/** Exact bytes as signed, plus the parsed value. Nothing is ever re-serialised for verification. */
class SignedRoster(val bytes: ByteArray, val sig: ByteArray, val roster: Roster) {
    val hash: ByteArray = Hash.sha256(bytes)
    val hashB64: String = B64.enc(hash)

    fun wire() = Signed(B64.enc(bytes), B64.enc(sig))
}

class SignedFact(val bytes: ByteArray, val sig: ByteArray, val fact: Fact) {
    /** One fact of each kind counts per stint. */
    val key: String get() = "${fact.id} ${fact.since} ${fact.kind}"

    fun wire() = Signed(B64.enc(bytes), B64.enc(sig))
}

class SignedCard(val bytes: ByteArray, val sig: ByteArray, val card: GroupCard)

/** Canonical JSON for cards and rosters: defaults included, so `v` and every field are always present. */
val GroupJson = Json {
    ignoreUnknownKeys = true
    encodeDefaults = true
    explicitNulls = false
}

object GroupCrypto {
    private val CARD_LABEL = "gf/group-card/v1".utf8()
    private val ROSTER_LABEL = "gf/group-roster/v2".utf8()
    private val FACT_LABEL = "gf/group-fact/v2".utf8()
    private val HINT_LABEL = "gf/group-hint/v1".utf8()
    const val HINT_NONCE = 16
    const val HINT_MAC = 16
    const val HINT_KEY = 32

    /** Rosters a departure's state carries at most: the leaver's own run at the end of their chain. */
    const val MAX_LAST = 8

    /** A b64u identity key in canonical form (33 bytes, DJB type 0x05), or null. */
    fun identityBytes(id: String): ByteArray? = try {
        val raw = B64.dec(id)
        if (raw.size == 33 && raw[0] == 0x05.toByte() && B64.enc(raw) == id) {
            IdentityKey(raw)
            raw
        } else {
            null
        }
    } catch (e: Exception) {
        null
    }

    fun isIdentity(id: String): Boolean = identityBytes(id) != null

    private fun verify(id: String, label: ByteArray, bytes: ByteArray, sig: ByteArray): Boolean = try {
        val raw = identityBytes(id) ?: return false
        IdentityKey(raw).publicKey.verifySignature(label + bytes, sig)
    } catch (e: Exception) {
        false
    }

    fun signCard(priv: ECPrivateKey, card: GroupCard): SignedCard {
        val bytes = GroupJson.encodeToString(GroupCard.serializer(), card).utf8()
        return SignedCard(bytes, priv.calculateSignature(CARD_LABEL + bytes), card)
    }

    fun signRoster(priv: ECPrivateKey, roster: Roster): SignedRoster {
        val bytes = GroupJson.encodeToString(Roster.serializer(), roster).utf8()
        return SignedRoster(bytes, priv.calculateSignature(ROSTER_LABEL + bytes), roster)
    }

    fun signFact(priv: ECPrivateKey, fact: Fact): SignedFact {
        val bytes = GroupJson.encodeToString(Fact.serializer(), fact).utf8()
        return SignedFact(bytes, priv.calculateSignature(FACT_LABEL + bytes), fact)
    }

    /** Parses a roster and checks its signature under `by`. Structure is checked separately ([RosterRules.wellFormed]). */
    fun openRoster(bytes: ByteArray, sig: ByteArray): SignedRoster? {
        if (bytes.size > 96 * 1024) {
            return null
        }
        val r = try {
            GroupJson.decodeFromString(Roster.serializer(), bytes.toString(Charsets.UTF_8))
        } catch (e: Exception) {
            return null
        }
        if (r.v != 2 || !verify(r.by, ROSTER_LABEL, bytes, sig)) {
            return null
        }
        return SignedRoster(bytes, sig, r)
    }

    fun openRoster(w: Signed): SignedRoster? = runCatching { openRoster(B64.dec(w.data), B64.dec(w.sig)) }.getOrNull()

    /** Parses a fact and checks its signature under `id` and its form. Whether it applies is [Membership]'s business. */
    fun openFact(bytes: ByteArray, sig: ByteArray): SignedFact? {
        if (bytes.size > 96 * 1024) {
            return null
        }
        val f = try {
            GroupJson.decodeFromString(Fact.serializer(), bytes.toString(Charsets.UTF_8))
        } catch (e: Exception) {
            return null
        }
        if (f.v != 2 || f.since < 1 || (f.kind != FactKind.ACCEPT && f.kind != FactKind.LEAVE) || !verify(f.id, FACT_LABEL, bytes, sig)) {
            return null
        }
        if (f.last < 0 || (f.last != 0L && f.kind != FactKind.LEAVE) || (f.card != null && f.kind != FactKind.ACCEPT)) {
            return null
        }
        return SignedFact(bytes, sig, f)
    }

    fun openFact(w: Signed): SignedFact? = runCatching { openFact(B64.dec(w.data), B64.dec(w.sig)) }.getOrNull()

    /**
     * Parses a card and checks its signature under `id`, the bundle's prekey signatures under the same key, and the field
     * formats. [validServer] applies the app's contact-server rules to the inbox URL.
     */
    fun openCard(bytes: ByteArray, sig: ByteArray, validServer: (String) -> Boolean): SignedCard? {
        if (bytes.size > 16 * 1024) {
            return null
        }
        val c = try {
            GroupJson.decodeFromString(GroupCard.serializer(), bytes.toString(Charsets.UTF_8))
        } catch (e: Exception) {
            return null
        }
        if (c.v != 1 || c.seq < 1 || c.since < 1 || !verify(c.id, CARD_LABEL, bytes, sig)) {
            return null
        }
        val ok = try {
            val key = IdentityKey(identityBytes(c.id)!!).publicKey
            B64.dec(c.hintKey).size == HINT_KEY &&
                B64.dec(c.inbox.sendSecret).size == MailboxCrypto.SECRET_BYTES &&
                isFingerprint(c.inbox.serverKey) &&
                validServer(c.inbox.server) &&
                c.bundle.deviceId == 1 &&
                key.verifySignature(B64.dec(c.bundle.signedPreKey), B64.dec(c.bundle.signedPreKeySig)) &&
                key.verifySignature(B64.dec(c.bundle.kyberPreKey), B64.dec(c.bundle.kyberPreKeySig)) &&
                // Signed garbage would pass the checks above, then fail every member's encryption to this card.
                ECPublicKey(B64.dec(c.bundle.signedPreKey)).let { true } &&
                KEMPublicKey(B64.dec(c.bundle.kyberPreKey)).let { true }
        } catch (e: Exception) {
            false
        }
        return if (ok) SignedCard(bytes, sig, c) else null
    }

    private fun isFingerprint(s: String): Boolean = try {
        s.length == 43 && B64.dec(s).size == 32
    } catch (e: Exception) {
        false
    }

    fun hint(hintKey: ByteArray, nonce: ByteArray, senderId: ByteArray): ByteArray =
        Hash.hmacSha256(hintKey, HINT_LABEL, nonce, senderId).copyOf(HINT_MAC)

    /** One libsignal session per remote identity for all groups. Never collides with `c<id>` (contacts) or `self`. */
    fun address(id: String): SignalProtocolAddress = SignalProtocolAddress("m" + tag(id), 1)

    /** A short, stable, opaque tag for a member (used in wire-id namespaces). */
    fun tag(id: String): String = B64.enc(Hash.sha256(B64.dec(id))).take(22)
}

/**
 * `type ‖ nonce(16) ‖ mac(16) ‖ libsignal ciphertext` (docs/groups.md, "Blob"): a group blob inside its wrapping
 * ([BlobWrap], under the inbox's [BlobWrap.groupKey]). The server only ever sees it wrapped.
 */
class GroupBlob(val type: Int, val nonce: ByteArray, val mac: ByteArray, val body: ByteArray) {
    fun encode(): ByteArray = byteArrayOf((type or 0x10).toByte()) + nonce + mac + body

    companion object {
        const val OVERHEAD = 1 + GroupCrypto.HINT_NONCE + GroupCrypto.HINT_MAC

        fun isGroup(raw: ByteArray): Boolean = raw.isNotEmpty() && (raw[0] == 0x12.toByte() || raw[0] == 0x13.toByte())

        fun decode(raw: ByteArray): GroupBlob? {
            if (raw.size <= OVERHEAD || !isGroup(raw)) {
                return null
            }
            val nonce = raw.copyOfRange(1, 1 + GroupCrypto.HINT_NONCE)
            val mac = raw.copyOfRange(1 + GroupCrypto.HINT_NONCE, OVERHEAD)
            return GroupBlob(raw[0].toInt() and 0x0f, nonce, mac, raw.copyOfRange(OVERHEAD, raw.size))
        }
    }
}

/**
 * The membership everyone acts on (docs/groups.md, "The view"): the roster with the facts held for its stints applied.
 * [members] keeps the roster's order; roles are effective ones: the [owner] (who may sign the next roster) is `owner`, an
 * invitee who accepted is `member`, and anyone whose stint ended is gone.
 */
class View(val roster: Roster, val members: List<RosterMember>, val owner: String?) {
    fun member(id: String): RosterMember? = members.firstOrNull { it.id == id }

    fun role(id: String): String? = member(id)?.role

    fun isOwner(id: String): Boolean = owner == id

    /** In the group and past the invitation stage. */
    fun isActive(id: String): Boolean = role(id).let { it == Role.OWNER || it == Role.MEMBER }

    fun ids(): List<String> = members.map { it.id }

    val name: String get() = roster.name
    val timer: Long get() = roster.timer
}

/** Facts against a roster: pure functions, so every member who holds the same ones computes the same view. */
object Membership {
    /**
     * Whether [f] is about a stint [r] lists (and, for an acceptance, one still invited). A departure that carries a
     * roster newer than [r] waits until [r] has caught up with it: whoever takes over from the leaver must build on it.
     */
    fun applies(r: Roster, f: Fact): Boolean {
        val m = r.member(f.id) ?: return false
        return f.g == r.g && m.since == f.since && (f.kind == FactKind.LEAVE || m.role == Role.INVITED) && f.last <= r.ver
    }

    /** Not about a stint of [r], and not one that may come later either: over, or never was. */
    fun stale(r: Roster, f: Fact): Boolean = !applies(r, f) && f.since <= r.ver && f.last <= r.ver

    /** Members of [r] whose stint a held departure ended. */
    fun gone(r: Roster, facts: Collection<Fact>): Set<String> =
        facts.filter { it.kind == FactKind.LEAVE && applies(r, it) }.map { it.id }.toSet()

    /**
     * Who may sign the roster after [r]: its owner, unless they left; then the first `member`, in roster order, who hasn't.
     * Only departures count, never acceptances, so of two honest members only one can believe it's them.
     */
    fun owner(r: Roster, facts: Collection<Fact>): String? {
        val gone = gone(r, facts)
        r.owner?.takeIf { it !in gone }?.let { return it }
        return r.members.firstOrNull { it.role == Role.MEMBER && it.id !in gone }?.id
    }

    /**
     * The view. With nobody left to own the group (the owner and every member left), it's over: acceptances nobody took
     * in don't count either, so everyone still listed is only invited, whatever they heard.
     */
    fun view(r: Roster, facts: Collection<Fact>): View {
        val gone = gone(r, facts)
        val owner = owner(r, facts)
        val accepted = if (owner == null) emptySet() else facts.filter { it.kind == FactKind.ACCEPT && applies(r, it) }.map { it.id }.toSet()
        val members = r.members.filter { it.id !in gone }.map {
            val role = when {
                it.id == owner -> Role.OWNER
                it.role == Role.OWNER -> Role.MEMBER
                it.role == Role.INVITED && it.id in accepted -> Role.MEMBER
                else -> it.role
            }
            if (role == it.role) it else it.copy(role = role)
        }
        return View(r, members, owner)
    }

    /**
     * The roster [me] signs after [base] if they're its effective owner: departures taken out, acceptances made members,
     * [me] the owner.
     */
    fun fold(base: Roster, facts: Collection<Fact>, me: String): Roster {
        val v = view(base, facts)
        val cards = facts.filter { it.kind == FactKind.ACCEPT && applies(base, it) }.associate { it.id to it.card }
        return base.copy(
            members = v.members.map {
                val role = if (it.role == Role.OWNER && it.id != me) Role.MEMBER else it.role
                // The roster admitting someone carries their card (from their acceptance); no other one does.
                val card = if (base.role(it.id) == Role.INVITED && role != Role.INVITED) cards[it.id] else null
                it.copy(role = role, card = card)
            },
        )
    }

    /** Whether the effective owner [me] has something to fold into a roster: facts it doesn't show, or ownership itself. */
    fun pending(r: Roster, facts: Collection<Fact>, me: String): Boolean =
        owner(r, facts) == me && (r.owner != me || facts.any { applies(r, it) })

    /**
     * The first half of [Head.d]: SHA-256 (first 12 bytes) of the b64u SHA-256 hashes of the facts' bytes that [r]
     * doesn't show yet (the ones that apply to it), sorted, one per line (UTF-8, `\n` between lines).
     */
    fun factDigest(r: Roster, facts: Collection<Pair<Fact, ByteArray>>): ByteArray {
        val lines = facts.filter { applies(r, it.first) }.map { B64.enc(Hash.sha256(it.second)) }.sorted()
        return Hash.sha256(lines.joinToString("\n").utf8()).copyOf(12)
    }

    /**
     * The second half of [Head.d]: SHA-256 (first 12 bytes) of `<id> <seq>` for every active member of [view] (ourselves
     * included), the `seq` of the card held for them (0 for none), sorted by id, one per line.
     */
    fun cardDigest(view: View, cardSeq: (String) -> Long): ByteArray {
        val lines = view.members.filter { view.isActive(it.id) }.map { it.id }.sorted().map { "$it ${cardSeq(it)}" }
        return Hash.sha256(lines.joinToString("\n").utf8()).copyOf(12)
    }

    /**
     * The departures the roster after [base] carries as its proof: every one it folds. They make a successor's signature
     * checkable on its own, and tell members who missed a departure that it was one (not a removal).
     */
    fun departures(base: Roster, facts: Collection<Fact>): List<Fact> =
        facts.filter { it.kind == FactKind.LEAVE && applies(base, it) }.distinctBy { it.id }
}

/** A change only the owner makes. Facts held are folded in first ([Membership.fold]). */
sealed class RosterOp {
    /** The changed roster (members and settings only; the caller stamps version, prev, author and time), or null. */
    abstract fun apply(base: Roster, me: String, ver: Long): Roster?

    data class Add(val ids: List<String>) : RosterOp() {
        override fun apply(base: Roster, me: String, ver: Long): Roster? {
            val fresh = ids.distinct().filter { base.role(it) == null && it != me }
            if (fresh.isEmpty()) {
                return null
            }
            return base.copy(members = base.members + fresh.map { RosterMember(it, Role.INVITED, ver) })
        }
    }

    data class Remove(val ids: List<String>) : RosterOp() {
        override fun apply(base: Roster, me: String, ver: Long): Roster? {
            val drop = ids.toSet() - me
            if (base.members.none { it.id in drop }) {
                return null
            }
            return base.copy(members = base.members.filter { it.id !in drop })
        }
    }

    /** Hands ownership to a member; we stay on as a member. */
    data class MakeOwner(val id: String) : RosterOp() {
        override fun apply(base: Roster, me: String, ver: Long): Roster? {
            if (base.role(id) != Role.MEMBER || base.role(me) != Role.OWNER) {
                return null
            }
            return base.copy(members = base.members.map {
                when (it.id) {
                    id -> it.copy(role = Role.OWNER)
                    me -> it.copy(role = Role.MEMBER)
                    else -> it
                }
            })
        }
    }

    data class Meta(val name: String? = null, val timer: Long? = null) : RosterOp() {
        override fun apply(base: Roster, me: String, ver: Long): Roster? {
            val next = base.copy(name = name ?: base.name, timer = timer ?: base.timer)
            return if (next == base) null else next
        }
    }
}

/** Roster acceptance (docs/groups.md, "Accepting a roster"). Pure functions over parsed, signature-checked rosters. */
object RosterRules {
    const val MAX_MEMBERS = 100

    /** Rule 1 (structure): this group, 1 to 100 members, no duplicates, valid ids and roles, exactly one owner. */
    fun wellFormed(r: Roster, g: String): Boolean {
        if (r.v != 2 || r.g != g || r.ver < 1 || r.members.isEmpty() || r.members.size > MAX_MEMBERS || r.proof.size > MAX_MEMBERS) {
            return false
        }
        if (r.members.map { it.id }.toSet().size != r.members.size) {
            return false
        }
        if (r.members.any { it.role !in Role.ALL || !GroupCrypto.isIdentity(it.id) || it.since !in 1..r.ver }) {
            return false
        }
        if (r.members.count { it.role == Role.OWNER } != 1) {
            return false
        }
        if (Sanitize.name(r.name) == null || r.timer !in 0..Sanitize.MAX_TIMER_SECS) {
            return false
        }
        if (!GroupCrypto.isIdentity(r.by)) {
            return false
        }
        return if (r.ver == 1L) r.prev.isEmpty() && r.owner == r.by && r.proof.isEmpty() else r.prev.isNotEmpty()
    }

    /**
     * Rule 2: [r] can follow [parent]: one version on, signed by the parent's effective owner given the departures in
     * [proof] (and no others: the roster has to carry what it relies on), none of them listed any more, and every stint
     * carried over unchanged (a new one starts at [r]'s version, as an invitation).
     */
    fun validChild(parent: Roster, r: Roster, proof: List<Fact>): Boolean {
        if (r.ver != parent.ver + 1 || r.prev.isEmpty()) {
            return false
        }
        if (proof.size != r.proof.size || proof.any { it.kind != FactKind.LEAVE || !Membership.applies(parent, it) } ||
            proof.map { it.id }.toSet().size != proof.size
        ) {
            return false
        }
        if (Membership.owner(parent, proof) != r.by || proof.any { f -> r.member(f.id)?.since == f.since }) {
            return false
        }
        return r.members.all { m ->
            val p = parent.member(m.id)
            (p != null && p.since == m.since) || (m.role == Role.INVITED && m.since == r.ver)
        }
    }

    /** Stamps a changed roster as the successor of [base]. */
    fun successor(base: SignedRoster, changed: Roster, me: String, nowSecs: Long, proof: List<Signed>): Roster =
        changed.copy(v = 2, ver = base.roster.ver + 1, prev = base.hashB64, by = me, ts = nowSecs, proof = proof)
}
