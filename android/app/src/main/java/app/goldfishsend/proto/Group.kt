package app.goldfishsend.proto

import kotlinx.serialization.SerialName
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
)

@Serializable
data class RosterMember(val id: String, val role: String)

@Serializable
data class Roster(
    val v: Int = 1,
    val g: String,
    val ver: Long,
    val prev: String = "",
    val name: String,
    val timer: Long = 0,
    val adminsOnly: Boolean = true,
    val members: List<RosterMember>,
    val by: String,
    val ts: Long,
) {
    fun role(id: String): String? = members.firstOrNull { it.id == id }?.role

    fun isAdmin(id: String): Boolean = role(id) == Role.ADMIN

    /** In the roster and past the invitation stage. */
    fun isActive(id: String): Boolean = role(id).let { it == Role.ADMIN || it == Role.MEMBER }

    fun ids(): List<String> = members.map { it.id }
}

object Role {
    const val ADMIN = "admin"
    const val MEMBER = "member"
    const val INVITED = "invited"

    val ALL = setOf(ADMIN, MEMBER, INVITED)
}

/** Exact bytes as signed, plus the parsed value. Nothing is ever re-serialised for verification. */
class SignedRoster(val bytes: ByteArray, val sig: ByteArray, val roster: Roster) {
    val hash: ByteArray = Hash.sha256(bytes)
    val hashB64: String = B64.enc(hash)
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
    private val ROSTER_LABEL = "gf/group-roster/v1".utf8()
    private val HINT_LABEL = "gf/group-hint/v1".utf8()
    const val HINT_NONCE = 16
    const val HINT_MAC = 16
    const val HINT_KEY = 32

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

    /** Parses a roster and checks its signature under `by`. Structure is checked separately ([RosterRules.wellFormed]). */
    fun openRoster(bytes: ByteArray, sig: ByteArray): SignedRoster? {
        if (bytes.size > 64 * 1024) {
            return null
        }
        val r = try {
            GroupJson.decodeFromString(Roster.serializer(), bytes.toString(Charsets.UTF_8))
        } catch (e: Exception) {
            return null
        }
        if (r.v != 1 || !verify(r.by, ROSTER_LABEL, bytes, sig)) {
            return null
        }
        return SignedRoster(bytes, sig, r)
    }

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
        if (c.v != 1 || c.seq < 1 || !verify(c.id, CARD_LABEL, bytes, sig)) {
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

/** `type ‖ nonce(16) ‖ mac(16) ‖ libsignal ciphertext` (docs/groups.md, "Blob"). */
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

/** A membership or settings change, re-applied on top of a concurrent winner if ours lost (docs/groups.md, rule 3). */
@Serializable
sealed class RosterOp {
    /** The changed roster (members and settings only; the caller stamps version, prev, author and time), or null if not applicable. */
    abstract fun apply(base: Roster, me: String): Roster?

    @Serializable
    @SerialName("add")
    data class Add(val ids: List<String>) : RosterOp() {
        override fun apply(base: Roster, me: String): Roster? {
            val fresh = ids.distinct().filter { base.role(it) == null && it != me }
            if (fresh.isEmpty()) {
                return null
            }
            return base.copy(members = base.members + fresh.map { RosterMember(it, Role.INVITED) })
        }
    }

    @Serializable
    @SerialName("remove")
    data class Remove(val ids: List<String>) : RosterOp() {
        override fun apply(base: Roster, me: String): Roster? {
            val drop = ids.toSet() - me
            if (base.members.none { it.id in drop }) {
                return null
            }
            return base.copy(members = base.members.filter { it.id !in drop })
        }
    }

    @Serializable
    @SerialName("role")
    data class SetRole(val id: String, val role: String) : RosterOp() {
        override fun apply(base: Roster, me: String): Roster? {
            val cur = base.role(id) ?: return null
            if (cur == Role.INVITED || cur == role || role == Role.INVITED || role !in Role.ALL) {
                return null
            }
            return base.copy(members = base.members.map { if (it.id == id) it.copy(role = role) else it })
        }
    }

    @Serializable
    @SerialName("meta")
    data class Meta(val name: String? = null, val timer: Long? = null, val adminsOnly: Boolean? = null) : RosterOp() {
        override fun apply(base: Roster, me: String): Roster? {
            val next = base.copy(name = name ?: base.name, timer = timer ?: base.timer, adminsOnly = adminsOnly ?: base.adminsOnly)
            return if (next == base) null else next
        }
    }

    @Serializable
    @SerialName("leave")
    data object Leave : RosterOp() {
        override fun apply(base: Roster, me: String): Roster? =
            if (base.role(me) == null) null else base.copy(members = base.members.filter { it.id != me })
    }

    /**
     * An admin records an invitee's acceptance that lost a version tie (the invitee signed it, but a concurrent roster won).
     * Only used when we hold that signed acceptance; see GroupEngine.enforceAcceptance.
     */
    @Serializable
    @SerialName("admit")
    data class Admit(val id: String) : RosterOp() {
        override fun apply(base: Roster, me: String): Roster? =
            if (base.role(id) != Role.INVITED) null else base.copy(members = base.members.map { if (it.id == id) it.copy(role = Role.MEMBER) else it })
    }

    @Serializable
    @SerialName("accept")
    data object Accept : RosterOp() {
        override fun apply(base: Roster, me: String): Roster? =
            if (base.role(me) != Role.INVITED) null else base.copy(members = base.members.map { if (it.id == me) it.copy(role = Role.MEMBER) else it })
    }

    fun encode(): String = OpJson.encodeToString(serializer(), this)

    companion object {
        private val OpJson = Json {
            classDiscriminator = "op"
            ignoreUnknownKeys = true
        }

        fun decode(s: String): RosterOp? = runCatching { OpJson.decodeFromString(serializer(), s) }.getOrNull()
    }
}

/** Roster acceptance (docs/groups.md, "Accepting a roster"). Pure functions over parsed, signature-checked rosters. */
object RosterRules {
    const val MAX_MEMBERS = 100

    /** Rule 1 (structure): this group, at most 100 members, no duplicates, valid ids and roles, at least one admin. */
    fun wellFormed(r: Roster, g: String): Boolean {
        if (r.v != 1 || r.g != g || r.ver < 1 || r.members.isEmpty() || r.members.size > MAX_MEMBERS) {
            return false
        }
        if (r.members.map { it.id }.toSet().size != r.members.size) {
            return false
        }
        if (r.members.any { it.role !in Role.ALL || !GroupCrypto.isIdentity(it.id) }) {
            return false
        }
        if (r.members.none { it.role == Role.ADMIN }) {
            return false
        }
        if (Sanitize.name(r.name) == null || r.timer !in 0..Sanitize.MAX_TIMER_SECS) {
            return false
        }
        return GroupCrypto.isIdentity(r.by) && (r.ver == 1L || r.prev.isNotEmpty())
    }

    /**
     * Rule 2 (authority) of [r] over the roster it changes, [base]. An admin may change anything. Anyone may remove
     * themselves (leave or decline), and an invited member may accept. If `adminsOnly` is off, an active member may also
     * change the name and timer, and nothing else.
     */
    fun authorized(base: Roster, r: Roster): Boolean {
        val by = r.by
        if (base.isAdmin(by)) {
            return true
        }
        val baseRole = base.role(by) ?: return false
        val newRole = r.role(by)
        val others = base.members.filter { it.id != by }.toSet() == r.members.filter { it.id != by }.toSet()
        val metaSame = r.name == base.name && r.timer == base.timer && r.adminsOnly == base.adminsOnly
        if (!others) {
            return false
        }
        if (metaSame) {
            return newRole == null || (baseRole == Role.INVITED && newRole == Role.MEMBER)
        }
        return !base.adminsOnly && r.adminsOnly == base.adminsOnly && newRole == baseRole && baseRole != Role.INVITED
    }

    sealed class Decision {
        /** Accept. [needSync]: versions were skipped, so ask an admin for the history. */
        data class Accept(val needSync: Boolean) : Decision()

        /** Same version, and the incoming one has the larger hash: it replaces ours. */
        data object Replace : Decision()

        /** Same version, ours has the larger hash: keep it. */
        data object Keep : Decision()

        data class Ignore(val reason: String) : Decision()
    }

    /** Rule 3 (order). [parent] looks up an earlier roster we have, by its b64u hash. */
    fun decide(current: SignedRoster, incoming: SignedRoster, parent: (String) -> Roster?): Decision {
        val c = current.roster
        val r = incoming.roster
        if (incoming.hashB64 == current.hashB64) {
            return Decision.Ignore("same")
        }
        return when {
            r.ver == c.ver + 1 && r.prev == current.hashB64 ->
                if (authorized(c, r)) Decision.Accept(false) else Decision.Ignore("unauthorized")
            r.ver == c.ver -> {
                val base = parent(r.prev)
                val ok = if (base != null) authorized(base, r) else c.isAdmin(r.by)
                // A removal beats a concurrent change by the person removed (typically their acceptance of the invitation
                // being withdrawn): otherwise they could stay in by winning the tie.
                val inKicks = r.role(c.by) == null && c.role(c.by) != null && r.by != c.by
                val curKicks = c.role(r.by) == null && r.role(r.by) != null && c.by != r.by
                val wins = if (inKicks != curKicks) inKicks else compareUnsigned(incoming.hash, current.hash) > 0
                when {
                    !ok -> Decision.Ignore("unauthorized")
                    wins -> Decision.Replace
                    else -> Decision.Keep
                }
            }
            // Skipped versions, or a successor of a concurrent sibling we never saw: only an admin of ours is trusted.
            r.ver > c.ver -> if (c.isAdmin(r.by)) Decision.Accept(true) else Decision.Ignore("unauthorized")
            else -> Decision.Ignore("old")
        }
    }

    fun compareUnsigned(a: ByteArray, b: ByteArray): Int {
        for (i in 0 until minOf(a.size, b.size)) {
            val d = (a[i].toInt() and 0xff) - (b[i].toInt() and 0xff)
            if (d != 0) {
                return d
            }
        }
        return a.size - b.size
    }

    /** Stamps a changed roster as the successor of [base]. */
    fun successor(base: SignedRoster, changed: Roster, me: String, nowSecs: Long): Roster =
        changed.copy(v = 1, ver = base.roster.ver + 1, prev = base.hashB64, by = me, ts = nowSecs)
}
