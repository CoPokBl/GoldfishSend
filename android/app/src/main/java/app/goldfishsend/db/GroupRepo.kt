package app.goldfishsend.db

import app.goldfishsend.group.GroupEngine
import app.goldfishsend.group.GroupModel
import app.goldfishsend.group.GroupStore
import app.goldfishsend.group.HeldBlob
import app.goldfishsend.group.FactLines
import app.goldfishsend.proto.GroupCard
import app.goldfishsend.proto.GroupCrypto
import app.goldfishsend.proto.GroupJson
import app.goldfishsend.proto.Roster
import app.goldfishsend.proto.SignedCard
import app.goldfishsend.proto.SignedRoster

/** A group's chat row and protocol id. */
data class GroupRef(val cid: Long, val gid: String, val state: Int)

/** Per-member delivery state for a group (from `group_cards`). */
data class MemberDelivery(val member: String, val pendingServerKey: String?, val unreachable: Boolean)

/**
 * [GroupStore] over the SQLCipher tables (schema v5). Signatures were checked before anything was stored, and stored
 * bytes are trusted on load (the database is encrypted and authenticated).
 */
class RepoGroupStore(private val repo: Repo) : GroupStore {
    private val db get() = repo.db

    override fun load(gid: String): GroupModel? {
        val row = db.queryOne(
            "SELECT cid, state, roster, roster_sig, my_card, my_card_sig, invited_by, facts, since FROM groups WHERE gid = ?", gid,
        ) { c ->
            arrayOf<Any?>(
                c.getLong(0), c.getInt(1),
                if (c.isNull(2)) null else c.getBlob(2), if (c.isNull(3)) null else c.getBlob(3),
                if (c.isNull(4)) null else c.getBlob(4), if (c.isNull(5)) null else c.getBlob(5),
                if (c.isNull(6)) null else c.getString(6), if (c.isNull(7)) null else c.getString(7),
                c.getLong(8),
            )
        } ?: return null
        val cid = row[0] as Long
        val roster = (row[2] as ByteArray?)?.let { bytes -> trustedRoster(bytes, row[3] as ByteArray) }
        val myCard = (row[4] as ByteArray?)?.let { bytes -> trustedCard(bytes, row[5] as ByteArray) }
        val cards = mutableMapOf<String, SignedCard>()
        db.query("SELECT member, card, sig FROM group_cards WHERE cid = ? AND gone = 0", cid) { c ->
            Triple(c.getString(0), c.getBlob(1), c.getBlob(2))
        }.forEach { (member, card, sig) -> trustedCard(card, sig)?.let { cards[member] = it } }
        return GroupModel(
            gid = gid,
            state = row[1] as Int,
            roster = roster,
            cards = cards,
            myCard = myCard,
            invitedBy = row[6] as String?,
            facts = FactLines.decode(row[7] as String?),
            since = row[8] as Long,
        )
    }

    override fun save(m: GroupModel) {
        db.tx {
            var cid = cidOf(m.gid)
            if (cid == null) {
                val r = m.roster?.roster
                cid = repo.createGroupContact(r?.name ?: "Group", r?.timer ?: 0)
                db.exec("INSERT INTO groups (cid, gid, state, created_at) VALUES (?, ?, ?, ?)", cid, m.gid, m.state, System.currentTimeMillis())
            }
            db.exec(
                "UPDATE groups SET state = ?, roster = ?, roster_sig = ?, my_card = ?, my_card_sig = ?, invited_by = ?, facts = ?, since = ? " +
                    "WHERE cid = ?",
                m.state, m.roster?.bytes, m.roster?.sig, m.myCard?.bytes, m.myCard?.sig, m.invitedBy, FactLines.encode(m.facts), m.since, cid,
            )
            val stored = db.query("SELECT member, seq, gone FROM group_cards WHERE cid = ?", cid) {
                it.getString(0) to (it.getLong(1) to (it.getInt(2) != 0))
            }.toMap()
            // Departed members' cards stay (marked gone) until what's queued to them is delivered; see pruneGoneCards.
            for (member in stored.keys - m.cards.keys) {
                if (stored[member]?.second == false) {
                    db.exec("UPDATE group_cards SET gone = 1 WHERE cid = ? AND member = ?", cid, member)
                }
            }
            for ((member, card) in m.cards) {
                val prev = stored[member]
                if (prev == null) {
                    db.exec(
                        "INSERT INTO group_cards (cid, member, card, sig, seq) VALUES (?, ?, ?, ?, ?)",
                        cid, member, card.bytes, card.sig, card.card.seq,
                    )
                } else if (prev.first != card.card.seq || prev.second) {
                    // A new card (new inbox or keys), or a member back again: delivery state starts fresh.
                    db.exec(
                        "UPDATE group_cards SET card = ?, sig = ?, seq = ?, pending_server_key = NULL, unreachable = 0, gone = 0 " +
                            "WHERE cid = ? AND member = ?",
                        card.bytes, card.sig, card.card.seq, cid, member,
                    )
                }
            }
        }
    }

    override fun addHistory(gid: String, r: SignedRoster) {
        val cid = cidOf(gid) ?: return
        val held = db.query("SELECT roster, sig FROM group_rosters WHERE cid = ? AND ver = ?", cid, r.roster.ver) { c ->
            trustedRoster(c.getBlob(0), c.getBlob(1))?.roster
        }.filterNotNull()
        if (!GroupEngine.fits(held, r.roster)) {
            return
        }
        db.exec(
            "INSERT OR IGNORE INTO group_rosters (cid, ver, hash, roster, sig) VALUES (?, ?, ?, ?, ?)",
            cid, r.roster.ver, r.hashB64, r.bytes, r.sig,
        )
        // Bounded: enough to answer `gsync`.
        db.exec(
            "DELETE FROM group_rosters WHERE cid = ? AND ver < (SELECT MAX(ver) FROM group_rosters WHERE cid = ?) - 200",
            cid, cid,
        )
    }

    override fun history(gid: String, hashB64: String): SignedRoster? {
        val cid = cidOf(gid) ?: return null
        return db.queryOne("SELECT roster, sig FROM group_rosters WHERE cid = ? AND hash = ?", cid, hashB64) { c ->
            trustedRoster(c.getBlob(0), c.getBlob(1))
        }
    }

    override fun historySince(gid: String, since: Long): List<SignedRoster> {
        val cid = cidOf(gid) ?: return emptyList()
        return db.query("SELECT roster, sig FROM group_rosters WHERE cid = ? AND ver > ? ORDER BY ver, hash", cid, since) { c ->
            trustedRoster(c.getBlob(0), c.getBlob(1))
        }.filterNotNull()
    }

    override fun storeChunk(gid: String, key: String, part: Int, parts: Int, data: String): String? {
        val cid = cidOf(gid) ?: return null
        repo.storeChunk(cid, key, part, parts, data)
        return repo.assembleChunks(cid, key, parts)
    }

    override fun hold(gid: String, hintKey: ByteArray, blob: ByteArray) {
        val cid = cidOf(gid) ?: return
        if (db.long("SELECT COUNT(*) FROM group_held WHERE cid = ?", cid) >= 200) {
            return
        }
        db.insert("INSERT INTO group_held (cid, hint_key, blob, received_at) VALUES (?, ?, ?, ?)", cid, hintKey, blob, System.currentTimeMillis())
    }

    override fun held(gid: String): List<HeldBlob> {
        val cid = cidOf(gid) ?: return emptyList()
        return db.query("SELECT id, hint_key, blob FROM group_held WHERE cid = ? ORDER BY id", cid) { HeldBlob(it.getLong(0), it.getBlob(1), it.getBlob(2)) }
    }

    override fun dropHeld(id: Long) = db.exec("DELETE FROM group_held WHERE id = ?", id)

    /** Lines of `gid by ver`, newest last, in one kv entry (no table: it's a handful). */
    private fun withdrawals(): List<List<String>> =
        repo.kvString(WITHDRAWN)?.lines()?.map { it.split(' ') }?.filter { it.size == 3 }.orEmpty()

    override fun withdrawn(gid: String, by: String): Long? =
        withdrawals().filter { it[0] == gid && it[1] == by }.mapNotNull { it[2].toLongOrNull() }.maxOrNull()

    override fun addWithdrawn(gid: String, by: String, ver: Long) {
        val v = maxOf(ver, withdrawn(gid, by) ?: ver)
        val kept = (withdrawals().filter { !(it[0] == gid && it[1] == by) } + listOf(listOf(gid, by, v.toString()))).takeLast(32)
        repo.kvPutString(WITHDRAWN, kept.joinToString("\n") { it.joinToString(" ") })
    }

    fun cidOf(gid: String): Long? = db.queryOne("SELECT cid FROM groups WHERE gid = ?", gid) { it.getLong(0) }

    private companion object {
        const val WITHDRAWN = "group_withdrawn"
    }

    private fun trustedRoster(bytes: ByteArray, sig: ByteArray): SignedRoster? =
        runCatching { SignedRoster(bytes, sig, GroupJson.decodeFromString(Roster.serializer(), bytes.toString(Charsets.UTF_8))) }.getOrNull()

    private fun trustedCard(bytes: ByteArray, sig: ByteArray): SignedCard? =
        runCatching { SignedCard(bytes, sig, GroupJson.decodeFromString(GroupCard.serializer(), bytes.toString(Charsets.UTF_8))) }.getOrNull()
}

// --- group queries on Repo ---

/** Where to deliver to a member: their card (including departed members' still-queued ones) and delivery state. */
class MemberRoute(val card: GroupCard, val pendingServerKey: String?, val unreachable: Boolean, val gone: Boolean)

fun Repo.memberRoutes(cid: Long): Map<String, MemberRoute> =
    db.query("SELECT member, card, pending_server_key, unreachable, gone FROM group_cards WHERE cid = ?", cid) { c ->
        val card = runCatching { GroupJson.decodeFromString(GroupCard.serializer(), c.getBlob(1).toString(Charsets.UTF_8)) }.getOrNull()
        card?.let { c.getString(0) to MemberRoute(it, if (c.isNull(2)) null else c.getString(2), c.getInt(3) != 0, c.getInt(4) != 0) }
    }.filterNotNull().toMap()

/** Departed members' cards with nothing left queued to them. Returns the members whose cards went. */
fun Repo.pruneGoneCards(): List<String> {
    val gone = db.query(
        "SELECT cid, member FROM group_cards g WHERE gone = 1 AND NOT EXISTS (SELECT 1 FROM outbox o WHERE o.contact_id = g.cid AND o.member_key = g.member)",
    ) { it.getLong(0) to it.getString(1) }
    for ((cid, member) in gone) {
        db.exec("DELETE FROM group_cards WHERE cid = ? AND member = ?", cid, member)
    }
    return gone.map { it.second }
}

fun Repo.groupRef(cid: Long): GroupRef? =
    db.queryOne("SELECT cid, gid, state FROM groups WHERE cid = ?", cid) { GroupRef(it.getLong(0), it.getString(1), it.getInt(2)) }

fun Repo.groupRefs(): List<GroupRef> = db.query("SELECT cid, gid, state FROM groups") { GroupRef(it.getLong(0), it.getString(1), it.getInt(2)) }

fun Repo.isGroup(cid: Long): Boolean = db.long("SELECT COUNT(*) FROM groups WHERE cid = ?", cid) > 0

fun Repo.setRotateNeeded(cid: Long, v: Boolean) = db.exec("UPDATE groups SET rotate_needed = ? WHERE cid = ?", v, cid)

fun Repo.groupsNeedingRotation(): List<Long> = db.query("SELECT cid FROM groups WHERE rotate_needed = 1") { it.getLong(0) }

fun Repo.memberDelivery(cid: Long): Map<String, MemberDelivery> =
    db.query("SELECT member, pending_server_key, unreachable FROM group_cards WHERE cid = ?", cid) {
        MemberDelivery(it.getString(0), if (it.isNull(1)) null else it.getString(1), it.getInt(2) != 0)
    }.associateBy { it.member }

fun Repo.setMemberPendingServerKey(cid: Long, member: String, key: String?) =
    db.exec("UPDATE group_cards SET pending_server_key = ? WHERE cid = ? AND member = ?", key, cid, member)

fun Repo.setMemberUnreachable(cid: Long, member: String, v: Boolean) =
    db.exec("UPDATE group_cards SET unreachable = ? WHERE cid = ? AND member = ?", v, cid, member)

/** The user trusted the new identity of a member's server (re-authenticated). */
fun Repo.trustMemberServerKey(cid: Long, member: String) =
    db.exec("UPDATE group_cards SET pending_server_key = NULL WHERE cid = ? AND member = ?", cid, member)

fun Repo.pruneGroupHeld(olderThan: Long) = db.exec("DELETE FROM group_held WHERE received_at < ?", olderThan)

/** Records a member's read receipt. Returns how many members have read [messageId]. */
fun Repo.addGroupRead(messageId: String, member: String): Long {
    db.exec("INSERT OR IGNORE INTO group_receipts (message_id, member) VALUES (?, ?)", messageId, member)
    return db.long("SELECT COUNT(*) FROM group_receipts WHERE message_id = ?", messageId)
}

fun Repo.groupReaders(messageId: String): List<String> =
    db.query("SELECT member FROM group_receipts WHERE message_id = ?", messageId) { it.getString(0) }

fun Repo.messageIdByWire(contactId: Long, wireId: String, outgoing: Boolean): String? =
    db.queryOne("SELECT id FROM messages WHERE contact_id = ? AND wire_id = ? AND outgoing = ?", contactId, wireId, outgoing) { it.getString(0) }

/** Every group (cid) a member is in, so their shared session is only dropped when the last group goes. */
fun Repo.groupsWithMember(member: String): Long =
    db.long("SELECT COUNT(*) FROM group_cards WHERE member = ?", member)

/** Incoming group message wire ids are namespaced by sender, so two members can't collide (or delete each other's). */
fun groupWire(sender: String, wireId: String): String = GroupCrypto.tag(sender) + ":" + wireId.take(64)
