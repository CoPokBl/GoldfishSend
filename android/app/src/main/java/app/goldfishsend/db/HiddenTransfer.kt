package app.goldfishsend.db

import app.goldfishsend.group.GroupModel
import app.goldfishsend.proto.GroupCard
import app.goldfishsend.proto.GroupCrypto
import app.goldfishsend.proto.GroupJson
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream

/** One table row as stored: column to null, Long, Double, String or ByteArray. */
typealias Row = Map<String, Any?>

sealed interface Where {
    data object All : Where

    /** [col] is one of [values] (byte arrays compare by content). */
    data class In(val col: String, val values: Collection<Any>) : Where

    /** [col] (text) starts with [prefix]. */
    data class Prefix(val col: String, val prefix: String) : Where
}

/** The little of the database [HiddenTransfer] needs, so the same rules run over SQLCipher and in tests. */
interface Tables {
    fun select(table: String, where: Where): List<Row>

    fun delete(table: String, where: Where)

    /** Inserts [row] and returns its rowid. With [orIgnore], a row that clashes with an existing key is skipped (null). */
    fun insert(table: String, row: Row, orIgnore: Boolean = false): Long?
}

/**
 * Moves what's sealed under one message root to another (the open profile's and the hidden chats' own): message keys
 * wrapped by the root (the ones not in an expiry bucket) and blobs sealed under it (chunks, queued content).
 */
interface Rewrap {
    /** A key wrapped for [id] ("<message id>", "held/<id>", "gheld/<ref>") under the source root, wrapped under the target's. */
    fun key(id: String, wrapped: ByteArray): ByteArray?

    /** A blob sealed as [label] under the source root, sealed as [newLabel] under the target's. */
    fun blob(label: String, newLabel: String, blob: ByteArray): ByteArray?

    /** A key wrapped under the expiry bucket [bucket] still opens (the bucket hasn't ended, and messages weren't erased). */
    fun bucketOpens(id: String, wrapped: ByteArray, bucket: Long): Boolean
}

/** Hidden chats, taken out of the database: every row that belongs to them, by table, and [meta] about when. */
class Snapshot(val tables: Map<String, List<Row>>, val meta: Map<String, String> = emptyMap()) {
    fun rows(table: String): List<Row> = tables[table].orEmpty()

    fun encode(): ByteArray {
        val bytes = ByteArrayOutputStream()
        val out = DataOutputStream(bytes)
        out.write(MAGIC)
        out.writeShort(meta.size)
        for ((k, v) in meta) {
            out.writeUTF(k)
            out.writeUTF(v)
        }
        out.writeShort(tables.size)
        for ((name, rows) in tables) {
            out.writeUTF(name)
            out.writeInt(rows.size)
            for (row in rows) {
                out.writeShort(row.size)
                for ((col, v) in row) {
                    out.writeUTF(col)
                    when (v) {
                        null -> out.writeByte(0)
                        is Long -> out.writeByte(1).also { out.writeLong(v) }
                        is Int -> out.writeByte(1).also { out.writeLong(v.toLong()) }
                        is Double -> out.writeByte(2).also { out.writeDouble(v) }
                        is String -> {
                            // writeUTF is limited to 64 KiB.
                            val b = v.toByteArray(Charsets.UTF_8)
                            out.writeByte(3)
                            out.writeInt(b.size)
                            out.write(b)
                        }
                        is ByteArray -> out.writeByte(4).also { out.writeInt(v.size) }.also { out.write(v) }
                        else -> error("unsupported value ${v::class}")
                    }
                }
            }
        }
        out.flush()
        return bytes.toByteArray()
    }

    companion object {
        private val MAGIC = "GFHS1".toByteArray()

        /** Null for anything that isn't an encoded snapshot. */
        fun decode(data: ByteArray): Snapshot? = try {
            val inp = DataInputStream(ByteArrayInputStream(data))
            val magic = ByteArray(MAGIC.size).also { inp.readFully(it) }
            if (!magic.contentEquals(MAGIC)) {
                null
            } else {
                val meta = (0 until inp.readUnsignedShort()).associate { inp.readUTF() to inp.readUTF() }
                val tables = LinkedHashMap<String, List<Row>>()
                repeat(inp.readUnsignedShort()) {
                    val name = inp.readUTF()
                    val n = inp.readInt()
                    require(n in 0..10_000_000)
                    tables[name] = List(n) {
                        val row = LinkedHashMap<String, Any?>()
                        repeat(inp.readUnsignedShort()) {
                            val col = inp.readUTF()
                            row[col] = when (inp.readUnsignedByte()) {
                                0 -> null
                                1 -> inp.readLong()
                                2 -> inp.readDouble()
                                3 -> String(ByteArray(len(inp)).also { inp.readFully(it) }, Charsets.UTF_8)
                                4 -> ByteArray(len(inp)).also { inp.readFully(it) }
                                else -> error("bad type")
                            }
                        }
                        row
                    }
                }
                Snapshot(tables, meta)
            }
        } catch (e: Exception) {
            null
        }

        private const val MAX_VALUE = 64 * 1024 * 1024

        private fun len(inp: DataInputStream): Int = inp.readInt().also { require(it in 0..MAX_VALUE) }
    }
}

/**
 * Takes hidden chats out of the database ([export]) and puts them back ([import]), for core/HiddenChats. A chat is
 * every row that belongs to it: its contact row, messages and their keys, chunks, queued sends, held messages, the
 * wire ids it remembers, its mailboxes, its Signal session and identity, for a group its rosters, cards, held messages
 * and the sessions of members no shown chat shares, its prekeys (invite and group card), the names it remembers, and the
 * TLS pins of servers only hidden chats use. What's sealed under the message root moves to the hidden chats' own root
 * ([Rewrap]); what's in an expiry bucket stays there, so it still disappears on time while hidden.
 */
object HiddenTransfer {
    private const val PIN = "tls_pin:"
    private const val BLOCKED = "tls_blocked:"

    /** Everything [export] reads and deletes, in an order that respects the foreign keys when deleting. */
    private class Selection(
        val cids: Set<Long>,
        val messageIds: List<String>,
        val addresses: List<String>,
        val signedPrekeys: List<Long>,
        val kyberPrekeys: List<Long>,
        val kvKeys: List<String>,
        val mailboxIds: Set<Long>,
    )

    private fun long(v: Any?): Long? = (v as? Number)?.toLong()

    private fun card(bytes: Any?): GroupCard? =
        (bytes as? ByteArray)?.let { runCatching { GroupJson.decodeFromString(GroupCard.serializer(), it.toString(Charsets.UTF_8)) }.getOrNull() }

    fun address(cid: Long) = "c$cid.1"

    private fun memberAddress(member: String) = GroupCrypto.address(member).let { "${it.name}.${it.deviceId}" }

    private fun select(t: Tables, cids: Set<Long>, hostKey: (String) -> String?): Selection {
        val ids = cids.toList()
        val messageIds = t.select("messages", Where.In("contact_id", ids)).map { it["id"] as String }
        // Members' sessions are shared by every group they're in: only those no shown group has go.
        val cards = t.select("group_cards", Where.All)
        val (hiddenCards, shownCards) = cards.partition { long(it["cid"]) in cids }
        val members = hiddenCards.map { it["member"] as String }.toSet() - shownCards.map { it["member"] as String }.toSet()
        val addresses = ids.map(::address) + members.map(::memberAddress)
        val mailboxes = t.select("mailboxes", Where.In("contact_id", ids))
        val bundles = t.select("groups", Where.In("cid", ids)).mapNotNull { card(it["my_card"])?.bundle }
        val signed = mailboxes.mapNotNull { long(it["invite_spk_id"]) } + bundles.map { it.signedPreKeyId.toLong() }
        val kyber = mailboxes.mapNotNull { long(it["invite_kyber_id"]) } + bundles.map { it.kyberPreKeyId.toLong() }
        val names = ids.flatMap { cid ->
            t.select("kv", Where.Prefix("k", "gname/$cid/")) + t.select("kv", Where.Prefix("k", "gjoin/$cid/"))
        }.map { it["k"] as String }
        // TLS pins of servers that only hidden chats use: a pin names a server, and so who's on it.
        val contacts = t.select("contacts", Where.All)
        fun servers(rows: List<Row>, cardRows: List<Row>) =
            (rows.mapNotNull { it["out_server"] as? String } + cardRows.mapNotNull { card(it["card"])?.inbox?.server }).mapNotNull(hostKey).toSet()
        val hiddenHosts = servers(contacts.filter { long(it["id"]) in cids }, hiddenCards) -
            servers(contacts.filter { long(it["id"]) !in cids }, shownCards)
        val pins = hiddenHosts.flatMap { listOf(PIN + it, BLOCKED + it) }
        val pinKeys = if (pins.isEmpty()) emptyList() else t.select("kv", Where.In("k", pins)).map { it["k"] as String }
        return Selection(
            cids, messageIds, addresses, signed, kyber, names + pinKeys,
            mailboxes.mapNotNull { long(it["id"]) }.toSet(),
        )
    }

    /** Reads every row of the chats [cids], with what's sealed under the message root moved to the hidden root. */
    private fun collect(t: Tables, s: Selection, rewrap: Rewrap): Map<String, List<Row>> {
        val ids = s.cids.toList()
        val out = LinkedHashMap<String, List<Row>>()
        out["contacts"] = t.select("contacts", Where.In("id", ids))
        out["groups"] = t.select("groups", Where.In("cid", ids))
        out["mailboxes"] = t.select("mailboxes", Where.In("contact_id", ids))
        out["messages"] = t.select("messages", Where.In("contact_id", ids))
        out["message_keys"] = t.select("message_keys", Where.In("message_id", s.messageIds)).mapNotNull { r ->
            moveKey(r, r["message_id"] as String, rewrap)
        }
        out["group_receipts"] = t.select("group_receipts", Where.In("message_id", s.messageIds))
        out["chunks"] = t.select("chunks", Where.In("contact_id", ids)).mapNotNull { r ->
            val label = chunkLabel(long(r["contact_id"])!!, r)
            rewrap.blob(label, label, r["body"] as ByteArray)?.let { r + ("body" to it) }
        }
        out["outbox"] = t.select("outbox", Where.In("contact_id", ids)).sortedBy { long(it["seq"]) }.mapNotNull { r ->
            val c = r["content"] as ByteArray? ?: return@mapNotNull r
            rewrap.blob("outbox", "outbox", c)?.let { r + ("content" to it) }
        }
        out["held_incoming"] = t.select("held_incoming", Where.In("contact_id", ids)).mapNotNull { r ->
            moveKey(r, "held/" + r["id"], rewrap)
        }
        out["gone_incoming"] = t.select("gone_incoming", Where.In("contact_id", ids))
        out["group_cards"] = t.select("group_cards", Where.In("cid", ids))
        out["group_rosters"] = t.select("group_rosters", Where.In("cid", ids))
        out["group_held"] = t.select("group_held", Where.In("cid", ids)).sortedBy { long(it["id"]) }.mapNotNull { r ->
            moveKey(r, "gheld/" + r["ref"], rewrap)
        }
        out["sig_session"] = t.select("sig_session", Where.In("address", s.addresses))
        out["sig_identity"] = t.select("sig_identity", Where.In("address", s.addresses))
        out["sig_signed_prekey"] = t.select("sig_signed_prekey", Where.In("id", s.signedPrekeys))
        out["sig_kyber_prekey"] = t.select("sig_kyber_prekey", Where.In("id", s.kyberPrekeys))
        out["kv"] = t.select("kv", Where.In("k", s.kvKeys))
        return out
    }

    /** A row whose key is wrapped by the root ([bucket] null) gets it re-wrapped; one that won't open is left out. */
    private fun moveKey(r: Row, id: String, rewrap: Rewrap): Row? {
        if (r["bucket"] != null) {
            return r
        }
        return rewrap.key(id, r["key"] as ByteArray)?.let { r + ("key" to it) }
    }

    private fun chunkLabel(cid: Long, r: Row) = "chunk/$cid/${r["wire_id"]}/${long(r["part"])}"

    /** Deletes every row of the chats [s] selected. */
    private fun remove(t: Tables, s: Selection) {
        val ids = s.cids.toList()
        t.delete("message_keys", Where.In("message_id", s.messageIds))
        t.delete("group_receipts", Where.In("message_id", s.messageIds))
        for (table in listOf("messages", "chunks", "outbox", "held_incoming", "gone_incoming")) {
            t.delete(table, Where.In("contact_id", ids))
        }
        for (table in listOf("group_held", "group_rosters", "group_cards", "groups")) {
            t.delete(table, Where.In("cid", ids))
        }
        // Explicitly: deleting the contact would only unbind them (ON DELETE SET NULL), leaving them looking like spares.
        t.delete("mailboxes", Where.In("contact_id", ids))
        t.delete("sig_session", Where.In("address", s.addresses))
        t.delete("sig_identity", Where.In("address", s.addresses))
        t.delete("sig_signed_prekey", Where.In("id", s.signedPrekeys))
        t.delete("sig_kyber_prekey", Where.In("id", s.kyberPrekeys))
        t.delete("kv", Where.In("k", s.kvKeys))
        t.delete("contacts", Where.In("id", ids))
        // A rotation still waiting for its verification push lists mailbox ids: the hidden ones mustn't be left behind.
        if (s.mailboxIds.isNotEmpty()) {
            for (r in t.select("rotations", Where.All)) {
                val listed = (r["mailbox_ids"] as String).split(',').filter { it.isNotEmpty() }
                val kept = listed.filter { it.toLongOrNull() !in s.mailboxIds }
                if (kept.size != listed.size) {
                    t.delete("rotations", Where.In("tag", listOf(r["tag"] as ByteArray)))
                    if (kept.isNotEmpty()) {
                        t.insert("rotations", r + ("mailbox_ids" to kept.joinToString(",")))
                    }
                }
            }
        }
    }

    /**
     * Takes the chats [cids] out of the database: returns everything that belongs to them, and deletes it. Run it in one
     * transaction with storing the result. [hostKey] turns a server URL into the host key TLS pins are kept under.
     */
    fun export(t: Tables, cids: Set<Long>, rewrap: Rewrap, hostKey: (String) -> String?, meta: Map<String, String> = emptyMap()): Snapshot {
        if (cids.isEmpty()) {
            return Snapshot(emptyMap(), meta)
        }
        val sel = select(t, cids, hostKey)
        val rows = collect(t, sel, rewrap)
        remove(t, sel)
        return Snapshot(rows, meta)
    }

    /** Deletes the chats [cids] outright (a duplicate that a hidden one replaces). */
    fun drop(t: Tables, cids: Set<Long>, hostKey: (String) -> String?) {
        if (cids.isNotEmpty()) {
            remove(t, select(t, cids, hostKey))
        }
    }

    /** What [import] did. [doomed]: mailboxes of hidden chats that couldn't come back, to delete on the server. */
    class Imported(val contactIds: Map<Long, Long>, val doomed: List<Row>, val messages: Int)

    /**
     * Puts [snap]'s chats back, re-wrapping under the open root ([rewrap], from the hidden root). What has expired since,
     * or whose key no longer opens (messages were erased, or their bucket ended), is left out. A chat whose id was taken
     * meanwhile gets a new one. A hidden group that the database also has (an invitation to it came in meanwhile, over a
     * shown chat) replaces that copy if it's only an invitation; otherwise the copy here wins and the hidden one goes.
     */
    fun import(t: Tables, snap: Snapshot, rewrap: Rewrap, now: Long, hostKey: (String) -> String?): Imported {
        val dropped = HashSet<Long>()
        val replace = HashSet<Long>()
        for (g in snap.rows("groups")) {
            val here = t.select("groups", Where.In("gid", listOf(g["gid"] as String))).firstOrNull() ?: continue
            if (long(here["state"])?.toInt() == GroupModel.INVITED) {
                replace += long(here["cid"])!!
            } else {
                dropped += long(g["cid"])!!
            }
        }
        drop(t, replace, hostKey)
        val map = HashMap<Long, Long>()
        for (c in snap.rows("contacts")) {
            val old = long(c["id"])!!
            if (old in dropped) {
                continue
            }
            val taken = t.select("contacts", Where.In("id", listOf(old))).isNotEmpty()
            map[old] = if (taken) t.insert("contacts", c - "id")!! else t.insert("contacts", c)!!
        }
        fun cid(r: Row, col: String): Long? = long(r[col])?.let { map[it] }
        for (g in snap.rows("groups")) {
            cid(g, "cid")?.let { t.insert("groups", g + ("cid" to it)) }
        }
        val doomed = snap.rows("mailboxes").filter { long(it["contact_id"]) in dropped }
        for (m in snap.rows("mailboxes")) {
            val to = cid(m, "contact_id") ?: continue
            if (t.select("mailboxes", Where.In("tag", listOf(m["tag"] as ByteArray))).isNotEmpty()) {
                continue
            }
            val free = t.select("mailboxes", Where.In("id", listOf(long(m["id"])!!))).isEmpty()
            t.insert("mailboxes", (if (free) m else m - "id") + ("contact_id" to to))
        }
        val keys = snap.rows("message_keys").associateBy { it["message_id"] as String }
        val imported = HashSet<String>()
        for (m in snap.rows("messages")) {
            val to = cid(m, "contact_id") ?: continue
            val id = m["id"] as String
            val exp = long(m["expires_at"])
            val k = keys[id]
            if ((exp != null && exp <= now) || k == null) {
                continue
            }
            val key = openKey(k, id, rewrap) ?: continue
            if (t.insert("messages", m + ("contact_id" to to), orIgnore = true) != null) {
                t.insert("message_keys", key, orIgnore = true)
                imported += id
            }
        }
        for (r in snap.rows("group_receipts")) {
            if (r["message_id"] in imported) {
                t.insert("group_receipts", r, orIgnore = true)
            }
        }
        for (r in snap.rows("chunks")) {
            val to = cid(r, "contact_id") ?: continue
            val body = rewrap.blob(chunkLabel(long(r["contact_id"])!!, r), chunkLabel(to, r), r["body"] as ByteArray) ?: continue
            t.insert("chunks", r + mapOf("contact_id" to to, "body" to body), orIgnore = true)
        }
        for (r in snap.rows("outbox").sortedBy { long(it["seq"]) }) {
            val to = cid(r, "contact_id") ?: continue
            val mid = r["message_id"] as String?
            if (mid != null && mid !in imported) {
                continue
            }
            val sealed = r["content"] as ByteArray?
            val content = sealed?.let { rewrap.blob("outbox", "outbox", it) }
            if (sealed != null && content == null) {
                continue
            }
            // A new seq, in the same order: the chat's sends keep their order.
            t.insert("outbox", r - "seq" + mapOf("contact_id" to to, "content" to content))
        }
        for (r in snap.rows("held_incoming")) {
            val to = cid(r, "contact_id") ?: continue
            if ((long(r["expires_at"]) ?: 0) <= now) {
                continue
            }
            openKey(r, "held/" + r["id"], rewrap)?.let { t.insert("held_incoming", it + ("contact_id" to to), orIgnore = true) }
        }
        for (r in snap.rows("gone_incoming")) {
            val to = cid(r, "contact_id") ?: continue
            if ((long(r["until"]) ?: 0) > now) {
                t.insert("gone_incoming", r + ("contact_id" to to), orIgnore = true)
            }
        }
        for (table in listOf("group_cards", "group_rosters")) {
            for (r in snap.rows(table)) {
                cid(r, "cid")?.let { t.insert(table, r + ("cid" to it), orIgnore = true) }
            }
        }
        for (r in snap.rows("group_held").sortedBy { long(it["id"]) }) {
            val to = cid(r, "cid") ?: continue
            if ((long(r["expires_at"]) ?: 0) <= now) {
                continue
            }
            openKey(r, "gheld/" + r["ref"], rewrap)?.let { t.insert("group_held", it - "id" + ("cid" to to)) }
        }
        val addresses = map.entries.associate { (old, new) -> address(old) to address(new) }
        for (table in listOf("sig_session", "sig_identity")) {
            for (r in snap.rows(table)) {
                val a = r["address"] as String
                if (a.startsWith("c") && a !in addresses) {
                    continue
                }
                // A member's session made here meanwhile (a shown group took them in) is the one in use: it stays.
                t.insert(table, r + ("address" to (addresses[a] ?: a)), orIgnore = true)
            }
        }
        for (table in listOf("sig_signed_prekey", "sig_kyber_prekey")) {
            for (r in snap.rows(table)) {
                t.insert(table, r, orIgnore = true)
            }
        }
        for (r in snap.rows("kv")) {
            val k = r["k"] as String
            val renamed = Regex("^(gname|gjoin)/(\\d+)/(.*)$").find(k)?.let { m ->
                val to = map[m.groupValues[2].toLong()] ?: return@let null
                "${m.groupValues[1]}/$to/${m.groupValues[3]}"
            }
            if (renamed == null && !k.startsWith("tls_")) {
                continue
            }
            t.insert("kv", r + ("k" to (renamed ?: k)), orIgnore = true)
        }
        return Imported(map, doomed, imported.size)
    }

    /** The row with its key wrapped under the open root, or null if it no longer opens. */
    private fun openKey(r: Row, id: String, rewrap: Rewrap): Row? {
        val bucket = long(r["bucket"])
        val key = r["key"] as ByteArray
        if (bucket != null) {
            return r.takeIf { rewrap.bucketOpens(id, key, bucket) }
        }
        return rewrap.key(id, key)?.let { r + ("key" to it) }
    }
}
