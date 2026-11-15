package app.goldfishsend

import android.content.Context
import app.goldfishsend.db.Db
import java.io.File
import java.nio.file.Files
import java.nio.file.LinkOption
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * What an attacker gets from a dump of the app's storage, and what they can see in it once they also hold a database key.
 *
 * Needles are searched as overlapping 16-byte windows (stride 8), so a value split across two SQLite pages (overflow
 * chains, WAL frames) is still found: any split leaves at least one whole window on one side.
 */
internal object Forensics {
    const val WINDOW = 16
    private const val STRIDE = 8

    class Needle(val label: String, val windows: List<ByteArray>)

    class Hit(val label: String, val where: String, val offset: Int) {
        override fun toString() = "$label in $where @$offset"
    }

    fun hex(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }

    private fun windows(n: Int): List<Int> {
        if (n <= WINDOW) {
            return listOf(0)
        }
        val starts = (0..n - WINDOW step STRIDE).toMutableList()
        if (starts.last() != n - WINDOW) {
            starts += n - WINDOW
        }
        return starts
    }

    /** Text as UTF-8, UTF-16LE and UTF-16BE (Java and SQLite store text in all of them). */
    fun text(label: String, s: String): Needle {
        val out = ArrayList<ByteArray>()
        for (st in windows(s.length)) {
            val w = s.substring(st, minOf(s.length, st + WINDOW))
            out += w.toByteArray(Charsets.UTF_8)
            out += w.toByteArray(Charsets.UTF_16LE)
            out += w.toByteArray(Charsets.UTF_16BE)
        }
        return Needle(label, out.filter { it.size >= 8 })
    }

    fun bytes(label: String, b: ByteArray): Needle {
        require(b.size >= 8) { "$label: needle too short" }
        return Needle(label, windows(b.size).map { b.copyOfRange(it, minOf(b.size, it + WINDOW)) })
    }

    /** Finds every needle window in a haystack, indexed by the window's first 8 bytes so big files scan in one pass. */
    class Scanner(needles: Collection<Needle>) {
        private val index = HashMap<Long, MutableList<Pair<String, ByteArray>>>()

        init {
            for (n in needles) {
                for (w in n.windows) {
                    index.getOrPut(prefix(w, 0)) { ArrayList() } += n.label to w
                }
            }
        }

        fun scan(where: String, data: ByteArray): List<Hit> {
            val hits = ArrayList<Hit>()
            if (data.size < 8 || index.isEmpty()) {
                return hits
            }
            var k = prefix(data, 0)
            var i = 0
            while (true) {
                index[k]?.let { list ->
                    for ((label, w) in list) {
                        if (i + w.size <= data.size && matches(data, i, w) && hits.none { it.label == label && it.where == where }) {
                            hits += Hit(label, where, i)
                        }
                    }
                }
                if (i + 8 >= data.size) {
                    break
                }
                k = (k shl 8) or (data[i + 8].toLong() and 0xff)
                i++
            }
            return hits
        }

        private fun matches(d: ByteArray, at: Int, w: ByteArray): Boolean {
            for (j in w.indices) {
                if (d[at + j] != w[j]) {
                    return false
                }
            }
            return true
        }

        private fun prefix(b: ByteArray, at: Int): Long {
            var k = 0L
            for (j in 0 until 8) {
                k = (k shl 8) or (b[at + j].toLong() and 0xff)
            }
            return k
        }
    }

    /** The app's storage roots: credential- and device-encrypted data dirs, and app-specific external storage. */
    fun roots(ctx: Context): List<File> = listOfNotNull(
        ctx.dataDir,
        ctx.createDeviceProtectedStorageContext().dataDir,
        ctx.externalCacheDir,
        ctx.getExternalFilesDir(null),
    ).distinct()

    /** Every regular file under the roots (symlinks such as `lib` point at the APK's code, not app data). */
    fun files(ctx: Context): List<File> = roots(ctx).flatMap { root ->
        if (!root.exists()) {
            emptyList()
        } else {
            Files.walk(root.toPath()).use { s ->
                s.filter { Files.isRegularFile(it, LinkOption.NOFOLLOW_LINKS) }.map { it.toFile() }.toList()
            }
        }
    }

    fun scanFiles(ctx: Context, scanner: Scanner): List<Hit> =
        files(ctx).flatMap { f -> runCatching { f.readBytes() }.getOrNull()?.let { scanner.scan(f.path, it) }.orEmpty() }

    // ---- SQLCipher 4 page decryption ----

    /** Per-page reserve: a 16-byte IV and a 64-byte HMAC-SHA512 (SQLCipher 4 defaults). */
    const val RESERVE = 80
    const val PAGE = 4096
    private const val SALT = 16
    private val SQLITE_HEADER = "SQLite format 3\u0000".toByteArray(Charsets.ISO_8859_1)

    /** The raw 256-bit SQLCipher key the app derives from [mk] (parsed from the app's own `x'<hex>'` key literal). */
    fun dbKey(mk: ByteArray): ByteArray {
        val blob = Db.keyBlob(mk)
        val hex = String(blob, 2, blob.size - 3, Charsets.ISO_8859_1)
        return ByteArray(hex.length / 2) { hex.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
    }

    /**
     * Decrypts one page: AES-256-CBC with the IV from the page's reserve. Page 1 keeps its first 16 bytes (the KDF salt)
     * in the clear; they're replaced by the SQLite magic, as SQLCipher does in memory. HMACs aren't checked.
     */
    fun decryptPage(buf: ByteArray, off: Int, pgno: Int, key: ByteArray): ByteArray {
        val start = if (pgno == 1) SALT else 0
        val iv = buf.copyOfRange(off + PAGE - RESERVE, off + PAGE - RESERVE + 16)
        val c = Cipher.getInstance("AES/CBC/NoPadding")
        c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
        val page = ByteArray(PAGE)
        c.doFinal(buf, off + start, PAGE - RESERVE - start, page, start)
        if (pgno == 1) {
            SQLITE_HEADER.copyInto(page)
        }
        return page
    }

    /** True if [page1] is a decrypted SQLite header page: 4096-byte pages, 80 reserved bytes, standard payload fractions. */
    fun isHeader(page1: ByteArray): Boolean =
        page1[16] == 0x10.toByte() && page1[17] == 0.toByte() && page1[20] == RESERVE.toByte() &&
            page1[21] == 64.toByte() && page1[22] == 32.toByte() && page1[23] == 32.toByte()

    class Decrypted(val path: String, val pages: List<ByteArray>) {
        val joined: ByteArray by lazy {
            val out = ByteArray(pages.size * PAGE)
            pages.forEachIndexed { i, p -> p.copyInto(out, i * PAGE) }
            out
        }
    }

    /**
     * Every page of the database file (live, free and unused alike), then every frame of its WAL if one exists. Fails if
     * the key doesn't decrypt the header, so a wrong key can't make the scan pass vacuously.
     */
    fun decryptDb(file: File, key: ByteArray): List<Decrypted> {
        val out = ArrayList<Decrypted>()
        val raw = file.readBytes()
        check(raw.size % PAGE == 0 && raw.isNotEmpty()) { "${file.name}: ${raw.size} bytes is not a whole number of pages" }
        val pages = (0 until raw.size / PAGE).map { decryptPage(raw, it * PAGE, it + 1, key) }
        check(isHeader(pages[0])) { "${file.name}: the key does not decrypt the header page" }
        out += Decrypted(file.path, pages)
        val wal = File(file.path + "-wal")
        if (wal.exists() && wal.length() > 32) {
            val w = wal.readBytes()
            val frames = ArrayList<ByteArray>()
            var off = 32
            while (off + 24 + PAGE <= w.size) {
                val pgno = ((w[off].toInt() and 0xff) shl 24) or ((w[off + 1].toInt() and 0xff) shl 16) or
                    ((w[off + 2].toInt() and 0xff) shl 8) or (w[off + 3].toInt() and 0xff)
                frames += decryptPage(w, off + 24, pgno, key)
                off += 24 + PAGE
            }
            out += Decrypted(wal.path, frames)
        }
        return out
    }

    fun scanDb(file: File, key: ByteArray, scanner: Scanner): List<Hit> = decryptDb(file, key).flatMap { d ->
        scanner.scan("${d.path} (decrypted)", d.joined).map { h ->
            val pgno = h.offset / PAGE + 1
            Hit(h.label, "${h.where} page $pgno, ${region(d.pages[pgno - 1], h.offset % PAGE, pgno)}", h.offset)
        }
    }

    /** Where in a b-tree page an offset lies, to tell a live row from a stale copy. */
    fun region(page: ByteArray, off: Int, pgno: Int): String {
        val hdr = if (pgno == 1) 100 else 0
        fun u16(at: Int) = ((page[at].toInt() and 0xff) shl 8) or (page[at + 1].toInt() and 0xff)
        val type = page[hdr].toInt() and 0xff
        if (type !in setOf(2, 5, 10, 13)) {
            return "not a b-tree page (free or overflow)"
        }
        val cells = hdr + (if (type == 2 || type == 5) 12 else 8) + 2 * u16(hdr + 3)
        val content = u16(hdr + 5).let { if (it == 0) 65536 else it }
        if (off < cells) {
            return "page header"
        }
        if (off < content) {
            return "unallocated space"
        }
        var fb = u16(hdr + 1)
        while (fb != 0 && fb + 4 <= PAGE) {
            if (off >= fb && off < fb + u16(fb + 2)) {
                return "freeblock"
            }
            fb = u16(fb)
        }
        return "cell area"
    }
}
