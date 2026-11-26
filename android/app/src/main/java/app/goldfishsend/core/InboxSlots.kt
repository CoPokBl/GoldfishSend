package app.goldfishsend.core

import app.goldfishsend.proto.Rand
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer

/** Seals the slot index under a key the app can use while locked but a copy of its files can't (see [LockedInbox]). */
interface IndexKey {
    /** Bytes [seal] adds, so the index always has the same size on disk. */
    val overhead: Int

    fun seal(plain: ByteArray): ByteArray

    /** Null if [sealed] isn't ours: corrupt, random filler, or sealed under a key that was destroyed. */
    fun open(sealed: ByteArray): ByteArray?

    fun destroy()
}

/**
 * The locked inbox on disk: one preallocated file of [slots] fixed-size slots, so its size and name never change with
 * what arrives. Free slots hold random bytes, which look like sealed ones. Which slots are used, in what order, by which
 * mailbox tag and with how many tries is in an index at the start of the file, sealed under [key]; it's written in
 * turn to one of two copies, so a write cut short leaves the other one intact. Every write resets the file's
 * modification time to [FIXED_MTIME]. Android-free, so the JVM tests use it too.
 *
 * Once every slot is taken, a newcomer whose tag holds fewer slots than the busiest tag replaces that tag's newest item;
 * one from the busiest tag itself is refused. So a single sender (or a hostile relay using one mailbox) can't push out
 * everyone else's messages, while one sender alone may still use every slot.
 */
internal class InboxSlots(private val file: File, private val key: IndexKey, private val slots: Int, val slotSize: Int) {
    class Entry(val slot: Int, val seq: Long, val tag: ByteArray)

    private class Index(var gen: Long, var nextSeq: Long, val seq: LongArray, val tries: IntArray, val tags: Array<ByteArray>) {
        fun copy() = Index(gen, nextSeq, seq.copyOf(), tries.copyOf(), Array(tags.size) { tags[it].copyOf() })
    }

    private val plainSize = HEADER + slots * PER_SLOT
    private val regionSize = plainSize + key.overhead
    private val fileSize = 2L * regionSize + slots.toLong() * slotSize

    /** The index as last read or written. Only this process writes the file, so it stays current. */
    private var cached: Index? = null

    /** Creates the file (random bytes throughout: an empty index) if it's missing or the wrong size. */
    @Synchronized
    fun prepare() {
        if (file.length() == fileSize) {
            return
        }
        file.parentFile?.mkdirs()
        cached = null
        RandomAccessFile(file, "rw").use { raf ->
            raf.setLength(0)
            val chunk = 64 * 1024
            var left = fileSize
            while (left > 0) {
                val n = minOf(left, chunk.toLong()).toInt()
                raf.write(Rand.bytes(n))
                left -= n
            }
        }
        // Both copies hold a valid empty index from the start, so only a destroyed key ever leaves none that opens.
        val ix = empty()
        save(ix)
        save(ix)
    }

    /** Stores [item] (exactly [slotSize] bytes) for mailbox [tag]. With [replace], it takes the place of [tag]'s item. */
    @Synchronized
    fun put(tag: ByteArray, item: ByteArray, replace: Boolean = false): Boolean {
        require(item.size == slotSize && tag.size == TAG)
        prepare()
        val ix = load()
        var slot = if (replace) (0 until slots).firstOrNull { ix.seq[it] != 0L && ix.tags[it].contentEquals(tag) } else null
        if (slot == null) {
            slot = (0 until slots).firstOrNull { ix.seq[it] == 0L }
        }
        if (slot == null) {
            val counts = HashMap<String, Int>()
            for (i in 0 until slots) {
                counts.merge(hex(ix.tags[i]), 1, Int::plus)
            }
            val busiest = counts.maxBy { it.value }
            if ((counts[hex(tag)] ?: 0) >= busiest.value) {
                return false
            }
            slot = (0 until slots).filter { hex(ix.tags[it]) == busiest.key }.maxBy { ix.seq[it] }
        }
        writeSlot(slot, item)
        ix.seq[slot] = ix.nextSeq++
        ix.tries[slot] = 0
        ix.tags[slot] = tag.copyOf()
        save(ix)
        return true
    }

    /** What's stored, oldest first. */
    @Synchronized
    fun entries(): List<Entry> {
        if (!file.exists()) {
            return emptyList()
        }
        val ix = load()
        return (0 until slots).filter { ix.seq[it] != 0L }.sortedBy { ix.seq[it] }.map { Entry(it, ix.seq[it], ix.tags[it].copyOf()) }
    }

    @Synchronized
    fun isEmpty(): Boolean = entries().isEmpty()

    /**
     * Counts an attempt at [e] and returns its bytes, or null if it's gone, or had [maxTries] attempts already (it's then
     * freed and counted as dropped). Counted before it's processed, so one that kills the process isn't retried forever.
     */
    @Synchronized
    fun claim(e: Entry, maxTries: Int): ByteArray? {
        val ix = load()
        if (ix.seq[e.slot] != e.seq) {
            return null
        }
        if (ix.tries[e.slot] >= maxTries) {
            release(ix, e.slot)
            ReceiveGuard.drop("locked inbox", RetriesExhausted())
            return null
        }
        ix.tries[e.slot]++
        save(ix)
        return readSlot(e.slot)
    }

    /** Takes back the attempt [claim] counted: [e] was never really tried (the app locked under it). */
    @Synchronized
    fun unclaim(e: Entry) {
        val ix = load()
        if (ix.seq[e.slot] == e.seq && ix.tries[e.slot] > 0) {
            ix.tries[e.slot]--
            save(ix)
        }
    }

    /** Done with [e]: its slot is overwritten with random bytes and freed. */
    @Synchronized
    fun free(e: Entry) {
        val ix = load()
        if (ix.seq[e.slot] == e.seq) {
            release(ix, e.slot)
        }
    }

    @Synchronized
    fun clear() {
        cached = null
        file.delete()
        key.destroy()
    }

    private fun release(ix: Index, slot: Int) {
        writeSlot(slot, Rand.bytes(slotSize))
        ix.seq[slot] = 0
        ix.tries[slot] = 0
        ix.tags[slot] = ByteArray(TAG)
        save(ix)
    }

    private fun empty() = Index(0, 1, LongArray(slots), IntArray(slots), Array(slots) { ByteArray(TAG) })

    /** The newer of the two index copies that opens; an empty index if neither does (new file, or the key is gone). */
    /** A copy the caller may change: the cache only ever holds what's on disk. */
    private fun load(): Index {
        cached?.let { return it.copy() }
        if (file.length() != fileSize) {
            return empty()
        }
        val copies = RandomAccessFile(file, "r").use { raf ->
            (0..1).mapNotNull { i ->
                val buf = ByteArray(regionSize)
                raf.seek(i.toLong() * regionSize)
                raf.readFully(buf)
                key.open(buf)?.takeIf { it.size == plainSize && it[0] == VERSION }?.let(::decode)
            }
        }
        val ix = copies.maxByOrNull { it.gen } ?: empty()
        cached = ix.copy()
        return ix
    }

    private fun decode(p: ByteArray): Index {
        val b = ByteBuffer.wrap(p, 1, p.size - 1)
        val ix = Index(b.long, b.long, LongArray(slots), IntArray(slots), Array(slots) { ByteArray(TAG) })
        for (i in 0 until slots) {
            ix.seq[i] = b.long
            ix.tries[i] = b.get().toInt() and 0xff
            b.get(ix.tags[i])
        }
        return ix
    }

    private fun save(ix: Index) {
        ix.gen++
        val b = ByteBuffer.allocate(plainSize)
        b.put(VERSION).putLong(ix.gen).putLong(ix.nextSeq)
        for (i in 0 until slots) {
            b.putLong(ix.seq[i]).put(ix.tries[i].coerceAtMost(255).toByte()).put(ix.tags[i])
        }
        val sealed = key.seal(b.array())
        check(sealed.size == regionSize)
        cached = null
        RandomAccessFile(file, "rw").use { raf ->
            raf.seek((ix.gen % 2) * regionSize)
            raf.write(sealed)
        }
        cached = ix.copy()
        file.setLastModified(FIXED_MTIME)
    }

    private fun writeSlot(slot: Int, bytes: ByteArray) {
        RandomAccessFile(file, "rw").use { raf ->
            raf.seek(2L * regionSize + slot.toLong() * slotSize)
            raf.write(bytes)
        }
    }

    private fun readSlot(slot: Int): ByteArray = RandomAccessFile(file, "r").use { raf ->
        val buf = ByteArray(slotSize)
        raf.seek(2L * regionSize + slot.toLong() * slotSize)
        raf.readFully(buf)
        buf
    }

    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    private class RetriesExhausted : Exception()

    companion object {
        const val TAG = 8
        private const val VERSION: Byte = 1

        /** Version, write generation, next sequence number. */
        private const val HEADER = 1 + 8 + 8

        /** Sequence number (0 = free), tries, mailbox tag. */
        private const val PER_SLOT = 8 + 1 + TAG

        /** What every write sets the file's modification time to (2020-01-01), so it doesn't date the last arrival. */
        const val FIXED_MTIME = 1_577_836_800_000L
    }
}
