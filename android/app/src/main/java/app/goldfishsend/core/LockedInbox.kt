package app.goldfishsend.core

import app.goldfishsend.crypto.InboxIndexKey
import app.goldfishsend.proto.B64
import app.goldfishsend.proto.PushEnvelope
import java.io.File
import java.nio.ByteBuffer
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.signal.libsignal.protocol.ecc.ECKeyPair
import org.signal.libsignal.protocol.ecc.ECPublicKey

/**
 * Pushes that arrive while the app is locked can't touch the encrypted DB. They're sealed (HPKE through libsignal) to the
 * inbox public key and kept on disk. The private key lives inside the DB, so they open only after unlock.
 *
 * They're kept in one preallocated file of fixed-size slots ([InboxSlots]), padded to the same size before sealing,
 * under an index sealed with a Keystore key ([InboxIndexKey]). So a copy of the files shows neither how many pushes
 * arrived, nor when, nor how big they were. The inbox is bounded and fair per mailbox: one sender can't fill it and
 * push out everyone else. An item whose processing fails is kept for a few retries instead of being lost; an item the
 * drain never got to (the app locked again under it) loses no retry.
 */
object LockedInbox {
    const val KIND_PUSH: Byte = 1
    const val KIND_ENDPOINT: Byte = 2
    private const val INFO = "gf/inbox/v1"
    const val SLOTS = 512

    /** The largest item: a Web Push payload is at most 4096 bytes, and an endpoint change much less. */
    const val MAX_ITEM = 4096
    private const val MAX_RETRIES = 3

    /** Endpoint changes share one slot (only the newest matters) under a tag no mailbox has. */
    private val ENDPOINT_TAG = ByteArray(InboxSlots.TAG) { 0xFF.toByte() }

    /** Anything that isn't a push envelope (so the drain drops it) shares one tag too. */
    private val OTHER_TAG = ByteArray(InboxSlots.TAG)

    private val mutex = Mutex()

    @Volatile
    private var slots: InboxSlots? = null

    private fun store(): InboxSlots = slots ?: synchronized(this) {
        slots ?: run {
            // The sealed size of a full slot (the HPKE overhead doesn't depend on the key).
            val size = ECKeyPair.generate().publicKey.seal(ByteArray(3 + MAX_ITEM), INFO, ByteArray(0)).size
            InboxSlots(File(File(Graph.app.noBackupFilesDir, "inbox"), "slots.bin"), InboxIndexKey(), SLOTS, size).also { slots = it }
        }
    }

    /** Seals and stores one item. False if it can't be kept (the inbox is full of this sender's, or no key exists yet). */
    fun put(kind: Byte, data: ByteArray): Boolean = try {
        val pub = Graph.prefs.inboxPublicKey
        val packed = pack(kind, data, MAX_ITEM)
        if (pub == null || packed == null) {
            false
        } else {
            val tag = if (kind == KIND_ENDPOINT) ENDPOINT_TAG else PushEnvelope.parse(data)?.tag ?: OTHER_TAG
            store().put(tag, ECPublicKey(B64.dec(pub)).seal(packed, INFO, ByteArray(0)), replace = kind == KIND_ENDPOINT)
        }
    } catch (e: Exception) {
        false
    }

    val isEmpty: Boolean
        get() = store().isEmpty()

    /** Opens and processes everything queued while locked, oldest first. */
    suspend fun drain(s: Session) = mutex.withLock {
        val store = store()
        // Made while unlocked, so the file's creation doesn't date the first push that arrives while locked.
        store.prepare()
        if (store.isEmpty()) {
            return@withLock
        }
        val priv = Graph.inboxPrivateKey(s)
        drainSlots(store, { s.closed }, { priv.open(it, INFO, ByteArray(0)) }) { kind, body ->
            when (kind) {
                KIND_PUSH -> Messenger.handle(s, body)
                KIND_ENDPOINT -> Mailboxes.onNewEndpoint(
                    s,
                    app.goldfishsend.proto.ProtoJson.decodeFromString(PushEndpointData.serializer(), body.toString(Charsets.UTF_8)),
                )
            }
        }
    }

    /**
     * Processes the items in [store], oldest first, until none are left: pushes parked while this runs (in the moment
     * before the session was visible) are picked up too. Each attempt is counted before the item is processed, so one
     * that keeps failing, or that kills the process (a native crash, out of memory), is tried at most [MAX_RETRIES] times
     * in all instead of on every unlock, and never holds up the items behind it. Once [closed] (the app locked), it
     * stops: what's left keeps its retries, and so does the item under way, which may have failed only because the
     * database closed under it (the receive path drops what fails without saying so).
     */
    internal suspend fun drainSlots(
        store: InboxSlots,
        closed: () -> Boolean,
        open: (ByteArray) -> ByteArray?,
        handle: suspend (Byte, ByteArray) -> Unit,
    ) {
        val tried = HashSet<Long>()
        while (true) {
            val todo = store.entries().filter { it.seq !in tried }
            if (todo.isEmpty()) {
                return
            }
            for (e in todo) {
                if (closed()) {
                    return
                }
                tried += e.seq
                val sealed = store.claim(e, MAX_RETRIES) ?: continue
                val item = try {
                    open(sealed)?.let(::unpack)
                } catch (x: Exception) {
                    null
                }
                if (item == null) {
                    // Sealed to an older key (rotated after a reboot wipe) or corrupt: it can never be opened.
                    store.free(e)
                    continue
                }
                try {
                    handle(item.first, item.second)
                } catch (x: CancellationException) {
                    throw x
                } catch (x: Throwable) {
                    if (closed()) {
                        store.unclaim(e)
                        return
                    }
                    // Kept (already counted) for the next drain.
                    ReceiveGuard.log?.invoke("locked inbox item failed: ${x.javaClass.simpleName}")
                    continue
                }
                if (closed()) {
                    store.unclaim(e)
                    return
                }
                store.free(e)
            }
        }
    }

    /** kind, length, data, zeros up to [max]: every item seals to the same size. Null if [data] is too big. */
    internal fun pack(kind: Byte, data: ByteArray, max: Int): ByteArray? {
        if (data.size > max) {
            return null
        }
        return ByteBuffer.allocate(3 + max).put(kind).putShort(data.size.toShort()).put(data).array()
    }

    internal fun unpack(p: ByteArray): Pair<Byte, ByteArray>? {
        if (p.size < 3) {
            return null
        }
        val len = ((p[1].toInt() and 0xff) shl 8) or (p[2].toInt() and 0xff)
        if (len > p.size - 3) {
            return null
        }
        return p[0] to p.copyOfRange(3, 3 + len)
    }

    /** Creates a fresh key pair. The old private key is overwritten in the DB (secure_delete zeroes the freed page). */
    fun rotateKeys(s: Session) {
        val kp = ECKeyPair.generate()
        s.repo.kvPut("inbox_priv", kp.privateKey.serialize())
        Graph.prefs.inboxPublicKey = B64.enc(kp.publicKey.serialize())
    }

    /** Deletes the file and destroys the index key. */
    fun clear() {
        store().clear()
        File(Graph.app.noBackupFilesDir, "inbox").deleteRecursively()
    }
}
