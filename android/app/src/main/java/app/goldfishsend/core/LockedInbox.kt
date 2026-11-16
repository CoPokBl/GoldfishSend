package app.goldfishsend.core

import app.goldfishsend.proto.B64
import app.goldfishsend.proto.Rand
import java.io.File
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.signal.libsignal.protocol.ecc.ECKeyPair
import org.signal.libsignal.protocol.ecc.ECPublicKey

/**
 * Pushes that arrive while the app is locked can't touch the encrypted DB. They're sealed (HPKE through libsignal) to the
 * inbox public key and written to disk. The private key lives inside the DB, so they open only after unlock.
 *
 * The inbox is bounded (count and bytes), so a flood can't fill storage. File names are random (no receive times), and
 * items whose processing fails are kept for a few retries instead of being lost.
 */
object LockedInbox {
    const val KIND_PUSH: Byte = 1
    const val KIND_ENDPOINT: Byte = 2
    private const val INFO = "gf/inbox/v1"
    const val MAX_FILES = 500
    const val MAX_BYTES = 8L * 1024 * 1024
    private const val MAX_RETRIES = 3
    private val mutex = Mutex()

    private fun dir(): File = File(Graph.app.noBackupFilesDir, "inbox").apply { mkdirs() }

    /** Seals and stores one item. Returns false if the inbox is full (or no key exists yet). */
    fun put(kind: Byte, data: ByteArray): Boolean {
        val pub = Graph.prefs.inboxPublicKey ?: return false
        val sealed = ECPublicKey(B64.dec(pub)).seal(byteArrayOf(kind) + data, INFO, ByteArray(0))
        val existing = dir().listFiles().orEmpty()
        if (existing.size >= MAX_FILES || existing.sumOf { it.length() } + sealed.size > MAX_BYTES) {
            return false
        }
        File(dir(), "${B64.enc(Rand.bytes(12))}.0.bin").writeBytes(sealed)
        return true
    }

    val isEmpty: Boolean
        get() = dir().listFiles().isNullOrEmpty()

    /** Opens and processes everything queued while locked, oldest first. */
    suspend fun drain(s: Session) = mutex.withLock {
        if (dir().listFiles().isNullOrEmpty()) {
            return@withLock
        }
        val priv = Graph.inboxPrivateKey(s)
        drainDir(dir(), { priv.open(it, INFO, ByteArray(0)) }) { kind, body ->
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
     * Processes the items in [dir], oldest first. Each attempt is counted in the file name before the item is processed,
     * so an item that keeps failing, or that kills the process (a native crash, out of memory), is tried at most
     * [MAX_RETRIES] times in all instead of on every unlock, and never holds up the items behind it.
     */
    internal suspend fun drainDir(dir: File, open: (ByteArray) -> ByteArray?, handle: suspend (Byte, ByteArray) -> Unit) {
        val files = dir.listFiles()?.sortedBy { it.lastModified() } ?: return
        for (f in files) {
            val pt = try {
                open(f.readBytes())
            } catch (e: Exception) {
                null
            }
            if (pt == null || pt.isEmpty()) {
                // Sealed to an older key (rotated after a reboot wipe) or corrupt: it can never be opened.
                f.delete()
                continue
            }
            val claimed = claim(f) ?: continue
            try {
                handle(pt[0], pt.copyOfRange(1, pt.size))
                claimed.delete()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Throwable) {
                // Kept (already counted) for the next drain.
                ReceiveGuard.log?.invoke("locked inbox item failed: ${e.javaClass.simpleName}")
            }
        }
    }

    /** Counts an attempt: renames the item to its next try, or deletes it once it has had [MAX_RETRIES]. */
    private fun claim(f: File): File? {
        val parts = f.name.split('.')
        val tries = parts.getOrNull(1)?.toIntOrNull() ?: MAX_RETRIES
        if (tries >= MAX_RETRIES) {
            f.delete()
            ReceiveGuard.drop("locked inbox", RetriesExhausted())
            return null
        }
        val next = File(f.parentFile, "${parts[0]}.${tries + 1}.bin")
        return if (f.renameTo(next)) next else f
    }

    private class RetriesExhausted : Exception()

    /** Creates a fresh key pair. The old private key is overwritten in the DB (secure_delete zeroes the freed page). */
    fun rotateKeys(s: Session) {
        val kp = ECKeyPair.generate()
        s.repo.kvPut("inbox_priv", kp.privateKey.serialize())
        Graph.prefs.inboxPublicKey = B64.enc(kp.publicKey.serialize())
    }

    fun clear() {
        dir().deleteRecursively()
    }
}
