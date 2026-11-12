package app.goldfishsend.core

import app.goldfishsend.proto.B64
import app.goldfishsend.proto.Rand
import java.io.File
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.signal.libsignal.protocol.ecc.ECPublicKey

/**
 * Pushes that arrive while the app is locked can't touch the encrypted DB. They're sealed (HPKE through libsignal) to the
 * inbox public key and written to disk. The private key lives inside the DB, so they open only after unlock.
 */
object LockedInbox {
    const val KIND_PUSH: Byte = 1
    const val KIND_ENDPOINT: Byte = 2
    private const val INFO = "gf/inbox/v1"
    private val mutex = Mutex()

    private fun dir(): File = File(Graph.app.noBackupFilesDir, "inbox").apply { mkdirs() }

    fun put(kind: Byte, data: ByteArray) {
        val pub = Graph.prefs.inboxPublicKey ?: return
        val sealed = ECPublicKey(B64.dec(pub)).seal(byteArrayOf(kind) + data, INFO, ByteArray(0))
        val name = "%013d-%s.bin".format(System.currentTimeMillis(), B64.enc(Rand.bytes(6)))
        File(dir(), name).writeBytes(sealed)
    }

    val isEmpty: Boolean
        get() = dir().listFiles().isNullOrEmpty()

    /** Opens and processes everything queued while locked, oldest first. */
    suspend fun drain(s: Session) = mutex.withLock {
        val files = dir().listFiles()?.sortedBy { it.name } ?: return@withLock
        if (files.isEmpty()) {
            return@withLock
        }
        val priv = Graph.inboxPrivateKey(s)
        for (f in files) {
            val pt = try {
                priv.open(f.readBytes(), INFO, ByteArray(0))
            } catch (e: Exception) {
                null
            }
            f.delete()
            if (pt == null || pt.isEmpty()) {
                continue
            }
            val body = pt.copyOfRange(1, pt.size)
            try {
                when (pt[0]) {
                    KIND_PUSH -> Messenger.handle(s, body)
                    KIND_ENDPOINT -> Mailboxes.onNewEndpoint(
                        s,
                        app.goldfishsend.proto.ProtoJson.decodeFromString(PushEndpointData.serializer(), body.toString(Charsets.UTF_8)),
                    )
                }
            } catch (e: Exception) {
                android.util.Log.w("LockedInbox", "item failed: ${e.javaClass.simpleName}")
            }
        }
    }

    fun clear() {
        dir().deleteRecursively()
    }
}
