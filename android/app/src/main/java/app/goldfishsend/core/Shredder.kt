package app.goldfishsend.core

import app.goldfishsend.proto.Rand
import app.goldfishsend.proto.wipe
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay

/**
 * Rotates the message root key (MRK) after messages are deleted. Deleting a row only removes it from the database file:
 * old copies of its pages (the rollback journal, flash wear levelling) can survive in a raw flash image, and they open
 * with the database key and the MRK, both of which a later coerced unlock hands over. Re-wrapping what's still live under
 * a fresh MRK, and destroying the Keystore key that wrapped the old one, leaves those copies unreadable for good.
 *
 * Explicit erases (erase all messages, clear chat, delete contact) rotate straight away. Single deletes and expiry
 * sweeps are batched a few seconds later. The pending mark lives in the database, so a rotation the process didn't
 * live to do happens at the next unlock or maintenance run.
 */
object Shredder {
    /** kv: the MRK, wrapped by the Keystore key named in [KV_ROOT_ALIAS] (absent: the original "gf_msg"). */
    const val KV_ROOT = "mrk"
    const val KV_ROOT_ALIAS = "mrk_alias"

    /** kv: the decoy profile's MRK, kept only inside the decoy database (it's opened by the duress PIN alone). */
    const val KV_DECOY_ROOT = "decoy_mrk"

    private const val BATCH_MS = 5_000L

    private var batch: Job? = null

    /** After a delete: rotate a little later, so a run of deletes costs one rotation. */
    fun schedule(s: Session) {
        synchronized(this) {
            batch?.cancel()
            batch = Graph.scope.launchSafe {
                delay(BATCH_MS)
                runPending(s)
            }
        }
    }

    /** Rotates now if anything was deleted since the last rotation and [s] is still the open session. */
    fun runPending(s: Session) {
        if (Graph.session.value === s && s.repo.shredPending) {
            rotate(s)
        }
    }

    /**
     * Replaces the MRK of [s]. Serialised process-wide: a rotation deletes every message-root Keystore key but its own,
     * so another one mustn't be halfway through. Throws if it couldn't (for example the phone is locked, so the new
     * Keystore key can't be used yet), and the pending mark stays for next time.
     */
    fun rotate(s: Session) {
        synchronized(this) {
            val next = Rand.bytes(32)
            try {
                if (s.decoy) {
                    s.repo.rotateMessageRoot(next) { s.repo.kvPut(KV_DECOY_ROOT, next) }
                    return
                }
                val wrapped = Graph.vault.wrapMessageRoot(next)
                try {
                    s.repo.rotateMessageRoot(next) {
                        s.repo.kvPut(KV_ROOT, wrapped.blob)
                        s.repo.kvPutString(KV_ROOT_ALIAS, wrapped.alias)
                    }
                } catch (e: Exception) {
                    Graph.vault.deleteMessageKey(wrapped.alias)
                    throw e
                }
                // Committed: the old root's key goes, and with it the only way to open stale copies.
                Graph.vault.keepOnlyMessageKey(wrapped.alias)
            } catch (e: Exception) {
                next.wipe()
                throw e
            }
        }
    }
}
