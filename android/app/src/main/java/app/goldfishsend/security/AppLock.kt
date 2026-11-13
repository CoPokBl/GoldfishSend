package app.goldfishsend.security

import android.os.SystemClock
import app.goldfishsend.core.Graph
import app.goldfishsend.core.LockedInbox
import app.goldfishsend.core.Mailboxes
import app.goldfishsend.core.Outbox
import app.goldfishsend.core.Session
import app.goldfishsend.core.Sweeper
import app.goldfishsend.core.launchSafe
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import app.goldfishsend.core.DuressAction
import app.goldfishsend.core.Messenger
import app.goldfishsend.proto.wipe

sealed class UnlockResult {
    data object Ok : UnlockResult()

    data class Wrong(val attemptsLeft: Int?) : UnlockResult()

    data object Wiped : UnlockResult()

    data object DeviceLocked : UnlockResult()
}

/** App lock: auto-lock timeout, lock on screen-off, wrong-passphrase wipe and duress PIN. */
object AppLock {
    @Volatile
    private var backgroundedAt: Long? = null

    const val KV_HIDDEN_ON = "hidden_on"
    const val KV_DURESS_ON = "duress_on"

    private val lockable: Boolean
        get() = Graph.vault.requiresUserUnlock

    fun onBackground() {
        backgroundedAt = SystemClock.elapsedRealtime()
        if (lockable && Graph.prefs.lockTimeoutSecs == 0) {
            Graph.lock()
        }
    }

    fun onForeground() {
        val at = backgroundedAt
        backgroundedAt = null
        if (lockable && at != null && SystemClock.elapsedRealtime() - at >= Graph.prefs.lockTimeoutSecs * 1000L) {
            Graph.lock()
        }
    }

    fun onScreenOff() {
        if (lockable && Graph.prefs.lockOnScreenOff) {
            Graph.lock()
        }
    }

    /** One attempt at a time, process-wide, so concurrent attempts can't race the failure counter. */
    private val attemptMutex = Mutex()

    suspend fun unlock(passphrase: CharArray): UnlockResult = withContext(Dispatchers.Default) {
        val vault = Graph.vault
        try {
            attemptMutex.withLock {
                val prefs = Graph.prefs
                // Count the attempt before checking it. A kill during the (slow) Argon2 check still costs an attempt.
                val failed = prefs.failedAttempts + 1
                prefs.failedAttempts = failed
                val real = try {
                    vault.unlockWithPassphrase(passphrase)
                } catch (e: Exception) {
                    prefs.failedAttempts = failed - 1
                    return@withLock UnlockResult.DeviceLocked
                }
                // Always check the duress slot too, so timing doesn't reveal whether a duress PIN exists.
                val duress = vault.unlockWithDuress(passphrase)
                when {
                    real != null -> {
                        duress?.wipe()
                        prefs.failedAttempts = 0
                        afterUnlock(Graph.openSession(real))
                        UnlockResult.Ok
                    }
                    duress != null -> {
                        prefs.failedAttempts = 0
                        onDuress(duress)
                    }
                    else -> {
                        val max = prefs.maxFailedAttempts
                        if (max > 0 && failed >= max) {
                            Wiper.wipeEverything(Graph.app)
                            UnlockResult.Wiped
                        } else {
                            UnlockResult.Wrong(if (max > 0) max - failed else null)
                        }
                    }
                }
            }
        } finally {
            passphrase.fill('\u0000')
        }
    }

    /** The duress PIN was entered. Depending on the user's choice: erase everything, or open a decoy view without hidden chats. */
    private suspend fun onDuress(mk: ByteArray): UnlockResult {
        val action = Graph.prefs.duressAction
        if (action == DuressAction.WIPE_ALL) {
            mk.wipe()
            Wiper.wipeEverything(Graph.app)
            return UnlockResult.Wiped
        }
        val s = Graph.openSession(mk)
        s.decoy = true
        s.hiddenRevealed.value = false
        if (action == DuressAction.DELETE_HIDDEN_CHATS) {
            for (cid in s.repo.hiddenContactIds()) {
                runCatching { Messenger.deleteContact(s, cid) }
            }
            Graph.vault.setHiddenPin(null)
            s.repo.kvPutString(KV_HIDDEN_ON, null)
        }
        afterUnlock(s)
        return UnlockResult.Ok
    }

    suspend fun unlockWithMasterKey(mk: ByteArray) {
        Graph.prefs.failedAttempts = 0
        afterUnlock(Graph.openSession(mk))
    }

    /** Catch-up work once the DB is open: locked inbox, expiry sweep, outbox, mailbox pool. */
    fun afterUnlock(s: Session) {
        Graph.scope.launchSafe {
            LockedInbox.drain(s)
            Sweeper.sweep(s)
            Outbox.kick()
            Mailboxes.cleanup(s)
            Mailboxes.ensurePool(s)
            Mailboxes.rotateContacts(s)
        }
    }
}
