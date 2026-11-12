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

    private val lockable: Boolean
        get() = Graph.vault.hasPassphrase

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

    suspend fun unlock(passphrase: CharArray): UnlockResult = withContext(Dispatchers.Default) {
        val vault = Graph.vault
        try {
            if (vault.hasDuress && vault.isDuress(passphrase)) {
                Wiper.wipeEverything(Graph.app)
                return@withContext UnlockResult.Wiped
            }
            val mk = try {
                vault.unlockWithPassphrase(passphrase)
            } catch (e: Exception) {
                return@withContext UnlockResult.DeviceLocked
            }
            if (mk == null) {
                val prefs = Graph.prefs
                val failed = prefs.failedAttempts + 1
                prefs.failedAttempts = failed
                val max = prefs.maxFailedAttempts
                if (max > 0 && failed >= max) {
                    Wiper.wipeEverything(Graph.app)
                    return@withContext UnlockResult.Wiped
                }
                return@withContext UnlockResult.Wrong(if (max > 0) max - failed else null)
            }
            afterUnlock(Graph.openSession(mk))
            UnlockResult.Ok
        } finally {
            passphrase.fill('\u0000')
        }
    }

    suspend fun unlockWithMasterKey(mk: ByteArray) {
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
        }
    }
}
