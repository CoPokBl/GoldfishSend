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
        val timeout = Graph.prefs.lockTimeoutSecs
        if (lockable && timeout == 0) {
            Graph.lock()
        } else if (lockable) {
            // Lock on schedule while in the background too, so the key doesn't stay in RAM (and pushes don't get processed
            // with names in notifications) until the user happens to come back.
            handler.removeCallbacks(timedLock)
            handler.postDelayed(timedLock, timeout * 1000L)
        }
    }

    fun onForeground() {
        handler.removeCallbacks(timedLock)
        val at = backgroundedAt
        backgroundedAt = null
        if (lockable && at != null && SystemClock.elapsedRealtime() - at >= Graph.prefs.lockTimeoutSecs * 1000L) {
            Graph.lock()
        }
        // The user is looking at the app. Background auto-unlocks never count as presence.
        if (Graph.isUnlocked) {
            Wiper.recordPresence()
        }
    }

    private val handler = android.os.Handler(android.os.Looper.getMainLooper())
    private val timedLock = Runnable {
        if (lockable && backgroundedAt != null) {
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
                // Always check the duress verifier too, so timing doesn't reveal whether a duress PIN exists.
                val duress = real == null && vault.isDuress(passphrase)
                when {
                    real != null -> {
                        prefs.failedAttempts = 0
                        afterUnlock(Graph.openSession(real))
                        Wiper.recordPresence()
                        UnlockResult.Ok
                    }
                    duress -> {
                        prefs.failedAttempts = 0
                        onDuress(passphrase)
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

    /**
     * The duress PIN was entered. It can't decrypt anything real. Either everything is erased, or the separate decoy
     * profile opens (keyed by the duress PIN alone), and the real data stays encrypted and untouched.
     */
    private suspend fun onDuress(pin: CharArray): UnlockResult {
        if (Graph.prefs.duressAction == DuressAction.WIPE_ALL) {
            Wiper.wipeEverything(Graph.app)
            return UnlockResult.Wiped
        }
        Graph.openDecoySession(Graph.vault.decoyKey(pin))
        return UnlockResult.Ok
    }

    suspend fun unlockWithMasterKey(mk: ByteArray) {
        Graph.prefs.failedAttempts = 0
        afterUnlock(Graph.openSession(mk))
        Wiper.recordPresence()
    }

    /** Catch-up work once the DB is open: locked inbox, expiry sweep, outbox, mailbox pool. */
    fun afterUnlock(s: Session) {
        // A decoy session never touches real data or the server.
        if (s.decoy) {
            return
        }
        Graph.scope.launchSafe {
            LockedInbox.drain(s)
            if (Graph.prefs.inboxRotatePending) {
                // A reboot wipe happened while locked. Pushes sealed since the reboot were just drained; anything older
                // was deleted. Replace the key pair so no remnant of an old sealed push can ever be opened.
                LockedInbox.rotateKeys(s)
                Graph.prefs.inboxRotatePending = false
            }
            Sweeper.sweep(s)
            Outbox.kick()
            Mailboxes.cleanup(s)
            Mailboxes.ensurePool(s)
            Mailboxes.rotateContacts(s)
        }
    }
}
