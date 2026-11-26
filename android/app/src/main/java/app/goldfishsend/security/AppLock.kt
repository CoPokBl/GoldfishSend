package app.goldfishsend.security

import android.os.SystemClock
import app.goldfishsend.core.Graph
import app.goldfishsend.core.LockedInbox
import app.goldfishsend.core.Mailboxes
import app.goldfishsend.core.Outbox
import app.goldfishsend.core.Session
import app.goldfishsend.core.Shredder
import app.goldfishsend.core.Sweeper
import app.goldfishsend.core.UnlockInterrupted
import app.goldfishsend.core.launchSafe
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import app.goldfishsend.core.DuressAction
import app.goldfishsend.crypto.KeyVault

sealed class UnlockResult {
    data object Ok : UnlockResult()

    data class Wrong(val attemptsLeft: Int?) : UnlockResult()

    data object Wiped : UnlockResult()

    data object DeviceLocked : UnlockResult()

    /** The app was locked (screen off, wipe) while this unlock was in progress, so it stays locked. */
    data object Interrupted : UnlockResult()
}

/** App lock: auto-lock timeout, lock on screen-off, wrong-passphrase wipe and duress PIN. */
object AppLock {
    @Volatile
    private var backgroundedAt: Long? = null

    const val KV_HIDDEN_ON = "hidden_on"
    const val KV_DURESS_ON = "duress_on"

    /** Whether hidden chats post (generic) notifications. In each profile's database, like the other hidden-chat state. */
    const val KV_NOTIFY_HIDDEN = "notify_hidden"

    private val lockable: Boolean
        get() = Graph.vault.requiresUserUnlock

    fun onBackground() {
        backgroundedAt = SystemClock.elapsedRealtime()
        // The open session's own setting: a decoy's auto-lock is the decoy's.
        val timeout = Graph.uiPrefs.lockTimeoutSecs
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
        if (lockable && at != null && SystemClock.elapsedRealtime() - at >= Graph.uiPrefs.lockTimeoutSecs * 1000L) {
            Graph.lock()
        }
        // The user is looking at the app. Background auto-unlocks never count as presence, and nor does a decoy session:
        // using the decoy mustn't hold off the real profile's erase-if-unused. recordPresence checks the inactivity limit
        // before it refreshes anything.
        if (Graph.realSession != null) {
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
        if (lockable && Graph.uiPrefs.lockOnScreenOff) {
            Graph.lock()
        }
    }

    /** One attempt at a time, process-wide, so concurrent attempts can't race the failure counters. */
    private val attemptMutex = Mutex()

    /**
     * Every attempt costs the same: the real secret and the duress slot are both checked (one Argon2 run each) whatever
     * the outcome, so timing reveals neither whether a duress PIN exists nor whether an unlock opened the real profile.
     *
     * Wrong attempts count towards the erase until the real secret is entered. The duress PIN doesn't reset that count
     * (it would otherwise hand out unlimited guesses at the real secret); it only resets the count the warning shows.
     */
    suspend fun unlock(passphrase: CharArray): UnlockResult = withContext(Dispatchers.Default) {
        // Before the slow part: a lock from here on (screen off) must win over this unlock.
        val since = Graph.lockEpoch
        val vault = Graph.vault
        android.os.Trace.beginAsyncSection("gf.unlock", 0)
        try {
            attemptMutex.withLock {
                val attempt = Attempt(Graph.prefs)
                val real = try {
                    vault.unlockWithPassphrase(passphrase)
                } catch (e: Exception) {
                    attempt.undo()
                    return@withLock UnlockResult.DeviceLocked
                }
                val duress = runCatching { vault.openDuress(passphrase) }.getOrNull()
                when {
                    real != null -> {
                        duress?.wipe()
                        attempt.right()
                        opened { afterUnlock(Graph.openSession(real, since)) }
                    }
                    duress != null -> {
                        attempt.duress()
                        onDuress(duress, since)
                    }
                    else -> wrongAttempt(attempt)
                }
            }
        } finally {
            passphrase.fill('\u0000')
            android.os.Trace.endAsyncSection("gf.unlock", 0)
        }
    }

    private fun wrongAttempt(attempt: Attempt): UnlockResult = when (val left = attempt.wrong()) {
        Attempt.ERASE -> {
            Wiper.wipeEverything(Graph.app)
            UnlockResult.Wiped
        }
        else -> UnlockResult.Wrong(left)
    }

    private suspend fun opened(open: suspend () -> Unit): UnlockResult = try {
        open()
        Wiper.recordPresence()
        UnlockResult.Ok
    } catch (e: UnlockInterrupted) {
        UnlockResult.Interrupted
    }

    /**
     * The duress PIN was entered. It can't decrypt anything real. Either everything is erased, or the separate decoy
     * profile opens (keyed by the duress slot alone), and the real data stays encrypted and untouched.
     */
    private suspend fun onDuress(match: KeyVault.DuressMatch, since: Long): UnlockResult {
        if (Graph.vault.duressAction == DuressAction.WIPE_ALL) {
            match.wipe()
            Wiper.wipeEverything(Graph.app)
            return UnlockResult.Wiped
        }
        return try {
            Graph.openDecoySession(match, since)
            UnlockResult.Ok
        } catch (e: UnlockInterrupted) {
            UnlockResult.Interrupted
        }
    }

    /**
     * After the biometric or screen-lock prompt, which calls back on the UI thread. [since] is [Graph.lockEpoch] from when
     * the prompt was shown. Only a real key gets here, so it resets the failure count like any real unlock.
     */
    suspend fun unlockWithMasterKey(mk: ByteArray, since: Long): UnlockResult = withContext(Dispatchers.IO) {
        Attempt.forgive(Graph.prefs)
        opened { afterUnlock(Graph.openSession(mk, since)) }
    }

    /**
     * Re-authentication inside an open session ("Confirm it's you"). It counts exactly like the lock screen: each wrong
     * answer is a failed attempt, and the erase happens at the same limit. A decoy session checks its own secret (the
     * duress PIN) against its own counter and limit, never the real ones, so it can't be used to test guesses at the real
     * secret, and it behaves like a real session would.
     */
    suspend fun reauthenticate(s: Session, secret: CharArray): UnlockResult = withContext(Dispatchers.Default) {
        try {
            attemptMutex.withLock {
                // The session's own counter: a decoy's never touches the real one.
                val attempt = Attempt(s.prefs)
                val ok = try {
                    s.secrets.checkSecret(secret)
                } catch (e: Exception) {
                    attempt.undo()
                    return@withLock UnlockResult.DeviceLocked
                }
                if (ok) {
                    attempt.right()
                    UnlockResult.Ok
                } else {
                    wrongAttempt(attempt)
                }
            }
        } finally {
            secret.fill('\u0000')
        }
    }

    /** Catch-up work once the DB is open: locked inbox, expiry sweep, outbox, mailbox pool. Stops if the session locks. */
    fun afterUnlock(s: Session) {
        // A decoy session never touches real data or the server.
        if (s.decoy) {
            return
        }
        s.scope.launchSafe {
            // Deletes the last session didn't get to shred (MessageVault): first, before anything else is written.
            runCatching { Shredder.runPending(s) }
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
