package app.goldfishsend.security

import app.goldfishsend.core.Prefs

/**
 * One attempt at a secret (lock screen or "Confirm it's you"), and the rules for the failure counters in [prefs]:
 *
 * - The attempt is counted as soon as it starts, so a kill during the slow check still costs it.
 * - Only the right secret clears the counters ([right]).
 * - The duress PIN isn't a wrong attempt, but it clears nothing that counts towards the erase ([duress]): otherwise
 *   whoever holds it could alternate guesses at the real secret with duress unlocks and never reach the limit. It only
 *   resets the count the "attempts left" warning goes by, as a real unlock would, so the warning doesn't give it away.
 * - The erase comes when the wrong attempts since the last real unlock reach the limit ([wrong]).
 */
internal class Attempt(private val prefs: Prefs) {
    private val failed = prefs.failedAttempts + 1
    private val shown = prefs.failedAttemptsShown + 1

    init {
        prefs.failedAttempts = failed
        prefs.failedAttemptsShown = shown
    }

    /** The check couldn't run (the phone's secure storage was unavailable): this attempt didn't happen. */
    fun undo() {
        prefs.failedAttempts = failed - 1
        prefs.failedAttemptsShown = shown - 1
    }

    fun right() = forgive(prefs)

    fun duress() {
        prefs.failedAttempts = failed - 1
        prefs.failedAttemptsShown = 0
    }

    /** A wrong secret: [ERASE] if that was the last one allowed, otherwise the attempts left to show (null: no limit). */
    fun wrong(): Int? {
        val max = prefs.maxFailedAttempts
        return when {
            max <= 0 -> null
            failed >= max -> ERASE
            else -> max - shown
        }
    }

    companion object {
        const val ERASE = 0

        /** The right secret (or a key only it could have unwrapped): everything is forgiven. */
        fun forgive(prefs: Prefs) {
            prefs.failedAttempts = 0
            prefs.failedAttemptsShown = 0
        }
    }
}
