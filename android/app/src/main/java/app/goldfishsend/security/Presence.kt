package app.goldfishsend.security

/**
 * Pure logic for the inactivity wipe ("erase everything if unused"). It measures when the *user* was last present
 * (an interactive unlock or bringing the app to the foreground), never background wake-ups, and resists clock changes:
 *
 * - Within the same boot, elapsed realtime is used. It's monotonic and can't be changed by setting the clock.
 * - Across a reboot, elapsed realtime restarts, so the larger of the wall-clock difference and the time since this boot
 *   is used. Winding the clock back can then only hide time before the reboot, never time since it.
 */
object Presence {
    data class Mark(val wallMs: Long, val elapsedMs: Long, val bootCount: Int)

    /** How long the user has been away, as a conservative (never too small after a reboot) estimate. */
    fun absentMs(last: Mark, nowWallMs: Long, nowElapsedMs: Long, bootCount: Int): Long {
        if (bootCount != -1 && bootCount == last.bootCount && nowElapsedMs >= last.elapsedMs) {
            return nowElapsedMs - last.elapsedMs
        }
        return maxOf(nowWallMs - last.wallMs, nowElapsedMs)
    }

    fun shouldWipe(last: Mark?, days: Int, nowWallMs: Long, nowElapsedMs: Long, bootCount: Int): Boolean {
        if (days <= 0 || last == null) {
            return false
        }
        return absentMs(last, nowWallMs, nowElapsedMs, bootCount) > days * 86_400_000L
    }

    enum class OnPresent { RECORD, WIPE }

    /**
     * Someone is using the app now. The absence is judged before it's overwritten: past the limit, whoever this is
     * must not be able to reset the clock (opening a still-unlocked app on a seized phone), so the wipe happens instead.
     */
    fun onPresent(last: Mark?, days: Int, nowWallMs: Long, nowElapsedMs: Long, bootCount: Int): OnPresent =
        if (shouldWipe(last, days, nowWallMs, nowElapsedMs, bootCount)) OnPresent.WIPE else OnPresent.RECORD
}
