package app.goldfishsend.baselineprofile

import androidx.benchmark.macro.junit4.BaselineProfileRule
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Generates the baseline profile (ahead-of-time compiled code) and the startup profile (DEX layout) for :app.
 * Run with `./gradlew :app:generateReleaseBaselineProfile` (see README.md, "Baseline profiles").
 */
@RunWith(AndroidJUnit4::class)
class BaselineProfileGenerator {
    @get:Rule
    val rule = BaselineProfileRule()

    /** Cold start to the chat list. Startup profile: these classes go first in classes.dex. */
    @Test
    fun startup() = rule.collect(targetPackage, includeInStartupProfile = true) {
        Seed.ensure(device, packageName, Lock.NONE)
        killProcess()
        startActivityAndWait()
        waitForChatList()
    }

    /** Cold start with the app PIN on: the lock screen, unlocking, and the chat list. */
    @Test
    fun startupLocked() = rule.collect(targetPackage, includeInStartupProfile = true) {
        Seed.ensure(device, packageName, Lock.PIN)
        killProcess()
        startActivityAndWait()
        unlockWithPin()
    }

    /** Everyday use after startup. Baseline profile only, so it doesn't push the startup classes apart. */
    @Test
    fun journeys() = rule.collect(targetPackage, includeInStartupProfile = false) {
        Seed.ensure(device, packageName, Lock.NONE)
        killProcess()
        startActivityAndWait()
        waitForChatList()
        scrollChatList()
        openChat(Seeded.LONG_CHAT)
        scrollConversation()
        typeAndSend("See you at the station at 7")
        backToChatList()
        openChat(Seeded.GROUP)
        scrollConversation(times = 2)
        typeAndSend("Count me in")
        backToChatList()
        openSettings()
    }
}
