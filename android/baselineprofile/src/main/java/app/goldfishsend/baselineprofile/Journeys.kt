package app.goldfishsend.baselineprofile

import android.os.SystemClock
import androidx.benchmark.macro.MacrobenchmarkScope
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.BySelector
import androidx.test.uiautomator.Direction
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.UiObject2
import androidx.test.uiautomator.Until

/** The app under test, passed by the baseline-profile plugin (see build.gradle.kts). */
val targetPackage: String
    get() = InstrumentationRegistry.getArguments().getString("targetAppId")
        ?: error("targetAppId not passed as an instrumentation argument")

enum class Lock { NONE, PIN }

/** The seeded data (app/src/benchmark): the chats at the top of the list, and the app PIN. */
object Seeded {
    const val LONG_CHAT = "Alice"
    const val GROUP = "Weekend trip"
    const val PIN = "1357"
}

/**
 * Seeds the app through its benchmark-only provider, once per test process and lock mode. Call it from a setup block
 * (after Macrobenchmark has set the compilation state), never from a measured block.
 */
object Seed {
    private var current: Lock? = null

    fun ensure(device: UiDevice, packageName: String, lock: Lock) {
        if (current == lock) {
            return
        }
        device.executeShellCommand("am force-stop $packageName")
        device.executeShellCommand("pm clear $packageName")
        val arg = if (lock == Lock.PIN) " --arg pin" else ""
        val out = device.executeShellCommand("content call --uri content://$packageName.benchseed --method seed$arg")
        check("seeded" in out) { "seeding failed: $out" }
        device.executeShellCommand("am force-stop $packageName")
        current = lock
    }
}

private const val TIMEOUT = 15_000L

fun UiDevice.need(selector: BySelector, timeout: Long = TIMEOUT): UiObject2 =
    wait(Until.findObject(selector), timeout) ?: error("not found on screen: $selector\n${screenText()}")

/** What's on screen, for failure messages. */
private fun UiDevice.screenText(): String {
    val out = java.io.ByteArrayOutputStream()
    dumpWindowHierarchy(out)
    return Regex("""(?:text|content-desc)="([^"]+)"""").findAll(out.toString()).joinToString(" | ") { it.groupValues[1] }
}

/** The chat list has drawn its chats. */
fun MacrobenchmarkScope.waitForChatList() {
    device.need(By.text(Seeded.LONG_CHAT))
}

fun MacrobenchmarkScope.unlockWithPin() {
    device.need(By.text("Enter your PIN"))
    for (d in Seeded.PIN) {
        device.need(By.text(d.toString())).click()
    }
    device.need(By.desc("Done")).click()
    // Argon2id (64 MiB) runs here, and is slow on an emulator.
    device.need(By.text(Seeded.LONG_CHAT), 60_000)
}

/** The biggest scrollable on screen: the chat list or the conversation. */
fun UiDevice.mainList(): UiObject2 {
    need(By.scrollable(true))
    return findObjects(By.scrollable(true)).maxBy { it.visibleBounds.height() }
}

/**
 * A quick swipe on [list], then a wait for the fling to settle. [Direction.DOWN] shows content further down. Compose
 * lists don't send the accessibility events UiObject2.fling waits for, so this swipes directly.
 */
fun UiDevice.fling(list: UiObject2, direction: Direction) {
    val b = list.visibleBounds
    val x = b.centerX()
    val high = b.top + b.height() / 5
    val low = b.bottom - b.height() / 5
    if (direction == Direction.DOWN) {
        swipe(x, low, x, high, 6)
    } else {
        swipe(x, high, x, low, 6)
    }
    SystemClock.sleep(1200)
}

fun MacrobenchmarkScope.scrollChatList() {
    val list = device.mainList()
    device.fling(list, Direction.DOWN)
    device.fling(list, Direction.UP)
}

fun MacrobenchmarkScope.openChat(name: String) {
    device.need(By.text(name)).click()
    device.need(By.desc("Send"))
    SystemClock.sleep(500)
}

/** The conversation is bottom-anchored, so older messages are up. */
fun MacrobenchmarkScope.scrollConversation(times: Int = 3) {
    val list = device.mainList()
    repeat(times) { device.fling(list, Direction.UP) }
    repeat(times) { device.fling(list, Direction.DOWN) }
}

fun MacrobenchmarkScope.typeAndSend(text: String) {
    device.need(By.clazz("android.widget.EditText")).click()
    // Key events through the IME path, like real typing.
    device.executeShellCommand("input text ${text.replace(" ", "%s")}")
    device.need(By.desc("Send").enabled(true)).click()
    device.need(By.text(text))
    SystemClock.sleep(500)
}

/** Back from a chat to the chat list (the first back may only close the keyboard). */
fun MacrobenchmarkScope.backToChatList() {
    repeat(3) {
        if (device.hasObject(By.text("Chats"))) {
            return
        }
        device.pressBack()
        SystemClock.sleep(400)
    }
    device.need(By.text("Chats"))
}

fun MacrobenchmarkScope.openSettings() {
    device.need(By.text("Settings")).click()
    device.need(By.text("Appearance"))
    val list = device.mainList()
    device.fling(list, Direction.DOWN)
    device.fling(list, Direction.UP)
    device.need(By.text("Chats")).click()
    waitForChatList()
}
