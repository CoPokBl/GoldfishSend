package app.goldfishsend.baselineprofile

import androidx.benchmark.macro.BaselineProfileMode
import androidx.benchmark.macro.CompilationMode
import androidx.benchmark.macro.ExperimentalMetricApi
import androidx.benchmark.macro.FrameTimingMetric
import androidx.benchmark.macro.MacrobenchmarkScope
import androidx.benchmark.macro.StartupMode
import androidx.benchmark.macro.StartupTimingMetric
import androidx.benchmark.macro.TraceSectionMetric
import androidx.benchmark.macro.junit4.MacrobenchmarkRule
import androidx.test.filters.LargeTest
import androidx.test.uiautomator.By
import androidx.test.uiautomator.Direction
import androidx.test.uiautomator.Until
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.Parameterized

/**
 * Macrobenchmarks for the journeys the baseline profile covers, each without AOT compilation ([CompilationMode.None])
 * and with the baseline profile. Run with `./gradlew :baselineprofile:connectedBenchmarkReleaseAndroidTest`
 * (see README.md, "Baseline profiles").
 */
@LargeTest
@RunWith(Parameterized::class)
@OptIn(ExperimentalMetricApi::class)
class Benchmarks(private val compilation: CompilationMode) {
    @get:Rule
    val rule = MacrobenchmarkRule()

    @Test
    fun coldStart() = startup(StartupMode.COLD)

    @Test
    fun warmStart() = startup(StartupMode.WARM)

    private fun startup(mode: StartupMode) = rule.measureRepeated(
        packageName = targetPackage,
        metrics = listOf(StartupTimingMetric()),
        compilationMode = compilation,
        startupMode = mode,
        iterations = ITERATIONS,
        setupBlock = {
            Seed.ensure(device, packageName, Lock.NONE)
            pressHome()
        },
    ) {
        startActivityAndWait()
        waitForChatList()
    }

    /** Cold start to the lock screen, then unlocking with the app PIN until the chat list shows. */
    @Test
    fun coldStartLockedAndUnlock() = rule.measureRepeated(
        packageName = targetPackage,
        metrics = listOf(StartupTimingMetric(), TraceSectionMetric("gf.unlock"), TraceSectionMetric("gf.chatList", TraceSectionMetric.Mode.First)),
        compilationMode = compilation,
        startupMode = StartupMode.COLD,
        iterations = ITERATIONS,
        setupBlock = {
            Seed.ensure(device, packageName, Lock.PIN)
            pressHome()
        },
    ) {
        startActivityAndWait()
        unlockWithPin()
    }

    @Test
    fun scrollChatList() = rule.measureRepeated(
        packageName = targetPackage,
        metrics = listOf(FrameTimingMetric()),
        compilationMode = compilation,
        iterations = ITERATIONS,
        setupBlock = { atChatList() },
    ) {
        val list = device.mainList()
        repeat(2) {
            device.fling(list, Direction.DOWN)
            device.fling(list, Direction.UP)
        }
    }

    @Test
    fun openChat() = rule.measureRepeated(
        packageName = targetPackage,
        metrics = listOf(
            FrameTimingMetric(),
            TraceSectionMetric("gf.messages", TraceSectionMetric.Mode.First),
            TraceSectionMetric("gf.messages", TraceSectionMetric.Mode.Sum),
        ),
        compilationMode = compilation,
        iterations = ITERATIONS,
        setupBlock = { atChatList() },
    ) {
        openChat(Seeded.LONG_CHAT)
        device.need(By.desc("Send"))
    }

    @Test
    fun scrollConversation() = rule.measureRepeated(
        packageName = targetPackage,
        metrics = listOf(FrameTimingMetric()),
        compilationMode = compilation,
        iterations = ITERATIONS,
        setupBlock = {
            atChatList()
            openChat(Seeded.LONG_CHAT)
        },
    ) {
        scrollConversation(times = 3)
    }

    /** Typing and sending in the long conversation: its frames, and how long re-loading the chat after a send takes. */
    @Test
    fun sendMessage() = rule.measureRepeated(
        packageName = targetPackage,
        metrics = listOf(
            FrameTimingMetric(),
            // Reports the count too.
            TraceSectionMetric("gf.messages", TraceSectionMetric.Mode.Sum),
        ),
        compilationMode = compilation,
        iterations = ITERATIONS,
        setupBlock = {
            atChatList()
            openChat(Seeded.LONG_CHAT)
        },
    ) {
        typeAndSend("Benchmark message ${++sent}")
    }

    /** A started app showing the chat list (started cold in the first iteration only). */
    private fun MacrobenchmarkScope.atChatList() {
        Seed.ensure(device, packageName, Lock.NONE)
        if (device.currentPackageName == packageName) {
            backToChatList()
        }
        // Not running, or the list was left scrolled: start again from the top.
        if (device.wait(Until.hasObject(By.text(Seeded.LONG_CHAT)), 2_000) != true) {
            killProcess()
            startActivityAndWait()
        }
        waitForChatList()
    }

    companion object {
        private const val ITERATIONS = 10

        /** Makes each sent message unique, so the benchmark waits for the new one. */
        private var sent = 0

        @JvmStatic
        @Parameterized.Parameters(name = "{0}")
        fun modes(): List<CompilationMode> = listOf(
            CompilationMode.None(),
            CompilationMode.Partial(BaselineProfileMode.Require),
        )
    }
}
