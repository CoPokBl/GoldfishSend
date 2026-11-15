package app.goldfishsend

import app.goldfishsend.proto.Pow
import app.goldfishsend.ui.components.IndicatorTiming
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ProgressTimingTest {
    @Test
    fun fastWorkNeverShowsAnIndicator() {
        val t = IndicatorTiming(150, 300)
        assertEquals(1150L, t.update(true, 1000))
        assertFalse(t.visible)
        assertNull(t.update(false, 1100))
        assertFalse(t.visible)
    }

    @Test
    fun slowWorkShowsItAfterTheDelayAndKeepsItForTheMinimum() {
        val t = IndicatorTiming(150, 300)
        assertEquals(1150L, t.update(true, 1000))
        // Called back on time.
        assertNull(t.update(true, 1150))
        assertTrue(t.visible)
        // Finished 50 ms after the indicator appeared: it stays until 300 ms have passed.
        assertEquals(1450L, t.update(false, 1200))
        assertTrue(t.visible)
        assertNull(t.update(false, 1450))
        assertFalse(t.visible)
    }

    @Test
    fun longWorkHidesAsSoonAsItEnds() {
        val t = IndicatorTiming(150, 300)
        t.update(true, 0)
        t.update(true, 150)
        assertNull(t.update(false, 5000))
        assertFalse(t.visible)
    }

    @Test
    fun restartingWhileStillShownKeepsItWithoutAnotherDelay() {
        val t = IndicatorTiming(150, 300)
        t.update(true, 0)
        t.update(true, 150)
        t.update(false, 200)
        assertNull(t.update(true, 250))
        assertTrue(t.visible)
    }

    @Test
    fun aNewRunWaitsForItsOwnDelay() {
        val t = IndicatorTiming(150, 300)
        t.update(true, 0)
        t.update(false, 100)
        // The delay counts from the new start, not the old one.
        assertEquals(1150L, t.update(true, 1000))
        assertFalse(t.visible)
    }

    @Test
    fun powProgressRisesAndNeverCompletes() {
        assertEquals(0f, Pow.estimatedProgress(0, 20), 0f)
        var last = 0f
        for (h in listOf(1L shl 10, 1L shl 16, 1L shl 19, 1L shl 20, 1L shl 21, 1L shl 24, 1L shl 30)) {
            val p = Pow.estimatedProgress(h, 20)
            assertTrue("$h: $p", p >= last)
            assertTrue(p < 1f)
            last = p
        }
        // About 80% after the expected number of tries.
        assertEquals(0.8f, Pow.estimatedProgress(1L shl 20, 20), 0.03f)
        // Absurd difficulties don't overflow.
        assertTrue(Pow.estimatedProgress(Long.MAX_VALUE, 200) in 0f..1f)
    }
}
