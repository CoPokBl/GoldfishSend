package app.goldfishsend

import app.goldfishsend.security.MemoryScrubber
import app.goldfishsend.ui.components.PinBuffer
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

class PinBufferTest {
    @Test
    fun pushPopTake() {
        val b = PinBuffer(maxLength = 8)
        "123456".forEach(b::push)
        b.pop()
        assertEquals(5, b.length)
        val out = b.take()
        assertArrayEquals("12345".toCharArray(), out)
        assertEquals(0, b.length)
    }

    @Test
    fun respectsMaxLength() {
        val b = PinBuffer(maxLength = 4)
        "1234567".forEach(b::push)
        assertArrayEquals("1234".toCharArray(), b.take())
    }

    @Test
    fun clearLeavesNothingBehind() {
        val b = PinBuffer(maxLength = 4)
        "9876".forEach(b::push)
        b.clear()
        assertEquals(0, b.length)
        // A later take must not return the cleared digits.
        assertEquals(0, b.take().size)
    }

    @Test
    fun popOnEmptyIsSafe() {
        val b = PinBuffer()
        b.pop()
        assertEquals(0, b.length)
    }
}

class MemoryScrubberTest {
    @Test
    fun scrubCompletesWithoutExhaustingTheHeap() {
        MemoryScrubber.scrub(targetFraction = 0.2, chunkBytes = 1 shl 16)
        // Still able to allocate normally afterwards.
        assertEquals(1024, ByteArray(1024).size)
    }
}
