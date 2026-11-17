package app.goldfishsend

import app.goldfishsend.net.NetRules
import app.goldfishsend.proto.PushEnvelope
import app.goldfishsend.proto.Sanitize
import app.goldfishsend.security.Presence
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SanitizeTest {
    @Test
    fun namesLoseBidiAndControlCharacters() {
        assertEquals("Alice", Sanitize.name("‮Alice‬"))
        assertEquals("evil apk", Sanitize.name("evil\u0000\u0007 ⁦apk⁩"))
        assertEquals("a b", Sanitize.name("  a \n\t  b  "))
        assertNull(Sanitize.name("‎‏؜"))
        assertNull(Sanitize.name(null))
        assertEquals("Zoë 🐟", Sanitize.name("Zoë 🐟"))
    }

    @Test
    fun namesAreCappedByCodePoint() {
        val long = "🐟".repeat(100)
        assertEquals(Sanitize.MAX_NAME, Sanitize.name(long)!!.codePointCount(0, Sanitize.name(long)!!.length))
    }

    @Test
    fun timestampsAreClamped() {
        val now = 1_000_000_000_000L
        assertEquals(now, Sanitize.timestamp(now + 999_999, now))
        assertEquals(now - Sanitize.MAX_BACKDATE_MS, Sanitize.timestamp(0, now))
        assertEquals(now - 5000, Sanitize.timestamp(now - 5000, now))
    }

    @Test
    fun localTimerIsTheCeiling() {
        assertEquals(3600, Sanitize.effectiveTimer(3600, 86400))
        assertEquals(60, Sanitize.effectiveTimer(3600, 60))
        // Sender omits exp: the chat timer still applies.
        assertEquals(3600, Sanitize.effectiveTimer(3600, null))
        assertEquals(3600, Sanitize.effectiveTimer(3600, 0))
        // No local timer: the sender's request applies.
        assertEquals(60, Sanitize.effectiveTimer(0, 60))
        assertEquals(0, Sanitize.effectiveTimer(0, null))
        assertEquals(Sanitize.MAX_TIMER_SECS, Sanitize.effectiveTimer(0, Long.MAX_VALUE))
    }
}

class PresenceTest {
    private val day = 86_400_000L

    @Test
    fun sameBootUsesElapsedTimeSoClockChangesDontMatter() {
        val last = Presence.Mark(wallMs = 10 * day, elapsedMs = 1000, bootCount = 7)
        // Wall clock wound back by 9 days, but 8 days have really passed on this boot.
        assertTrue(Presence.shouldWipe(last, 7, nowWallMs = 1 * day, nowElapsedMs = 1000 + 8 * day, bootCount = 7))
        assertFalse(Presence.shouldWipe(last, 7, nowWallMs = 100 * day, nowElapsedMs = 1000 + day, bootCount = 7))
    }

    @Test
    fun afterRebootTimeSinceBootIsALowerBound() {
        val last = Presence.Mark(wallMs = 50 * day, elapsedMs = 5 * day, bootCount = 3)
        // Clock wound back after a reboot: the 8 days since boot still count.
        assertTrue(Presence.shouldWipe(last, 7, nowWallMs = 40 * day, nowElapsedMs = 8 * day, bootCount = 4))
        assertEquals(10 * day, Presence.absentMs(last, nowWallMs = 60 * day, nowElapsedMs = 1000, bootCount = 4))
    }

    @Test
    fun offOrUnknownNeverWipes() {
        assertFalse(Presence.shouldWipe(null, 7, 1000 * day, 1000 * day, 1))
        val last = Presence.Mark(0, 0, 1)
        assertFalse(Presence.shouldWipe(last, 0, 1000 * day, 1000 * day, 1))
    }
}

class ProtocolUpdatesTest {
    @Test
    fun paddedVerificationBodiesUseTheFirst16Bytes() {
        val tag = ByteArray(8) { 1 }
        val code = ByteArray(16) { (it + 1).toByte() }
        val padded = code + ByteArray(200) { 7 }
        val env = PushEnvelope.parse(PushEnvelope.build(PushEnvelope.TYPE_VERIFICATION, tag, padded))
        assertTrue(env is PushEnvelope.Verification)
        assertArrayEquals(code, (env as PushEnvelope.Verification).code)
        assertNotNull(PushEnvelope.parse(PushEnvelope.build(PushEnvelope.TYPE_VERIFICATION, tag, code)))
        assertNull(PushEnvelope.parse(PushEnvelope.build(PushEnvelope.TYPE_VERIFICATION, tag, ByteArray(15))))
    }

    @Test
    fun contactServersMustUseStandardPorts() {
        val onion = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"
        assertTrue(NetRules.isAcceptableContactServer("https", "relay.example.org", 443, false))
        assertFalse(NetRules.isAcceptableContactServer("https", "relay.example.org", 8443, false))
        assertFalse(NetRules.isAcceptableContactServer("http", "relay.example.org", 80, false))
        assertTrue(NetRules.isAcceptableContactServer("http", onion, 80, false))
        assertFalse(NetRules.isAcceptableContactServer("http", onion, 6379, false))
        assertFalse(NetRules.isAcceptableContactServer("http", "notreal.onion", 80, false))
    }
}
