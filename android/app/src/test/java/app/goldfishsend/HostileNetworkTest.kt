package app.goldfishsend

import app.goldfishsend.core.Outbox
import app.goldfishsend.core.PowBudget
import app.goldfishsend.core.Prefs
import app.goldfishsend.net.NetRules
import app.goldfishsend.net.ProxyMode
import app.goldfishsend.net.Route
import app.goldfishsend.net.ServerApi
import java.net.InetSocketAddress
import java.net.Proxy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Client-side limits on what a hostile server (often a contact's own) can make the app do. */
class HostileNetworkTest {
    private val hour = 3600_000L
    private val now = 1_800_000_000_000L

    // --- backoff ---

    @Test
    fun aHugeRetryAfterNeitherOverflowsNorStallsForEver() {
        // 9223372036854775 s × 1000 is just under Long.MAX_VALUE: added to the clock it used to wrap into the past.
        for (ra in listOf(9_223_372_036_854_775L, Long.MAX_VALUE, Long.MAX_VALUE / 1000 + 1)) {
            val d = Outbox.backoffDelayMs(1, ra, 0)
            assertEquals(ServerApi.MAX_RETRY_AFTER_SECONDS * 1000, d)
            assertTrue(System.currentTimeMillis() + d > System.currentTimeMillis())
        }
    }

    @Test
    fun aNegativeRetryAfterFallsBackToTheNormalBackoff() {
        assertEquals(10_000L, Outbox.backoffDelayMs(1, -5, 0))
        assertEquals(10_000L, Outbox.backoffDelayMs(1, null, 0))
        assertEquals(30 * 60_000L, Outbox.backoffDelayMs(50, null, 0))
        assertEquals(120_000L, Outbox.backoffDelayMs(1, 120, 0))
    }

    @Test
    fun retryAfterIsClamped() {
        assertNull(ServerApi.clampRetryAfter(null))
        assertEquals(1L, ServerApi.clampRetryAfter(-1))
        assertEquals(ServerApi.MAX_RETRY_AFTER_SECONDS, ServerApi.clampRetryAfter(Long.MAX_VALUE))
        assertEquals(30L, ServerApi.clampRetryAfter(30))
    }

    // --- proof-of-work budget ---

    @Test
    fun oneServerGetsTwoWorstCaseSolvesThenWaits() {
        var st = PowBudget.State()
        repeat(2) {
            val (next, wait) = PowBudget.charge(st, "https://evil.example", PowBudget.MAX_SOLVE, now)
            assertNotNull(next)
            assertEquals(0L, wait)
            st = next!!
        }
        val (refused, wait) = PowBudget.charge(st, "https://evil.example", PowBudget.MAX_SOLVE, now)
        assertNull(refused)
        assertEquals(PowBudget.SERVER_REFILL_MS, wait)
        // It refills by one worst-case solve per period.
        assertNotNull(PowBudget.charge(st, "https://evil.example", PowBudget.MAX_SOLVE, now + PowBudget.SERVER_REFILL_MS).first)
    }

    @Test
    fun manyServersShareOneBudget() {
        var st = PowBudget.State()
        for (i in 0 until 2) {
            st = PowBudget.charge(st, "https://s$i.example", PowBudget.MAX_SOLVE, now).first!!
        }
        val (refused, wait) = PowBudget.charge(st, "https://s9.example", PowBudget.MAX_SOLVE, now)
        assertNull(refused)
        assertEquals(PowBudget.GLOBAL_REFILL_MS, wait)
    }

    @Test
    fun normalSendChallengesStillGetThrough() {
        // The default send challenge: 6 bits of 16 MiB, t = 1.
        val normal = (1L shl 6) * 16 * 1024
        var st = PowBudget.State()
        var paid = 0
        var t = now
        // A day of a paid send every 10 minutes to one server.
        repeat(144) {
            val (next, _) = PowBudget.charge(st, "https://friend.example", normal, t)
            if (next != null) {
                st = next
                paid++
            }
            t += 10 * 60_000L
        }
        assertEquals(144, paid)
    }

    @Test
    fun aServerThatRefusesAPaidSendCoolsDown() {
        var st = PowBudget.charge(PowBudget.State(), "https://evil.example", 1024, now).first!!
        st = PowBudget.refused(st, "https://evil.example", now)
        val (refused, wait) = PowBudget.charge(st, "https://evil.example", 1024, now + hour)
        assertNull(refused)
        assertEquals(PowBudget.REFUSED_COOLDOWN_MS - hour, wait)
        assertNotNull(PowBudget.charge(st, "https://evil.example", 1024, now + PowBudget.REFUSED_COOLDOWN_MS).first)
        // Others aren't affected.
        assertNotNull(PowBudget.charge(st, "https://friend.example", 1024, now + hour).first)
    }

    @Test
    fun budgetForgetsServersOnceTheyAreFullAgainAndSurvivesClockJumps() {
        val st = PowBudget.charge(PowBudget.State(), "https://friend.example", 1024, now).first!!
        assertEquals(setOf("https://friend.example"), st.servers.keys)
        val later = PowBudget.prune(st, now + PowBudget.SERVER_REFILL_MS)
        assertTrue(later.servers.isEmpty())
        assertNull(later.global)
        // A clock that went backwards refills nothing, and one far ahead can't overflow.
        assertEquals(PowBudget.CAPACITY - 1024, PowBudget.level(st.servers.values.first(), PowBudget.SERVER_REFILL_MS, now - 10 * hour))
        assertEquals(PowBudget.CAPACITY, PowBudget.level(st.servers.values.first(), PowBudget.SERVER_REFILL_MS, Long.MAX_VALUE))
    }

    // --- routing ---

    @Test
    fun torOnlyForOtherPeoplesServers() {
        val onion = "aaaqeayeaudaocajbifqydiob4ibceqtcqkrmfyydenbwha5dyp3kead.onion"
        // Our own server, with the option on: direct.
        assertEquals(Route.Direct, NetRules.route(ProxyMode.ORBOT, "own.example", "https", 0, ownServerDirect = true))
        assertEquals(Route.Direct, NetRules.route(ProxyMode.EMBEDDED_TOR, "own.example", "https", 0, ownServerDirect = true))
        // Everyone else's still goes through Tor.
        assertEquals(Route.Socks(NetRules.ORBOT_HOST, NetRules.ORBOT_PORT), NetRules.route(ProxyMode.ORBOT, "contact.example", "https", 0))
        // An onion server is never reached directly, own or not, and plain http stays refused.
        assertEquals(Route.Socks(NetRules.ORBOT_HOST, NetRules.ORBOT_PORT), NetRules.route(ProxyMode.ORBOT, onion, "http", 0, ownServerDirect = true))
        assertTrue(NetRules.route(ProxyMode.ORBOT, "own.example", "http", 0, ownServerDirect = true) is Route.Blocked)
    }

    @Test
    fun aConnectionMadeOnAnotherRouteDoesNotMatch() {
        val socks = Proxy(Proxy.Type.SOCKS, InetSocketAddress.createUnresolved("127.0.0.1", 9050))
        assertTrue(NetRules.proxyMatches(Route.Direct, Proxy.NO_PROXY))
        assertFalse(NetRules.proxyMatches(Route.Direct, socks))
        assertTrue(NetRules.proxyMatches(Route.Socks("127.0.0.1", 9050), socks))
        // Switched Direct -> Tor: the pooled direct connection must not be reused.
        assertFalse(NetRules.proxyMatches(Route.Socks("127.0.0.1", 9050), Proxy.NO_PROXY))
        // Built-in Tor restarted on another port.
        assertFalse(NetRules.proxyMatches(Route.Socks("127.0.0.1", 9150), socks))
        assertFalse(NetRules.proxyMatches(Route.Blocked(app.goldfishsend.net.BlockReason.TOR_STARTING), socks))
    }

    // --- our own server's pin ---

    @Test
    fun theBuiltInKeyBeatsOneOnlyTrustedOnFirstUse() {
        // Stored by a build without the key built in: the shipped key governs now.
        assertEquals("built", Prefs.effectiveServerKey("tofu", storedOnFirstUse = true, builtIn = "built"))
        assertEquals("built", Prefs.effectiveServerKey(null, storedOnFirstUse = false, builtIn = "built"))
        // One the user chose (typed, or a change they trusted) still wins.
        assertEquals("chosen", Prefs.effectiveServerKey("chosen", storedOnFirstUse = false, builtIn = "built"))
        // Another server: no built-in key.
        assertEquals("tofu", Prefs.effectiveServerKey("tofu", storedOnFirstUse = true, builtIn = null))
        assertNull(Prefs.effectiveServerKey(null, storedOnFirstUse = false, builtIn = null))
    }
}
