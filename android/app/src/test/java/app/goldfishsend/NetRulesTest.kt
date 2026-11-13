package app.goldfishsend

import app.goldfishsend.net.BlockReason
import app.goldfishsend.net.NetRules
import app.goldfishsend.net.PinPolicy
import app.goldfishsend.net.ProxyMode
import app.goldfishsend.net.Route
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NetRulesTest {
    /** Computed independently with Python: pubkey = bytes 0..31, version 3, SHA3-256 checksum. */
    private val onion = "aaaqeayeaudaocajbifqydiob4ibceqtcqkrmfyydenbwha5dyp3kead.onion"

    /** Same address with one checksum bit flipped. */
    private val badChecksum = "aaaqeayeaudaocajbifqydiob4ibceqtcqkrmfyydenbwha5dyp3iead.onion"

    @Test
    fun validV3OnionAddresses() {
        assertTrue(NetRules.isValidV3Onion(onion))
        assertTrue(NetRules.isValidV3Onion(onion.uppercase()))
        assertTrue(NetRules.isValidV3Onion("www.$onion"))
        assertTrue(NetRules.isValidV3Onion("$onion."))
    }

    @Test
    fun invalidOnionAddressesAreRejected() {
        assertFalse(NetRules.isValidV3Onion(badChecksum))
        assertFalse(NetRules.isValidV3Onion("expyuzz4wqqyqhjn.onion")) // v2: retired
        assertFalse(NetRules.isValidV3Onion(onion.replace('a', '1'))) // '1' isn't base32
        assertFalse(NetRules.isValidV3Onion(onion.removeSuffix(".onion")))
        assertFalse(NetRules.isValidV3Onion("example.com"))
        // A wrong version byte (3 → 4) breaks the version check.
        assertFalse(NetRules.isValidV3Onion(onion.dropLast(".onion".length + 1) + "e.onion"))
    }

    @Test
    fun serverSchemeRules() {
        assertTrue(NetRules.isAcceptableServerScheme("https", "relay.example.org", allowHttp = false))
        assertFalse(NetRules.isAcceptableServerScheme("http", "relay.example.org", allowHttp = false))
        assertTrue(NetRules.isAcceptableServerScheme("http", "relay.example.org", allowHttp = true))
        assertTrue(NetRules.isAcceptableServerScheme("http", onion, allowHttp = false))
        assertTrue(NetRules.isAcceptableServerScheme("https", onion, allowHttp = false))
        assertFalse(NetRules.isAcceptableServerScheme("http", badChecksum, allowHttp = false))
        assertFalse(NetRules.isAcceptableServerScheme("ftp", onion, allowHttp = true))
    }

    @Test
    fun directModeRefusesOnionServices() {
        assertEquals(Route.Blocked(BlockReason.TOR_REQUIRED), NetRules.route(ProxyMode.DIRECT, onion, "http", 0))
        assertEquals(Route.Direct, NetRules.route(ProxyMode.DIRECT, "relay.example.org", "https", 0))
    }

    @Test
    fun orbotAlwaysUsesItsSocksPort() {
        assertEquals(Route.Socks("127.0.0.1", 9050), NetRules.route(ProxyMode.ORBOT, "relay.example.org", "https", 0))
        assertEquals(Route.Socks("127.0.0.1", 9050), NetRules.route(ProxyMode.ORBOT, onion, "http", 0))
    }

    @Test
    fun builtInTorFailsClosedUntilReady() {
        assertEquals(Route.Blocked(BlockReason.TOR_STARTING), NetRules.route(ProxyMode.EMBEDDED_TOR, "relay.example.org", "https", 0))
        assertEquals(Route.Blocked(BlockReason.TOR_STARTING), NetRules.route(ProxyMode.EMBEDDED_TOR, onion, "http", 0))
        assertEquals(Route.Socks("127.0.0.1", 39123), NetRules.route(ProxyMode.EMBEDDED_TOR, "relay.example.org", "https", 39123))
    }

    @Test
    fun cleartextOnlyToOnionsOutsideDebug() {
        for (mode in ProxyMode.entries) {
            assertEquals(mode.name, Route.Blocked(BlockReason.CLEARTEXT), NetRules.route(mode, "relay.example.org", "http", 9999))
        }
        assertEquals(Route.Direct, NetRules.route(ProxyMode.DIRECT, "10.0.2.2", "http", 0, allowHttp = true))
    }
}

class PinPolicyTest {
    private val a = "sha256/AAAA"
    private val b = "sha256/BBBB"

    @Test
    fun offOrOnionSkips() {
        assertEquals(PinPolicy.Decision.Skip, PinPolicy.decide(enabled = false, onion = false, stored = setOf(a), presented = b))
        assertEquals(PinPolicy.Decision.Skip, PinPolicy.decide(enabled = true, onion = true, stored = setOf(a), presented = b))
    }

    @Test
    fun firstUseIsRecorded() {
        assertEquals(PinPolicy.Decision.RecordFirst(a), PinPolicy.decide(enabled = true, onion = false, stored = null, presented = a))
        assertEquals(PinPolicy.Decision.RecordFirst(a), PinPolicy.decide(enabled = true, onion = false, stored = emptySet(), presented = a))
    }

    @Test
    fun matchingKeyIsAccepted() {
        assertEquals(PinPolicy.Decision.Accept, PinPolicy.decide(enabled = true, onion = false, stored = setOf(a, b), presented = b))
    }

    @Test
    fun changedKeyIsAMismatch() {
        assertEquals(
            PinPolicy.Decision.Mismatch(setOf(a), b),
            PinPolicy.decide(enabled = true, onion = false, stored = setOf(a), presented = b),
        )
    }

    @Test
    fun pinFormatMatchesOpenSslPipeline() {
        // sha256("") in base64, as `openssl dgst -sha256 -binary | openssl enc -base64` prints it.
        assertEquals("sha256/47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=", PinPolicy.pinOfSpki(ByteArray(0)))
        assertEquals("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=", PinPolicy.displayFingerprint(PinPolicy.pinOfSpki(ByteArray(0))))
        assertEquals("relay.example.org:443", PinPolicy.hostKey("Relay.Example.ORG", 443))
    }
}
