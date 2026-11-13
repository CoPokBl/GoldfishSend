package app.goldfishsend.net

import org.bouncycastle.crypto.digests.SHA3Digest

/** How the app reaches GoldfishSend servers. */
enum class ProxyMode {
    /** A normal connection. The server sees this device's IP address. */
    DIRECT,

    /** Tor built into the app (Guardian Project tor-android, running in-process). */
    EMBEDDED_TOR,

    /** An external Tor app (Orbot) on its default SOCKS port, 127.0.0.1:9050. */
    ORBOT,
}

/** Where a request may go. [Blocked] means fail closed: never fall back to a direct connection. */
sealed interface Route {
    data object Direct : Route

    data class Socks(val host: String, val port: Int) : Route

    data class Blocked(val reason: BlockReason) : Route
}

enum class BlockReason {
    /** An .onion server was requested but Tor is off. */
    TOR_REQUIRED,

    /** Built-in Tor is selected but hasn't finished connecting yet. */
    TOR_STARTING,

    /** Plain http to something that isn't an onion service (outside debug builds). */
    CLEARTEXT,
}

/**
 * Pure networking rules, free of Android APIs so they can be unit-tested on the JVM.
 */
object NetRules {
    const val ORBOT_HOST = "127.0.0.1"
    const val ORBOT_PORT = 9050

    private const val BASE32 = "abcdefghijklmnopqrstuvwxyz234567"
    private val CHECKSUM_LABEL = ".onion checksum".toByteArray(Charsets.US_ASCII)

    fun isOnionHost(host: String): Boolean = host.lowercase().trimEnd('.').endsWith(".onion")

    /**
     * Validates a v3 onion hostname (optionally with subdomains, e.g. `www.<56 chars>.onion`): 56 base32 characters
     * that decode to pubkey(32) ‖ checksum(2) ‖ version(1), where version = 3 and
     * checksum = SHA3-256(".onion checksum" ‖ pubkey ‖ version)[0..2] (Tor rend-spec-v3).
     */
    fun isValidV3Onion(host: String): Boolean {
        val h = host.lowercase().trimEnd('.')
        if (!h.endsWith(".onion")) {
            return false
        }
        val label = h.removeSuffix(".onion").substringAfterLast('.')
        if (label.length != 56) {
            return false
        }
        val bytes = base32Decode(label) ?: return false
        if (bytes.size != 35 || bytes[34] != 3.toByte()) {
            return false
        }
        val digest = SHA3Digest(256)
        digest.update(CHECKSUM_LABEL, 0, CHECKSUM_LABEL.size)
        digest.update(bytes, 0, 32)
        digest.update(bytes[34])
        val out = ByteArray(32)
        digest.doFinal(out, 0)
        return out[0] == bytes[32] && out[1] == bytes[33]
    }

    /**
     * Picks the route for a request to [host] over [scheme].
     *
     * @param torPort the built-in Tor SOCKS port, or 0 if it isn't ready.
     * @param allowHttp debug builds allow plain http to any host (local development servers).
     */
    fun route(mode: ProxyMode, host: String, scheme: String, torPort: Int, allowHttp: Boolean = false): Route {
        val onion = isOnionHost(host)
        if (onion && mode == ProxyMode.DIRECT) {
            return Route.Blocked(BlockReason.TOR_REQUIRED)
        }
        if (scheme == "http" && !onion && !allowHttp) {
            return Route.Blocked(BlockReason.CLEARTEXT)
        }
        return when (mode) {
            ProxyMode.DIRECT -> Route.Direct
            ProxyMode.ORBOT -> Route.Socks(ORBOT_HOST, ORBOT_PORT)
            ProxyMode.EMBEDDED_TOR -> if (torPort > 0) Route.Socks("127.0.0.1", torPort) else Route.Blocked(BlockReason.TOR_STARTING)
        }
    }

    /**
     * Server URLs: https anywhere, and also plain http to a valid v3 onion service, whose onion address already
     * authenticates and encrypts the connection end to end.
     */
    /** See ServerApi.isValidContactServer: https on 443, or a v3 onion (http on 80 or https on 443). */
    fun isAcceptableContactServer(scheme: String, host: String, port: Int, allowHttp: Boolean): Boolean {
        if (allowHttp) {
            return isAcceptableServerScheme(scheme, host, true)
        }
        return when {
            isOnionHost(host) -> isValidV3Onion(host) && ((scheme == "http" && port == 80) || (scheme == "https" && port == 443))
            else -> scheme == "https" && port == 443
        }
    }

    fun isAcceptableServerScheme(scheme: String, host: String, allowHttp: Boolean): Boolean = when (scheme) {
        "https" -> !isOnionHost(host) || isValidV3Onion(host)
        "http" -> allowHttp || isValidV3Onion(host)
        else -> false
    }

    private fun base32Decode(s: String): ByteArray? {
        var buffer = 0L
        var bits = 0
        val out = java.io.ByteArrayOutputStream(s.length * 5 / 8)
        for (c in s) {
            val v = BASE32.indexOf(c)
            if (v < 0) {
                return null
            }
            buffer = (buffer shl 5) or v.toLong()
            bits += 5
            if (bits >= 8) {
                bits -= 8
                out.write(((buffer shr bits) and 0xFF).toInt())
            }
        }
        return out.toByteArray()
    }
}
