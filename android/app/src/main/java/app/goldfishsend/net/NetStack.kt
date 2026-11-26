package app.goldfishsend.net

import android.content.Context
import app.goldfishsend.BuildConfig
import app.goldfishsend.core.Graph
import app.goldfishsend.core.NetPrefs
import app.goldfishsend.core.PinMismatch
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.ProxySelector
import java.net.SocketAddress
import java.net.URI
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.Interceptor
import okhttp3.Response

/** The request was refused before anything was sent. */
open class BlockedRequestException(val reason: String) : IOException(reason)

class TorRequiredException : BlockedRequestException("tor_required")

class TorStartingException : BlockedRequestException("tor_connecting")

class CleartextBlockedException : BlockedRequestException("insecure_server")

class PinMismatchException(val mismatch: PinMismatch) : BlockedRequestException("server_key_changed")

/** A pooled connection was made on another route (before a connection-mode change). It's closed, and nothing was sent. */
class StaleRouteException : IOException("stale route")

/**
 * Network policy for every request to a GoldfishSend server:
 * - [RouteInterceptor] (application level) picks Direct, Orbot or built-in Tor, and **fails closed**: it never
 *   falls back to a direct connection when Tor is selected or the target is an onion service.
 * - [TorProxySelector] supplies the proxy for each connection, re-evaluated every time.
 * - [PinInterceptor] (network level) checks that the connection is on the current route, and the TLS key against its
 *   trust-on-first-use pin, before a single byte of the request is written.
 */
object NetStack {
    /** How long a request waits for built-in Tor to finish connecting before failing (and being retried later). */
    private const val TOR_WAIT_MS = 45_000L

    fun currentMode(): ProxyMode = NetPrefs.proxyMode

    /** Starts or stops built-in Tor to match the setting. Call at startup and whenever the mode changes. */
    fun apply(ctx: Context) {
        if (currentMode() == ProxyMode.EMBEDDED_TOR) {
            TorManager.start(ctx)
        } else {
            TorManager.stop()
        }
    }

    /** Our own server as host:port (see [PinPolicy.hostKey]), parsed once per server URL. */
    @Volatile
    private var own: Pair<String, String?> = "" to null

    fun ownHostKey(): String? {
        val url = Graph.prefs.serverUrl
        own.takeIf { it.first == url }?.let { return it.second }
        val key = url.trim().trimEnd('/').plus("/").toHttpUrlOrNull()?.let { PinPolicy.hostKey(it.host, it.port) }
        own = url to key
        return key
    }

    fun isOwnServer(host: String, port: Int): Boolean = ownHostKey() == PinPolicy.hostKey(host, port)

    /** The route for a request to [host]:[port] right now. */
    fun routeFor(host: String, scheme: String, port: Int): Route {
        val mode = currentMode()
        val ownDirect = mode != ProxyMode.DIRECT && NetPrefs.torOnlyForContacts && isOwnServer(host, port)
        return NetRules.route(mode, host, scheme, TorManager.socksPort, BuildConfig.ALLOW_HTTP, ownDirect)
    }

    object RouteInterceptor : Interceptor {
        override fun intercept(chain: Interceptor.Chain): Response {
            val url = chain.request().url
            when (val r = routeFor(url.host, url.scheme, url.port)) {
                is Route.Blocked -> when (r.reason) {
                    BlockReason.TOR_REQUIRED -> throw TorRequiredException()
                    BlockReason.CLEARTEXT -> throw CleartextBlockedException()
                    BlockReason.TOR_STARTING -> if (TorManager.awaitReady(TOR_WAIT_MS) <= 0) {
                        throw TorStartingException()
                    }
                }
                else -> Unit
            }
            return chain.proceed(chain.request())
        }
    }

    /**
     * OkHttp falls back to a direct connection if a selector returns an empty list, so a blocked route returns a
     * proxy that can't connect (the discard port on loopback) instead. The connection fails, and nothing leaks.
     */
    object TorProxySelector : ProxySelector() {
        private val blackhole = Proxy(Proxy.Type.SOCKS, InetSocketAddress.createUnresolved("127.0.0.1", 9))

        override fun select(uri: URI?): List<Proxy> {
            val host = uri?.host ?: return listOf(blackhole)
            val scheme = uri.scheme ?: "https"
            val port = uri.port.takeIf { it > 0 } ?: if (scheme == "http") 80 else 443
            return when (val r = routeFor(host, scheme, port)) {
                Route.Direct -> listOf(Proxy.NO_PROXY)
                is Route.Socks -> listOf(Proxy(Proxy.Type.SOCKS, InetSocketAddress.createUnresolved(r.host, r.port)))
                is Route.Blocked -> listOf(blackhole)
            }
        }

        override fun connectFailed(uri: URI?, sa: SocketAddress?, ioe: IOException?) {
            TorManager.refresh()
        }
    }

    object PinInterceptor : Interceptor {
        override fun intercept(chain: Interceptor.Chain): Response {
            val request = chain.request()
            val url = request.url
            val connection = chain.connection()
            if (connection != null && !NetRules.proxyMatches(routeFor(url.host, url.scheme, url.port), connection.route().proxy)) {
                // Made before the mode changed (pooled, or in use when it changed). Closing the socket keeps OkHttp from
                // handing it out again; the request fails before anything is written, and is retried on a new connection.
                runCatching { connection.socket().close() }
                throw StaleRouteException()
            }
            val handshake = connection?.handshake()
            val leaf = handshake?.peerCertificates?.firstOrNull()
            if (leaf != null) {
                val hostKey = PinPolicy.hostKey(url.host, url.port)
                val presented = PinPolicy.pinOf(leaf)
                val onion = NetRules.isOnionHost(url.host)
                if (NetPrefs.pinServers && !onion && !NetPrefs.canCheckPins(hostKey)) {
                    throw BlockedRequestException("locked")
                }
                val decision = PinPolicy.decide(
                    enabled = NetPrefs.pinServers,
                    onion = onion,
                    stored = NetPrefs.pins(hostKey),
                    presented = presented,
                )
                when (decision) {
                    is PinPolicy.Decision.Mismatch -> {
                        val m = PinMismatch(hostKey, decision.expected, decision.presented)
                        NetPrefs.reportMismatch(m)
                        throw PinMismatchException(m)
                    }
                    is PinPolicy.Decision.RecordFirst -> NetPrefs.recordFirstPin(hostKey, decision.pin)
                    else -> Unit
                }
            }
            return chain.proceed(request)
        }
    }
}
