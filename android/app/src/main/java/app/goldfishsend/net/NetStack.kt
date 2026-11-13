package app.goldfishsend.net

import android.content.Context
import app.goldfishsend.BuildConfig
import app.goldfishsend.core.NetPrefs
import app.goldfishsend.core.PinMismatch
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.ProxySelector
import java.net.SocketAddress
import java.net.URI
import okhttp3.Interceptor
import okhttp3.Response

/** The request was refused before anything was sent. */
open class BlockedRequestException(val reason: String) : IOException(reason)

class TorRequiredException : BlockedRequestException("tor_required")

class TorStartingException : BlockedRequestException("tor_connecting")

class CleartextBlockedException : BlockedRequestException("insecure_server")

class PinMismatchException(val mismatch: PinMismatch) : BlockedRequestException("server_key_changed")

/**
 * Network policy for every request to a GoldfishSend server:
 * - [RouteInterceptor] (application level) picks Direct, Orbot or built-in Tor, and **fails closed**: it never
 *   falls back to a direct connection when Tor is selected or the target is an onion service.
 * - [TorProxySelector] supplies the proxy for each connection, re-evaluated every time.
 * - [PinInterceptor] (network level) checks the TLS key against its trust-on-first-use pin before a single byte of
 *   the request is written.
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

    object RouteInterceptor : Interceptor {
        override fun intercept(chain: Interceptor.Chain): Response {
            val url = chain.request().url
            val mode = currentMode()
            when (val r = NetRules.route(mode, url.host, url.scheme, TorManager.socksPort, BuildConfig.ALLOW_HTTP)) {
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
            return when (val r = NetRules.route(currentMode(), host, scheme, TorManager.socksPort, BuildConfig.ALLOW_HTTP)) {
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
            val handshake = chain.connection()?.handshake()
            val leaf = handshake?.peerCertificates?.firstOrNull()
            if (leaf != null) {
                val url = request.url
                val hostKey = PinPolicy.hostKey(url.host, url.port)
                val presented = PinPolicy.pinOf(leaf)
                val decision = PinPolicy.decide(
                    enabled = NetPrefs.pinServers,
                    onion = NetRules.isOnionHost(url.host),
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
