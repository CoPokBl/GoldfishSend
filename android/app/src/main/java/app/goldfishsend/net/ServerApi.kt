package app.goldfishsend.net

import app.goldfishsend.BuildConfig
import app.goldfishsend.proto.B64
import java.io.IOException
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import okhttp3.ConnectionSpec
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okhttp3.TlsVersion

@Serializable
data class ServerInfo(
    val protocol: Int,
    val vapidPublicKey: String,
    val maxMessageBytes: Int,
    val maxInviteBytes: Int = 4096,
    val defaultTtlSeconds: Long = 259200,
    val maxTtlSeconds: Long = 1209600,
    val powDifficulty: Int = 0,
)

@Serializable
data class PowChallenge(val challenge: String, val difficulty: Int, val expiresAt: Long)

@Serializable
data class PowSolution(val challenge: String, val nonce: String)

@Serializable
data class CreateMailboxRequest(
    val pow: PowSolution,
    val sendSecret: String,
    val ownerHash: String,
    val endpoint: String,
    val p256dh: String,
    val auth: String,
)

@Serializable
data class MailboxItem(val sendSecret: String, val ownerSecret: String)

@Serializable
data class VerifyRequest(val items: List<MailboxItem>, val code: String)

@Serializable
data class RotateRequest(val items: List<MailboxItem>, val endpoint: String, val p256dh: String, val auth: String)

@Serializable
data class ItemsRequest(val items: List<MailboxItem>)

@Serializable
data class ExpiresResponse(val expiresAt: String)

@Serializable
data class IdResponse(val id: String)

@Serializable
private data class ErrorBody(val error: String = "unknown", val scope: String? = null)

/**
 * A failed server call. [code] is the protocol error code (or "network"/"http_<n>"), and [human] is a
 * friendly sentence that's safe to show users. Callers decide whether to retry using [retryable].
 */
class ApiException(
    val code: String,
    val status: Int,
    val retryAfterSeconds: Long? = null,
    cause: Throwable? = null,
    /** For `rate_limited`: which limit was hit, one of `ip`, `network`, `mailbox` or `global` (docs/protocol.md). */
    val scope: String? = null,
) : IOException("api error $code ($status)", cause) {
    /** Only the per-IP send limit can be paid off with a proof of work. Retrying any other scope just wastes CPU. */
    val powCanHelp: Boolean
        get() = status == 429 && scope == "ip"

    val retryable: Boolean
        get() = code == "network" || code == "rate_limited" || status >= 500 || status == 0

    val human: String
        get() = humanize(code)

    companion object {
        fun humanize(code: String): String = when (code) {
            "network" -> "Couldn't reach the server. We'll keep trying."
            "rate_limited" -> "Things are busy right now. We'll try again shortly."
            "not_found" -> "This contact can't be reached anymore."
            "too_large" -> "That message is too long."
            "mailbox_full" -> "Waiting for them to come back online."
            "invalid_endpoint", "endpoint_unreachable" -> "Your push service couldn't be reached. Check that it's running."
            "pow_invalid", "verification_failed" -> "Setup hiccup. Retrying automatically."
            "insecure_server" -> "That server isn't using a secure connection."
            "tor_required" -> "This contact's server is a Tor (.onion) address. Turn on Tor in Settings › Connection to reach it."
            "tor_connecting" -> "Connecting to Tor…"
            "server_key_changed" -> "This server's identity changed. Check Settings › Connection before continuing."
            else -> "Something went wrong. We'll try again."
        }
    }
}

/** One client per server base URL. All calls are suspend functions and run on Dispatchers.IO. */
class ServerApi(baseUrl: String, private val http: OkHttpClient) {
    private val base: HttpUrl = parseBase(baseUrl)

    suspend fun info(): ServerInfo = get("v1/info", ServerInfo.serializer())

    suspend fun powChallenge(): PowChallenge = postJson("v1/pow/challenge", null, PowChallenge.serializer())

    suspend fun createMailbox(req: CreateMailboxRequest) {
        postJson<Unit>("v1/mailboxes", Json.encodeToString(CreateMailboxRequest.serializer(), req), null)
    }

    suspend fun verify(items: List<MailboxItem>, code: ByteArray): ExpiresResponse =
        postJson("v1/mailboxes/verify", Json.encodeToString(VerifyRequest.serializer(), VerifyRequest(items, B64.enc(code))), ExpiresResponse.serializer())

    suspend fun rotate(req: RotateRequest) {
        send<Unit>("v1/mailboxes/endpoint", "PUT", Json.encodeToString(RotateRequest.serializer(), req), null)
    }

    suspend fun refresh(items: List<MailboxItem>): ExpiresResponse =
        postJson("v1/mailboxes/refresh", Json.encodeToString(ItemsRequest.serializer(), ItemsRequest(items)), ExpiresResponse.serializer())

    suspend fun delete(items: List<MailboxItem>) {
        postJson<Unit>("v1/mailboxes/delete", Json.encodeToString(ItemsRequest.serializer(), ItemsRequest(items)), null)
    }

    /**
     * Sends an E2E blob. [pow] is an optional solved challenge as "challenge.nonce" (b64u), which pays for the request when
     * the per-IP limit was hit (shared IPs, Tor). The body is always `application/octet-stream` (the server returns 415 otherwise).
     */
    suspend fun sendMessage(sendSecret: ByteArray, blob: ByteArray, idempotencyKey: ByteArray, ttlSeconds: Long?, pow: String? = null): String =
        withContext(Dispatchers.IO) {
            val b = Request.Builder()
                .url(url("v1/messages"))
                .header("GF-Send-Token", B64.enc(sendSecret))
                .header("GF-Idempotency-Key", B64.enc(idempotencyKey))
                .post(blob.toRequestBody(OCTET))
            if (ttlSeconds != null) {
                b.header("GF-TTL", ttlSeconds.toString())
            }
            if (pow != null) {
                b.header("GF-PoW", pow)
            }
            execute(b.build()) { r -> decode(r, IdResponse.serializer()).id }
        }

    suspend fun uploadInvite(blob: ByteArray, ttlSeconds: Long): String = withContext(Dispatchers.IO) {
        val req = Request.Builder()
            .url(url("v1/invites"))
            .header("GF-TTL", ttlSeconds.toString())
            .post(blob.toRequestBody(OCTET))
            .build()
        execute(req) { r -> decode(r, IdResponse.serializer()).id }
    }

    /** Returns the invite blob, or null if it was already used or has expired. */
    suspend fun fetchInvite(id: String): ByteArray? = withContext(Dispatchers.IO) {
        val req = Request.Builder().url(url("v1/invites/$id")).get().build()
        try {
            execute(req) { r -> r.body.bytes() }
        } catch (e: ApiException) {
            if (e.status == 404) null else throw e
        }
    }

    // --- plumbing ---

    private fun url(path: String): HttpUrl = base.resolve(path)!!

    private suspend fun <T> get(path: String, ser: KSerializer<T>): T = withContext(Dispatchers.IO) {
        execute(Request.Builder().url(url(path)).get().build()) { decode(it, ser) }
    }

    private suspend fun <T> postJson(path: String, json: String?, ser: KSerializer<T>?): T =
        send(path, "POST", json, ser)

    @Suppress("UNCHECKED_CAST")
    private suspend fun <T> send(path: String, method: String, json: String?, ser: KSerializer<T>?): T =
        withContext(Dispatchers.IO) {
            val body = (json ?: "").toRequestBody(JSON)
            execute(Request.Builder().url(url(path)).method(method, body).build()) { r ->
                if (ser == null) Unit as T else decode(r, ser)
            }
        }

    private fun <T> execute(req: Request, onOk: (Response) -> T): T {
        val resp = try {
            http.newCall(req).execute()
        } catch (e: BlockedRequestException) {
            // Refused by our own network policy (Tor required or starting, server key changed). Nothing was sent.
            throw ApiException(e.reason, 0, cause = e)
        } catch (e: IOException) {
            throw ApiException("network", 0, cause = e)
        }
        resp.use { r ->
            if (r.isSuccessful) {
                return onOk(r)
            }
            val body = try {
                lenient.decodeFromString(ErrorBody.serializer(), r.body.string())
            } catch (e: Exception) {
                ErrorBody("http_${r.code}")
            }
            throw ApiException(body.error, r.code, r.header("Retry-After")?.toLongOrNull(), scope = body.scope)
        }
    }

    private fun <T> decode(r: Response, ser: KSerializer<T>): T = lenient.decodeFromString(ser, r.body.string())

    companion object {
        private val JSON = "application/json".toMediaType()
        /** Required verbatim by POST /v1/messages and /v1/invites. */
        val OCTET = "application/octet-stream".toMediaType()
        private val lenient = Json { ignoreUnknownKeys = true }

        /**
         * Normalizes a base URL. It must be https, or plain http to a valid v3 onion service (the onion address
         * authenticates and encrypts the connection). Debug builds also allow any http. Whether Tor is on is checked
         * per request (see [NetStack]), so a contact's onion server is still accepted and the user is asked to turn Tor on.
         */
        fun parseBase(raw: String): HttpUrl {
            val trimmed = raw.trim().trimEnd('/')
            val u = "$trimmed/".toHttpUrlOrNull() ?: throw ApiException("invalid_server", 0)
            if (NetRules.isOnionHost(u.host) && !NetRules.isValidV3Onion(u.host)) {
                throw ApiException("invalid_server", 0)
            }
            if (!NetRules.isAcceptableServerScheme(u.scheme, u.host, BuildConfig.ALLOW_HTTP)) {
                throw ApiException("insecure_server", 0)
            }
            if (u.query != null || u.fragment != null || u.username.isNotEmpty()) {
                throw ApiException("invalid_server", 0)
            }
            return u
        }

        fun isValidServer(raw: String): Boolean = try {
            parseBase(raw)
            true
        } catch (e: ApiException) {
            false
        }

        /**
         * Routing (Direct, Orbot or built-in Tor) and server-key pinning are applied per request by [NetStack]. Cleartext
         * is enabled at the OkHttp level only so http onion services work. [NetStack.RouteInterceptor] and the network
         * security config both refuse plain http to anything else (outside debug builds).
         */
        fun buildClient(): OkHttpClient {
            val modern = ConnectionSpec.Builder(ConnectionSpec.RESTRICTED_TLS)
                .tlsVersions(TlsVersion.TLS_1_3, TlsVersion.TLS_1_2)
                .build()
            return OkHttpClient.Builder()
                .connectionSpecs(listOf(modern, ConnectionSpec.CLEARTEXT))
                // Generous enough for Tor: the route interceptor may wait for Tor to bootstrap.
                .connectTimeout(30, TimeUnit.SECONDS)
                .readTimeout(30, TimeUnit.SECONDS)
                .writeTimeout(30, TimeUnit.SECONDS)
                .callTimeout(120, TimeUnit.SECONDS)
                .retryOnConnectionFailure(true)
                .followRedirects(false)
                .followSslRedirects(false)
                .cache(null)
                .proxySelector(NetStack.TorProxySelector)
                .addInterceptor(NetStack.RouteInterceptor)
                .addNetworkInterceptor(NetStack.PinInterceptor)
                .build()
        }
    }
}
