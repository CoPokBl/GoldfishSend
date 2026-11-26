package app.goldfishsend.net

import app.goldfishsend.BuildConfig
import app.goldfishsend.proto.B64
import java.io.IOException
import java.util.concurrent.ConcurrentHashMap
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
data class PowChallenge(
    val scheme: String,
    val purpose: String = "create",
    val challenge: String,
    val difficulty: Int,
    val memoryKiB: Int,
    val iterations: Int,
    val ttlSeconds: Long = 300,
    val expiresAt: Long,
) {
    val params get() = app.goldfishsend.proto.Pow.Params(difficulty, memoryKiB, iterations)

    /** For the solver. Throws [app.goldfishsend.proto.Pow.TooHardException] for another scheme or a malformed challenge. */
    fun toPow(): app.goldfishsend.proto.Pow.Challenge {
        val bytes = runCatching { app.goldfishsend.proto.B64.dec(challenge) }.getOrNull()
        if (scheme != app.goldfishsend.proto.Pow.SCHEME || bytes == null || bytes.size != 32) {
            throw app.goldfishsend.proto.Pow.TooHardException(params, "scheme")
        }
        return app.goldfishsend.proto.Pow.Challenge(bytes, params, ttlSeconds.coerceIn(1, 3600) * 1000)
    }
}

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

/**
 * [endpointGone]: the server can no longer deliver to the push endpoint it has for these mailboxes. The client should
 * re-register with its distributor (or re-run endpoint verification so the server probes again). Absent means false.
 */
@Serializable
data class ExpiresResponse(val expiresAt: String, val endpointGone: Boolean = false)

@Serializable
data class IdResponse(val id: String)

/** One item of `POST /v1/messages/batch`. [ttlSeconds] null means the server default. */
class BatchItem(val sendSecret: ByteArray, val idempotencyKey: ByteArray, val ttlSeconds: Long?, val blob: ByteArray)

/** Per-item result: 202 with [id], or 404/429/507 with [error], [scope] and [retryAfter] (seconds). */
@Serializable
data class BatchResult(
    val status: Int,
    val id: String? = null,
    val error: String? = null,
    val scope: String? = null,
    val retryAfter: Long? = null,
)

@Serializable
data class BatchResponse(val results: List<BatchResult>)

/** The server doesn't have `POST /v1/messages/batch`: send one by one. */
class BatchUnsupportedException : IOException("batch send unsupported")

/** `u8 count ‖ count × (sendSecret(32) ‖ idempotencyKey(16) ‖ u32 ttlSeconds ‖ u16 len ‖ blob)`, big-endian. */
object MessageBatch {
    const val MAX_ITEMS = 32
    const val ITEM_HEADER = 32 + 16 + 4 + 2

    /** Inner body budget: the gateway's 16 KiB inner body limit. */
    const val MAX_BODY = 16 * 1024

    fun size(blobs: List<Int>): Int = 1 + blobs.sumOf { ITEM_HEADER + it }

    fun encode(items: List<BatchItem>): ByteArray {
        require(items.size in 1..MAX_ITEMS) { "batch size" }
        val out = java.io.ByteArrayOutputStream(size(items.map { it.blob.size }))
        val d = java.io.DataOutputStream(out)
        d.writeByte(items.size)
        for (i in items) {
            require(i.sendSecret.size == 32 && i.idempotencyKey.size == 16 && i.blob.size in 1..0xFFFF)
            d.write(i.sendSecret)
            d.write(i.idempotencyKey)
            d.writeInt(((i.ttlSeconds ?: 0L).coerceIn(0L, 0xFFFFFFFFL)).toInt())
            d.writeShort(i.blob.size)
            d.write(i.blob)
        }
        d.flush()
        return out.toByteArray()
    }

    /** The reverse of [encode], strict (used by tests and the in-memory server). Null if malformed. */
    fun decode(body: ByteArray): List<BatchItem>? {
        if (body.isEmpty()) {
            return null
        }
        val count = body[0].toInt() and 0xff
        if (count !in 1..MAX_ITEMS) {
            return null
        }
        val buf = java.nio.ByteBuffer.wrap(body, 1, body.size - 1)
        val items = ArrayList<BatchItem>(count)
        repeat(count) {
            if (buf.remaining() < ITEM_HEADER) {
                return null
            }
            val secret = ByteArray(32).also { buf.get(it) }
            val idem = ByteArray(16).also { buf.get(it) }
            val ttl = buf.int.toLong() and 0xFFFFFFFFL
            val len = buf.short.toInt() and 0xFFFF
            if (len < 1 || buf.remaining() < len) {
                return null
            }
            val blob = ByteArray(len).also { buf.get(it) }
            items += BatchItem(secret, idem, if (ttl == 0L) null else ttl, blob)
        }
        return if (buf.remaining() == 0) items else null
    }
}

@Serializable
private data class ErrorBody(val error: String = "unknown", val scope: String? = null)

@Serializable
private data class SkewBody(val error: String? = null, val serverTime: Long? = null)

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
    /** For `server_identity_changed`: the fingerprint (b64u) the server presents now. It's never pinned automatically. */
    val presentedKey: String? = null,
) : IOException("api error $code ($status)", cause) {
    /**
     * On sends, the per-IP and per-network limits can be paid off with a proof of work (shared IPs, Tor, CGNAT).
     * Mailbox and global limits can't, so retrying them with PoW just wastes CPU.
     */
    val powCanHelp: Boolean
        get() = status == 429 && (scope == "ip" || scope == "network")

    val retryable: Boolean
        get() = code == "network" || code == "rate_limited" || status >= 500 || status == 0

    val human: String
        get() = humanize(code)

    companion object {
        fun humanize(code: String): String = when (code) {
            "network" -> "Couldn't reach the server. We'll keep trying."
            "rate_limited" -> "Things are busy right now. We'll try again shortly."
            "bad_server" -> "That server sent something unexpected. We'll try again later."
            "response_too_large" -> "That server sent something unexpected. We'll try again later."
            "not_found" -> "This contact can't be reached anymore."
            "too_large" -> "That message is too long."
            "mailbox_full" -> "Waiting for them to come back online."
            "invalid_endpoint", "endpoint_unreachable" -> "Your push service couldn't be reached. Check that it's running."
            "pow_invalid", "verification_failed" -> "Setup hiccup. Retrying automatically."
            "insecure_server" -> "That server isn't using a secure connection."
            "tor_required" -> "This contact's server is a Tor (.onion) address. Turn on Tor in Settings › Connection to reach it."
            "tor_connecting" -> "Connecting to Tor…"
            "server_key_changed" -> "This server's identity changed. Check Settings › Connection before continuing."
            "server_identity_changed" -> "Couldn't verify this server's identity, so nothing was sent. It may have been replaced, or someone may be intercepting the connection."
            "clock_skew" -> "Your phone's clock looks wrong. Check the date and time settings."
            else -> "Something went wrong. We'll try again."
        }
    }
}

/**
 * How the transport treats one server's identity key (docs/protocol.md, "Server key").
 *
 * @param expected the pinned fingerprint (b64u), or null to trust the first key fetched.
 * @param onFirstUse called with the fingerprint when [expected] is null and a key was fetched (trust on first use).
 * @param onMismatch called with the presented fingerprint when it doesn't match [expected]. It's never pinned.
 * @param onVerified called after a response authenticated under the pinned key.
 */
class ServerPin(
    val expected: String?,
    val onFirstUse: (String) -> Unit = {},
    val onMismatch: (String) -> Unit = {},
    val onVerified: () -> Unit = {},
)

/** Verified server key blobs (per fingerprint) and per-server clock offsets. */
interface GatewayState {
    fun blob(fp: String): ByteArray?

    fun putBlob(fp: String, blob: ByteArray)

    fun dropBlob(fp: String)

    fun clockOffset(server: String): Long

    fun setClockOffset(server: String, seconds: Long)

    /** In memory only (tests, and the default before the app's persistent store is wired in). */
    class Memory : GatewayState {
        private val blobs = ConcurrentHashMap<String, ByteArray>()
        private val offsets = ConcurrentHashMap<String, Long>()

        override fun blob(fp: String): ByteArray? = blobs[fp]

        override fun putBlob(fp: String, blob: ByteArray) {
            blobs[fp] = blob
        }

        override fun dropBlob(fp: String) {
            blobs.remove(fp)
        }

        override fun clockOffset(server: String): Long = offsets[server] ?: 0L

        override fun setClockOffset(server: String, seconds: Long) {
            offsets[server] = seconds
        }
    }
}

/**
 * One client per server base URL. All calls are suspend functions and run on Dispatchers.IO.
 *
 * Every call goes through the encrypted gateway (`POST /v1/gw`, docs/protocol.md): the request is sealed to the server's
 * hybrid ML-KEM-768 + P-256 key, which is pinned by fingerprint ([pin]). Only the holder of that key can read the request
 * or produce a response that opens, so a forged TLS certificate or a TLS-terminating proxy learns nothing.
 */
class ServerApi(
    baseUrl: String,
    private val http: OkHttpClient,
    private val pin: ServerPin = ServerPin(null),
    private val state: GatewayState = defaultState,
    private val clock: () -> Long = { System.currentTimeMillis() },
    /**
     * False once the install this client was made for has been wiped. From then on nothing is sent and nothing is
     * written back (pins, the cached server key): a job still running from before the wipe could otherwise go out
     * directly, after the wipe reset the connection mode, and leave the server's key in the wiped settings.
     */
    private val live: () -> Boolean = { true },
) {
    private val base: HttpUrl = parseBase(baseUrl)
    private val serverId: String = base.toString()

    /** The fingerprint trusted on first use, so one instance stays consistent afterwards. */
    @Volatile
    private var learned: String? = null

    suspend fun info(): ServerInfo = get("v1/info", ServerInfo.serializer())

    /**
     * Fetches and verifies the server's key without making a call, and returns its fingerprint (b64u). With no pin, this
     * is the trust-on-first-use step.
     */
    suspend fun identity(): String = withContext(Dispatchers.IO) { serverKey(force = false).fingerprintB64 }

    /** A challenge for creating a mailbox (our own server), or with [forSend] one that only pays a send limit. */
    suspend fun powChallenge(forSend: Boolean = false): PowChallenge =
        postJson(if (forSend) "v1/pow/challenge?purpose=send" else "v1/pow/challenge?purpose=create", null, PowChallenge.serializer())

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
            val headers = mutableListOf(
                "content-type" to OCTET_TYPE,
                "gf-send-token" to B64.enc(sendSecret),
                "gf-idempotency-key" to B64.enc(idempotencyKey),
            )
            if (ttlSeconds != null) {
                headers += "gf-ttl" to ttlSeconds.toString()
            }
            if (pow != null) {
                headers += "gf-pow" to pow
            }
            exchange("POST", "v1/messages", headers, blob) { r -> decode(r, IdResponse.serializer()).id }
        }

    /**
     * Sends up to 32 E2E blobs in one request (docs/groups.md, "Server: batch send"). Per-item results come back in order.
     * A whole-batch failure throws [ApiException], to be retried as a whole with the same idempotency keys. A server
     * without the endpoint throws [BatchUnsupportedException].
     */
    suspend fun sendBatch(items: List<BatchItem>, pow: String? = null): List<BatchResult> = withContext(Dispatchers.IO) {
        val headers = mutableListOf("content-type" to OCTET_TYPE)
        if (pow != null) {
            headers += "gf-pow" to pow
        }
        try {
            exchange("POST", "v1/messages/batch", headers, MessageBatch.encode(items)) { r ->
                val results = decode(r, BatchResponse.serializer()).results
                if (results.size != items.size) {
                    throw ApiException("bad_server", 502, retryAfterSeconds = 60)
                }
                results
            }
        } catch (e: ApiException) {
            // Through the gateway, an unknown inner route is a bare 404 from routing (no JSON error code), unlike a send's
            // `not_found`.
            if (e.status == 404 && e.code == "http_404") {
                throw BatchUnsupportedException()
            }
            throw e
        }
    }

    suspend fun uploadInvite(blob: ByteArray, ttlSeconds: Long): String = withContext(Dispatchers.IO) {
        val headers = listOf("content-type" to OCTET_TYPE, "gf-ttl" to ttlSeconds.toString())
        exchange("POST", "v1/invites", headers, blob) { r -> decode(r, IdResponse.serializer()).id }
    }

    /** Returns the invite blob, or null if it was already used or has expired. */
    suspend fun fetchInvite(id: String): ByteArray? = withContext(Dispatchers.IO) {
        try {
            exchange("GET", "v1/invites/$id", emptyList(), ByteArray(0)) { r -> r.body }
        } catch (e: ApiException) {
            if (e.status == 404) null else throw e
        }
    }

    // --- plumbing ---

    private fun url(path: String): HttpUrl = base.resolve(path)!!

    private suspend fun <T> get(path: String, ser: KSerializer<T>): T = withContext(Dispatchers.IO) {
        exchange("GET", path, emptyList(), ByteArray(0)) { decode(it, ser) }
    }

    private suspend fun <T> postJson(path: String, json: String?, ser: KSerializer<T>?): T =
        send(path, "POST", json, ser)

    @Suppress("UNCHECKED_CAST")
    private suspend fun <T> send(path: String, method: String, json: String?, ser: KSerializer<T>?): T =
        withContext(Dispatchers.IO) {
            val body = (json ?: "").toByteArray(Charsets.UTF_8)
            exchange(method, path, listOf("content-type" to JSON_TYPE), body) { r ->
                if (ser == null) Unit as T else decode(r, ser)
            }
        }

    /**
     * One API call through the gateway. It retries once after `421 unknown_key` (re-fetching the key, which must still match
     * the pin) and once after an authenticated `clock_skew` (adopting the server's clock).
     */
    private fun <T> exchange(
        method: String,
        path: String,
        headers: List<Pair<String, String>>,
        body: ByteArray,
        onOk: (GatewayCodec.InnerResponse) -> T,
    ): T {
        var forceKey = false
        var refetched = false
        var skewRetried = false
        var replayRetried = false
        while (true) {
            val key = serverKey(forceKey)
            forceKey = false
            val inner = try {
                GatewayCodec.encodeRequest(
                    GatewayCodec.InnerRequest(
                        GatewayCodec.methodCode(method),
                        clock() / 1000 + state.clockOffset(serverId),
                        "/" + path.trimStart('/'),
                        headers,
                        body,
                    ),
                )
            } catch (e: GatewayCodec.FormatException) {
                throw ApiException("too_large", 413, cause = e)
            }
            val sealed = Gateway.seal(key, inner)
            val req = Request.Builder().url(url("v1/gw")).post(sealed.body.toRequestBody(OCTET)).build()
            val plaintext: ByteArray? = try {
                call(req) { r ->
                    when {
                        r.code == 421 && !refetched -> null
                        r.code != 200 -> throw untrusted(r)
                        else -> try {
                            Gateway.openResponse(sealed.respSecret, readCapped(r))
                        } catch (e: ApiException) {
                            throw e
                        } catch (e: Exception) {
                            throw ApiException("bad_server", 502, retryAfterSeconds = 60, cause = e)
                        }
                    }
                }
            } finally {
                sealed.respSecret.fill(0)
            }
            if (plaintext == null) {
                // 421 is unauthenticated: re-fetch the key, which must still match the pin. It never re-pins.
                refetched = true
                state.dropBlob(key.fingerprintB64)
                forceKey = true
                continue
            }
            val resp = try {
                GatewayCodec.decodeResponse(plaintext)
            } catch (e: GatewayCodec.FormatException) {
                throw ApiException("bad_server", 502, retryAfterSeconds = 60, cause = e)
            }
            checkLive()
            // The response opened under the pinned key, so it really came from the server.
            pin.onVerified()
            if (resp.status == 400 && !skewRetried) {
                val skew = runCatching { lenient.decodeFromString(SkewBody.serializer(), resp.body.toString(Charsets.UTF_8)) }.getOrNull()
                if (skew?.error == "clock_skew" && skew.serverTime != null) {
                    state.setClockOffset(serverId, skew.serverTime - clock() / 1000)
                    skewRetried = true
                    continue
                }
            }
            if (resp.status in 200..299) {
                return onOk(resp)
            }
            val err = try {
                lenient.decodeFromString(ErrorBody.serializer(), resp.body.toString(Charsets.UTF_8))
            } catch (e: Exception) {
                ErrorBody("http_${resp.status}")
            }
            if (resp.status == 409 && err.error == "replay" && !replayRetried) {
                // OkHttp may resend a request after a dropped connection. Seal it afresh: sends carry an idempotency key,
                // so a request the server did process isn't applied twice.
                replayRetried = true
                continue
            }
            throw ApiException(err.error, resp.status, resp.header("retry-after")?.toLongOrNull(), scope = err.scope)
        }
    }

    /**
     * The server's key: from the cache when the pin is known, otherwise fetched from `GET /v1/key` and checked against the
     * pin. A different key fails closed with `server_identity_changed`.
     */
    private fun serverKey(force: Boolean): ServerKey {
        val expected = pin.expected ?: learned
        if (expected != null && !force) {
            state.blob(expected)?.let { cached ->
                ServerKey.parse(cached)?.takeIf { it.fingerprintB64 == expected }?.let { return it }
                state.dropBlob(expected)
            }
        }
        val blob = call(Request.Builder().url(url("v1/key")).get().build()) { r ->
            if (r.code != 200) {
                throw untrusted(r)
            }
            readCapped(r, MAX_KEY_BYTES)
        }
        val key = ServerKey.parse(blob) ?: throw ApiException("bad_server", 502, retryAfterSeconds = 300)
        // A wipe may have happened while the key was on its way: then nothing of it is recorded.
        checkLive()
        val fp = key.fingerprintB64
        if (expected == null) {
            learned = fp
            pin.onFirstUse(fp)
        } else if (fp != expected) {
            pin.onMismatch(fp)
            throw ApiException("server_identity_changed", 0, presentedKey = fp)
        }
        state.putBlob(fp, key.blob)
        return key
    }

    private fun checkLive() {
        if (!live()) {
            throw ApiException("stopped", 0)
        }
    }

    /** Runs one plain HTTP request, mapping transport failures. */
    private fun <T> call(req: Request, onResponse: (Response) -> T): T {
        checkLive()
        val resp = try {
            http.newCall(req).execute()
        } catch (e: BlockedRequestException) {
            // Refused by our own network policy (Tor required or starting, TLS key changed). Nothing was sent.
            throw ApiException(e.reason, 0, cause = e)
        } catch (e: IOException) {
            throw ApiException("network", 0, cause = e)
        }
        return resp.use(onResponse)
    }

    /**
     * An error from outside the gateway. Anyone on the path (a proxy, or an attacker) can produce one, so only its status
     * is used, never its body. In particular a plaintext 404 is not the server's `not_found` and can't make us drop a contact.
     */
    private fun untrusted(r: Response): ApiException = when {
        r.code == 413 -> ApiException("too_large", 413)
        r.code == 429 -> ApiException("rate_limited", 429, r.header("Retry-After")?.toLongOrNull()?.coerceIn(1, 3600) ?: 30)
        r.code >= 500 -> ApiException("http_${r.code}", r.code)
        else -> ApiException("bad_server", 502, retryAfterSeconds = 300)
    }

    /**
     * A 2xx body that doesn't parse (a broken or hostile server: a contact picks their own) is an API error like any other,
     * so callers back off. kotlinx.serialization doesn't only throw SerializationException on malformed JSON.
     */
    private fun <T> decode(r: GatewayCodec.InnerResponse, ser: KSerializer<T>): T = try {
        lenient.decodeFromString(ser, r.body.toString(Charsets.UTF_8))
    } catch (e: Exception) {
        throw ApiException("bad_server", 502, retryAfterSeconds = 300, cause = e)
    }

    companion object {
        /**
         * The largest response body we'll read. Every protocol response is far smaller (invites are at most 4 KiB). A hostile
         * server (for example a contact's) can't stream gigabytes into memory.
         */
        const val MAX_RESPONSE_BYTES = 64 * 1024L

        /** A key blob is 1250 bytes. */
        const val MAX_KEY_BYTES = 4096L

        /** Replaced by the app at startup with a store that keeps verified keys across launches. */
        @Volatile
        var defaultState: GatewayState = GatewayState.Memory()

        /** Reads at most [max] bytes of the body, failing instead of buffering anything larger. */
        fun readCapped(r: Response, max: Long = MAX_RESPONSE_BYTES): ByteArray {
            val body = r.body
            val declared = body.contentLength()
            if (declared > max) {
                throw ApiException("response_too_large", r.code)
            }
            val source = body.source()
            val buf = okio.Buffer()
            while (true) {
                val n = source.read(buf, 8192)
                if (n == -1L) {
                    break
                }
                if (buf.size > max) {
                    throw ApiException("response_too_large", r.code)
                }
            }
            return buf.readByteArray()
        }

        private const val JSON_TYPE = "application/json"

        /** Required verbatim by POST /v1/messages, /v1/invites and /v1/gw. */
        private const val OCTET_TYPE = "application/octet-stream"
        val OCTET = OCTET_TYPE.toMediaType()
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
         * Stricter check for server URLs that come from other people (invites, `hello`, `mailbox` messages): https on the
         * default port 443, or a valid v3 onion. That keeps a contact from steering our requests at arbitrary ports or
         * local services. Debug builds keep the looser rule for local testing.
         */
        fun isValidContactServer(raw: String): Boolean {
            val u = try {
                parseBase(raw)
            } catch (e: ApiException) {
                return false
            }
            return NetRules.isAcceptableContactServer(u.scheme, u.host, u.port, BuildConfig.ALLOW_HTTP)
        }

        /**
         * Routing (Direct, Orbot or built-in Tor) and optional TLS-key pinning are applied per request by [NetStack].
         * Cleartext is enabled at the OkHttp level only so http onion services work. [NetStack.RouteInterceptor] and the
         * network security config both refuse plain http to anything else (outside debug builds).
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
