package app.goldfishsend

import app.goldfishsend.net.Gateway
import app.goldfishsend.net.GatewayCodec
import app.goldfishsend.net.ServerKey
import app.goldfishsend.proto.B64
import app.goldfishsend.proto.Pow
import java.io.File
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * docs/test-vectors/gateway-codec-fuzz.json: seeded, generated cases (written by the server's GatewayCodecVectorTests) with
 * the server's verdict on each. This side must agree on every one: the inner codec both ways, padding, the response
 * envelope, key blobs and fingerprints, and proof of work. Mismatches are collected, so a failure lists all of them.
 */
class GatewayCodecFuzzVectorsTest {
    private val root: JsonObject by lazy {
        var dir: File? = File("").absoluteFile
        while (dir != null && !File(dir, "docs/protocol.md").exists()) {
            dir = dir.parentFile
        }
        val file = File(dir ?: error("repo root not found"), "docs/test-vectors/gateway-codec-fuzz.json")
        Json.parseToJsonElement(file.readText()).jsonObject
    }

    private fun cases(name: String): List<JsonObject> = root.getValue(name).jsonArray.map { it.jsonObject }

    private fun check(name: String, block: (JsonObject) -> String?) {
        val cases = cases(name)
        assertTrue("no $name cases", cases.isNotEmpty())
        val mismatches = cases.mapIndexedNotNull { i, c ->
            try {
                block(c)?.let { "$name[$i]: $it" }
            } catch (e: Throwable) {
                "$name[$i]: threw $e"
            }
        }
        assertTrue("${mismatches.size} of ${cases.size} $name disagree with the server:\n" + mismatches.take(25).joinToString("\n"), mismatches.isEmpty())
    }

    @Test
    fun requestDecoding() = check("requests") { c ->
        val data = bytes(c.getValue("data"))
        val decoded = runCatching { GatewayCodec.decodeRequest(data) }
        val ok = c.bool("ok")
        when {
            decoded.isSuccess != ok -> "server ok=$ok (${c["why"]}), app ${decoded.exceptionOrNull() ?: "accepted"}: ${c["data"]}"
            !ok -> null
            else -> {
                val r = decoded.getOrThrow()
                listOfNotNull(
                    "method".takeIf { r.method != c.int("method") },
                    "timestamp".takeIf { r.timestamp != c.long("timestamp") },
                    "path".takeIf { r.path != c.str("path") },
                    "headers".takeIf { r.headers != headers(c.getValue("headers")) },
                    "body".takeIf { !r.body.contentEquals(bytes(c.getValue("body"))) },
                ).takeIf { it.isNotEmpty() }?.let { "decoded $it differ: ${c["data"]}" }
            }
        }
    }

    @Test
    fun responseDecoding() = check("responses") { c ->
        val data = bytes(c.getValue("data"))
        val decoded = runCatching { GatewayCodec.decodeResponse(data) }
        val ok = c.bool("ok")
        when {
            decoded.isSuccess != ok -> "server ok=$ok (${c["why"]}), app ${decoded.exceptionOrNull() ?: "accepted"}: ${c["data"]}"
            !ok -> null
            else -> {
                val r = decoded.getOrThrow()
                listOfNotNull(
                    "status".takeIf { r.status != c.int("status") },
                    "headers".takeIf { r.headers != headers(c.getValue("headers")) },
                    "body".takeIf { !r.body.contentEquals(bytes(c.getValue("body"))) },
                ).takeIf { it.isNotEmpty() }?.let { "decoded $it differ: ${c["data"]}" }
            }
        }
    }

    @Test
    fun requestEncoding() = check("encodeRequests") { c ->
        val encoded = runCatching {
            GatewayCodec.encodeRequest(
                GatewayCodec.InnerRequest(
                    GatewayCodec.methodCode(c.str("method")),
                    c.long("timestamp"),
                    c.str("path"),
                    headers(c.getValue("headers")),
                    bytes(c.getValue("body")),
                ),
            )
        }
        val ok = c.bool("ok")
        val brief = "${c["method"]} ${c["path"]} ${c["headers"]} ts=${c["timestamp"]} body=${bytes(c.getValue("body")).size} B"
        when {
            encoded.isSuccess != ok -> "server ok=$ok, app ${encoded.exceptionOrNull() ?: "encoded"}: $brief"
            ok && !encoded.getOrThrow().contentEquals(bytes(c.getValue("data"))) -> "different bytes: $brief"
            else -> null
        }
    }

    @Test
    fun padding() = check("padding") { c ->
        val n = c.int("n")
        val request = c.int("request")
        val app = GatewayCodec.paddedSize(n)
        when {
            app != c.int("response") -> "paddedSize($n) = $app, server response size ${c.int("response")}"
            request > 0 && app != request -> "paddedSize($n) = $app, server request size $request"
            else -> null
        }
    }

    @Test
    fun keyBlobs() = check("blobs") { c ->
        val blob = unhex(c.str("blob"))
        val fp = Gateway.fingerprint(blob)
        val parsed = ServerKey.parse(blob)
        listOfNotNull(
            "parse ok=${parsed != null}, server ${c.bool("ok")} (${c.str("why")})".takeIf { (parsed != null) != c.bool("ok") },
            "fingerprint".takeIf { B64.enc(fp) != c.str("fp") },
            "keyId".takeIf { hex(fp.copyOf(8)) != c.str("keyId") || (parsed != null && hex(parsed.keyId) != c.str("keyId")) },
            "display".takeIf { Gateway.displayFingerprint(B64.enc(fp)) != c.str("display") },
        ).takeIf { it.isNotEmpty() }?.joinToString("; ")
    }

    @Test
    fun responseEnvelopes() = check("envelopes") { c ->
        val opened = runCatching { Gateway.openResponse(unhex(c.str("respSecret")), unhex(c.str("sealed"))) }
        val ok = c.bool("ok")
        when {
            opened.isSuccess != ok -> "server ok=$ok, app ${opened.exceptionOrNull() ?: "opened"}"
            ok && hex(opened.getOrThrow()) != c.str("inner") -> "different plaintext"
            else -> null
        }
    }

    @Test
    fun proofOfWork() = check("pow") { c ->
        val app = Pow.check(unhex(c.str("challenge")), unhex(c.str("nonce")), c.int("difficulty"))
        if (app != c.bool("ok")) "app $app, server ${c.bool("ok")}" else null
    }

    private fun JsonObject.str(key: String) = getValue(key).jsonPrimitive.content

    private fun JsonObject.int(key: String) = getValue(key).jsonPrimitive.int

    private fun JsonObject.long(key: String) = getValue(key).jsonPrimitive.long

    private fun JsonObject.bool(key: String) = getValue(key).jsonPrimitive.boolean

    /** `{hex, len}`: the hex bytes followed by zeros up to len. */
    private fun bytes(e: JsonElement): ByteArray {
        val o = e.jsonObject
        return unhex(o.str("hex")).copyOf(o.int("len"))
    }

    private fun headers(e: JsonElement): List<Pair<String, String>> =
        (e as JsonArray).map { it.jsonArray[0].jsonPrimitive.content to it.jsonArray[1].jsonPrimitive.content }

    private fun hex(b: ByteArray): String = GatewayTest.hex(b)

    private fun unhex(s: String): ByteArray = GatewayTest.unhex(s)
}
