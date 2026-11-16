package app.goldfishsend.fuzz

import app.goldfishsend.fuzz.FuzzKit.content
import app.goldfishsend.fuzz.FuzzKit.str
import app.goldfishsend.proto.B64
import app.goldfishsend.proto.Chunker
import app.goldfishsend.proto.Content
import app.goldfishsend.proto.E2eBlob
import app.goldfishsend.proto.GroupBlob
import app.goldfishsend.proto.InviteBundle
import app.goldfishsend.proto.InviteCrypto
import app.goldfishsend.proto.InviteLink
import app.goldfishsend.proto.MailboxCrypto
import app.goldfishsend.proto.Padding
import app.goldfishsend.proto.PushEnvelope
import app.goldfishsend.proto.Sanitize
import com.code_intelligence.jazzer.api.FuzzedDataProvider
import com.code_intelligence.jazzer.junit.FuzzTest
import java.security.GeneralSecurityException

/**
 * Decoders of bytes and text from strangers (invite links and blobs), contacts and group members (E2E content) and the
 * relay or push server (push payloads, blobs). Property: no input throws anything but the documented rejection, and valid
 * values round-trip. Without -Pgf.fuzz these replay the committed inputs in ParserFuzzTestInputs.
 */
class ParserFuzzTest {
    @FuzzTest(maxDuration = "30s")
    fun inviteLinkText(bytes: ByteArray) {
        val raw = bytes.toString(Charsets.UTF_8)
        InviteLink.isOutdated(raw)
        val link = InviteLink.parse(raw) ?: return
        check(InviteLink.parse(link.toUri()) == link) { "link doesn't round-trip" }
    }

    /** A valid link, pasted inside a message or opened as a deep link, parses back to itself. */
    @FuzzTest(maxDuration = "30s")
    fun inviteLinkInText(data: FuzzedDataProvider) {
        val server = data.str(120)
        val fp = B64.enc(data.consumeBytes(32).copyOf(32))
        val id = B64.enc(data.consumeBytes(16).copyOf(16))
        val key = data.consumeBytes(32).copyOf(32)
        val before = data.str(60).takeUnless { it.contains(InviteLink.SCHEME_PREFIX) } ?: ""
        val after = data.str(60)
        val link = InviteLink(server, fp, id, key)
        check(InviteLink.parse(link.toUri()) == link) { "bare link" }
        val sep = listOf(" ", "\n", "\t", " ")[data.consumeInt(0, 3)]
        check(InviteLink.parse(before + sep + link.toUri() + sep + after) == link) { "link in text" }
        check(!InviteLink.isOutdated(link.toUri()))
    }

    /** The invite blob, fetched from the inviter's server, is AES-GCM under the link key. Then JSON. */
    @FuzzTest(maxDuration = "30s")
    fun inviteBlob(bytes: ByteArray) {
        val b = rejectsOnly(IllegalArgumentException::class.java) { InviteBundle.decode(bytes) }
        b?.let { check(InviteBundle.decode(it.encode()) == it) }
        rejectsOnly(IllegalArgumentException::class.java, GeneralSecurityException::class.java) { InviteCrypto.decrypt(ByteArray(32), bytes) }
    }

    @FuzzTest(maxDuration = "30s")
    fun inviteBundleRoundTrip(data: FuzzedDataProvider) {
        val b = InviteBundle(
            v = data.consumeInt(), server = data.str(80), serverKey = if (data.consumeBoolean()) data.str(50) else null,
            sendSecret = data.str(50), registrationId = data.consumeInt(), deviceId = data.consumeInt(),
            identityKey = data.str(50), signedPreKeyId = data.consumeInt(), signedPreKey = data.str(50),
            signedPreKeySig = data.str(90), kyberPreKeyId = data.consumeInt(), kyberPreKey = data.str(50),
            kyberPreKeySig = data.str(90), name = if (data.consumeBoolean()) data.str(80) else null,
        )
        val key = data.consumeBytes(32).copyOf(32)
        check(InviteBundle.decode(b.encode()) == b)
        check(InviteCrypto.decrypt(key, InviteCrypto.encrypt(key, b)) == b)
    }

    /** The plaintext inside the Web Push layer, and the E2E blob inside it, as the relay or push server delivers it. */
    @FuzzTest(maxDuration = "30s")
    fun pushPayload(bytes: ByteArray) {
        when (val env = PushEnvelope.parse(bytes)) {
            is PushEnvelope.Message -> {
                check(PushEnvelope.build(PushEnvelope.TYPE_MESSAGE, env.tag, env.blob).contentEquals(bytes))
                blobs(env.blob)
            }
            is PushEnvelope.Verification -> {
                check(env.code.size == PushEnvelope.CODE_BYTES && env.tag.size == MailboxCrypto.TAG_BYTES)
                check(bytes.copyOfRange(PushEnvelope.HEADER, PushEnvelope.HEADER + PushEnvelope.CODE_BYTES).contentEquals(env.code))
            }
            null -> blobs(bytes)
        }
    }

    private fun blobs(raw: ByteArray) {
        E2eBlob.decode(raw)?.let { check(it.encode().contentEquals(raw)) }
        GroupBlob.decode(raw)?.let { check(it.encode().contentEquals(raw)) }
        check(GroupBlob.decode(raw) == null || GroupBlob.isGroup(raw) && E2eBlob.decode(raw) == null)
    }

    /** A decrypted libsignal plaintext from a contact or group member: padding, then Content JSON. */
    @FuzzTest(maxDuration = "60s")
    fun decryptedPlaintext(padded: ByteArray) {
        val c = rejectsOnly(IllegalArgumentException::class.java) { Content.decode(Padding.unpad(padded)) } ?: return
        c.groupId
        check(Content.decode(c.encode()) == c) { "decoded content doesn't round-trip" }
    }

    /** Every content value survives padding and, if it's too large for one message, chunking. */
    @FuzzTest(maxDuration = "60s")
    fun contentRoundTrip(data: FuzzedDataProvider) {
        val c = data.content()
        val max = if (data.consumeBoolean()) Padding.MAX_PREKEY_PLAINTEXT else Padding.MAX_PLAINTEXT
        check(Content.decode(Padding.unpad(Padding.pad(c.encode()))) == c) { "content doesn't round-trip" }
        val parts = rejectsOnly(IllegalArgumentException::class.java) { Chunker.splitContent(c, max) } ?: return
        for (p in parts) {
            check(Padding.paddedSize(p.encode().size) <= max) { "part too large" }
        }
        if (parts.size > 1) {
            check(parts.size <= Chunker.MAX_PARTS)
            val chunks = parts.map { it as Content.Chunk }
            check(chunks.all { it.parts == parts.size } && chunks.map { it.part } == parts.indices.toList())
            check(Content.decode(B64.dec(chunks.joinToString("") { it.data })) == c) { "chunks don't reassemble" }
        }
    }

    /** 1:1 texts keep their own `part`/`parts` split. */
    @FuzzTest(maxDuration = "60s")
    fun textChunker(data: FuzzedDataProvider) {
        val max = if (data.consumeBoolean()) Padding.MAX_PREKEY_PLAINTEXT else Padding.MAX_PLAINTEXT
        val id = data.str(30)
        val ts = data.consumeLong()
        val exp = if (data.consumeBoolean()) data.consumeLong() else null
        val once = if (data.consumeBoolean()) true else null
        val body = data.consumeRemainingAsString().let { String(it.toByteArray(Charsets.UTF_8), Charsets.UTF_8) }
        val parts = Chunker.split(id, body, ts, exp, once, max)
        check(parts.joinToString("") { it.body } == body) { "parts don't reassemble" }
        for (p in parts) {
            check(Padding.paddedSize(p.encode().size) <= max) { "part too large" }
        }
        if (parts.size > 1) {
            check(parts.mapIndexed { i, p -> p.part == i && p.parts == parts.size }.all { it })
        }
    }

    /** Display names chosen by contacts and members. */
    @FuzzTest(maxDuration = "30s")
    fun displayName(bytes: ByteArray) {
        val raw = bytes.toString(Charsets.UTF_8)
        val n = Sanitize.name(raw) ?: return
        check(n.codePointCount(0, n.length) <= Sanitize.MAX_NAME) { "too long" }
        check(n == n.trim() && n.isNotEmpty())
        n.codePoints().forEach { cp ->
            val t = Character.getType(cp)
            check(t != Character.CONTROL.toInt() && t != Character.FORMAT.toInt() && t != Character.SURROGATE.toInt()) { "kept U+%04X".format(cp) }
            check(cp == ' '.code || !Character.isWhitespace(cp)) { "kept whitespace U+%04X".format(cp) }
        }
        check(Sanitize.name(n) == n) { "not idempotent" }
    }

    companion object {
        /** Runs [block]; an exception of one of [allowed] types is the expected rejection (null). Anything else fails. */
        fun <T> rejectsOnly(vararg allowed: Class<out Throwable>, block: () -> T): T? = try {
            block()
        } catch (e: Throwable) {
            if (allowed.none { it.isInstance(e) }) {
                throw AssertionError("unexpected ${e.javaClass.name}", e)
            }
            null
        }
    }
}
