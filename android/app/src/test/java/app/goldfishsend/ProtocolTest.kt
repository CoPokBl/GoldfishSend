package app.goldfishsend

import app.goldfishsend.proto.Aead
import app.goldfishsend.proto.B64
import app.goldfishsend.proto.Chunker
import app.goldfishsend.proto.Content
import app.goldfishsend.proto.E2eBlob
import app.goldfishsend.proto.Hash
import app.goldfishsend.proto.InviteBundle
import app.goldfishsend.proto.InviteCrypto
import app.goldfishsend.proto.InviteLink
import app.goldfishsend.proto.MailboxCrypto
import app.goldfishsend.proto.Padding
import app.goldfishsend.proto.Pow
import app.goldfishsend.proto.PushEnvelope
import app.goldfishsend.proto.Rand
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

class PowTest {
    private val challenge = ByteArray(32) { 7 }

    @Test
    fun leadingZeroBits() {
        assertEquals(0, Pow.leadingZeroBits(byteArrayOf(0x80.toByte())))
        assertEquals(7, Pow.leadingZeroBits(byteArrayOf(0x01)))
        assertEquals(8, Pow.leadingZeroBits(byteArrayOf(0x00, 0xff.toByte())))
        assertEquals(12, Pow.leadingZeroBits(byteArrayOf(0x00, 0x08)))
        assertEquals(16, Pow.leadingZeroBits(byteArrayOf(0, 0)))
    }

    @Test
    fun nonceIsBigEndian() {
        assertEquals("0000000000000102", hex(Pow.nonceBytes(0x0102)))
        assertEquals("ffffffffffffffff", hex(Pow.nonceBytes(-1)))
    }

    /** Vector computed independently (Python hashlib): first nonce with ≥12 zero bits for challenge = 0x07 × 32. */
    @Test
    fun matchesIndependentVector() {
        val nonce = Pow.nonceBytes(1949)
        assertTrue(Pow.check(challenge, nonce, 12))
        assertEquals(
            "000822a69cc36d2131369cc589f472c007fbbe3d30c39a8cf54238dc1107f8cc",
            hex(Hash.sha256("gf/pow/v1".toByteArray(), challenge, nonce)),
        )
        // The single-threaded search from 0 must find exactly this first solution.
        assertArrayEquals(nonce, Pow.solveRange(challenge, 12, 0, 1))
    }

    @Test
    fun parallelSolverProducesValidNonce() = runBlocking {
        val ch = Rand.bytes(32)
        val nonce = Pow.solve(ch, 14)
        assertEquals(8, nonce.size)
        assertTrue(Pow.check(ch, nonce, 14))
    }

    @Test
    fun rejectsWrongNonce() {
        assertFalse(Pow.check(challenge, Pow.nonceBytes(1948), 12))
    }
}

class PaddingTest {
    @Test
    fun padsToBlockMultiples() {
        assertEquals(256, Padding.pad(ByteArray(0)).size)
        assertEquals(256, Padding.pad(ByteArray(255)).size)
        assertEquals(512, Padding.pad(ByteArray(256)).size)
        assertEquals(2048, Padding.pad(ByteArray(2047)).size)
    }

    @Test
    fun layoutIsIso7816() {
        val p = Padding.pad(byteArrayOf(1, 2, 3))
        assertEquals(1.toByte(), p[0])
        assertEquals(0x80.toByte(), p[3])
        assertTrue(p.copyOfRange(4, p.size).all { it == 0.toByte() })
    }

    @Test
    fun roundTrip() {
        for (len in listOf(0, 1, 100, 255, 256, 1000, 3000)) {
            val data = Rand.bytes(len)
            assertArrayEquals(data, Padding.unpad(Padding.pad(data)))
        }
        // Data that itself ends in 0x80 / zeros must survive.
        val tricky = byteArrayOf(5, 0x80.toByte(), 0, 0)
        assertArrayEquals(tricky, Padding.unpad(Padding.pad(tricky)))
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsMissingMarker() {
        Padding.unpad(ByteArray(256))
    }
}

class EnvelopeTest {
    private val tag = ByteArray(8) { it.toByte() }

    @Test
    fun parsesMessage() {
        val env = PushEnvelope.parse(PushEnvelope.build(PushEnvelope.TYPE_MESSAGE, tag, byteArrayOf(3, 9, 9)))
        assertTrue(env is PushEnvelope.Message)
        env as PushEnvelope.Message
        assertArrayEquals(tag, env.tag)
        assertArrayEquals(byteArrayOf(3, 9, 9), env.blob)
    }

    @Test
    fun parsesVerification() {
        val code = Rand.bytes(16)
        val raw = byteArrayOf(0x01, 0x02) + tag + code
        val env = PushEnvelope.parse(raw)
        assertTrue(env is PushEnvelope.Verification)
        assertArrayEquals(code, (env as PushEnvelope.Verification).code)
    }

    @Test
    fun rejectsMalformed() {
        assertNull(PushEnvelope.parse(ByteArray(9)))
        assertNull(PushEnvelope.parse(byteArrayOf(0x02, 0x01) + tag + byteArrayOf(1)))
        assertNull(PushEnvelope.parse(byteArrayOf(0x01, 0x03) + tag + byteArrayOf(1)))
        assertNull(PushEnvelope.parse(byteArrayOf(0x01, 0x02) + tag + ByteArray(15)))
        assertNull(PushEnvelope.parse(byteArrayOf(0x01, 0x01) + tag))
    }

    @Test
    fun e2eBlobRoundTrip() {
        val b = E2eBlob(E2eBlob.PREKEY, byteArrayOf(1, 2, 3)).encode()
        assertEquals(3, b[0].toInt())
        val d = E2eBlob.decode(b)!!
        assertEquals(E2eBlob.PREKEY, d.type)
        assertArrayEquals(byteArrayOf(1, 2, 3), d.body)
        assertNull(E2eBlob.decode(byteArrayOf(4, 1)))
        assertEquals(3983, E2eBlob.MAX_BYTES)
    }
}

class MailboxCryptoTest {
    private val secret = ByteArray(32) { it.toByte() }

    /** Vectors computed independently with Python hashlib. */
    @Test
    fun tagMatchesSpec() {
        assertEquals("3bfa8321742bc8e8", hex(MailboxCrypto.tag(secret)))
        assertEquals(8, MailboxCrypto.tag(Rand.bytes(32)).size)
    }

    @Test
    fun ownerHashMatchesSpec() {
        assertEquals("630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd", hex(MailboxCrypto.ownerHash(secret)))
    }

    @Test
    fun base64urlNoPadding() {
        assertEquals("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", B64.enc(secret))
        assertArrayEquals(byteArrayOf(-5, -1), B64.dec("-_8"))
    }
}

class InviteTest {
    private val key = Rand.bytes(32)
    private val id = B64.enc(Rand.bytes(16))

    @Test
    fun uriRoundTrip() {
        for (server in listOf("https://relay.example.org", "https://h.example:8443/sub/path", "http://10.0.2.2:5000")) {
            val link = InviteLink(server, id, key)
            val uri = link.toUri()
            assertTrue(uri.startsWith("gfsend://invite#v=1&s="))
            assertEquals(link, InviteLink.parse(uri))
        }
    }

    @Test
    fun parseRejectsBadInput() {
        val good = InviteLink("https://x.example", id, key).toUri()
        assertNull(InviteLink.parse("https://x.example/#v=1"))
        assertNull(InviteLink.parse(good.replace("v=1", "v=2")))
        assertNull(InviteLink.parse("gfsend://invite#v=1&s=https%3A%2F%2Fx&i=$id&k=${B64.enc(ByteArray(16))}"))
        assertNull(InviteLink.parse("gfsend://invite#v=1&s=https%3A%2F%2Fx&i=abc&k=${B64.enc(key)}"))
        assertNull(InviteLink.parse("gfsend://invite"))
        assertNotNull(InviteLink.parse("  $good  "))
    }

    private fun bundle() = InviteBundle(
        server = "https://relay.example.org",
        sendSecret = B64.enc(Rand.bytes(32)),
        registrationId = 1234,
        identityKey = B64.enc(Rand.bytes(33)),
        signedPreKeyId = 7,
        signedPreKey = B64.enc(Rand.bytes(33)),
        signedPreKeySig = B64.enc(Rand.bytes(64)),
        kyberPreKeyId = 8,
        kyberPreKey = B64.enc(Rand.bytes(1569)),
        kyberPreKeySig = B64.enc(Rand.bytes(64)),
        name = "Ada",
    )

    @Test
    fun blobRoundTrip() {
        val b = bundle()
        val blob = InviteCrypto.encrypt(key, b)
        assertTrue(blob.size <= 4096)
        assertEquals(b, InviteCrypto.decrypt(key, blob))
    }

    @Test
    fun blobIsAuthenticated() {
        val blob = InviteCrypto.encrypt(key, bundle())
        blob[blob.size - 1] = (blob[blob.size - 1].toInt() xor 1).toByte()
        try {
            InviteCrypto.decrypt(key, blob)
            fail("tampered blob accepted")
        } catch (e: Exception) {
            // expected
        }
        try {
            InviteCrypto.decrypt(Rand.bytes(32), InviteCrypto.encrypt(key, bundle()))
            fail("wrong key accepted")
        } catch (e: Exception) {
            // expected
        }
    }

    @Test
    fun blobUsesSpecAad() {
        val b = bundle()
        val blob = Aead.seal(key, b.encode(), "gf/invite/v1".toByteArray())
        assertEquals(b, InviteCrypto.decrypt(key, blob))
    }

    @Test
    fun bundleJsonFieldNames() {
        val json = bundle().encode().toString(Charsets.UTF_8)
        for (f in listOf("\"v\":1", "\"server\"", "\"sendSecret\"", "\"registrationId\"", "\"deviceId\":1", "\"identityKey\"", "\"signedPreKeyId\"",
            "\"signedPreKey\"", "\"signedPreKeySig\"", "\"kyberPreKeyId\"", "\"kyberPreKey\"", "\"kyberPreKeySig\"", "\"name\"")) {
            assertTrue("missing $f in $json", json.contains(f))
        }
    }
}

class ContentTest {
    private fun rt(c: Content) = assertEquals(c, Content.decode(c.encode()))

    @Test
    fun roundTripsAllTypes() {
        rt(Content.Hello("https://s.example", "abc", "Bob"))
        rt(Content.Hello("https://s.example", "abc"))
        rt(Content.Text("id1", "hello \"world\" 🐟", 1700000000000, 3600, true, 0, 2))
        rt(Content.Text("id2", "plain", 1))
        rt(Content.Receipt(listOf("a", "b"), Content.Receipt.READ))
        rt(Content.Timer(86400))
        rt(Content.Delete(listOf("x")))
        rt(Content.Mailbox("https://s.example", "zzz"))
    }

    @Test
    fun usesTDiscriminatorAndOmitsNulls() {
        val json = Content.Text("i", "b", 5).encode().toString(Charsets.UTF_8)
        assertTrue(json, json.contains("\"t\":\"text\""))
        assertFalse(json, json.contains("exp"))
        assertFalse(json, json.contains("null"))
    }

    @Test
    fun decodesSpecLiterals() {
        assertEquals(
            Content.Receipt(listOf("m1"), "delivered"),
            Content.decode("""{"t":"receipt","ids":["m1"],"kind":"delivered"}""".toByteArray()),
        )
        assertEquals(Content.Timer(0), Content.decode("""{"t":"timer","secs":0}""".toByteArray()))
        // Unknown fields from newer clients are ignored.
        assertEquals(
            Content.Hello("https://a", "s", null),
            Content.decode("""{"t":"hello","server":"https://a","sendSecret":"s","future":true}""".toByteArray()),
        )
    }

    @Test
    fun chunkerFitsBudgetAndReassembles() {
        val body = buildString {
            repeat(900) { append("Quoted \"text\" with emoji 🐟 and ünïcödé. ") }
        }
        for (max in listOf(Padding.MAX_PREKEY_PLAINTEXT, Padding.MAX_PLAINTEXT)) {
            val parts = Chunker.split("mid", body, 123, 60, null, max)
            assertTrue(parts.size > 1)
            for (p in parts) {
                assertTrue("part too big for $max", Padding.paddedSize(p.encode().size) <= max)
                assertEquals(parts.size, p.parts)
            }
            assertEquals(body, parts.sortedBy { it.part }.joinToString("") { it.body })
        }
        val short = Chunker.split("s", "hi", 1, null, null, Padding.MAX_PLAINTEXT)
        assertEquals(1, short.size)
        assertNull(short[0].parts)
    }
}
