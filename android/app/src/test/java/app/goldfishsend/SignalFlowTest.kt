package app.goldfishsend

import app.goldfishsend.proto.B64
import app.goldfishsend.proto.BlobWrap
import app.goldfishsend.proto.Chunker
import app.goldfishsend.proto.Content
import app.goldfishsend.proto.E2eBlob
import app.goldfishsend.proto.InviteBundle
import app.goldfishsend.proto.InviteCrypto
import app.goldfishsend.proto.Padding
import app.goldfishsend.proto.PushEnvelope
import app.goldfishsend.proto.Rand
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.IdentityKeyPair
import org.signal.libsignal.protocol.SessionBuilder
import org.signal.libsignal.protocol.SessionCipher
import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.ecc.ECKeyPair
import org.signal.libsignal.protocol.ecc.ECPublicKey
import org.signal.libsignal.protocol.kem.KEMKeyPair
import org.signal.libsignal.protocol.kem.KEMKeyType
import org.signal.libsignal.protocol.kem.KEMPublicKey
import org.signal.libsignal.protocol.message.CiphertextMessage
import org.signal.libsignal.protocol.message.PreKeySignalMessage
import org.signal.libsignal.protocol.message.SignalMessage
import org.signal.libsignal.protocol.state.KyberPreKeyRecord
import org.signal.libsignal.protocol.state.PreKeyBundle
import org.signal.libsignal.protocol.state.SignedPreKeyRecord
import org.signal.libsignal.protocol.state.impl.InMemorySignalProtocolStore

/**
 * Exercises the exact libsignal calls used by Invites/Messenger/Outbox (with in-memory stores) and checks that
 * real ciphertexts fit the push budget from protocol.md.
 */
/**
 * Mirrors SignalStore's one-time semantics: markKyberPreKeyUsed deletes both the Kyber and the signed prekey.
 */
private class OneTimeStore(kp: IdentityKeyPair, reg: Int) : InMemorySignalProtocolStore(kp, reg) {
    val deletedKyber = mutableSetOf<Int>()
    val deletedSigned = mutableSetOf<Int>()

    override fun loadKyberPreKey(id: Int): KyberPreKeyRecord {
        if (id in deletedKyber) throw org.signal.libsignal.protocol.InvalidKeyIdException("deleted")
        return super.loadKyberPreKey(id)
    }

    override fun containsKyberPreKey(id: Int): Boolean = id !in deletedKyber && super.containsKyberPreKey(id)

    override fun loadSignedPreKey(id: Int): SignedPreKeyRecord {
        if (id in deletedSigned) throw org.signal.libsignal.protocol.InvalidKeyIdException("deleted")
        return super.loadSignedPreKey(id)
    }

    override fun containsSignedPreKey(id: Int): Boolean = id !in deletedSigned && super.containsSignedPreKey(id)

    override fun markKyberPreKeyUsed(kyberId: Int, signedId: Int, baseKey: ECPublicKey) {
        deletedKyber += kyberId
        deletedSigned += signedId
    }
}

class SignalFlowTest {
    private val self = SignalProtocolAddress("self", 1)
    private val alice = OneTimeStore(IdentityKeyPair.generate(), 1111)
    private val bob = InMemorySignalProtocolStore(IdentityKeyPair.generate(), 2222)
    private val aliceSeenFromBob = SignalProtocolAddress("c1", 1)
    private val bobSeenFromAlice = SignalProtocolAddress("c7", 1)

    /** Alice creates an invite exactly as Invites.create does. */
    private fun aliceInvite(): InviteBundle {
        val id = alice.identityKeyPair
        val spk = ECKeyPair.generate()
        val spkSig = id.privateKey.calculateSignature(spk.publicKey.serialize())
        alice.storeSignedPreKey(10, SignedPreKeyRecord(10, System.currentTimeMillis(), spk, spkSig))
        val kyber = KEMKeyPair.generate(KEMKeyType.KYBER_1024)
        val kyberSig = id.privateKey.calculateSignature(kyber.publicKey.serialize())
        alice.storeKyberPreKey(11, KyberPreKeyRecord(11, System.currentTimeMillis(), kyber, kyberSig))
        return InviteBundle(
            server = "https://relay.example.org",
            sendSecret = B64.enc(Rand.bytes(32)),
            registrationId = alice.localRegistrationId,
            identityKey = B64.enc(id.publicKey.serialize()),
            signedPreKeyId = 10,
            signedPreKey = B64.enc(spk.publicKey.serialize()),
            signedPreKeySig = B64.enc(spkSig),
            kyberPreKeyId = 11,
            kyberPreKey = B64.enc(kyber.publicKey.serialize()),
            kyberPreKeySig = B64.enc(kyberSig),
            name = "Alice",
            wrapKey = B64.enc(aliceWrap),
        )
    }

    /** Alice's mailbox's wrap key (from her invite) and Bob's (from his hello). */
    private val aliceWrap = BlobWrap.newKey()
    private val bobWrap = BlobWrap.newKey()

    private fun wrapFor(remote: SignalProtocolAddress) = if (remote == aliceSeenFromBob) aliceWrap else bobWrap

    /** Encrypted and wrapped for [remote]'s mailbox, exactly as Outbox sends it. The type byte is inside the wrapping. */
    private fun encrypt(store: InMemorySignalProtocolStore, remote: SignalProtocolAddress, content: Content): ByteArray {
        val msg = SessionCipher(store, self, remote).encrypt(Padding.pad(content.encode()))
        return BlobWrap.seal(wrapFor(remote), E2eBlob(msg.type, msg.serialize()).encode())
    }

    private fun type(remote: SignalProtocolAddress, wrapped: ByteArray): Int = BlobWrap.open(wrapFor(remote), wrapped)!![0].toInt()

    private fun decrypt(store: InMemorySignalProtocolStore, remote: SignalProtocolAddress, raw: ByteArray): Content {
        // [store] receives on its own mailbox: Alice's when the sender is Bob.
        val blob = E2eBlob.decode(BlobWrap.open(if (remote == bobSeenFromAlice) aliceWrap else bobWrap, raw)!!)!!
        val cipher = SessionCipher(store, self, remote)
        val pt = if (blob.type == E2eBlob.PREKEY) cipher.decrypt(PreKeySignalMessage(blob.body)) else cipher.decrypt(SignalMessage(blob.body))
        return Content.decode(Padding.unpad(pt))
    }

    @Test
    fun inviteHandshakeAndConversation() {
        val key = Rand.bytes(32)
        val invite = InviteCrypto.decrypt(key, InviteCrypto.encrypt(key, aliceInvite()))
        assertTrue("invite blob must fit maxInviteBytes", InviteCrypto.encrypt(key, invite).size <= 4096)

        // Bob processes the bundle exactly as Invites.accept does.
        val pk = PreKeyBundle(
            invite.registrationId, invite.deviceId, PreKeyBundle.NULL_PRE_KEY_ID, null,
            invite.signedPreKeyId, ECPublicKey(B64.dec(invite.signedPreKey)), B64.dec(invite.signedPreKeySig),
            IdentityKey(B64.dec(invite.identityKey)),
            invite.kyberPreKeyId, KEMPublicKey(B64.dec(invite.kyberPreKey)), B64.dec(invite.kyberPreKeySig),
        )
        SessionBuilder(bob, aliceSeenFromBob, self).process(pk)

        val hello = Content.Hello("https://bob.example", B64.enc(Rand.bytes(32)), "Bob", wrapKey = B64.enc(bobWrap))
        val helloBlob = encrypt(bob, aliceSeenFromBob, hello)
        assertEquals(CiphertextMessage.PREKEY_TYPE, type(aliceSeenFromBob, helloBlob))
        // The server sees none of it: the size is one of the fixed ones, and Bob's identity key isn't in the bytes.
        assertTrue(helloBlob.size in BlobWrap.SIZES)
        assertFalse(helloBlob.toList().windowed(33).any { it.toByteArray().contentEquals(bob.identityKeyPair.publicKey.serialize()) })
        assertEquals(hello, decrypt(alice, bobSeenFromAlice, helloBlob))

        assertTrue("one-time prekeys must be consumed", 11 in alice.deletedKyber && 10 in alice.deletedSigned)

        // Bob keeps sending PreKey messages until Alice replies. They must still decrypt after the prekeys are deleted.
        val text = Content.Text("t1", "hi", 1)
        assertEquals(CiphertextMessage.PREKEY_TYPE, type(aliceSeenFromBob, encrypt(bob, aliceSeenFromBob, text).also {
            assertEquals(text, decrypt(alice, bobSeenFromAlice, it))
        }))

        val reply = encrypt(alice, bobSeenFromAlice, Content.Text("t2", "hello Bob", 2))
        assertEquals(CiphertextMessage.WHISPER_TYPE, type(bobSeenFromAlice, reply))
        assertEquals("hello Bob", (decrypt(bob, aliceSeenFromBob, reply) as Content.Text).body)

        val after = encrypt(bob, aliceSeenFromBob, Content.Receipt(listOf("t2"), "read"))
        assertEquals(CiphertextMessage.WHISPER_TYPE, type(aliceSeenFromBob, after))
        decrypt(alice, bobSeenFromAlice, after)
    }

    /**
     * Largest padded plaintexts allowed by protocol.md must fit maxMessageBytes once encrypted and wrapped, a group's with
     * its 32-byte hint too.
     */
    @Test
    fun maxSizedMessagesFitPushBudget() {
        val invite = aliceInvite()
        val pk = PreKeyBundle(
            invite.registrationId, 1, PreKeyBundle.NULL_PRE_KEY_ID, null,
            invite.signedPreKeyId, ECPublicKey(B64.dec(invite.signedPreKey)), B64.dec(invite.signedPreKeySig),
            IdentityKey(B64.dec(invite.identityKey)),
            invite.kyberPreKeyId, KEMPublicKey(B64.dec(invite.kyberPreKey)), B64.dec(invite.kyberPreKeySig),
        )
        SessionBuilder(bob, aliceSeenFromBob, self).process(pk)

        val longBody = "x".repeat(20_000)
        // PreKey phase: chunks padded to ≤ 2048.
        val preParts = Chunker.split("big", longBody, 1, null, null, Padding.MAX_PREKEY_PLAINTEXT)
        var maxPre = 0
        for (p in preParts) {
            val blob = encrypt(bob, aliceSeenFromBob, p)
            assertEquals(CiphertextMessage.PREKEY_TYPE, type(aliceSeenFromBob, blob))
            assertTrue(blob.size in BlobWrap.SIZES)
            maxPre = maxOf(maxPre, BlobWrap.open(aliceWrap, blob)!!.size)
            decrypt(alice, bobSeenFromAlice, blob)
        }
        // Group blobs carry the hint inside too, and every group message may be a PreKey one.
        assertTrue("PreKey blob $maxPre exceeds ${BlobWrap.MAX_INNER}", maxPre + 32 <= BlobWrap.MAX_INNER)

        // Whisper phase: chunks padded to ≤ 3584, in both directions.
        decrypt(bob, aliceSeenFromBob, encrypt(alice, bobSeenFromAlice, Content.Text("r", "ok", 1)))
        var maxWhisper = 0
        for (p in Chunker.split("big2", longBody, 1, null, null, Padding.MAX_PLAINTEXT)) {
            val blob = encrypt(bob, aliceSeenFromBob, p)
            assertEquals(CiphertextMessage.WHISPER_TYPE, type(aliceSeenFromBob, blob))
            assertTrue(blob.size in BlobWrap.SIZES)
            maxWhisper = maxOf(maxWhisper, BlobWrap.open(aliceWrap, blob)!!.size)
            decrypt(alice, bobSeenFromAlice, blob)
        }
        assertTrue("Whisper blob $maxWhisper exceeds ${BlobWrap.MAX_INNER}", maxWhisper <= BlobWrap.MAX_INNER)

        // And the largest wrapped blob must fit the push envelope's 3993-byte plaintext.
        assertEquals(E2eBlob.MAX_BYTES, BlobWrap.SIZES.last())
        val env = PushEnvelope.build(PushEnvelope.TYPE_MESSAGE, ByteArray(8), ByteArray(BlobWrap.SIZES.last()))
        assertEquals(3993, env.size)
        println("max PreKey blob = $maxPre B, max Whisper blob = $maxWhisper B inside the wrapping (budget ${BlobWrap.MAX_INNER})")
    }
}
