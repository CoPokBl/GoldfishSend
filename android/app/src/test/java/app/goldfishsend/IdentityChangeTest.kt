package app.goldfishsend

import app.goldfishsend.crypto.BoundPrekeys
import app.goldfishsend.crypto.IdentityCheck
import app.goldfishsend.proto.Padding
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.signal.libsignal.protocol.IdentityKeyPair
import org.signal.libsignal.protocol.SessionBuilder
import org.signal.libsignal.protocol.SessionCipher
import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.ecc.ECKeyPair
import org.signal.libsignal.protocol.kem.KEMKeyPair
import org.signal.libsignal.protocol.kem.KEMKeyType
import org.signal.libsignal.protocol.message.PreKeySignalMessage
import org.signal.libsignal.protocol.state.IdentityKeyStore
import org.signal.libsignal.protocol.state.KyberPreKeyRecord
import org.signal.libsignal.protocol.state.PreKeyBundle
import org.signal.libsignal.protocol.state.SignalProtocolStore
import org.signal.libsignal.protocol.state.SignedPreKeyRecord
import org.signal.libsignal.protocol.state.impl.InMemorySignalProtocolStore

/**
 * A changed identity on a 1:1 mailbox (docs/threat-model.md): only the prekeys that chat's own invite advertised can
 * start a session there, and only a message that decrypts counts as a change, with nothing recorded before.
 */
class IdentityChangeTest {
    private val self = SignalProtocolAddress("self", 1)
    private val carol = SignalProtocolAddress("c1", 1)
    private val bob = InMemorySignalProtocolStore(IdentityKeyPair.generate(), 2222)
    private var chats = 100

    /** Stores a signed and a Kyber prekey on Bob's side, as Invites.create or a group card does, and returns the bundle. */
    private fun prekeys(spkId: Int, kyberId: Int): PreKeyBundle {
        val id = bob.identityKeyPair
        val spk = ECKeyPair.generate()
        val spkSig = id.privateKey.calculateSignature(spk.publicKey.serialize())
        bob.storeSignedPreKey(spkId, SignedPreKeyRecord(spkId, System.currentTimeMillis(), spk, spkSig))
        val kyber = KEMKeyPair.generate(KEMKeyType.KYBER_1024)
        val kyberSig = id.privateKey.calculateSignature(kyber.publicKey.serialize())
        bob.storeKyberPreKey(kyberId, KyberPreKeyRecord(kyberId, System.currentTimeMillis(), kyber, kyberSig))
        return PreKeyBundle(
            bob.localRegistrationId, 1, PreKeyBundle.NULL_PRE_KEY_ID, null,
            spkId, spk.publicKey, spkSig, id.publicKey, kyberId, kyber.publicKey, kyberSig,
        )
    }

    /** Someone with their own identity starts a session from [bundle] and writes one PreKey message. */
    private fun helloFrom(bundle: PreKeyBundle, sender: InMemorySignalProtocolStore = InMemorySignalProtocolStore(IdentityKeyPair.generate(), 7)): PreKeySignalMessage {
        val bobAddr = SignalProtocolAddress("b", 1)
        SessionBuilder(sender, bobAddr, self).process(bundle)
        return PreKeySignalMessage(SessionCipher(sender, self, bobAddr).encrypt(Padding.pad("hi".toByteArray())).serialize())
    }

    /** Whether [m] decrypts with [store] as a message from a chat that has no session yet. */
    private fun decrypts(store: SignalProtocolStore, m: PreKeySignalMessage, from: SignalProtocolAddress = SignalProtocolAddress("c${chats++}", 1)): Boolean =
        try {
            SessionCipher(store, self, from).decrypt(m)
            true
        } catch (e: Exception) {
            false
        }

    /**
     * Before: every prekey sat in one store, so a hello built from a group card's last-resort prekeys (every member has
     * them) or from another invite's prekeys started a session on any chat's mailbox, and took the chat over.
     */
    @Test
    fun aChatOnlyLendsItsOwnInvitesPrekeys() {
        prekeys(10, 11)
        val groupCard = prekeys(20, 21)
        val otherInvite = prekeys(30, 31)
        assertTrue("the hole: the plain store lends any prekey", decrypts(bob, helloFrom(groupCard)))
        assertFalse(decrypts(BoundPrekeys(bob, setOf(10), setOf(11)), helloFrom(groupCard)))
        assertFalse(decrypts(BoundPrekeys(bob, setOf(10), setOf(11)), helloFrom(otherInvite)))
        // A chat begun by scanning advertised nothing: no PreKey message may start a session on it.
        assertFalse(decrypts(BoundPrekeys(bob, emptySet(), emptySet()), helloFrom(otherInvite)))
        assertTrue(decrypts(bob, helloFrom(otherInvite)))
    }

    @Test
    fun theSignedAndKyberPrekeyMustBothBeTheChats() {
        val own = prekeys(10, 11)
        val other = prekeys(30, 31)
        // The chat's own signed prekey with another invite's Kyber prekey.
        val mixed = PreKeyBundle(
            own.registrationId, 1, PreKeyBundle.NULL_PRE_KEY_ID, null,
            own.signedPreKeyId, own.signedPreKey, own.signedPreKeySignature, own.identityKey,
            other.kyberPreKeyId, other.kyberPreKey, other.kyberPreKeySignature,
        )
        assertFalse(decrypts(BoundPrekeys(bob, setOf(10), setOf(11)), helloFrom(mixed)))
        assertTrue(decrypts(BoundPrekeys(bob, setOf(10), setOf(11)), helloFrom(own)))
    }

    /** The chat's own sender keeps writing PreKey messages until we reply; those still decrypt once its prekeys are used. */
    @Test
    fun theChatsOwnFollowUpPreKeyMessagesStillDecrypt() {
        val own = prekeys(10, 11)
        val alice = InMemorySignalProtocolStore(IdentityKeyPair.generate(), 5)
        val bound = BoundPrekeys(bob, setOf(10), setOf(11))
        assertTrue(decrypts(bound, helloFrom(own, alice), carol))
        val bobAddr = SignalProtocolAddress("b", 1)
        val next = PreKeySignalMessage(SessionCipher(alice, self, bobAddr).encrypt(Padding.pad("again".toByteArray())).serialize())
        assertTrue(decrypts(bound, next, carol))
    }

    /**
     * Before: the identity in an unauthenticated PreKey message was saved (or made pending) before its MAC was checked,
     * so anyone who could address the mailbox could break the chat for good, or raise endless safety-number alerts.
     */
    @Test
    fun aForgedIdentityChangeIsRejectedAndRecordsNothing() {
        assertTrue(decrypts(bob, helloFrom(prekeys(10, 11)), carol))
        val trusted = bob.getIdentity(carol)
        val session = bob.loadSession(carol).serialize()

        // A different identity, and a body whose MAC doesn't check out.
        val forged = helloFrom(prekeys(40, 41)).serialize().also { it[it.size - 3] = (it[it.size - 3].toInt() xor 1).toByte() }
        try {
            IdentityCheck.authenticate(BoundPrekeys(bob, setOf(40), setOf(41)), self, carol, PreKeySignalMessage(forged))
            fail("a forged message must not authenticate")
        } catch (e: Exception) {
            // Expected: dropped as undecryptable.
        }
        assertEquals(trusted, bob.getIdentity(carol))
        assertArrayEquals(session, bob.loadSession(carol).serialize())
        assertTrue("its prekeys aren't used up", bob.containsKyberPreKey(41) && bob.containsSignedPreKey(40))
    }

    @Test
    fun anAuthenticChangeIsProvenWithoutTouchingTheStore() {
        assertTrue(decrypts(bob, helloFrom(prekeys(10, 11)), carol))
        val trusted = bob.getIdentity(carol)
        val session = bob.loadSession(carol).serialize()
        val m = helloFrom(prekeys(40, 41))
        assertFalse(bob.isTrustedIdentity(carol, m.identityKey, IdentityKeyStore.Direction.RECEIVING))
        IdentityCheck.authenticate(BoundPrekeys(bob, setOf(40), setOf(41)), self, carol, m)
        // Nothing changed: the identity is only accepted later, by the user, and the message replayed then.
        assertEquals(trusted, bob.getIdentity(carol))
        assertArrayEquals(session, bob.loadSession(carol).serialize())
        assertTrue(bob.containsKyberPreKey(41) && bob.containsSignedPreKey(40))
    }
}
