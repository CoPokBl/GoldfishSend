package app.goldfishsend

import androidx.test.ext.junit.runners.AndroidJUnit4
import app.goldfishsend.core.Graph
import app.goldfishsend.core.LockedInbox
import app.goldfishsend.db.Db
import app.goldfishsend.db.MsgKind
import app.goldfishsend.db.MsgStatus
import app.goldfishsend.proto.B64
import app.goldfishsend.proto.PushEnvelope
import app.goldfishsend.security.Wiper
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.signal.libsignal.protocol.ecc.ECPublicKey

/** On-device checks of the Keystore hierarchy, SQLCipher, libsignal JNI, crypto-shredding and the locked inbox. */
@RunWith(AndroidJUnit4::class)
class DeviceSecurityTest {
    private val ctx get() = Graph.app

    @Before
    fun clean() {
        // A wipe ends the process; the test runner's must survive it.
        Wiper.endProcess = {}
        Graph.lock()
        Graph.vault.destroyAll()
        Db.deleteFiles(ctx)
        LockedInbox.clear()
    }

    @After
    fun tearDown() = clean()

    @Test
    fun passphraselessSetupUnlocksAndStoresEncrypted() = runBlocking {
        val mk = Graph.vault.setup(null)
        val s = Graph.openSession(mk)
        val identity = s.signal.identityKeyPair.publicKey.serialize()
        val cid = s.repo.createContact("Test", true, 0, "https://x.example", ByteArray(32))
        val id = s.repo.insertMessage(cid, "w1", false, MsgKind.TEXT, "secret body", 1, 1, 0, false, null, MsgStatus.DELIVERED)!!
        assertEquals("secret body", s.repo.message(id)!!.body)
        Graph.lock()

        // The DB file must not contain plaintext.
        val raw = Db.file(ctx).readBytes()
        assertFalse(String(raw, Charsets.ISO_8859_1).contains("secret body"))
        assertFalse(String(raw, Charsets.ISO_8859_1).contains("SQLite format 3"))

        val s2 = Graph.tryAutoUnlock()!!
        assertArrayEquals(identity, s2.signal.identityKeyPair.publicKey.serialize())
        assertEquals("secret body", s2.repo.message(id)!!.body)
    }

    @Test
    fun passphraseWrongAndRight() = runBlocking {
        val mk = Graph.vault.setup("correct horse".toCharArray())
        val copy = mk.copyOf()
        Graph.openSession(mk)
        Graph.lock()
        assertNull(Graph.vault.unlockWithoutPassphrase())
        assertNull(Graph.vault.unlockWithPassphrase("wrong".toCharArray()))
        assertArrayEquals(copy, Graph.vault.unlockWithPassphrase("correct horse".toCharArray()))
    }

    @Test
    fun destroyingMessageKeyShredsMessagesButKeepsContacts() = runBlocking {
        val s = Graph.openSession(Graph.vault.setup(null))
        val cid = s.repo.createContact("Keep me", false, 0, null, null)
        s.repo.insertMessage(cid, "w", true, MsgKind.TEXT, "gone after reboot", 1, null, 0, false, null, MsgStatus.SENT)
        Graph.lock()
        // What "erase messages on restart" does at boot, without unlocking.
        Graph.vault.destroyMessageKey()
        val s2 = Graph.tryAutoUnlock()!!
        assertEquals("Keep me", s2.repo.contact(cid)!!.name)
        val bodies = s2.repo.messages(cid, System.currentTimeMillis()).map { it.body }
        assertFalse(bodies.contains("gone after reboot"))
        assertTrue(bodies.any { it.contains("restarted") })
    }

    @Test
    fun lockedInboxRoundTrip() = runBlocking {
        val s = Graph.openSession(Graph.vault.setup(null))
        assertNotNull(Graph.prefs.inboxPublicKey)
        // Seal while "locked" and check the ciphertext opens with the DB-held private key.
        val payload = PushEnvelope.build(PushEnvelope.TYPE_VERIFICATION, ByteArray(8), ByteArray(16))
        val sealed = ECPublicKey(B64.dec(Graph.prefs.inboxPublicKey!!)).seal(byteArrayOf(1) + payload, "gf/inbox/v1", ByteArray(0))
        val opened = Graph.inboxPrivateKey(s).open(sealed, "gf/inbox/v1", ByteArray(0))
        assertArrayEquals(byteArrayOf(1) + payload, opened)
        LockedInbox.put(LockedInbox.KIND_PUSH, payload)
        assertFalse(LockedInbox.isEmpty)
        LockedInbox.drain(s)
        assertTrue(LockedInbox.isEmpty)
    }

    @Test
    fun panicWipeDestroysEverything() = runBlocking {
        Graph.openSession(Graph.vault.setup(null))
        Graph.prefs.onboarded = true
        Wiper.wipeEverything(ctx)
        assertFalse(Graph.vault.isSetUp)
        assertFalse(Db.file(ctx).exists())
        assertFalse(Graph.prefs.onboarded)
        assertNull(Graph.session.value)
    }
}
