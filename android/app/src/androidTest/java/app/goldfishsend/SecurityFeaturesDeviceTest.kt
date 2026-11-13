package app.goldfishsend

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import app.goldfishsend.core.DuressAction
import app.goldfishsend.core.Graph
import app.goldfishsend.core.LockedInbox
import app.goldfishsend.crypto.UnlockMethod
import app.goldfishsend.db.Db
import app.goldfishsend.security.AppLock
import app.goldfishsend.security.UnlockResult
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

/** On-device checks for the app PIN, duress PIN, hidden chats, decoy sessions and the v2 schema. */
@RunWith(AndroidJUnit4::class)
class SecurityFeaturesDeviceTest {
    private val ctx get() = Graph.app

    @Before
    fun clean() {
        Graph.lock()
        Graph.vault.destroyAll()
        Db.deleteFiles(ctx)
        LockedInbox.clear()
        Graph.prefs.clear()
    }

    @After
    fun tearDown() = clean()

    private fun vaultPrefs() = ctx.getSharedPreferences("gf_vault", Context.MODE_PRIVATE).all

    @Test
    fun decoySlotsLookTheSameWhetherOrNotFeaturesAreOn() {
        val mk = Graph.vault.setup("123456".toCharArray())
        val before = vaultPrefs()
        assertTrue(before.containsKey("duress") && before.containsKey("hidden_pin"))
        val emptyShape = (before["duress"] as String).length to (before["hidden_pin"] as String).length

        Graph.vault.setDuress("4321".toCharArray())
        Graph.vault.setHiddenPin("777777".toCharArray())
        val after = vaultPrefs()
        assertEquals(emptyShape, (after["duress"] as String).length to (after["hidden_pin"] as String).length)
        assertEquals(before.keys, after.keys)
    }

    @Test
    fun duressPinIsAVerifierThatCanNeverOpenRealData() {
        val mk = Graph.vault.setup("123456".toCharArray())
        Graph.vault.changePassphrase(mk.copyOf(), "123456".toCharArray(), isPin = true)
        val s = kotlinx.coroutines.runBlocking { Graph.openSession(mk.copyOf()) }
        s.repo.createContact("Real", false, 0, "https://x.example", ByteArray(32))
        Graph.lock()
        Graph.vault.setDuress("4321".toCharArray())

        assertTrue(Graph.vault.isDuress("4321".toCharArray()))
        assertFalse(Graph.vault.isDuress("123456".toCharArray()))
        assertNull(Graph.vault.unlockWithPassphrase("4321".toCharArray()))
        // Nothing derived from the duress PIN is the master key, and the real database refuses it.
        val decoyKey = Graph.vault.decoyKey("4321".toCharArray())
        assertFalse(decoyKey.contentEquals(mk))
        try {
            Db.open(ctx, decoyKey)
            org.junit.Assert.fail("the duress PIN must not open the real database")
        } catch (e: Exception) {
            // expected
        }
        Graph.vault.setDuress(null)
        assertFalse(Graph.vault.isDuress("4321".toCharArray()))
    }

    @Test
    fun hiddenPinCheck() {
        Graph.vault.setup(null)
        assertFalse(Graph.vault.isHiddenPin("000000".toCharArray()))
        Graph.vault.setHiddenPin("246810".toCharArray())
        assertTrue(Graph.vault.isHiddenPin("246810".toCharArray()))
        assertFalse(Graph.vault.isHiddenPin("246811".toCharArray()))
    }

    @Test
    fun duressOpensAPersistentIndependentDecoyProfile() = runBlocking<Unit> {
        val mk = Graph.vault.setup("123456".toCharArray())
        Graph.vault.changePassphrase(mk.copyOf(), "123456".toCharArray(), isPin = true)
        Graph.vault.setDuress("4321".toCharArray())
        val s = Graph.openSession(mk)
        val real = s.repo.createContact("Real friend", false, 0, "https://x.example", ByteArray(32))
        Graph.lock()

        Graph.prefs.duressAction = DuressAction.DECOY
        assertEquals(UnlockResult.Ok, AppLock.unlock("4321".toCharArray()))
        val decoy = Graph.session.value!!
        assertTrue(decoy.decoy)
        assertNull(Graph.realSession)
        assertTrue(decoy.repo.contacts().isEmpty())
        val fake = decoy.repo.createContact("Mum", false, 0, null, null)
        Graph.lock()

        // Same decoy contents next time.
        assertEquals(UnlockResult.Ok, AppLock.unlock("4321".toCharArray()))
        assertEquals(listOf("Mum"), Graph.session.value!!.repo.contacts().map { it.name })
        Graph.lock()

        // The real PIN shows the real data, untouched, and nothing of the decoy.
        assertEquals(UnlockResult.Ok, AppLock.unlock("123456".toCharArray()))
        val back = Graph.session.value!!
        assertFalse(back.decoy)
        assertEquals(listOf(real), back.repo.contacts().map { it.id })
        fake.toString()
    }

    @Test
    fun aPushDuringADecoySessionIsKeptForTheRealUnlock() = runBlocking<Unit> {
        val mk = Graph.vault.setup("123456".toCharArray())
        Graph.vault.changePassphrase(mk.copyOf(), "123456".toCharArray(), isPin = true)
        Graph.vault.setDuress("4321".toCharArray())
        Graph.openSession(mk)
        Graph.lock()
        Graph.prefs.duressAction = DuressAction.DECOY
        assertEquals(UnlockResult.Ok, AppLock.unlock("4321".toCharArray()))
        assertTrue(Graph.session.value!!.decoy)

        val push = app.goldfishsend.proto.PushEnvelope.build(
            app.goldfishsend.proto.PushEnvelope.TYPE_MESSAGE, ByteArray(8) { 5 }, byteArrayOf(3, 1, 2, 3),
        )
        app.goldfishsend.core.Messenger.onPushPayload(push)
        assertFalse("kept in the locked inbox, not processed by the decoy", LockedInbox.isEmpty)
        Graph.lock()

        assertEquals(UnlockResult.Ok, AppLock.unlock("123456".toCharArray()))
        // The real unlock drains it (in the background).
        repeat(50) {
            if (LockedInbox.isEmpty) return@repeat
            Thread.sleep(100)
        }
        assertTrue(LockedInbox.isEmpty)
    }

    @Test
    fun failedAttemptsAreCountedAndErase() = runBlocking {
        val mk = Graph.vault.setup("123456".toCharArray())
        Graph.vault.changePassphrase(mk, "123456".toCharArray(), isPin = true)
        Graph.prefs.onboarded = true
        Graph.prefs.maxFailedAttempts = 3
        assertEquals(UnlockResult.Wrong(2), AppLock.unlock("000000".toCharArray()))
        assertEquals(UnlockResult.Wrong(1), AppLock.unlock("000001".toCharArray()))
        assertEquals(UnlockResult.Wiped, AppLock.unlock("000002".toCharArray()))
        assertFalse(Graph.vault.isSetUp)
    }

    @Test
    fun schemaV2RotationBookkeeping() = runBlocking {
        val mk = Graph.vault.setup(null)
        val s = Graph.openSession(mk)
        val cid = s.repo.createContact("C", false, 0, "https://x.example", ByteArray(32))
        val old = s.repo.insertMailbox(2, ByteArray(32) { 1 }, ByteArray(32) { 2 }, ByteArray(8) { 3 })
        s.repo.setMailboxState(old, 2)
        s.repo.bindMailbox(old, cid)
        val fresh = s.repo.insertMailbox(2, ByteArray(32) { 4 }, ByteArray(32) { 5 }, ByteArray(8) { 6 })
        s.repo.setMailboxState(fresh, 2)
        s.repo.bindMailbox(fresh, cid)
        s.repo.markReplaced(old, 1)
        assertEquals(fresh, s.repo.mailboxForContact(cid)!!.id)

        // Draining starts only once the contact uses the new mailbox, then ends after the drain window.
        assertTrue(s.repo.drainedMailboxes(Long.MAX_VALUE).isEmpty())
        s.repo.startDraining(cid, fresh, 1000)
        assertEquals(listOf(old), s.repo.drainedMailboxes(2000).map { it.id })
    }
}
