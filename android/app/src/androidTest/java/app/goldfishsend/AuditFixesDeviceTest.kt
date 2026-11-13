package app.goldfishsend

import androidx.test.ext.junit.runners.AndroidJUnit4
import app.goldfishsend.core.Graph
import app.goldfishsend.core.LockedInbox
import app.goldfishsend.core.Messenger
import app.goldfishsend.crypto.BucketKeys
import app.goldfishsend.crypto.KeyVault
import app.goldfishsend.crypto.UnlockMethod
import app.goldfishsend.db.Db
import app.goldfishsend.db.MsgKind
import app.goldfishsend.db.MsgStatus
import app.goldfishsend.security.AppLock
import app.goldfishsend.security.Presence
import app.goldfishsend.security.UnlockResult
import app.goldfishsend.security.Wiper
import java.security.KeyStore
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

/** On-device checks for the client audit fixes (M2, M3, M4, M5, M6, M7). */
@RunWith(AndroidJUnit4::class)
class AuditFixesDeviceTest {
    private val ctx get() = Graph.app

    @Before
    fun clean() {
        Graph.lock()
        Graph.vault.destroyAll()
        BucketKeys.destroyAll()
        Db.deleteFiles(ctx)
        LockedInbox.clear()
        Graph.prefs.clear()
    }

    @After
    fun tearDown() = clean()

    private fun aliases(): List<String> = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.aliases().toList()

    // ---- M4: master-key rotation ----

    @Test
    fun changingUnlockMethodRotatesTheMasterKeyAndDeviceAlias() = runBlocking<Unit> {
        val mk = Graph.vault.setup(null)
        val original = mk.copyOf()
        val s = Graph.openSession(mk)
        val cid = s.repo.createContact("Bob", false, 0, "https://x.example", ByteArray(32))
        val id = s.repo.insertMessage(cid, "w", false, MsgKind.TEXT, "keep me", 1, 1, 0, false, null, MsgStatus.DELIVERED)!!
        val aliasesBefore = aliases().filter { it.startsWith("gf_device") }

        Graph.changeUnlock(s, KeyVault.Target.Secret("135790".toCharArray(), isPin = true))
        assertEquals(UnlockMethod.APP_SECRET, Graph.vault.unlockMethod)
        assertTrue(Graph.vault.secretIsPin)
        assertFalse(Graph.vault.hasPendingRotation)
        // A brand-new MK: the old one no longer opens the database.
        val newMk = s.masterKeyCopy()
        assertFalse(newMk.contentEquals(original))
        Graph.lock()
        try {
            Db.open(ctx, original)
            org.junit.Assert.fail("the old master key must not open the rekeyed database")
        } catch (e: Exception) {
            // expected
        }
        // The old device alias is gone; exactly one (new) device alias remains.
        val aliasesAfter = aliases().filter { it.startsWith("gf_device") }
        assertEquals(1, aliasesAfter.size)
        assertTrue(aliasesBefore.none { it in aliasesAfter })

        assertEquals(UnlockResult.Ok, AppLock.unlock("135790".toCharArray()))
        assertEquals("keep me", Graph.session.value!!.repo.message(id)!!.body)
    }

    @Test
    fun duressSurvivesAnUnlockMethodChange() = runBlocking<Unit> {
        val mk = Graph.vault.setup(null)
        val s = Graph.openSession(mk)
        Graph.changeUnlock(s, KeyVault.Target.Secret("111222".toCharArray(), isPin = true))
        Graph.vault.setDuress("4321".toCharArray())
        // A new device-key alias: the verifier moves with it.
        Graph.changeUnlock(s, KeyVault.Target.Secret("333444".toCharArray(), isPin = true))
        assertTrue(Graph.vault.isDuress("4321".toCharArray()))
        assertArrayEquals(s.masterKeyCopy(), Graph.vault.unlockWithPassphrase("333444".toCharArray()))
        assertNull(Graph.vault.unlockWithPassphrase("111222".toCharArray()))
        assertNull(Graph.vault.unlockWithPassphrase("4321".toCharArray()))
    }

    @Test
    fun crashAfterRekeyIsRecoveredWithTheOldCredential() = runBlocking<Unit> {
        val mk = Graph.vault.setup("246802".toCharArray())
        Graph.vault.changePassphrase(mk.copyOf(), "246802".toCharArray(), isPin = true)
        val s = Graph.openSession(mk.copyOf())
        val cid = s.repo.createContact("Carol", false, 0, "https://x.example", ByteArray(32))
        // Simulate a crash between the rekey and the promotion.
        val newMk = app.goldfishsend.proto.Rand.bytes(32)
        Graph.vault.stageRotation(s.masterKeyCopy(), newMk, KeyVault.Target.Secret("999888".toCharArray(), isPin = true))
        s.db.rekey(newMk)
        Graph.lock()
        assertTrue(Graph.vault.hasPendingRotation)

        // The old PIN still works, recovers the new key and finishes the change.
        assertEquals(UnlockResult.Ok, AppLock.unlock("246802".toCharArray()))
        assertNotNull(Graph.session.value!!.repo.contact(cid))
        assertFalse(Graph.vault.hasPendingRotation)
        Graph.lock()
        assertEquals(UnlockResult.Ok, AppLock.unlock("999888".toCharArray()))
    }

    @Test
    fun crashBeforeRekeyDiscardsTheStage() = runBlocking<Unit> {
        val mk = Graph.vault.setup(null)
        val s = Graph.openSession(mk.copyOf())
        Graph.vault.stageRotation(s.masterKeyCopy(), app.goldfishsend.proto.Rand.bytes(32), KeyVault.Target.Secret("555666".toCharArray(), true))
        Graph.lock()
        assertNotNull(Graph.tryAutoUnlock())
        assertFalse(Graph.vault.hasPendingRotation)
        assertEquals(UnlockMethod.NONE, Graph.vault.unlockMethod)
    }

    // ---- M3: view-once ----

    @Test
    fun viewOnceCanOnlyBeOpenedOnce() = runBlocking<Unit> {
        val s = Graph.openSession(Graph.vault.setup(null))
        val cid = s.repo.createContact("Dan", false, 0, "https://x.example", ByteArray(32))
        val id = s.repo.insertMessage(cid, "v", false, MsgKind.TEXT, "secret once", 1, 1, 0, true, null, MsgStatus.DELIVERED)!!
        assertEquals("secret once", Messenger.consumeViewOnce(s, id))
        assertNull(Messenger.consumeViewOnce(s, id))
        assertNull(s.repo.message(id))
    }

    // ---- M2: reboot wipe while locked ----

    @Test
    fun rebootWipeWhileLockedClearsTheInboxAndRotatesItsKey() = runBlocking<Unit> {
        Graph.prefs.onboarded = true
        Graph.prefs.wipeOnReboot = true
        val s = Graph.openSession(Graph.vault.setup(null))
        val pubBefore = Graph.prefs.inboxPublicKey
        Graph.lock()
        LockedInbox.put(LockedInbox.KIND_PUSH, ByteArray(40) { 1 })
        assertFalse(LockedInbox.isEmpty)

        Wiper.wipeMessages()
        assertTrue(LockedInbox.isEmpty)
        assertTrue(Graph.prefs.inboxRotatePending)

        val s2 = Graph.tryAutoUnlock()!!
        AppLock.afterUnlock(s2)
        // afterUnlock runs on a background scope; wait for the rotation.
        repeat(50) {
            if (!Graph.prefs.inboxRotatePending) return@repeat
            Thread.sleep(100)
        }
        assertFalse(Graph.prefs.inboxRotatePending)
        assertTrue(Graph.prefs.inboxPublicKey != pubBefore)
        s.toString()
    }

    @Test
    fun theSameBootIsOnlyHandledOnce() {
        Graph.prefs.onboarded = true
        Graph.prefs.wipeOnReboot = true
        Wiper.checkBoot(ctx, fromBootBroadcast = false)
        val count = Graph.prefs.lastBootCount
        LockedInbox.put(LockedInbox.KIND_PUSH, ByteArray(8))
        // A late BOOT_COMPLETED for a boot already handled must not wipe again.
        Wiper.checkBoot(ctx, fromBootBroadcast = true)
        assertEquals(count, Graph.prefs.lastBootCount)
        assertFalse(Graph.prefs.inboxRotatePending)
    }

    // ---- M6: inactivity ----

    @Test
    fun inactivityUsesPresenceNotBackgroundUnlocks() = runBlocking<Unit> {
        Graph.prefs.onboarded = true
        Graph.prefs.inactivityWipeDays = 3
        val mk = Graph.vault.setup(null)
        // First check with no mark yet: starts the clock instead of erasing.
        Wiper.checkInactivity(ctx)
        assertNotNull(Graph.prefs.presence)
        // A background auto-unlock doesn't count as presence.
        val mark = Graph.prefs.presence!!
        Graph.openSession(mk)
        assertEquals(mark, Graph.prefs.presence)
        // Pretend the user was last here 4 days ago on this boot.
        Graph.prefs.presence = Presence.Mark(mark.wallMs, mark.elapsedMs - 4 * 86_400_000L, mark.bootCount)
        Wiper.checkInactivity(ctx)
        assertFalse(Graph.vault.isSetUp)
    }

    // ---- M7: bucket keys ----

    @Test
    fun expiringMessagesAreShreddedByDeletingTheirBucketKeyWithoutTheSession() = runBlocking<Unit> {
        val s = Graph.openSession(Graph.vault.setup(null))
        val cid = s.repo.createContact("Eve", false, 0, "https://x.example", ByteArray(32))
        val past = System.currentTimeMillis() - 2 * BucketKeys.HOUR_MS
        val gone = s.repo.insertMessage(cid, "a", false, MsgKind.TEXT, "expired", 1, 1, 60, false, past, MsgStatus.DELIVERED)!!
        val kept = s.repo.insertMessage(cid, "b", false, MsgKind.TEXT, "forever", 1, 1, 0, false, null, MsgStatus.DELIVERED)!!
        assertTrue(aliases().any { it == "gf_mb_" + BucketKeys.bucketOf(past) })
        Graph.lock()

        // While locked: the expiry alarm destroys the finished bucket through the Keystore alone.
        assertTrue(BucketKeys.shredExpired() >= 1)
        assertFalse(aliases().any { it == "gf_mb_" + BucketKeys.bucketOf(past) })

        val s2 = Graph.tryAutoUnlock()!!
        // The row may still exist until the next sweep, but its key is gone forever.
        assertEquals("", s2.repo.message(gone)?.body ?: "")
        assertEquals("forever", s2.repo.message(kept)!!.body)
    }

    // ---- M5: atomic pool claims ----

    @Test
    fun aPoolMailboxCanOnlyBeClaimedOnce() = runBlocking<Unit> {
        val s = Graph.openSession(Graph.vault.setup(null))
        val id = s.repo.insertMailbox(0, ByteArray(32) { 1 }, ByteArray(32) { 2 }, ByteArray(8) { 3 })
        s.repo.setMailboxState(id, 2)
        assertTrue(s.repo.claimMailbox(id, 1, 0))
        assertFalse(s.repo.claimMailbox(id, 0, 0))
        assertNull(s.repo.claimPoolMailbox(0, 0))
    }
}
