package app.goldfishsend

import androidx.test.ext.junit.runners.AndroidJUnit4
import app.goldfishsend.core.Graph
import app.goldfishsend.core.LockedInbox
import app.goldfishsend.core.Mailboxes
import app.goldfishsend.core.Prefs
import app.goldfishsend.crypto.BucketKeys
import app.goldfishsend.db.Db
import app.goldfishsend.db.Mailbox
import app.goldfishsend.proto.B64
import app.goldfishsend.proto.Content
import app.goldfishsend.proto.InviteLink
import app.goldfishsend.proto.Rand
import app.goldfishsend.security.SecurityAudit
import app.goldfishsend.security.Severity
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** On-device checks for server identity pins (gateway v1): schema v4, contact pins, own-server changes and invites v2. */
@RunWith(AndroidJUnit4::class)
class ServerIdentityDeviceTest {
    private val ctx get() = Graph.app
    private val fpA = B64.enc(ByteArray(32) { 1 })
    private val fpB = B64.enc(ByteArray(32) { 2 })

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

    @Test
    fun schemaV3UpgradesToV4KeepingContacts() = runBlocking<Unit> {
        val mk = Graph.vault.setup(null)
        val keep = mk.copyOf()
        var s = Graph.openSession(mk)
        val cid = s.repo.createContact("Bob", true, 0, "https://bob.example", ByteArray(32) { 9 })
        // Turn this into a version-3 database: without the v4 columns.
        s.db.exec("ALTER TABLE contacts DROP COLUMN out_server_key")
        s.db.exec("ALTER TABLE contacts DROP COLUMN pending_server_key")
        s.db.exec("PRAGMA user_version = 3")
        Graph.lock()
        s = Graph.openSession(keep)
        assertEquals(app.goldfishsend.db.Schema.VERSION.toLong(), s.db.long("PRAGMA user_version"))
        val c = s.repo.contact(cid)!!
        assertEquals("Bob", c.name)
        assertEquals("https://bob.example", c.outServer)
        assertNull(c.outServerKey)
        assertNull(c.pendingServerKey)
    }

    @Test
    fun contactPinsFollowTrustOnFirstUseAndE2eAnnouncements() = runBlocking<Unit> {
        val s = Graph.openSession(Graph.vault.setup(null))
        val cid = s.repo.createContact("Bob", false, 0, "https://bob.example", ByteArray(32), outServerKey = null)
        // Learned once; never overwritten by a later first use.
        s.repo.learnOutServerKey(cid, "https://bob.example", fpA)
        s.repo.learnOutServerKey(cid, "https://bob.example", fpB)
        assertEquals(fpA, s.repo.contact(cid)!!.outServerKey)
        // A mismatch is held for review and doesn't change the pin.
        s.repo.setPendingServerKey(cid, fpB)
        assertEquals(fpA, s.repo.contact(cid)!!.outServerKey)
        assertEquals(fpB, s.repo.contact(cid)!!.pendingServerKey)
        // Trusting only applies to the exact key that was reviewed.
        s.repo.trustPendingServerKey(cid, fpA)
        assertEquals(fpB, s.repo.contact(cid)!!.pendingServerKey)
        s.repo.trustPendingServerKey(cid, fpB)
        assertEquals(fpB, s.repo.contact(cid)!!.outServerKey)
        assertNull(s.repo.contact(cid)!!.pendingServerKey)

        // An E2E mailbox message with a key replaces the pin and resolves a pending change.
        s.repo.setPendingServerKey(cid, fpA)
        s.repo.updateContactOutbound(cid, "https://bob.example", ByteArray(32) { 3 }, fpA)
        assertEquals(fpA, s.repo.contact(cid)!!.outServerKey)
        assertNull(s.repo.contact(cid)!!.pendingServerKey)
        // Without a key: kept on the same server, dropped (trust on first use) when the server changes.
        s.repo.updateContactOutbound(cid, "https://bob.example", ByteArray(32) { 4 }, null)
        assertEquals(fpA, s.repo.contact(cid)!!.outServerKey)
        s.repo.updateContactOutbound(cid, "https://elsewhere.example", ByteArray(32) { 5 }, null)
        assertNull(s.repo.contact(cid)!!.outServerKey)
        // First use is tied to the server it was learned for.
        s.repo.learnOutServerKey(cid, "https://bob.example", fpB)
        assertNull(s.repo.contact(cid)!!.outServerKey)
    }

    @Test
    fun changedOwnServerIdentityIsACriticalAlertThatCantBeDismissed() {
        val clean = SecurityAudit.run(ctx, 0)
        assertTrue(clean.active.none { it.id == "server_identity" })
        Graph.prefs.serverKey = fpA
        Graph.prefs.serverKeyChanged = fpB
        val report = SecurityAudit.run(ctx, 0)
        val f = report.active.firstOrNull { it.id == "server_identity" }
        assertNotNull(f)
        assertEquals(Severity.CRITICAL, f!!.severity)
        assertFalse(f.dismissible)
        Graph.prefs.dismissFinding(f.dismissKey)
        assertTrue(SecurityAudit.run(ctx, 0).active.any { it.id == "server_identity" })
    }

    @Test
    fun trustingANewOwnServerKeyAnnouncesItToEveryContact() = runBlocking<Unit> {
        val s = Graph.openSession(Graph.vault.setup(null))
        Graph.prefs.serverKey = fpA
        Graph.prefs.serverKeyChanged = fpB
        val cid = s.repo.createContact("Bob", false, 0, "https://bob.example", ByteArray(32), fpA)
        val send = Rand.bytes(32)
        val mb = s.repo.insertMailbox(Mailbox.PURPOSE_CONTACT, send, Rand.bytes(32), Rand.bytes(8))
        s.repo.setMailboxState(mb, Mailbox.STATE_ACTIVE)
        s.repo.bindMailbox(mb, cid)

        Mailboxes.trustNewServerKey(s, fpB)
        assertEquals(fpB, Graph.prefs.serverKey)
        assertNull(Graph.prefs.serverKeyChanged)
        val announced = s.repo.outboxAll().filter { it.contactId == cid }.mapNotNull { s.repo.openOutboxContent(it) }
            .map { Content.decode(it) }.filterIsInstance<Content.Mailbox>()
        assertEquals(1, announced.size)
        assertEquals(fpB, announced[0].serverKey)
        assertEquals(B64.enc(send), announced[0].sendSecret)
        assertEquals(Graph.prefs.serverUrl, announced[0].server)
    }

    @Test
    fun builtInKeyOnlyAppliesToTheDefaultServer() {
        val builtIn = BuildConfig.DEFAULT_SERVER_KEY
        if (builtIn.isEmpty()) {
            assertNull(Prefs.builtInServerKey(BuildConfig.DEFAULT_SERVER_URL))
            assertNull(Graph.prefs.serverKey)
        } else {
            assertEquals(builtIn, Prefs.builtInServerKey(BuildConfig.DEFAULT_SERVER_URL))
        }
        assertNull(Prefs.builtInServerKey("https://other.example"))
        Graph.prefs.serverUrl = "https://other.example"
        assertNull(Graph.prefs.serverKey)
        Graph.prefs.serverKey = fpA
        assertEquals(fpA, Graph.prefs.serverKey)
    }

    @Test
    fun inviteLinksCarryTheServerFingerprint() {
        val link = InviteLink("https://relay.example", fpA, B64.enc(Rand.bytes(16)), Rand.bytes(32))
        val parsed = InviteLink.parse(link.toUri())
        assertEquals(fpA, parsed!!.serverKey)
        val v1 = "gfsend://invite#v=1&s=https%3A%2F%2Frelay.example&i=${B64.enc(Rand.bytes(16))}&k=${B64.enc(Rand.bytes(32))}"
        assertNull(InviteLink.parse(v1))
        assertTrue(InviteLink.isOutdated(v1))
    }
}
