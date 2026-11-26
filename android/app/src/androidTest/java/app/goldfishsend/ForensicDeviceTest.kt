package app.goldfishsend

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.work.WorkManager
import app.goldfishsend.Forensics.Needle
import app.goldfishsend.core.DuressAction
import app.goldfishsend.core.Graph
import app.goldfishsend.core.Groups
import app.goldfishsend.core.LockedInbox
import app.goldfishsend.core.Messenger
import app.goldfishsend.core.Outbox
import app.goldfishsend.core.Session
import app.goldfishsend.core.Sweeper
import app.goldfishsend.crypto.BucketKeys
import app.goldfishsend.crypto.MessageVault
import app.goldfishsend.db.Db
import app.goldfishsend.db.Mailbox
import app.goldfishsend.proto.Aead
import app.goldfishsend.proto.B64
import app.goldfishsend.proto.Chunker
import app.goldfishsend.proto.Content
import app.goldfishsend.proto.E2eBlob
import app.goldfishsend.proto.MailboxCrypto
import app.goldfishsend.proto.Padding
import app.goldfishsend.proto.PushEnvelope
import app.goldfishsend.proto.Rand
import app.goldfishsend.proto.utf8
import app.goldfishsend.security.AppLock
import app.goldfishsend.security.UnlockResult
import app.goldfishsend.security.Wiper
import java.io.File
import java.security.KeyStore
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.signal.libsignal.protocol.IdentityKeyPair
import org.signal.libsignal.protocol.SessionBuilder
import org.signal.libsignal.protocol.SessionCipher
import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.ecc.ECKeyPair
import org.signal.libsignal.protocol.kem.KEMKeyPair
import org.signal.libsignal.protocol.kem.KEMKeyType
import org.signal.libsignal.protocol.message.PreKeySignalMessage
import org.signal.libsignal.protocol.message.SignalMessage
import org.signal.libsignal.protocol.state.KyberPreKeyRecord
import org.signal.libsignal.protocol.state.PreKeyBundle
import org.signal.libsignal.protocol.state.SessionRecord
import org.signal.libsignal.protocol.state.SignedPreKeyRecord
import org.signal.libsignal.protocol.state.impl.InMemorySignalProtocolStore

/**
 * No deleted plaintext or keys can be recovered from a dump of the app's storage, even by someone who also
 * holds the database key (a coerced unlock).
 *
 * Messages with random markers go through the real receive and send paths (libsignal sessions with peers, the outbox,
 * chunking, the locked inbox, groups), and are then deleted every way the app can delete them. Every file under the app's
 * data directories is then searched byte for byte, and every page of each database (live, free and unused) plus any WAL
 * frames are decrypted with the real key and searched too. Positive controls make sure the search does find live data,
 * so a broken decryption or scan can't pass by finding nothing.
 */
@RunWith(AndroidJUnit4::class)
class ForensicDeviceTest {
    private val ctx: Context get() = Graph.app
    private val opened = mutableListOf<Pair<Session, String>>()

    /** Keys that must never be written anywhere in the clear: master, database, message-root, bucket and message keys. */
    private val secrets = mutableListOf<Needle>()

    /** Everything stored for a message (ciphertext, wrapped keys, outbox and chunk blobs), by message label. */
    private val artifacts = LinkedHashMap<String, MutableList<Needle>>()
    private val deleted = LinkedHashSet<String>()

    /** Every message marker, live or deleted. Bodies are always encrypted per message, so none may ever appear. */
    private val markers = mutableListOf<Needle>()

    /** Plaintext names that live inside the database (contacts, groups) and must go when deleted. */
    private val names = LinkedHashMap<String, Needle>()

    @Before
    fun clean() {
        Graph.lock()
        runCatching { WorkManager.getInstance(ctx).cancelAllWork().result.get() }
        Graph.vault.destroyAll()
        BucketKeys.destroyAll()
        for (n in listOf("goldfish.db", Db.DECOY_NAME, "ga.db", "gb.db")) {
            Db.deleteFiles(ctx, n)
        }
        LockedInbox.clear()
        Graph.prefs.clear()
    }

    @After
    fun tearDown() {
        for ((s, _) in opened) {
            s.db.close()
        }
        clean()
    }

    // ---------------------------------------------------------------- helpers

    private fun marker(): String = "gfm" + Forensics.hex(Rand.bytes(16))

    private fun newMarker(label: String): String = marker().also { markers += Forensics.text("marker $label", it) }

    private fun mrkOf(s: Session): ByteArray =
        MessageVault::class.java.getDeclaredField("mrk").apply { isAccessible = true }.get(s.messages) as ByteArray

    /** Records everything the database holds for message [id], and its raw key (which must never be on disk). */
    private fun capture(s: Session, label: String, id: String) {
        val row = s.db.queryOne(
            "SELECT m.ciphertext, k.key, k.bucket FROM messages m JOIN message_keys k ON k.message_id = m.id WHERE m.id = ?", id,
        ) { Triple(it.getBlob(0), it.getBlob(1), if (it.isNull(2)) null else it.getLong(2)) } ?: error("$label: no row")
        val art = artifacts.getOrPut(label) { mutableListOf() }
        art += Forensics.bytes("$label ciphertext", row.first)
        art += Forensics.bytes("$label wrapped key", row.second)
        val wrapping = row.third?.let { s.messages.bucketStore!!.key(it, create = false)!! } ?: mrkOf(s)
        row.third?.let { secrets += Forensics.bytes("bucket key $it", wrapping) }
        secrets += Forensics.bytes("$label message key", Aead.open(wrapping, row.second, ("gf/msgkey/$id").utf8()))
        s.db.query("SELECT content, blob FROM outbox WHERE message_id = ?", id) {
            (if (it.isNull(0)) null else it.getBlob(0)) to (if (it.isNull(1)) null else it.getBlob(1))
        }.forEach { (content, blob) ->
            content?.let { art += Forensics.bytes("$label outbox content", it) }
            // Only the encrypted body: the rest of a Signal message (ratchet keys, post-quantum ratchet chunks) is session
            // state that other messages and the session record legitimately share.
            blob?.let {
                val e2e = E2eBlob.decode(it)!!
                val msg = if (e2e.type == E2eBlob.PREKEY) PreKeySignalMessage(e2e.body).whisperMessage else SignalMessage(e2e.body)
                art += Forensics.bytes("$label outbox ciphertext", msg.body)
            }
        }
    }

    private fun captureChunks(s: Session, label: String, cid: Long) {
        val rows = s.db.query("SELECT body FROM chunks WHERE contact_id = ?", cid) { it.getBlob(0) }
        assertTrue("$label: a chunk is waiting", rows.isNotEmpty())
        artifacts.getOrPut(label) { mutableListOf() } += rows.map { Forensics.bytes("$label chunk", it) }
    }

    private fun gone(vararg labels: String) {
        deleted += labels
    }

    private fun deletedNeedles(): List<Needle> = artifacts.filterKeys { it in deleted }.values.flatten()

    private fun liveNeedles(): List<Needle> = artifacts.filterKeys { it !in deleted }.values.flatten()

    private fun assertNoHits(what: String, hits: List<Forensics.Hit>) {
        if (hits.isNotEmpty()) {
            fail("$what:\n" + hits.joinToString("\n"))
        }
    }

    /**
     * The attacker's view. In the raw files nothing at all may be found: no name, body, key or stored blob. In the
     * decrypted pages of each database in [dbs], no body, raw key, deleted blob or [deletedNames] may be found. As
     * controls, each name in [live] must be found in its database's decrypted pages.
     */
    private fun inspect(dbs: Map<File, ByteArray>, deletedNames: List<String>, live: List<Triple<File, ByteArray, String>>) {
        val everything = Forensics.Scanner(markers + secrets + names.values + deletedNeedles() + liveNeedles())
        assertNoHits("found in the app's files (no database key needed)", Forensics.scanFiles(ctx, everything))
        for (f in Forensics.files(ctx).filter { it.name.endsWith("-journal") }) {
            assertEquals("${f.path}: a leftover rollback journal", 0L, f.length())
        }
        val forbidden = Forensics.Scanner(markers + secrets + deletedNeedles() + deletedNames.map { names.getValue(it) })
        for ((file, key) in dbs) {
            assertNoHits("recoverable with the database key", Forensics.scanDb(file, key, forbidden))
        }
        for ((file, key, name) in live) {
            val found = Forensics.scanDb(file, key, Forensics.Scanner(listOf(names.getValue(name))))
            assertTrue("control: live name $name is visible in ${file.name}", found.isNotEmpty())
        }
    }

    private fun assertLiveRowsVisible(file: File, key: ByteArray, labels: List<String>) {
        for (n in labels.flatMap { artifacts.getValue(it) }) {
            assertTrue("control: ${n.label} is visible in ${file.name}", Forensics.scanDb(file, key, Forensics.Scanner(listOf(n))).isNotEmpty())
        }
    }

    // ---------------------------------------------------------------- 1:1 peers

    private val peerMain = SignalProtocolAddress("main", 1)
    private val peerSelf = SignalProtocolAddress("self", 1)

    /** A contact on another phone: an in-memory libsignal store talking to this app through its mailbox. */
    private inner class Peer(val name: String) {
        val store = InMemorySignalProtocolStore(IdentityKeyPair.generate(), 1 + Rand.int(16000))
        var cid = 0L
        lateinit var tag: ByteArray
        lateinit var secrets: List<ByteArray>

        /** What the relay saw for each message label: the E2E blobs a server operator could have kept. */
        val relayed = LinkedHashMap<String, MutableList<ByteArray>>()

        /** Contact, bound inbound mailbox and published prekeys on our side, as an accepted invite leaves them. */
        fun connect(s: Session, outServer: String?) {
            cid = s.repo.createContact(name, true, 0, outServer, outServer?.let { Rand.bytes(32) })
            val send = MailboxCrypto.newSecret()
            val owner = MailboxCrypto.newSecret()
            secrets = listOf(send, owner)
            tag = MailboxCrypto.tag(send)
            val mb = s.repo.insertMailbox(Mailbox.PURPOSE_CONTACT, send, owner, tag)
            s.repo.setMailboxState(mb, Mailbox.STATE_ACTIVE)
            s.repo.bindMailbox(mb, cid)
            val identity = s.signal.identityKeyPair
            val spkId = 1 + Rand.int(1_000_000)
            val spk = ECKeyPair.generate()
            val spkSig = identity.privateKey.calculateSignature(spk.publicKey.serialize())
            s.signal.storeSignedPreKey(spkId, SignedPreKeyRecord(spkId, System.currentTimeMillis(), spk, spkSig))
            val kyberId = spkId + 1
            val kyber = KEMKeyPair.generate(KEMKeyType.KYBER_1024)
            val kyberSig = identity.privateKey.calculateSignature(kyber.publicKey.serialize())
            s.signal.storeKyberPreKey(kyberId, KyberPreKeyRecord(kyberId, System.currentTimeMillis(), kyber, kyberSig))
            SessionBuilder(store, peerMain, peerSelf).process(
                PreKeyBundle(
                    s.signal.localRegistrationId, 1, PreKeyBundle.NULL_PRE_KEY_ID, null, spkId, spk.publicKey, spkSig,
                    identity.publicKey, kyberId, kyber.publicKey, kyberSig,
                ),
            )
        }

        fun encrypt(label: String?, content: Content): ByteArray {
            val msg = SessionCipher(store, peerSelf, peerMain).encrypt(Padding.pad(content.encode()))
            return E2eBlob(msg.type, msg.serialize()).encode().also { b -> label?.let { relayed.getOrPut(it) { mutableListOf() } += b } }
        }

        fun envelope(blob: ByteArray) = PushEnvelope.build(PushEnvelope.TYPE_MESSAGE, tag, blob)

        suspend fun send(s: Session, label: String?, content: Content) = Messenger.handle(s, envelope(encrypt(label, content)))

        /** Sends a text with a fresh marker. Returns the marker and the local message id. */
        suspend fun text(s: Session, label: String, exp: Long? = null, once: Boolean? = null): Pair<String, String> {
            val m = newMarker(label)
            val wire = Content.newId()
            send(s, label, Content.Text(wire, "$label: $m", System.currentTimeMillis(), exp, once))
            val id = s.repo.messageByWire(cid, wire, false)?.id ?: error("$label not stored")
            capture(s, label, id)
            return m to id
        }
    }

    private fun lastOutgoing(s: Session, cid: Long): String =
        s.db.queryOne("SELECT id FROM messages WHERE contact_id = ? AND outgoing = 1 ORDER BY rowid DESC LIMIT 1", cid) { it.getString(0) }!!

    /**
     * Runs the outbox until every row of [id] has been encrypted. No server is reachable, so each send fails and holds
     * the queue; rows encrypted ahead of [id] are taken off it as a server accepting them would.
     */
    private suspend fun encryptQueued(s: Session, id: String) {
        repeat(100) {
            s.db.exec("DELETE FROM outbox WHERE blob IS NOT NULL AND (message_id IS NULL OR message_id != ?)", id)
            s.db.exec("UPDATE outbox SET next_at = 0")
            Outbox.process(s)
            if (s.db.long("SELECT COUNT(*) FROM outbox WHERE message_id = ? AND blob IS NULL", id) == 0L) {
                return
            }
            Thread.sleep(50)
        }
        val rows = s.db.query("SELECT seq, contact_id, message_id, attempts, next_at, blob IS NULL FROM outbox") {
            (0..5).joinToString(" ") { i -> it.getString(i) ?: "null" }
        }
        fail("outbox never encrypted $id:\n" + rows.joinToString("\n"))
    }

    private fun aliases(): List<String> = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.aliases().toList()

    /** Locks, stops background work and waits for in-flight writes to finish, so the files are what a seizure finds. */
    private fun seize() {
        Graph.lock()
        runCatching { WorkManager.getInstance(ctx).cancelAllWork().result.get() }
        Thread.sleep(500)
    }

    // ---------------------------------------------------------------- tests

    @Test
    fun theForensicToolsFindDataInFilesPagesWalFramesAndSplitValues() {
        val m = marker()
        val needle = Forensics.Scanner(listOf(Forensics.text("probe", m)))
        // A value cut anywhere (an overflow chain, two WAL frames) is still found.
        for (p in 1 until m.length) {
            val split = m.substring(0, p).toByteArray() + Rand.bytes(100) + m.substring(p).toByteArray()
            assertTrue("split at $p", needle.scan("split", split).isNotEmpty())
        }
        val mk = Rand.bytes(32)
        val db = Db.open(ctx, mk, "probe.db")
        try {
            assertEquals("wal", db.queryOne("PRAGMA journal_mode = WAL") { it.getString(0) })
            db.exec("INSERT INTO kv (k, v) VALUES (?, ?)", "probe", m.toByteArray(Charsets.UTF_16LE))
            val file = Db.file(ctx, "probe.db")
            assertTrue("encrypted at rest", needle.scan("raw", file.readBytes() + File(file.path + "-wal").readBytes()).isEmpty())
            val parts = Forensics.decryptDb(file, Forensics.dbKey(mk))
            assertEquals(2, parts.size)
            assertTrue("found in a decrypted WAL frame", needle.scan("wal", parts[1].joined).isNotEmpty())
        } finally {
            db.close()
            Db.deleteFiles(ctx, "probe.db")
        }
        val canary = File(ctx.filesDir, "probe").apply { writeBytes(m.toByteArray(Charsets.UTF_16BE)) }
        try {
            assertTrue(Forensics.scanFiles(ctx, needle).any { it.where == canary.path })
        } finally {
            canary.delete()
        }
    }

    @Test
    fun deletedOneToOneMessagesAreUnrecoverableFromFilesAndWithTheDatabaseKey() = runBlocking<Unit> {
        val pin = "246813"
        val duress = "9753"
        Graph.prefs.onboarded = true
        // Nothing may leave the device: every server in this test refuses connections.
        Graph.prefs.serverUrl = "http://127.0.0.1:9"
        Graph.prefs.readReceipts = true
        Graph.prefs.timerStartsOnRead = false
        val mk = Graph.vault.setup(pin.toCharArray())
        Graph.vault.changePassphrase(mk.copyOf(), pin.toCharArray(), isPin = true)
        Graph.vault.setDuress(duress.toCharArray())
        val dbFile = Db.file(ctx)
        val dbKey = Forensics.dbKey(mk)
        secrets += Forensics.bytes("master key", mk.copyOf())
        secrets += Forensics.bytes("database key", dbKey)
        var s = Graph.openSession(mk.copyOf())
        val oldMrk = mrkOf(s).copyOf()
        secrets += Forensics.bytes("message root key", oldMrk)

        val bobName = "Bob " + marker()
        val carolName = "Carol " + marker()
        val daveName = "Dave " + marker()
        for (n in listOf(bobName, carolName, daveName)) {
            names[n] = Forensics.text("name $n", n)
        }
        val bob = Peer(bobName).apply { connect(s, null) }
        val carol = Peer(carolName).apply { connect(s, null) }
        val dave = Peer(daveName).apply { connect(s, null) }

        // A message that stays: the positive control for the decrypted-page search.
        val (_, keptId) = bob.text(s, "kept")

        // Delete for me.
        val (_, a) = bob.text(s, "deleteForMe")
        Messenger.deleteForMe(s, a)
        gone("deleteForMe")

        // View-once, after viewing.
        val (onceMarker, b) = bob.text(s, "viewOnce", once = true)
        assertTrue(Messenger.consumeViewOnce(s, b)!!.contains(onceMarker))
        gone("viewOnce")

        // Deleted by the sender (delete for everyone, received).
        val cWire = Content.newId()
        val cMarker = newMarker("remoteDelete")
        bob.send(s, "remoteDelete", Content.Text(cWire, "remoteDelete: $cMarker", System.currentTimeMillis()))
        capture(s, "remoteDelete", s.repo.messageByWire(bob.cid, cWire, false)!!.id)
        bob.send(s, null, Content.Delete(listOf(cWire)))
        assertNull(s.repo.messageByWire(bob.cid, cWire, false))
        gone("remoteDelete")

        // A long message that arrives in two parts: the first part waits in the chunks table.
        val dMarker = newMarker("chunked")
        val dWire = Content.newId()
        val dParts = Chunker.split(dWire, "chunked: $dMarker " + "lorem ipsum ".repeat(250), System.currentTimeMillis(), null, null, Padding.MAX_PREKEY_PLAINTEXT)
        assertTrue(dParts.size >= 2)
        bob.send(s, "chunked", dParts[0])
        captureChunks(s, "chunked", bob.cid)
        for (p in dParts.drop(1)) {
            bob.send(s, "chunked", p)
        }
        val d = s.repo.messageByWire(bob.cid, dWire, false)!!
        assertTrue(d.body.contains(dMarker))
        capture(s, "chunked", d.id)
        Messenger.deleteForMe(s, d.id)
        gone("chunked")

        // Outgoing, deleted for everyone after it was encrypted for sending.
        val eMarker = newMarker("deleteForEveryone")
        Messenger.sendText(s, bob.cid, "deleteForEveryone: $eMarker")
        val e = lastOutgoing(s, bob.cid)
        capture(s, "deleteForEveryone", e)
        s.repo.updateContactOutbound(bob.cid, "http://127.0.0.1:9", Rand.bytes(32), null)
        encryptQueued(s, e)
        capture(s, "deleteForEveryone", e)
        Messenger.deleteForEveryone(s, e)
        gone("deleteForEveryone")

        // Disappearing messages: started on receipt, started on read (the key moves to a time bucket), and outgoing.
        Messenger.setTimer(s, bob.cid, 1)
        val (_, g) = bob.text(s, "expiresOnReceipt", exp = 1)
        Graph.prefs.timerStartsOnRead = true
        val (_, h) = bob.text(s, "expiresOnRead", exp = 1)
        Messenger.markChatRead(s, bob.cid)
        capture(s, "expiresOnRead", h)
        val iMarker = newMarker("expiresOutgoing")
        Messenger.sendText(s, bob.cid, "expiresOutgoing: $iMarker")
        val i = lastOutgoing(s, bob.cid)
        capture(s, "expiresOutgoing", i)
        Thread.sleep(2_500)
        Sweeper.sweep(s)
        for (id in listOf(g, h, i)) {
            assertEquals("expired message swept", 0L, s.db.long("SELECT COUNT(*) FROM messages WHERE id = ?", id))
        }
        gone("expiresOnReceipt", "expiresOnRead", "expiresOutgoing")
        Messenger.setTimer(s, bob.cid, 0)

        // Clear chat: a received message, an outgoing one still queued, and half of a long incoming one.
        dave.text(s, "clearedIncoming")
        val lMarker = newMarker("clearedQueued")
        Messenger.sendText(s, dave.cid, "clearedQueued: $lMarker")
        capture(s, "clearedQueued", lastOutgoing(s, dave.cid))
        val mMarker = newMarker("clearedPartial")
        val mParts = Chunker.split(Content.newId(), "clearedPartial: $mMarker " + "dolor sit ".repeat(300), System.currentTimeMillis(), null, null, Padding.MAX_PREKEY_PLAINTEXT)
        dave.send(s, "clearedPartial", mParts[0])
        captureChunks(s, "clearedPartial", dave.cid)
        s.repo.clearConversation(dave.cid)
        gone("clearedIncoming", "clearedQueued", "clearedPartial")

        // Contact deletion: their messages, name, identity key, mailbox secrets and session go.
        carol.text(s, "deletedContactIncoming")
        val oMarker = newMarker("deletedContactOutgoing")
        Messenger.sendText(s, carol.cid, "deletedContactOutgoing: $oMarker")
        capture(s, "deletedContactOutgoing", lastOutgoing(s, carol.cid))
        artifacts["carol"] = (listOf(Forensics.bytes("carol identity key", carol.store.identityKeyPair.publicKey.serialize().copyOfRange(1, 33))) +
            carol.secrets.map { Forensics.bytes("carol mailbox secret", it) }).toMutableList()
        Messenger.deleteContact(s, carol.cid)
        assertNull(s.repo.contact(carol.cid))
        gone("deletedContactIncoming", "deletedContactOutgoing", "carol")

        // --- Seizure 1: the app is locked; the attacker has the files and the database key.
        assertEquals(1L, s.db.long("PRAGMA secure_delete"))
        assertEquals("delete", s.db.queryOne("PRAGMA journal_mode") { it.getString(0) })
        seize()
        inspect(mapOf(dbFile to dbKey), listOf(carolName), listOf(Triple(dbFile, dbKey, bobName), Triple(dbFile, dbKey, daveName)))
        assertLiveRowsVisible(dbFile, dbKey, listOf("kept"))

        // Forward secrecy on the device: the stored ratchet can't decrypt what the relay saw of deleted messages.
        val attacker = Db.open(ctx, mk)
        val state = InMemorySignalProtocolStore(
            IdentityKeyPair(attacker.queryOne("SELECT v FROM kv WHERE k = 'identity'") { it.getBlob(0) }!!),
            String(attacker.queryOne("SELECT v FROM kv WHERE k = 'registration_id'") { it.getBlob(0) }!!).toInt(),
        )
        val bobAddr = Messenger.remote(bob.cid)
        state.storeSession(bobAddr, SessionRecord(attacker.queryOne("SELECT record FROM sig_session WHERE address = ?", "c${bob.cid}.1") { it.getBlob(0) }!!))
        attacker.close()
        fun attackerDecrypts(blob: ByteArray): Boolean = runCatching {
            val e2e = E2eBlob.decode(blob)!!
            val cipher = SessionCipher(state, Messenger.LOCAL, bobAddr)
            if (e2e.type == E2eBlob.PREKEY) cipher.decrypt(PreKeySignalMessage(e2e.body)) else cipher.decrypt(SignalMessage(e2e.body))
        }.isSuccess
        assertTrue("control: the reconstructed ratchet opens a new message", attackerDecrypts(bob.encrypt(null, Content.Receipt(listOf("x"), "read"))))
        for ((label, blobs) in bob.relayed) {
            for (blob in blobs) {
                assertFalse("$label: the relay's copy is decryptable from the stored ratchet", attackerDecrypts(blob))
            }
        }

        // --- Wipe messages while locked (panic response or restart wipe), with a push waiting in the locked inbox.
        val pMarker = newMarker("lockedInbox")
        Messenger.onPushPayload(bob.envelope(bob.encrypt("lockedInbox", Content.Text(Content.newId(), "lockedInbox: $pMarker", System.currentTimeMillis()))))
        val inboxFiles = File(ctx.noBackupFilesDir, "inbox").listFiles().orEmpty()
        assertEquals(1, inboxFiles.size)
        val before = Db.open(ctx, mk)
        artifacts["lockedInbox"] = (inboxFiles.map { Forensics.bytes("locked inbox item", it.readBytes()) } +
            Forensics.bytes("old inbox private key", before.queryOne("SELECT v FROM kv WHERE k = 'inbox_priv'") { it.getBlob(0) }!!) +
            Forensics.bytes("old wrapped message root", before.queryOne("SELECT v FROM kv WHERE k = 'mrk'") { it.getBlob(0) }!!) +
            before.query("SELECT v FROM kv WHERE k LIKE 'bk/%'") { Forensics.bytes("wrapped bucket key", it.getBlob(0)) }).toMutableList()
        before.close()
        Wiper.wipeMessages()
        assertTrue(LockedInbox.isEmpty)
        assertTrue(aliases().none { it.startsWith("gf_mb_") || it.startsWith("gf_msg") })
        // Until the next unlock the rows are still there, but nothing can open their keys any more.
        val shredded = Db.open(ctx, mk)
        assertNull(Graph.vault.unwrapMessageRoot(shredded.queryOne("SELECT v FROM kv WHERE k = 'mrk'") { it.getBlob(0) }!!, shredded.queryOne("SELECT v FROM kv WHERE k = 'mrk_alias'") { String(it.getBlob(0)) }))
        shredded.close()

        s = Graph.openSession(mk.copyOf())
        secrets += Forensics.bytes("new message root key", mrkOf(s).copyOf())
        AppLock.afterUnlock(s)
        repeat(100) {
            if (!Graph.prefs.inboxRotatePending) return@repeat
            Thread.sleep(50)
        }
        assertFalse(Graph.prefs.inboxRotatePending)
        assertNull(s.repo.message(keptId))
        gone("kept", "lockedInbox")

        // --- Seizure 2, before and after the idle VACUUM that follows bulk deletes (MaintenanceWorker).
        seize()
        inspect(mapOf(dbFile to dbKey), listOf(carolName), listOf(Triple(dbFile, dbKey, bobName), Triple(dbFile, dbKey, daveName)))
        s = Graph.openSession(mk.copyOf())
        assertEquals("1", s.repo.kvString("needs_vacuum"))
        s.repo.vacuumIfNeeded()
        seize()
        inspect(mapOf(dbFile to dbKey), listOf(carolName), listOf(Triple(dbFile, dbKey, bobName), Triple(dbFile, dbKey, daveName)))

        // --- The duress PIN: a verifier only. Nothing derived from it opens the real data.
        assertNull(Graph.vault.unlockWithPassphrase(duress.toCharArray()))
        val decoyKey = Graph.vault.decoyKey(duress.toCharArray())
        val decoyDbKey = Forensics.dbKey(decoyKey)
        assertFalse(decoyDbKey.contentEquals(dbKey))
        try {
            Forensics.decryptDb(dbFile, decoyDbKey)
            fail("the duress PIN's key decrypts the real database")
        } catch (e: IllegalStateException) {
            // expected
        }
        try {
            Db.open(ctx, decoyKey).close()
            fail("the duress PIN opens the real database")
        } catch (e: Exception) {
            // expected
        }
        // Its decoy profile is a separate database that holds none of the real data.
        Graph.prefs.duressAction = DuressAction.DECOY
        assertEquals(UnlockResult.Ok, AppLock.unlock(duress.toCharArray()))
        val decoy = Graph.session.value!!
        assertTrue(decoy.decoy)
        assertTrue(decoy.repo.contacts().isEmpty())
        val decoyName = "Mum " + marker()
        names[decoyName] = Forensics.text("name $decoyName", decoyName)
        decoy.repo.createContact(decoyName, false, 0, null, null)
        seize()
        val decoyFile = Db.file(ctx, Db.DECOY_NAME)
        inspect(mapOf(decoyFile to decoyDbKey), listOf(bobName, daveName, carolName), listOf(Triple(decoyFile, decoyDbKey, decoyName)))

        // --- Duress erase (the same path as panic wipe and too many wrong PINs): nothing at all is left.
        Graph.prefs.duressAction = DuressAction.WIPE_ALL
        assertEquals(UnlockResult.Wiped, AppLock.unlock(duress.toCharArray()))
        runCatching { WorkManager.getInstance(ctx).cancelAllWork().result.get() }
        Thread.sleep(500)
        assertFalse(Graph.vault.isSetUp)
        assertTrue(aliases().none { it.startsWith("gf_") })
        for (n in listOf(Db.file(ctx), decoyFile)) {
            for (suffix in listOf("", "-journal", "-wal", "-shm")) {
                assertFalse("${n.name}$suffix survived the erase", File(n.path + suffix).exists())
            }
        }
        val all = Forensics.Scanner(markers + secrets + names.values + deletedNeedles() + liveNeedles() + Forensics.bytes("decoy key", decoyKey))
        assertNoHits("found after the erase", Forensics.scanFiles(ctx, all))
    }

    @Test
    fun deletedGroupMessagesAreUnrecoverableFromFilesAndWithTheDatabaseKey() = runBlocking<Unit> {
        Graph.prefs.serverUrl = "http://127.0.0.1:9"
        Graph.prefs.readReceipts = true
        val keys = HashMap<String, ByteArray>()
        val alice = GroupKit.profile("ga.db", opened, keys)
        val bob = GroupKit.profile("gb.db", opened, keys)
        val aliceFile = Db.file(ctx, "ga.db")
        val bobFile = Db.file(ctx, "gb.db")
        val aliceKey = Forensics.dbKey(keys.getValue("ga.db"))
        val bobKey = Forensics.dbKey(keys.getValue("gb.db"))
        for ((n, k) in keys) {
            secrets += Forensics.bytes("$n master key", k)
        }
        secrets += Forensics.bytes("ga.db key", aliceKey)
        secrets += Forensics.bytes("gb.db key", bobKey)
        secrets += Forensics.bytes("ga.db message root", mrkOf(alice))
        secrets += Forensics.bytes("gb.db message root", mrkOf(bob))
        val server = { _: String -> "http://127.0.0.1:9" }
        GroupKit.befriend(alice, bob, "bob", server("bob"))
        GroupKit.befriend(bob, alice, "alice", server("alice"))
        val groupName = "Group " + marker()
        names[groupName] = Forensics.text("group name", groupName)
        val (aCid, bCid) = GroupKit.createAndJoin(alice, bob, B64.enc(Rand.bytes(32)), groupName, server)
        val route = suspend { GroupKit.route(listOf(alice, bob)) }

        fun idOf(s: Session, cid: Long, m: String) = s.repo.messages(cid, System.currentTimeMillis()).first { it.body.contains(m) }.id

        // Bob -> Alice, deleted by each.
        val x = newMarker("x")
        Groups.sendText(bob, bCid, "x: $x")
        capture(bob, "x@bob", idOf(bob, bCid, x))
        route()
        capture(alice, "x@alice", idOf(alice, aCid, x))
        Messenger.deleteForMe(alice, idOf(alice, aCid, x))
        Messenger.deleteForMe(bob, idOf(bob, bCid, x))
        gone("x@bob", "x@alice")

        // Alice -> Bob, deleted for everyone.
        val y = newMarker("y")
        Groups.sendText(alice, aCid, "y: $y")
        capture(alice, "y@alice", idOf(alice, aCid, y))
        route()
        capture(bob, "y@bob", idOf(bob, bCid, y))
        Messenger.deleteForEveryone(alice, idOf(alice, aCid, y))
        route()
        assertTrue(bob.repo.messages(bCid, System.currentTimeMillis()).none { it.body.contains(y) })
        gone("y@alice", "y@bob")

        // View-once from Bob, opened by Alice.
        val z = newMarker("z")
        Groups.sendText(bob, bCid, "z: $z", viewOnce = true)
        capture(bob, "z@bob", idOf(bob, bCid, z))
        route()
        val zAlice = idOf(alice, aCid, z)
        capture(alice, "z@alice", zAlice)
        assertTrue(Messenger.consumeViewOnce(alice, zAlice)!!.contains(z))
        Messenger.deleteForMe(bob, idOf(bob, bCid, z))
        gone("z@bob", "z@alice")

        // A message that stays, as the positive control.
        val k = newMarker("kept")
        Groups.sendText(alice, aCid, "kept: $k")
        route()
        capture(alice, "kept@alice", idOf(alice, aCid, k))

        seize()
        inspect(mapOf(aliceFile to aliceKey, bobFile to bobKey), emptyList(), listOf(Triple(aliceFile, aliceKey, groupName), Triple(bobFile, bobKey, groupName)))
        assertLiveRowsVisible(aliceFile, aliceKey, listOf("kept@alice"))

        // Clear chat, with a message still queued for Bob.
        val w = newMarker("w")
        Groups.sendText(alice, aCid, "w: $w")
        capture(alice, "w@alice", idOf(alice, aCid, w))
        alice.repo.clearConversation(aCid)
        gone("kept@alice", "w@alice")
        seize()
        inspect(mapOf(aliceFile to aliceKey), emptyList(), listOf(Triple(aliceFile, aliceKey, groupName)))

        // Delete the group.
        artifacts["alice group inbox"] = alice.repo.mailboxesForContact(aCid).flatMap {
            listOf(Forensics.bytes("group inbox secret", it.sendSecret), Forensics.bytes("group hint key", it.hintKey!!))
        }.toMutableList()
        Messenger.deleteContact(alice, aCid)
        assertNull(alice.repo.contact(aCid))
        gone("alice group inbox")

        // Bob is still in the group, so its name stays in his database (the control), and nowhere in Alice's.
        seize()
        inspect(mapOf(aliceFile to aliceKey), listOf(groupName), listOf(Triple(bobFile, bobKey, groupName)))
    }
}
