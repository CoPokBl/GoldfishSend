package app.goldfishsend.bench

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.net.Uri
import android.os.Bundle
import app.goldfishsend.core.Graph
import app.goldfishsend.core.Groups
import app.goldfishsend.core.Messenger
import app.goldfishsend.core.Session
import app.goldfishsend.crypto.BucketKeys
import app.goldfishsend.crypto.KeyVault
import app.goldfishsend.crypto.MessageVault
import app.goldfishsend.db.Db
import app.goldfishsend.db.Mailbox
import app.goldfishsend.db.MsgKind
import app.goldfishsend.db.MsgStatus
import app.goldfishsend.group.GroupEngine
import app.goldfishsend.proto.B64
import app.goldfishsend.proto.CardBundle
import app.goldfishsend.proto.CardInbox
import app.goldfishsend.proto.GroupCard
import app.goldfishsend.proto.MailboxCrypto
import app.goldfishsend.proto.Rand
import app.goldfishsend.ui.screens.safetyNumber
import kotlinx.coroutines.runBlocking
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
import org.signal.libsignal.protocol.state.SignedPreKeyRecord

/**
 * Seeds a realistic profile for the macrobenchmarks and baseline-profile generation, through the app's own vault, Repo
 * and group engine:
 *
 *     adb shell content call --uri content://app.goldfishsend.bench.benchseed --method seed [--arg pin]
 *
 * With `pin`, the app is locked with the app PIN [PIN]. Every server is 127.0.0.1, so background work fails at once
 * and nothing leaves the device.
 */
class BenchSeedProvider : ContentProvider() {
    override fun onCreate(): Boolean = true

    override fun call(method: String, arg: String?, extras: Bundle?): Bundle {
        require(method == "seed") { "unknown method" }
        runBlocking { seed(lock = arg == "pin") }
        return Bundle().apply { putString("result", "seeded") }
    }

    override fun query(uri: Uri, p: Array<out String>?, s: String?, a: Array<out String>?, o: String?): Cursor? = null

    override fun getType(uri: Uri): String? = null

    override fun insert(uri: Uri, values: ContentValues?): Uri? = null

    override fun delete(uri: Uri, s: String?, a: Array<out String>?): Int = 0

    override fun update(uri: Uri, values: ContentValues?, s: String?, a: Array<out String>?): Int = 0

    private suspend fun seed(lock: Boolean) {
        val app = Graph.app
        Graph.lock()
        Graph.vault.destroyAll()
        BucketKeys.destroyAll()
        Db.deleteFiles(app)
        Graph.prefs.clear()

        val s = Graph.openSession(Graph.vault.setup(null))
        s.repo.displayName = "Sam"
        s.signal.identityKeyPair
        Graph.prefs.serverUrl = SERVER
        Graph.prefs.pushStatus = "ok"

        val rnd = java.util.Random(7)
        val now = System.currentTimeMillis()
        val people = NAMES.mapIndexed { i, name ->
            val id = s.repo.createContact(name, i % 3 == 0, if (i == 4) 86_400 else 0, SERVER, Rand.bytes(32), FAKE_KEY)
            if (i == 0) {
                s.repo.setContactIdentity(id, handshake(s, id))
            } else {
                s.repo.setContactIdentity(id, IdentityKeyPair.generate().publicKey.serialize())
            }
            s.repo.setReceivedAny(id)
            id
        }
        s.db.tx {
            // The long conversation: the first contact, a few weeks of chatting.
            conversation(s, rnd, people[0], LONG_CHAT, now, null)
            people.drop(1).forEachIndexed { i, id ->
                conversation(s, rnd, id, 3 + rnd.nextInt(25), now - (i + 1) * 47 * 60_000L, null)
            }
        }
        val group = group(s, people.subList(1, 7))
        val senders = people.subList(1, 7).map { B64.enc(s.repo.contact(it)!!.identityKey!!) }
        s.db.tx {
            conversation(s, rnd, group, GROUP_CHAT, now - 20 * 60_000L, senders)
        }
        s.db.tx {
            s.db.exec("UPDATE messages SET read_at = ts WHERE outgoing = 0")
            s.db.exec("UPDATE contacts SET last_activity = COALESCE((SELECT MAX(ts) FROM messages WHERE contact_id = contacts.id), last_activity)")
            // A few unread chats further down the list (the journeys open the first ones, which stay read).
            for ((i, id) in people.drop(8).take(4).withIndex()) {
                s.db.exec("UPDATE contacts SET unread = ? WHERE id = ?", i + 1, id)
            }
            // The group was created offline: drop what it queued for the invitees.
            s.db.exec("DELETE FROM outbox")
        }
        Graph.prefs.onboarded = true
        if (lock) {
            Graph.changeUnlock(s, KeyVault.Target.Secret(PIN.toCharArray(), isPin = true))
        }
        Graph.lock()
    }

    private fun conversation(s: Session, rnd: java.util.Random, cid: Long, count: Int, last: Long, senders: List<String>?) {
        var ts = last - count * 37 * 60_000L
        repeat(count) { i ->
            ts += 60_000L + rnd.nextInt(72 * 60_000)
            val outgoing = rnd.nextInt(5) < 2
            val body = buildString {
                append(LINES[rnd.nextInt(LINES.size)])
                // Some longer, multi-line messages.
                if (rnd.nextInt(6) == 0) {
                    append(' ').append(LINES[rnd.nextInt(LINES.size)])
                }
                if (rnd.nextInt(12) == 0) {
                    append("\n\n").append(LINES[rnd.nextInt(LINES.size)]).append(' ').append(LINES[rnd.nextInt(LINES.size)])
                }
            }
            val at = if (i == count - 1) last else minOf(ts, last - (count - i) * 1000L)
            s.repo.insertMessage(
                cid, "seed-$cid-$i", outgoing, MsgKind.TEXT, body, at, if (outgoing) null else at, 0, false, null,
                if (outgoing) MsgStatus.READ else MsgStatus.DELIVERED,
                senderKey = if (!outgoing && senders != null) senders[rnd.nextInt(senders.size)] else null,
            )
        }
    }

    /**
     * A real PQXDH session with contact [cid], made with a second profile on its own database, as an invite and its first
     * reply would. Sending to that contact then encrypts with libsignal through the app's stores, which also checks the
     * R8 rules of the minified benchmark build. Returns the peer's identity key.
     */
    private fun handshake(s: Session, cid: Long): ByteArray {
        val app = Graph.app
        Db.deleteFiles(app, PEER_DB)
        val peer = Session(Db.open(app, Rand.bytes(32), PEER_DB), Rand.bytes(32), MessageVault(Rand.bytes(32)))
        try {
            val id = peer.signal.identityKeyPair
            val spk = ECKeyPair.generate()
            val spkSig = id.privateKey.calculateSignature(spk.publicKey.serialize())
            peer.signal.storeSignedPreKey(7, SignedPreKeyRecord(7, 0, spk, spkSig))
            val kyber = KEMKeyPair.generate(KEMKeyType.KYBER_1024)
            val kyberSig = id.privateKey.calculateSignature(kyber.publicKey.serialize())
            peer.signal.storeKyberPreKey(8, KyberPreKeyRecord(8, 0, kyber, kyberSig))
            val bundle = PreKeyBundle(
                peer.signal.localRegistrationId, 1, PreKeyBundle.NULL_PRE_KEY_ID, null,
                7, spk.publicKey, spkSig, id.publicKey, 8, kyber.publicKey, kyberSig,
            )
            SessionBuilder(s.signal, Messenger.remote(cid), Messenger.LOCAL).process(bundle)
            val us = SignalProtocolAddress("c1", 1)
            val hello = SessionCipher(s.signal, Messenger.LOCAL, Messenger.remote(cid)).encrypt("hello".toByteArray())
            SessionCipher(peer.signal, Messenger.LOCAL, us).decrypt(PreKeySignalMessage(hello.serialize()))
            val reply = SessionCipher(peer.signal, Messenger.LOCAL, us).encrypt("hi".toByteArray())
            SessionCipher(s.signal, Messenger.LOCAL, Messenger.remote(cid)).decrypt(SignalMessage(reply.serialize()))
            // libsignal paths the journeys don't reach, which the minified build must keep too: safety numbers, and the
            // locked inbox's HPKE.
            checkNotNull(safetyNumber(s, id.publicKey.serialize())) { "safety number failed" }
            val kp = ECKeyPair.generate()
            val sealed = kp.publicKey.seal("x".toByteArray(), "gf/inbox/v1", ByteArray(0))
            check(kp.privateKey.open(sealed, "gf/inbox/v1", ByteArray(0)).contentEquals("x".toByteArray()))
            return id.publicKey.serialize()
        } finally {
            peer.close()
            Db.deleteFiles(app, PEER_DB)
        }
    }

    /** A group we created, with [members] invited, and its inbox, as Groups.create makes them without the server. */
    private suspend fun group(s: Session, members: List<Long>): Long {
        val gid = B64.enc(Rand.bytes(32))
        val secret = MailboxCrypto.newSecret()
        val mbId = s.repo.insertMailbox(Mailbox.PURPOSE_GROUP, secret, MailboxCrypto.newSecret(), MailboxCrypto.tag(secret))
        s.repo.setMailboxState(mbId, Mailbox.STATE_ACTIVE)
        val hint = Rand.bytes(32)
        val identity = s.signal.identityKeyPair
        val spkId = 1000 + Rand.int(100000)
        val spk = ECKeyPair.generate()
        val spkSig = identity.privateKey.calculateSignature(spk.publicKey.serialize())
        s.signal.storeSignedPreKey(spkId, SignedPreKeyRecord(spkId, 0, spk, spkSig))
        val kyberId = spkId + 1
        val kyber = KEMKeyPair.generate(KEMKeyType.KYBER_1024)
        val kyberSig = identity.privateKey.calculateSignature(kyber.publicKey.serialize())
        s.signal.storeKyberPreKey(kyberId, KyberPreKeyRecord(kyberId, 0, kyber, kyberSig))
        s.signal.markLastResort(kyberId)
        val card = GroupCard(
            g = gid, id = Groups.me(s), name = "Sam",
            inbox = CardInbox(SERVER, FAKE_KEY, B64.enc(secret)),
            hintKey = B64.enc(hint),
            bundle = CardBundle(
                s.signal.localRegistrationId, 1, spkId, B64.enc(spk.publicKey.serialize()), B64.enc(spkSig),
                kyberId, B64.enc(kyber.publicKey.serialize()), B64.enc(kyberSig),
            ),
            seq = 1,
        )
        val invitees = members.map { B64.enc(s.repo.contact(it)!!.identityKey!!) }
        s.lock.lock()
        try {
            return s.db.tx {
                Groups.engine(s).create(gid, "Weekend trip", invitees, GroupEngine.makeCard(identity, card), 0)
                val cid = Groups.store(s).cidOf(gid)!!
                s.repo.bindGroupInbox(mbId, cid, hint)
                cid
            }
        } finally {
            s.lock.unlock()
        }
    }

    companion object {
        const val PIN = "1357"
        private const val SERVER = "https://127.0.0.1"
        private const val PEER_DB = "bench-peer.db"
        private val FAKE_KEY = B64.enc(ByteArray(32) { 5 })
        private const val LONG_CHAT = 600
        private const val GROUP_CHAT = 200

        private val NAMES = listOf(
            "Alice", "Bruno", "Chiara", "Dev", "Emeka", "Fatima", "Georg", "Hana", "Ilse", "Jonas", "Kofi", "Lena",
            "Mateo", "Nadia", "Oskar", "Priya", "Quinn", "Rosa", "Sven", "Tariq", "Uma", "Viktor", "Wen", "Xavier",
            "Yara", "Zoe", "Amir", "Bea", "Carl", "Dana",
        )

        private val LINES = listOf(
            "Hey!", "Are you around later?", "Sure, sounds good 👍", "On my way", "Running 10 minutes late, sorry",
            "Did you see the message from the landlord?", "Haha yes", "No way 😂", "Can you send me the address again?",
            "I'll bring snacks", "What time works for you tomorrow?", "Let's do 7", "Thanks so much!",
            "The train is delayed again, typical", "I finished the book you lent me, the ending was wild",
            "Do you still have the charger I left at yours?", "Good morning ☀️", "Happy birthday!! 🎉",
            "I'm at the station now, by the coffee place near platform 4", "ok", "👍", "Call me when you can",
            "That photo from Saturday is great, can you send it?", "Remind me to book the tickets tonight",
            "I think the shop closes at 6 on Sundays, so we'd better go before lunch if we want to get everything",
            "Sounds like a plan", "Sorry, missed your call", "Lol", "Where are we meeting?", "See you there",
            "Just landed ✈️", "Can't make it tonight, something came up. Next week?",
            "Did you manage to fix the bike? If not I can lend you my tools at the weekend",
            "Nice!", "Let me check and get back to you", "Yes please", "Not yet", "I'll let you know",
        )
    }
}
