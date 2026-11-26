package app.goldfishsend.core

import app.goldfishsend.crypto.HiddenBoxes
import app.goldfishsend.crypto.HiddenKey
import app.goldfishsend.crypto.MessageVault
import app.goldfishsend.db.DbTables
import app.goldfishsend.db.HiddenTransfer
import app.goldfishsend.db.KV_HIDDEN_ROOT
import app.goldfishsend.db.KV_SHRED_PENDING
import app.goldfishsend.db.Rewrap
import app.goldfishsend.db.Snapshot
import app.goldfishsend.proto.Rand
import app.goldfishsend.proto.wipe
import kotlinx.coroutines.sync.withLock
import org.signal.libsignal.protocol.ecc.ECPublicKey

/**
 * Hidden chats, encrypted under their own PIN (docs/threat-model.md, "Hidden chats").
 *
 * While they're put away, nothing of them is in the profile's tables: every row that belongs to them (contact, messages,
 * keys, mailboxes, Signal sessions, group state; see [HiddenTransfer]) is taken out and kept as one snapshot, sealed to
 * the hidden public key ([HiddenBoxes]). Its private key comes only from the hidden-chats PIN ([HiddenKey]), so the open
 * real profile, its database key and its settings say nothing about them: not their names, not their messages, not how
 * many there are, not even whether any exist. The PIN shows them again ([reveal]): the snapshot goes back into the tables
 * and they work like any chat until they're put away again ([hide], or the app locking).
 *
 * The app seals to the public key without the PIN: a push for a mailbox the profile doesn't know may be a put-away
 * hidden chat's, so it's parked ([park]) and delivered when they're shown; and hidden chats left in the tables by a crash
 * are put away at the next unlock ([prepare]). Every slot always exists, as filler when the feature is off: a snapshot
 * nobody can open, a public key whose private key was thrown away, a PIN slot no PIN opens.
 *
 * Message keys that the profile's root wraps are moved to the hidden chats' own root, sealed in turn under the profile's
 * ([KV_HIDDEN_ROOT]), so erasing messages and the restart wipe destroy put-away messages too, and keys in an expiry bucket
 * stay there, so they still disappear on time. The root is replaced each time hidden chats are put away, so a stale copy
 * of an earlier snapshot doesn't open the messages deleted since.
 */
object HiddenChats {
    /** kv: the public key the hidden chats are sealed to (filler while the feature is off). */
    private const val KV_PUB = "hidden_pub"

    /** kv: the snapshot of put-away hidden chats (filler of the same size while they're shown, or the feature is off). */
    private const val KV_SNAPSHOT = "hidden_snap"

    /** Parked pushes kept at most; the oldest go first. */
    const val MAX_PARKED = 2000

    /**
     * When a session opens, before anything else: makes sure every slot exists, and puts away hidden chats that a crash
     * (or the process being killed) left in the tables while they were shown. Needs no PIN.
     */
    fun prepare(s: Session) {
        s.db.tx {
            if (s.repo.kvGet(KV_PUB) == null) {
                s.repo.kvPut(KV_PUB, HiddenKey.fillerPublicKey().serialize())
            }
            if (s.repo.kvGet(KV_SNAPSHOT) == null) {
                s.repo.kvPut(KV_SNAPSHOT, HiddenBoxes.fillerSnapshot())
            }
            root(s).wipe()
        }
        if (s.repo.hiddenContactIds().isNotEmpty()) {
            // While they were shown, the snapshot was filler: nothing is lost by writing it now. The root stays, so pushes
            // parked since still open.
            seal(s, rotate = false)
        }
    }

    /** Shows hidden chats if [pin] is their PIN. False otherwise, after the same one KDF run as a right PIN. */
    suspend fun reveal(s: Session, pin: CharArray): Boolean {
        val secret = s.secrets.openHidden(pin) ?: return false
        val key = HiddenKey(secret)
        secret.wipe()
        if (s.hidden != null) {
            key.wipe()
            return true
        }
        var endpointChanged = false
        val parked = s.lock.withLock {
            s.db.tx {
                val sealed = s.repo.kvGet(KV_SNAPSHOT)
                val snap = sealed?.let { HiddenBoxes.openSnapshot(key.privateKey, it) }?.let(Snapshot::decode)
                val root = root(s)
                val hidden = MessageVault(root.copyOf())
                try {
                    if (snap != null) {
                        val done = HiddenTransfer.import(DbTables(s.db), snap, rewrap(hidden, s.messages, s), System.currentTimeMillis(), NetPrefs::hostKeyOf)
                        // A hidden group whose copy here won: its mailboxes are nobody's now.
                        val doomed = done.doomed.map { r -> r["send_secret"] as ByteArray to r["owner_secret"] as ByteArray }
                        if (doomed.isNotEmpty() && !s.decoy) {
                            s.repo.doomSecrets(doomed, Graph.prefs.serverUrl, Graph.prefs.serverKey)
                        }
                        endpointChanged = done.contactIds.isNotEmpty() && snap.meta[META_ENDPOINT] != s.repo.kvString(KV_ENDPOINT)
                    }
                    // Consumed: filler of the same size in its place, so nothing shows that it was.
                    s.repo.kvPut(KV_SNAPSHOT, HiddenBoxes.fillerSnapshot(sealed))
                    val pushes = s.db.query("SELECT blob FROM hidden_inbox ORDER BY id") { it.getBlob(0) }
                        .mapNotNull { HiddenBoxes.openPush(key.privateKey, root, it) }
                    s.db.exec("DELETE FROM hidden_inbox")
                    pushes
                } finally {
                    hidden.wipe()
                    root.wipe()
                }
            }
        }
        s.hidden = key
        s.hiddenRevealed.value = true
        // Their chats are back: what arrived meanwhile is delivered like any push. A push nobody's mailbox knows is dropped
        // now (every hidden chat's mailbox is known while they're shown).
        s.replayingHidden = true
        try {
            for ((tag, raw) in parked) {
                Messenger.receiveParked(s, tag, raw)
            }
        } finally {
            s.replayingHidden = false
        }
        s.db.notifyChanged()
        afterReveal(s, endpointChanged)
        return true
    }

    /** Catch-up for the chats just shown: their mailboxes were left alone while they were put away. */
    private fun afterReveal(s: Session, endpointChanged: Boolean) {
        Sweeper.schedule(s)
        Outbox.kick()
        if (s.decoy) {
            return
        }
        s.scope.launchSafe {
            if (endpointChanged) {
                // Our push endpoint changed while they were put away: their mailboxes still point at the old one.
                s.repo.kvPutString("rotation_needed", "1")
                runCatching { Mailboxes.rotateAll(s) }
            }
            runCatching { Mailboxes.refreshAll(s) }
            runCatching { Mailboxes.deleteDoomed(s) }
            runCatching { Mailboxes.rotateContacts(s) }
        }
    }

    /** "Hide": puts the hidden chats shown now away again. */
    suspend fun hide(s: Session) {
        s.lock.withLock { putAway(s) }
        s.db.notifyChanged()
    }

    /** The app is locking (the session is closing): hidden chats shown now are put away. */
    fun onLock(s: Session) {
        putAway(s)
    }

    private fun putAway(s: Session) {
        val key = s.hidden ?: return
        // Nothing else is under the root now (pushes aren't parked while hidden chats are shown): a fresh one.
        seal(s, rotate = true)
        s.hidden = null
        key.wipe()
        s.hiddenRevealed.value = false
    }

    /**
     * Takes every chat marked hidden out of the tables and seals it to the hidden public key as the snapshot, in one
     * transaction. Needs no PIN.
     */
    private fun seal(s: Session, rotate: Boolean) {
        s.db.tx {
            val pub = ECPublicKey(s.repo.kvGet(KV_PUB) ?: HiddenKey.fillerPublicKey().serialize())
            if (rotate) {
                s.repo.kvPut(KV_HIDDEN_ROOT, null)
            }
            val root = root(s)
            val hidden = MessageVault(root)
            try {
                val cids = s.repo.hiddenContactIds().toSet()
                val meta = mapOfNotNull(META_ENDPOINT to s.repo.kvString(KV_ENDPOINT))
                val snap = HiddenTransfer.export(DbTables(s.db), cids, rewrap(s.messages, hidden, s), NetPrefs::hostKeyOf, meta)
                s.repo.kvPut(KV_SNAPSHOT, HiddenBoxes.sealSnapshot(pub, snap.encode()))
                if (cids.isNotEmpty() || rotate) {
                    // What was taken out (and the root replaced) may linger in stale pages: the profile's root is replaced
                    // soon, so they don't open ([Shredder]).
                    s.repo.kvPutString(KV_SHRED_PENDING, "1")
                    s.repo.markNeedsVacuum()
                }
            } finally {
                hidden.wipe()
            }
        }
    }

    /**
     * A push for a mailbox this profile doesn't know. It may be a put-away hidden chat's, so it's kept, sealed to their
     * public key, until they're shown. While they're shown, every hidden chat's mailbox is known: it's nobody's.
     */
    fun park(s: Session, tag: ByteArray, raw: ByteArray) {
        if (s.hidden != null) {
            return
        }
        val pub = s.repo.kvGet(KV_PUB) ?: return
        val kept = s.db.tx {
            val root = root(s)
            val blob = HiddenBoxes.sealPush(ECPublicKey(pub), root, tag, raw)
            root.wipe()
            if (blob == null) {
                return@tx false
            }
            s.db.insert("INSERT INTO hidden_inbox (blob) VALUES (?)", blob)
            s.db.exec("DELETE FROM hidden_inbox WHERE id <= (SELECT MAX(id) FROM hidden_inbox) - ?", MAX_PARKED)
            true
        }
        // It can't be told apart from any other unknown push: the same generic notification as for a shown hidden chat.
        if (kept && !s.decoy && s.repo.kvString(app.goldfishsend.security.AppLock.KV_NOTIFY_HIDDEN) == "1") {
            Notifier.newMessage(Graph.app, null, null)
        }
    }

    /**
     * A new hidden-chats PIN, with a new secret. Hidden chats not shown now are gone for good: their secret is replaced,
     * and their snapshot and parked pushes go. The new (empty) hidden chats are shown, so chats can be hidden at once.
     */
    suspend fun setNewPin(s: Session, pin: CharArray) {
        s.lock.withLock {
            val secret = HiddenKey.newSecret()
            val key = HiddenKey(secret)
            s.secrets.setHidden(pin, secret)
            secret.wipe()
            s.db.tx {
                s.repo.kvPut(KV_PUB, key.publicKey.serialize())
                s.repo.kvPut(KV_SNAPSHOT, HiddenBoxes.fillerSnapshot(s.repo.kvGet(KV_SNAPSHOT)))
                s.db.exec("DELETE FROM hidden_inbox")
                s.repo.kvPut(KV_HIDDEN_ROOT, null)
                root(s).wipe()
                s.repo.kvPutString(KV_SHRED_PENDING, "1")
            }
            s.hidden?.wipe()
            s.hidden = key
            s.hiddenRevealed.value = true
        }
        s.db.notifyChanged()
    }

    /** A new PIN for the hidden chats shown now (same secret, so nothing else changes). False if they aren't shown. */
    suspend fun changePin(s: Session, pin: CharArray): Boolean = s.lock.withLock {
        val key = s.hidden ?: return@withLock false
        s.secrets.setHidden(pin, key.secret)
        true
    }

    /**
     * Turns hidden chats off: the ones shown now become ordinary chats, and every slot is filler again. False if they
     * aren't shown (they can't be turned off without their PIN).
     */
    suspend fun turnOff(s: Session): Boolean {
        val done = s.lock.withLock {
            val key = s.hidden ?: return@withLock false
            s.db.tx {
                for (id in s.repo.hiddenContactIds()) {
                    s.repo.setHidden(id, false)
                }
                s.repo.kvPut(KV_PUB, HiddenKey.fillerPublicKey().serialize())
                s.repo.kvPut(KV_SNAPSHOT, HiddenBoxes.fillerSnapshot(s.repo.kvGet(KV_SNAPSHOT)))
                s.db.exec("DELETE FROM hidden_inbox")
            }
            s.secrets.setHidden(null, null)
            s.hidden = null
            key.wipe()
            s.hiddenRevealed.value = false
            true
        }
        s.db.notifyChanged()
        return done
    }

    /** The hidden chats' message root, made if there's none (first use, or messages were erased). The caller wipes it. */
    private fun root(s: Session): ByteArray {
        s.repo.kvGet(KV_HIDDEN_ROOT)?.let { b ->
            runCatching { s.messages.openBlob(KV_HIDDEN_ROOT, b) }.getOrNull()?.let { return it }
        }
        val r = Rand.bytes(32)
        s.repo.kvPut(KV_HIDDEN_ROOT, s.messages.sealBlob(KV_HIDDEN_ROOT, r))
        return r
    }

    private fun rewrap(from: MessageVault, to: MessageVault, s: Session) = object : Rewrap {
        override fun key(id: String, wrapped: ByteArray): ByteArray? = from.moveKey(to, id, wrapped)

        override fun blob(label: String, newLabel: String, blob: ByteArray): ByteArray? = from.moveBlob(to, label, newLabel, blob)

        // Expiry buckets are the profile's own (only it has them): the hidden root never wraps one.
        override fun bucketOpens(id: String, wrapped: ByteArray, bucket: Long): Boolean = s.messages.bucketOpens(id, wrapped, bucket)
    }

    private fun mapOfNotNull(vararg pairs: Pair<String, String?>): Map<String, String> =
        pairs.mapNotNull { (k, v) -> v?.let { k to it } }.toMap()

    /** kv: our push endpoint (see [Mailboxes.onNewEndpoint]). */
    private const val KV_ENDPOINT = "push_endpoint"
    private const val META_ENDPOINT = "endpoint"
}
