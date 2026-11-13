package app.goldfishsend.core

import app.goldfishsend.security.MemoryScrubber
import android.app.Application
import app.goldfishsend.crypto.BucketKeys
import app.goldfishsend.crypto.KeyVault
import app.goldfishsend.crypto.MessageVault
import app.goldfishsend.crypto.SignalStore
import app.goldfishsend.db.Db
import app.goldfishsend.db.MsgKind
import app.goldfishsend.db.MsgStatus
import app.goldfishsend.db.Repo
import app.goldfishsend.net.ServerApi
import app.goldfishsend.net.ServerPin
import app.goldfishsend.proto.B64
import app.goldfishsend.proto.Content
import app.goldfishsend.proto.Rand
import app.goldfishsend.proto.wipe
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import okhttp3.OkHttpClient
import org.signal.libsignal.protocol.ecc.ECKeyPair
import org.signal.libsignal.protocol.ecc.ECPrivateKey

/** Everything that exists while the app is unlocked. Closing it wipes the keys from RAM. */
class Session(val db: Db, private var mk: ByteArray, val messages: MessageVault) {
    val signal = SignalStore(db)
    val repo = Repo(db, messages)

    /** Serialises libsignal and DB mutations: libsignal stores aren't safe for concurrent ratchet updates. */
    val lock = Mutex()

    /** Hidden chats are only listed after the hidden-chats PIN was entered in this session. Resets on lock. */
    val hiddenRevealed = kotlinx.coroutines.flow.MutableStateFlow(false)

    /**
     * Opened with the duress PIN in a non-erasing mode. Hidden chats can't be revealed, and hidden-chat and duress settings
     * read as off.
     */
    @Volatile
    var decoy = false

    fun masterKeyCopy(): ByteArray = mk.copyOf()

    /** After a master-key rotation. Takes ownership of [newMk]. */
    fun replaceMasterKey(newMk: ByteArray) {
        mk.wipe()
        mk = newMk
    }

    fun close() {
        db.close()
        mk.wipe()
        messages.wipe()
    }
}

/** Process-wide service locator. Kept deliberately small, with no DI framework. */
object Graph {
    lateinit var app: Application
        private set

    val prefs: Prefs by lazy { Prefs(app) }
    val vault: KeyVault by lazy { KeyVault(app) }

    private val errors = CoroutineExceptionHandler { _, e -> android.util.Log.w("GoldfishSend", "background task failed: ${e.javaClass.simpleName}") }
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO + errors)

    private val _session = MutableStateFlow<Session?>(null)
    val session: StateFlow<Session?> = _session

    private val unlockMutex = Mutex()

    @Volatile
    private var http: OkHttpClient? = null

    fun init(application: Application) {
        app = application
        ServerApi.defaultState = NetPrefs.gatewayState
    }

    fun httpClient(): OkHttpClient = http ?: synchronized(this) {
        http ?: ServerApi.buildClient().also { http = it }
    }

    /** Drops pooled connections (for example after switching to or from Tor) so none are reused on the old route. */
    fun resetHttp() {
        http?.let { runCatching { it.connectionPool.evictAll() } }
        http = null
    }

    /**
     * Our own server, pinned to [Prefs.serverKey]. On first use the fingerprint is recorded; a different key sets
     * [Prefs.serverKeyChanged] (shown in the Security tab and as a dialog) and nothing is sent until it's resolved.
     */
    fun api(): ServerApi {
        val url = prefs.serverUrl
        return ServerApi(url, httpClient(), ownPin(url))
    }

    private fun ownPin(url: String) = ServerPin(
        expected = prefs.serverKey,
        onFirstUse = { fp ->
            synchronized(this) {
                if (prefs.serverUrl == url && prefs.serverKey == null) {
                    prefs.serverKey = fp
                }
            }
        },
        onMismatch = { fp ->
            if (prefs.serverUrl == url) {
                prefs.serverKeyChanged = fp
            }
        },
        onVerified = {
            if (prefs.serverUrl == url && prefs.serverKeyChanged != null) {
                prefs.serverKeyChanged = null
            }
        },
    )

    /** Some other server (a contact's, or one being checked before switching), with an explicit [pin]. */
    fun api(server: String, pin: ServerPin): ServerApi = ServerApi(server, httpClient(), pin)

    /** Our own server's fingerprint, fetching it (trust on first use) if it isn't known yet. */
    suspend fun ownServerKey(): String = prefs.serverKey ?: api().identity()

    val isUnlocked: Boolean
        get() = _session.value != null

    /**
     * The open *real* session, or null. A decoy session (duress PIN) is visible to the UI through [session], but every
     * background path (pushes, outbox, mailboxes, workers, sweeps) uses this, so real data is never processed with,
     * written into, or dropped by the decoy. While a decoy is open, the app behaves as locked for real data: pushes go
     * to the locked inbox and are delivered at the next real unlock.
     */
    val realSession: Session?
        get() = _session.value?.takeUnless { it.decoy }

    /**
     * Opens the decoy profile with a key derived only from the duress PIN. It has its own database, Signal identity and
     * message root (kept inside the decoy DB, never under the real Keystore aliases), and persists across duress unlocks.
     */
    suspend fun openDecoySession(decoyKey: ByteArray): Session = unlockMutex.withLock {
        _session.value?.let {
            decoyKey.wipe()
            return it
        }
        val db = try {
            Db.open(app, decoyKey, Db.DECOY_NAME)
        } catch (e: Exception) {
            // A different duress PIN than the one that made this decoy: start a fresh one.
            Db.deleteFiles(app, Db.DECOY_NAME)
            Db.open(app, decoyKey, Db.DECOY_NAME)
        }
        val boot = Repo(db, MessageVault(ByteArray(32)))
        val mrk = boot.kvGet("decoy_mrk") ?: Rand.bytes(32).also { boot.kvPut("decoy_mrk", it) }
        val s = Session(db, decoyKey, MessageVault(mrk))
        s.decoy = true
        _session.value = s
        s
    }

    /** Opens the DB with MK. Takes ownership of [mk]. */
    suspend fun openSession(mk: ByteArray): Session = unlockMutex.withLock {
        _session.value?.let {
            mk.wipe()
            return it
        }
        var key = mk
        val db = try {
            Db.open(app, key)
        } catch (e: Exception) {
            // An unlock-method change died after the rekey but before it was recorded: the old MK unwraps a link to the new one.
            val next = if (vault.hasPendingRotation) vault.recoverRotation(key) else null
            if (next == null) {
                key.wipe()
                throw e
            }
            val d = Db.open(app, next)
            key.wipe()
            key = next
            vault.promoteRotation()
            d
        }
        if (vault.hasPendingRotation) {
            // The rekey never happened: discard the staged wrapping.
            vault.abortRotation()
        }
        val tmpVault = MessageVault(ByteArray(32))
        val bootstrapRepo = Repo(db, tmpVault)
        var shredded = false
        val wrapped = bootstrapRepo.kvGet("mrk")
        var mrk = wrapped?.let { vault.unwrapMessageRoot(it) }
        if (mrk == null) {
            if (wrapped != null) {
                // The message key was destroyed (restart wipe / panic): clear the now-unreadable rows.
                bootstrapRepo.wipeAllMessages()
                shredded = true
            }
            mrk = Rand.bytes(32)
            bootstrapRepo.kvPut("mrk", vault.wrapMessageRoot(mrk))
        }
        // Locked-inbox key pair: pushes arriving while locked are sealed to the public key.
        if (bootstrapRepo.kvGet("inbox_priv") == null || prefs.inboxPublicKey == null) {
            val kp = ECKeyPair.generate()
            bootstrapRepo.kvPut("inbox_priv", kp.privateKey.serialize())
            prefs.inboxPublicKey = B64.enc(kp.publicKey.serialize())
        }
        val s = Session(db, key, MessageVault(mrk, BucketKeys.DbStore(db)))
        if (shredded) {
            for (c in s.repo.contacts()) {
                s.repo.insertMessage(
                    c.id, "sys-" + Content.newId(), false, MsgKind.SYSTEM, "Messages were erased when your phone restarted.",
                    System.currentTimeMillis(), null, 0, false, null, MsgStatus.READ,
                )
            }
        }
        _session.value = s
        s
    }

    /**
     * Changes how the app is unlocked, with a brand-new master key (see KeyVault "master-key rotation"). [target] is the
     * new method. The DB is rekeyed, the duress slot follows, and the biometric shortcut must be set up again.
     */
    suspend fun changeUnlock(s: Session, target: KeyVault.Target) {
        // Never from a decoy session: its key isn't the real master key.
        if (s.decoy) {
            return
        }
        val oldMk = s.masterKeyCopy()
        val newMk = Rand.bytes(32)
        try {
            vault.stageRotation(oldMk, newMk, target)
            try {
                s.lock.withLock {
                    s.db.rekey(newMk)
                }
            } catch (e: Exception) {
                // The database still uses the old key: drop the staged wrapping, nothing changed.
                vault.abortRotation()
                throw e
            }
            vault.promoteRotation()
            if (target is KeyVault.Target.None || target is KeyVault.Target.ScreenLock) {
                // The duress PIN can't exist without an app secret.
                s.repo.kvPutString("duress_on", null)
            }
            prefs.biometricUnlock = false
            s.replaceMasterKey(newMk.copyOf())
        } finally {
            oldMk.wipe()
            newMk.wipe()
        }
    }

    fun inboxPrivateKey(s: Session): ECPrivateKey = ECPrivateKey(s.repo.kvGet("inbox_priv")!!)

    /** Locks: closes the DB and wipes keys from memory. */
    fun lock() {
        val s = _session.value ?: return
        _session.value = null
        s.close()
        if (prefs.wipeMemoryOnLock) {
            MemoryScrubber.scrubAsync()
        }
    }

    /**
     * For installs without a passphrase: unlock silently using the device-bound key (only works while
     * the device itself is unlocked). Used by background work and push handling.
     */
    suspend fun tryAutoUnlock(): Session? {
        _session.value?.let { return if (it.decoy) null else it }
        if (!vault.isSetUp || vault.requiresUserUnlock) {
            return null
        }
        val mk = vault.unlockWithoutPassphrase() ?: return null
        return try {
            openSession(mk)
        } catch (e: Exception) {
            null
        }
    }
}
