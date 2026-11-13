package app.goldfishsend.core

import app.goldfishsend.security.MemoryScrubber
import android.app.Application
import app.goldfishsend.crypto.KeyVault
import app.goldfishsend.crypto.MessageVault
import app.goldfishsend.crypto.SignalStore
import app.goldfishsend.db.Db
import app.goldfishsend.db.MsgKind
import app.goldfishsend.db.MsgStatus
import app.goldfishsend.db.Repo
import app.goldfishsend.net.ServerApi
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
class Session(val db: Db, private val mk: ByteArray, val messages: MessageVault) {
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
    }

    fun httpClient(): OkHttpClient = http ?: synchronized(this) {
        http ?: ServerApi.buildClient().also { http = it }
    }

    /** Drops pooled connections (for example after switching to or from Tor) so none are reused on the old route. */
    fun resetHttp() {
        http?.let { runCatching { it.connectionPool.evictAll() } }
        http = null
    }

    fun api(server: String = prefs.serverUrl): ServerApi = ServerApi(server, httpClient())

    val isUnlocked: Boolean
        get() = _session.value != null

    /** Opens the DB with MK. Takes ownership of [mk]. */
    suspend fun openSession(mk: ByteArray): Session = unlockMutex.withLock {
        _session.value?.let {
            mk.wipe()
            return it
        }
        val db = Db.open(app, mk)
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
        val s = Session(db, mk, MessageVault(mrk))
        if (shredded) {
            for (c in s.repo.contacts()) {
                s.repo.insertMessage(
                    c.id, "sys-" + Content.newId(), false, MsgKind.SYSTEM, "Messages were erased when your phone restarted.",
                    System.currentTimeMillis(), null, 0, false, null, MsgStatus.READ,
                )
            }
        }
        prefs.lastUnlockAt = System.currentTimeMillis()
        _session.value = s
        s
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
        _session.value?.let { return it }
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
