package app.goldfishsend.core

import app.goldfishsend.security.MemoryScrubber
import app.goldfishsend.security.ProfileSecrets
import app.goldfishsend.security.VaultSecrets
import app.goldfishsend.security.DecoySecrets
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
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import org.signal.libsignal.protocol.ecc.ECKeyPair
import org.signal.libsignal.protocol.ecc.ECPrivateKey

/**
 * Everything that exists while the app is unlocked. Closing it wipes the keys from RAM and stops its background work.
 *
 * [decoy]: opened with the duress PIN in the decoy mode. It has its own settings ([prefs]) and PIN checks ([secrets]),
 * so nothing done in it reads or changes the real profile's.
 */
class Session(
    val db: Db,
    private var mk: ByteArray,
    val messages: MessageVault,
    val decoy: Boolean = false,
    prefs: Prefs? = null,
    secrets: ProfileSecrets? = null,
) {
    val signal = SignalStore(db)
    val repo = Repo(db, messages)

    /** This profile's settings: the device's own for the real profile, the decoy's own copy for a decoy. */
    val prefs: Prefs = prefs ?: Graph.prefs

    /** This profile's PIN checks and slots. */
    val secrets: ProfileSecrets = secrets ?: VaultSecrets

    /**
     * Work that belongs to this session (catch-up after unlock, group create/join, the mailbox pool). It's cancelled when
     * the session closes, so nothing started for the real profile carries on, or reports back, once it's locked.
     */
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO + Graph.errors)

    /** Serialises libsignal and DB mutations: libsignal stores aren't safe for concurrent ratchet updates. */
    val lock = Mutex()

    /** Hidden chats are only listed after the hidden-chats PIN was entered in this session. Resets on lock. */
    val hiddenRevealed = kotlinx.coroutines.flow.MutableStateFlow(false)

    fun masterKeyCopy(): ByteArray = mk.copyOf()

    /** After a master-key rotation. Takes ownership of [newMk]. */
    fun replaceMasterKey(newMk: ByteArray) {
        mk.wipe()
        mk = newMk
    }

    fun close() {
        // Stop the work first: whatever is still running then finds the job cancelled, not a closed database.
        scope.cancel()
        db.close()
        mk.wipe()
        messages.wipe()
    }
}

/** A lock arrived while an unlock was in progress: the session it opened was closed again, and the app stays locked. */
class UnlockInterrupted : Exception("locked while unlocking")

/** Process-wide service locator. Kept deliberately small, with no DI framework. */
object Graph {
    lateinit var app: Application
        private set

    val prefs: Prefs by lazy { Prefs(app) }
    val vault: KeyVault by lazy { KeyVault(app) }

    internal val errors = CoroutineExceptionHandler { _, e -> android.util.Log.w("GoldfishSend", "background task failed: ${e.javaClass.simpleName}") }
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO + errors)

    private val _session = MutableStateFlow<Session?>(null)
    val session: StateFlow<Session?> = _session

    private val unlockMutex = Mutex()

    /** Guards publishing a session against [lock], so a lock can't slip in between the check and the publish. */
    private val sessionLock = Any()

    /**
     * Bumped by every [lock], with or without an open session. An unlock reads it before it starts (before the slow key
     * derivation) and only publishes its session if no lock came in meanwhile: a lock on screen-off during an unlock is
     * never lost.
     */
    @Volatile
    var lockEpoch = 0L
        private set

    /** The settings of whatever is open: the decoy's own while a decoy session is, the device's otherwise. */
    val uiPrefs: Prefs
        get() = _session.value?.prefs ?: prefs

    @Volatile
    private var http: OkHttpClient? = null

    fun init(application: Application) {
        app = application
        // Application.onCreate reads all three preference files straight away. Each one loads on its own thread once
        // requested, so asking for them together means the main thread waits for the slowest, not for the sum.
        for (f in listOf("gf_prefs", "gf_vault", "gf_net_prefs")) {
            application.getSharedPreferences(f, android.content.Context.MODE_PRIVATE)
        }
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
     * Opens the decoy profile with the key the duress slot holds ([KeyVault.openDuress]). It has its own database, Signal
     * identity, message root, settings and PINs (all kept inside the decoy DB, never under the real Keystore aliases or
     * preference files), and persists across duress unlocks until the duress PIN changes. Takes ownership of [match].
     * Throws [UnlockInterrupted] if the app was locked after [since].
     */
    suspend fun openDecoySession(match: KeyVault.DuressMatch, since: Long = lockEpoch): Session =
        withContext(Dispatchers.IO) { openDecoy(match, since) }

    private suspend fun openDecoy(match: KeyVault.DuressMatch, since: Long): Session = unlockMutex.withLock {
        _session.value?.let {
            match.wipe()
            return it
        }
        val decoyKey = match.decoyKey
        val db = try {
            Db.open(app, decoyKey, Db.DECOY_NAME)
        } catch (e: Exception) {
            // Unreadable (it can only have been made with this key): start a fresh one.
            Db.deleteFiles(app, Db.DECOY_NAME)
            Db.open(app, decoyKey, Db.DECOY_NAME)
        }
        val boot = Repo(db, MessageVault(ByteArray(32)))
        val kv = RepoKv(boot)
        val mrk = boot.kvGet("decoy_mrk") ?: Rand.bytes(32).also { boot.kvPut("decoy_mrk", it) }
        val secrets = DecoySecrets(kv, secretKdf = vault::secretKek)
        secrets.rememberSecret(match.salt, match.secretTag)
        val decoyPrefs = DecoyPrefs.open(kv) { decoySeed() }
        match.salt.wipe()
        match.secretTag.wipe()
        val s = Session(db, decoyKey, MessageVault(mrk), decoy = true, prefs = decoyPrefs, secrets = secrets)
        publish(s, since)
        s
    }

    /** What a new decoy's settings start as (see [DecoyPrefs]): only what's visible from the lock screen anyway. */
    private fun decoySeed(): Map<String, Any?> = DecoyPrefs.mirror(
        app.getSharedPreferences(Prefs.FILE, android.content.Context.MODE_PRIVATE).all,
        mapOf(
            "biometric" to (prefs.biometricUnlock && vault.hasBiometric),
            "decoy_proxy_mode" to NetPrefs.proxyMode.name,
        ),
    )

    /** Publishes [s] unless a lock came in after [since]; otherwise closes it and throws [UnlockInterrupted]. */
    private fun publish(s: Session, since: Long) {
        val ok = synchronized(sessionLock) {
            (lockEpoch == since).also {
                if (it) {
                    _session.value = s
                }
            }
        }
        if (!ok) {
            s.close()
            throw UnlockInterrupted()
        }
    }

    /**
     * Opens the DB with MK. Takes ownership of [mk]. Runs on the IO dispatcher whoever calls it: opening (and on first use
     * creating) the database must never block the UI thread. Throws [UnlockInterrupted] if the app was locked after
     * [since] (read it before the secret is checked, so a lock during the key derivation counts too).
     */
    suspend fun openSession(mk: ByteArray, since: Long = lockEpoch): Session = withContext(Dispatchers.IO) { open(mk, since) }

    private suspend fun open(mk: ByteArray, since: Long): Session = unlockMutex.withLock {
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
        publish(s, since)
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

    /**
     * Locks: closes the DB, stops the session's work and wipes keys from memory. An unlock still in progress when this
     * is called doesn't open afterwards ([lockEpoch]).
     */
    fun lock() {
        val s = synchronized(sessionLock) {
            lockEpoch++
            _session.value.also { _session.value = null }
        } ?: return
        Actions.ended(s.scope)
        Mailboxes.ended()
        s.close()
        if (s.prefs.wipeMemoryOnLock) {
            MemoryScrubber.scrubAsync()
        }
    }

    /**
     * For installs without a passphrase: unlock silently using the device-bound key (only works while
     * the device itself is unlocked). Used by background work and push handling.
     */
    suspend fun tryAutoUnlock(): Session? {
        _session.value?.let { return if (it.decoy) null else it }
        // The Keystore call and the database open stay off the UI thread (the unlocking screen calls this too).
        return withContext(Dispatchers.IO) { autoUnlock() }
    }

    private suspend fun autoUnlock(): Session? {
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
