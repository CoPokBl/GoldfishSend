package app.goldfishsend.core

import android.content.Context
import android.content.SharedPreferences
import app.goldfishsend.db.Repo
import app.goldfishsend.db.groupRefs
import app.goldfishsend.db.memberRoutes
import app.goldfishsend.net.NetStack
import app.goldfishsend.net.ProxyMode
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull

/** A server whose TLS key no longer matches its pin. The UI asks the user what to do. */
data class PinMismatch(val hostKey: String, val expected: Set<String>, val presented: String)

/**
 * Network settings (connection mode, server key pins). Kept in their own SharedPreferences file, and wiped
 * along with everything else on a panic wipe.
 *
 * That file isn't encrypted and is readable while the app is locked, so it only ever names our own server. Anything
 * about other people's servers (TLS pins, which name their hosts) lives in the encrypted database, and their identity
 * key blobs only in memory: together they'd give away who we talk to.
 */
object NetPrefs {
    private const val FILE = "gf_net_prefs"
    private const val KEY_MODE = "proxy_mode"
    private const val KEY_PIN = "pin_servers"
    private const val KEY_TOR_CONTACTS_ONLY = "tor_contacts_only"
    private const val PIN_PREFIX = "pin:"
    private const val BLOCKED_PREFIX = "blocked:"

    /** In the database's kv table, for servers other than our own. */
    private const val DB_PREFIX = "tls_"

    private val sp: SharedPreferences by lazy { Graph.app.getSharedPreferences(FILE, Context.MODE_PRIVATE) }

    private val _version = MutableStateFlow(0L)

    /** Bumped on every change so Compose screens recompose. */
    val version: StateFlow<Long> = _version

    private val _mismatch = MutableStateFlow<PinMismatch?>(null)

    /** The most recent key mismatch that hasn't been answered yet. */
    val mismatch: StateFlow<PinMismatch?> = _mismatch

    private fun changed() {
        _version.value++
    }

    /** The connection mode. Defaults to Direct, or to Orbot for installs that had the old Orbot switch on. */
    var proxyMode: ProxyMode
        get() = sp.getString(KEY_MODE, null)?.let { runCatching { ProxyMode.valueOf(it) }.getOrNull() }
            ?: if (Graph.prefs.socksProxy) ProxyMode.ORBOT else ProxyMode.DIRECT
        set(v) {
            sp.edit().putString(KEY_MODE, v.name).apply()
            // Keep the legacy flag in step for code that still reads it.
            Graph.prefs.socksProxy = v == ProxyMode.ORBOT
            changed()
        }

    /**
     * With Tor on: reach our own server directly and only other people's servers (contacts', group members', invites')
     * through Tor. Our own server sees our IP address anyway when Tor is off, and this makes it faster; theirs still don't.
     * Off by default.
     */
    var torOnlyForContacts: Boolean
        get() = sp.getBoolean(KEY_TOR_CONTACTS_ONLY, false)
        set(v) {
            sp.edit().putBoolean(KEY_TOR_CONTACTS_ONLY, v).apply()
            changed()
        }

    /** Trust-on-first-use pinning of server TLS keys. Off by default, because servers legitimately rotate keys. */
    var pinServers: Boolean
        get() = sp.getBoolean(KEY_PIN, false)
        set(v) {
            sp.edit().putBoolean(KEY_PIN, v).apply()
            changed()
        }

    // --- where a host's pins live ---

    private fun isOwn(hostKey: String) = NetStack.ownHostKey() == hostKey

    /** Other servers' pins need the unlocked real database (never the decoy's). Null while locked. */
    private fun db(): Repo? = Graph.realSession?.repo

    private fun read(prefix: String, hostKey: String): Set<String> = if (isOwn(hostKey)) {
        sp.getStringSet(prefix + hostKey, null)?.toSet() ?: emptySet()
    } else {
        db()?.kvString(DB_PREFIX + prefix + hostKey)?.split('\n')?.filter { it.isNotEmpty() }?.toSet() ?: emptySet()
    }

    private fun write(prefix: String, hostKey: String, v: Set<String>?) {
        if (isOwn(hostKey)) {
            sp.edit().apply { if (v == null) remove(prefix + hostKey) else putStringSet(prefix + hostKey, v) }.apply()
        } else {
            db()?.kvPutString(DB_PREFIX + prefix + hostKey, v?.joinToString("\n"))
        }
    }

    /**
     * Whether pins for [hostKey] can be checked now. Other servers' pins are in the database, so while it's locked a
     * request to one of them (which nothing should make) fails closed instead of skipping the check.
     */
    fun canCheckPins(hostKey: String): Boolean = isOwn(hostKey) || db() != null

    fun pins(hostKey: String): Set<String> = read(PIN_PREFIX, hostKey)

    /** Every pinned server, for display: hostKey to pins. */
    fun allPins(): Map<String, Set<String>> {
        val out = sp.all
            .filterKeys { it.startsWith(PIN_PREFIX) }
            .mapNotNull { (k, v) -> (v as? Set<*>)?.filterIsInstance<String>()?.toSet()?.let { k.removePrefix(PIN_PREFIX) to it } }
            .toMap()
            .toMutableMap()
        db()?.let { repo ->
            for (k in repo.kvKeys(DB_PREFIX + PIN_PREFIX)) {
                val host = k.removePrefix(DB_PREFIX + PIN_PREFIX)
                out.putIfAbsent(host, pins(host))
            }
        }
        return out
    }

    /** Records the first pin for a server. It never overwrites an existing pin: that needs [trustNewKey]. */
    @Synchronized
    fun recordFirstPin(hostKey: String, pin: String) {
        if (pins(hostKey).isEmpty()) {
            write(PIN_PREFIX, hostKey, setOf(pin))
            changed()
        }
    }

    /** The user confirmed that the new key is legitimate. Replace the pin and unblock. */
    @Synchronized
    fun trustNewKey(hostKey: String, pin: String) {
        write(PIN_PREFIX, hostKey, setOf(pin))
        write(BLOCKED_PREFIX, hostKey, null)
        if (_mismatch.value?.hostKey == hostKey) {
            _mismatch.value = null
        }
        changed()
    }

    /** The user chose to keep the server blocked. Don't ask again for this exact key. */
    @Synchronized
    fun keepBlocked(hostKey: String, pin: String) {
        write(BLOCKED_PREFIX, hostKey, blockedKeys(hostKey) + pin)
        if (_mismatch.value?.hostKey == hostKey) {
            _mismatch.value = null
        }
        changed()
    }

    /** Keys the user has refused for this server. */
    fun blockedKeys(hostKey: String): Set<String> = read(BLOCKED_PREFIX, hostKey)

    fun isBlockedKey(hostKey: String, pin: String): Boolean = pin in blockedKeys(hostKey)

    /** Called from the network layer when a key doesn't match (fail closed). */
    fun reportMismatch(m: PinMismatch) {
        if (!isBlockedKey(m.hostKey, m.presented)) {
            _mismatch.value = m
        }
    }

    fun forgetPins(hostKey: String) {
        write(PIN_PREFIX, hostKey, null)
        write(BLOCKED_PREFIX, hostKey, null)
        changed()
    }

    /** Host keys of every server we still send to: contacts' and group members'. */
    fun usedServers(repo: Repo): Set<String> {
        val urls = repo.contacts().mapNotNull { it.outServer } +
            repo.groupRefs().flatMap { g -> repo.memberRoutes(g.cid).values.map { it.card.inbox.server } }
        return urls.mapNotNull(::hostKeyOf).toSet()
    }

    /** The host key a server URL's pins are kept under, or null if it isn't a URL. */
    fun hostKeyOf(url: String): String? =
        url.trim().trimEnd('/').plus("/").toHttpUrlOrNull()?.let { app.goldfishsend.net.PinPolicy.hostKey(it.host, it.port) }

    /**
     * Drops pins of servers we no longer use (not in [servers], host keys from [usedServers]) from the database, for
     * example after the last contact on that server was deleted.
     */
    fun pruneOtherPins(repo: Repo, servers: Set<String> = usedServers(repo)) {
        var dropped = false
        for (prefix in listOf(PIN_PREFIX, BLOCKED_PREFIX)) {
            for (k in repo.kvKeys(DB_PREFIX + prefix)) {
                if (k.removePrefix(DB_PREFIX + prefix) !in servers) {
                    repo.kvPut(k, null)
                    dropped = true
                }
            }
        }
        if (dropped) {
            changed()
        }
    }

    /**
     * Keeps only what's about our own server in the unencrypted file: its pins and the key blob of [ownKey], its pinned
     * fingerprint. Entries for a server we've moved away from (or that an earlier build kept for everyone) go.
     */
    fun pruneToOwnServer(ownKey: String?) {
        val own = NetStack.ownHostKey()
        val stale = sp.all.keys.filter { k ->
            when {
                k.startsWith(SERVER_KEY_PREFIX) -> k.removePrefix(SERVER_KEY_PREFIX) != ownKey
                k.startsWith(PIN_PREFIX) -> k.removePrefix(PIN_PREFIX) != own
                k.startsWith(BLOCKED_PREFIX) -> k.removePrefix(BLOCKED_PREFIX) != own
                else -> false
            }
        }
        if (stale.isNotEmpty()) {
            sp.edit().apply { stale.forEach { remove(it) } }.apply()
            changed()
        }
    }

    fun clear() {
        sp.edit().clear().commit()
        _mismatch.value = null
        offsets.clear()
        blobs.clear()
        changed()
    }

    private const val SERVER_KEY_PREFIX = "skey:"
    private val offsets = java.util.concurrent.ConcurrentHashMap<String, Long>()
    private val blobs = java.util.concurrent.ConcurrentHashMap<String, ByteArray>()

    /**
     * Verified server identity key blobs, by fingerprint, so the app doesn't fetch `GET /v1/key` every time. Only our own
     * server's is kept across launches; other servers' stay in memory, since a list of them would name contacts' servers.
     * They're public keys, and a blob is only ever used if it still hashes to the pinned fingerprint. Clock offsets stay
     * in memory.
     */
    val gatewayState: app.goldfishsend.net.GatewayState = object : app.goldfishsend.net.GatewayState {
        override fun blob(fp: String): ByteArray? = blobs[fp]
            ?: sp.getString(SERVER_KEY_PREFIX + fp, null)?.let { runCatching { app.goldfishsend.proto.B64.dec(it) }.getOrNull() }

        override fun putBlob(fp: String, blob: ByteArray) {
            if (fp != Graph.prefs.serverKey) {
                blobs[fp] = blob
            } else if (sp.getString(SERVER_KEY_PREFIX + fp, null) == null) {
                sp.edit().putString(SERVER_KEY_PREFIX + fp, app.goldfishsend.proto.B64.enc(blob)).apply()
            }
        }

        override fun dropBlob(fp: String) {
            blobs.remove(fp)
            sp.edit().remove(SERVER_KEY_PREFIX + fp).apply()
        }

        override fun clockOffset(server: String): Long = offsets[server] ?: 0L

        override fun setClockOffset(server: String, seconds: Long) {
            offsets[server] = seconds
        }
    }
}
