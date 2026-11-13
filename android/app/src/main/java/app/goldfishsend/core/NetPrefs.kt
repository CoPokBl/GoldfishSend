package app.goldfishsend.core

import android.content.Context
import android.content.SharedPreferences
import app.goldfishsend.net.ProxyMode
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/** A server whose TLS key no longer matches its pin. The UI asks the user what to do. */
data class PinMismatch(val hostKey: String, val expected: Set<String>, val presented: String)

/**
 * Network settings (connection mode, server key pins). Kept in their own SharedPreferences file, and wiped
 * along with everything else on a panic wipe.
 */
object NetPrefs {
    private const val FILE = "gf_net_prefs"
    private const val KEY_MODE = "proxy_mode"
    private const val KEY_PIN = "pin_servers"
    private const val PIN_PREFIX = "pin:"
    private const val BLOCKED_PREFIX = "blocked:"

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

    /** Trust-on-first-use pinning of server TLS keys. Off by default, because servers legitimately rotate keys. */
    var pinServers: Boolean
        get() = sp.getBoolean(KEY_PIN, false)
        set(v) {
            sp.edit().putBoolean(KEY_PIN, v).apply()
            changed()
        }

    fun pins(hostKey: String): Set<String> = sp.getStringSet(PIN_PREFIX + hostKey, null)?.toSet() ?: emptySet()

    /** Every pinned server, for display: hostKey to pins. */
    fun allPins(): Map<String, Set<String>> = sp.all
        .filterKeys { it.startsWith(PIN_PREFIX) }
        .mapNotNull { (k, v) -> (v as? Set<*>)?.filterIsInstance<String>()?.toSet()?.let { k.removePrefix(PIN_PREFIX) to it } }
        .toMap()

    /** Records the first pin for a server. It never overwrites an existing pin: that needs [trustNewKey]. */
    @Synchronized
    fun recordFirstPin(hostKey: String, pin: String) {
        if (pins(hostKey).isEmpty()) {
            sp.edit().putStringSet(PIN_PREFIX + hostKey, setOf(pin)).apply()
            changed()
        }
    }

    /** The user confirmed that the new key is legitimate. Replace the pin and unblock. */
    @Synchronized
    fun trustNewKey(hostKey: String, pin: String) {
        sp.edit()
            .putStringSet(PIN_PREFIX + hostKey, setOf(pin))
            .remove(BLOCKED_PREFIX + hostKey)
            .apply()
        if (_mismatch.value?.hostKey == hostKey) {
            _mismatch.value = null
        }
        changed()
    }

    /** The user chose to keep the server blocked. Don't ask again for this exact key. */
    @Synchronized
    fun keepBlocked(hostKey: String, pin: String) {
        val blocked = sp.getStringSet(BLOCKED_PREFIX + hostKey, null)?.toSet() ?: emptySet()
        sp.edit().putStringSet(BLOCKED_PREFIX + hostKey, blocked + pin).apply()
        if (_mismatch.value?.hostKey == hostKey) {
            _mismatch.value = null
        }
        changed()
    }

    /** Keys the user has refused for this server. */
    fun blockedKeys(hostKey: String): Set<String> = sp.getStringSet(BLOCKED_PREFIX + hostKey, null)?.toSet() ?: emptySet()

    fun isBlockedKey(hostKey: String, pin: String): Boolean = pin in blockedKeys(hostKey)

    /** Called from the network layer when a key doesn't match (fail closed). */
    fun reportMismatch(m: PinMismatch) {
        if (!isBlockedKey(m.hostKey, m.presented)) {
            _mismatch.value = m
        }
    }

    fun forgetPins(hostKey: String) {
        sp.edit().remove(PIN_PREFIX + hostKey).remove(BLOCKED_PREFIX + hostKey).apply()
        changed()
    }

    fun clear() {
        sp.edit().clear().commit()
        _mismatch.value = null
        changed()
    }
}
