package app.goldfishsend.core

import android.content.Context
import app.goldfishsend.BuildConfig
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

enum class ThemeMode { SYSTEM, LIGHT, DARK }

enum class NotificationContent { NONE, NAME, NAME_AND_MESSAGE }

/**
 * Non-secret app configuration, readable while the app is locked (lock settings, theme, wipe triggers).
 * Secrets never go here. They live in the encrypted DB or the Keystore-wrapped vault.
 */
enum class PanicResponse { OFF, LOCK, WIPE_MESSAGES, WIPE_EVERYTHING }

/**
 * What the duress PIN does. WIPE_ALL erases everything. DECOY opens a separate, independent decoy profile, while the real
 * data stays encrypted and untouched (the duress PIN can't decrypt it).
 */
enum class DuressAction { WIPE_ALL, DECOY }

class Prefs(context: Context) {
    private val sp = context.getSharedPreferences("gf_prefs", Context.MODE_PRIVATE)
    private val _version = MutableStateFlow(0L)

    /** Bumped on every change, so Compose can recompose. */
    val version: StateFlow<Long> = _version

    private fun changed() {
        _version.value = _version.value + 1
    }

    private fun bool(key: String, def: Boolean) = sp.getBoolean(key, def)
    private fun setBool(key: String, v: Boolean) {
        sp.edit().putBoolean(key, v).apply()
        changed()
    }
    private fun int(key: String, def: Int) = sp.getInt(key, def)
    private fun setInt(key: String, v: Int) {
        sp.edit().putInt(key, v).apply()
        changed()
    }
    private fun long(key: String, def: Long) = sp.getLong(key, def)
    private fun setLong(key: String, v: Long) {
        sp.edit().putLong(key, v).apply()
        changed()
    }
    private fun str(key: String): String? = sp.getString(key, null)
    private fun setStr(key: String, v: String?) {
        sp.edit().putString(key, v).apply()
        changed()
    }

    var onboarded: Boolean
        get() = bool("onboarded", false)
        set(v) = setBool("onboarded", v)

    var serverUrl: String
        get() = str("server_url") ?: BuildConfig.DEFAULT_SERVER_URL
        set(v) = setStr("server_url", v)

    var themeMode: ThemeMode
        get() = ThemeMode.entries[int("theme", 0)]
        set(v) = setInt("theme", v.ordinal)

    var amoled: Boolean
        get() = bool("amoled", false)
        set(v) = setBool("amoled", v)

    var dynamicColor: Boolean
        get() = bool("dynamic_color", true)
        set(v) = setBool("dynamic_color", v)

    var screenshotProtection: Boolean
        get() = bool("flag_secure", true)
        set(v) = setBool("flag_secure", v)

    var notificationContent: NotificationContent
        get() = NotificationContent.entries[int("notif_content", 0)]
        set(v) = setInt("notif_content", v.ordinal)

    var readReceipts: Boolean
        get() = bool("read_receipts", true)
        set(v) = setBool("read_receipts", v)

    /** Seconds in the background before the app locks (0 = immediately). Only applies when a passphrase is set. */
    var lockTimeoutSecs: Int
        get() = int("lock_timeout", 60)
        set(v) = setInt("lock_timeout", v)

    var lockOnScreenOff: Boolean
        get() = bool("lock_screen_off", true)
        set(v) = setBool("lock_screen_off", v)

    /** Wrong passphrase attempts before everything is wiped (0 = never). */
    var maxFailedAttempts: Int
        get() = int("max_failed", 10)
        set(v) = setInt("max_failed", v)

    /** Written synchronously (commit), so a crash or kill mid-attempt can't hand out a free guess. */
    var failedAttempts: Int
        get() = int("failed", 0)
        set(v) {
            sp.edit().putInt("failed", v).commit()
            changed()
        }

    var wipeOnReboot: Boolean
        get() = bool("wipe_on_reboot", false)
        set(v) = setBool("wipe_on_reboot", v)

    var lastBootCount: Int
        get() = int("boot_count", -1)
        set(v) = setInt("boot_count", v)

    /** Wipe everything if the app isn't unlocked for this many days (0 = off). */
    var inactivityWipeDays: Int
        get() = int("inactivity_days", 0)
        set(v) = setInt("inactivity_days", v)

    /** Last time the user was present (interactive unlock or app in the foreground). Null until first recorded. */
    var presence: app.goldfishsend.security.Presence.Mark?
        get() {
            if (!sp.contains("presence_wall")) {
                return null
            }
            return app.goldfishsend.security.Presence.Mark(
                sp.getLong("presence_wall", 0), sp.getLong("presence_elapsed", 0), sp.getInt("presence_boot", -1),
            )
        }
        set(v) {
            val e = sp.edit()
            if (v == null) {
                e.remove("presence_wall").remove("presence_elapsed").remove("presence_boot")
            } else {
                e.putLong("presence_wall", v.wallMs).putLong("presence_elapsed", v.elapsedMs).putInt("presence_boot", v.bootCount)
            }
            e.commit()
        }

    /** Set by a reboot wipe while locked: the locked-inbox key pair is replaced at the next unlock (after draining). */
    var inboxRotatePending: Boolean
        get() = bool("inbox_rotate", false)
        set(v) = setBool("inbox_rotate", v)

    /** Disappearing timer applied to new chats. */
    var defaultTimerSecs: Long
        get() = long("default_timer", 7 * 24 * 3600L)
        set(v) = setLong("default_timer", v)

    var timerStartsOnRead: Boolean
        get() = bool("timer_on_read", true)
        set(v) = setBool("timer_on_read", v)

    var clipboardClearSecs: Int
        get() = int("clip_clear", 30)
        set(v) = setInt("clip_clear", v)

    var socksProxy: Boolean
        get() = bool("socks", false)
        set(v) = setBool("socks", v)

    var biometricUnlock: Boolean
        get() = bool("biometric", false)
        set(v) = setBool("biometric", v)

    /** Public half of the locked-inbox key (messages arriving while locked are sealed to it). */
    var inboxPublicKey: String?
        get() = str("inbox_pub")
        set(v) = setStr("inbox_pub", v)

    /** Human-readable push status for the UI: ok / none / failed / pending. */
    var pushStatus: String
        get() = str("push_status") ?: "none"
        set(v) = setStr("push_status", v)

    /** Host of the current push endpoint (not the full URL), for the security audit. */
    var pushHost: String?
        get() = str("push_host")
        set(v) = setStr("push_host", v)

    // --- Security features (each one optional, see PLAN.md §11.10) ---

    /** Shuffle the in-app PIN keypad's digits each time it's shown. Off by default because it slows entry. */
    var scramblePinPad: Boolean
        get() = bool("scramble_pin", false)
        set(v) = setBool("scramble_pin", v)

    /**
     * Move each contact to a fresh inbound mailbox every N days (0 = never). This limits how long the server can link
     * traffic to one mailbox. On by default: it's invisible, and the old mailbox stays alive until the contact has switched.
     */
    var mailboxRotationDays: Int
        get() = int("mbx_rotation_days", 30)
        set(v) = setInt("mbx_rotation_days", v)

    /** What a PanicKit trigger app may do. OFF by default: no app can act on GoldfishSend until the user connects one. */
    var panicResponse: PanicResponse
        get() = runCatching { PanicResponse.valueOf(str("panic_response") ?: "") }.getOrDefault(PanicResponse.OFF)
        set(v) = setStr("panic_response", v.name)

    /** Package of the panic trigger app the user approved. Destructive responses only come from this app. */
    var panicTrigger: String?
        get() = str("panic_trigger")
        set(v) = setStr("panic_trigger", v)

    /** What the duress PIN does. WIPE_ALL keeps the original behaviour. The others open the app without hidden chats. */
    var duressAction: DuressAction
        get() = when (val v = str("duress_action")) {
            null -> DuressAction.WIPE_ALL
            // Older non-erasing choices (they needed the real key) become the decoy profile.
            "HIDE_HIDDEN_CHATS", "DELETE_HIDDEN_CHATS" -> DuressAction.DECOY
            else -> runCatching { DuressAction.valueOf(v) }.getOrDefault(DuressAction.WIPE_ALL)
        }
        set(v) = setStr("duress_action", v.name)

    /** Whether hidden chats post notifications at all (generic ones, never contents). Off by default. */
    var notifyHiddenChats: Boolean
        get() = bool("notify_hidden", false)
        set(v) = setBool("notify_hidden", v)

    /**
     * Pause any contact whose safety number changes until the user reviews it. Verified contacts are always paused.
     * Off by default for unverified contacts, matching Signal: the change is accepted with a visible notice.
     */
    var holdAllKeyChanges: Boolean
        get() = bool("hold_all_key_changes", false)
        set(v) = setBool("hold_all_key_changes", v)

    /** Overwrite freed app memory after locking. On by default: the only cost is a brief CPU spike. */
    var wipeMemoryOnLock: Boolean
        get() = bool("wipe_memory_on_lock", true)
        set(v) = setBool("wipe_memory_on_lock", v)

    /** Dismiss keys of Security-tab findings the user chose to hide (see Finding.dismissKey). */
    val dismissedFindings: Set<String>
        get() = sp.getStringSet("dismissed_findings", null)?.toSet() ?: emptySet()

    fun dismissFinding(key: String) {
        // Bounded: stale keys from situations that no longer exist are harmless but shouldn't pile up forever.
        val next = (dismissedFindings + key).toList().takeLast(200).toSet()
        sp.edit().putStringSet("dismissed_findings", next).apply()
        changed()
    }

    fun restoreFinding(key: String) {
        sp.edit().putStringSet("dismissed_findings", dismissedFindings - key).apply()
        changed()
    }

    fun clear() {
        sp.edit().clear().commit()
        changed()
    }
}
