package app.goldfishsend.security

import android.accessibilityservice.AccessibilityServiceInfo
import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.PowerManager
import android.provider.Settings
import android.view.accessibility.AccessibilityManager
import android.view.inputmethod.InputMethodManager
import app.goldfishsend.core.Graph
import app.goldfishsend.core.NotificationContent
import app.goldfishsend.push.PushHub
import java.io.File
import java.time.LocalDate
import java.time.temporal.ChronoUnit

enum class Severity(val weight: Int) { CRITICAL(25), WARNING(10), INFO(2), OK(0) }

/** One-tap fixes the app can apply itself, or system screens it can open. */
enum class Fix {
    SYSTEM_UPDATE,
    SECURITY_SETTINGS,
    DEVELOPER_SETTINGS,
    ACCESSIBILITY_SETTINGS,
    INPUT_METHOD_SETTINGS,
    GET_OPEN_SOURCE_KEYBOARD,
    BATTERY_SETTINGS,
    SET_PASSPHRASE,
    ENABLE_SCREENSHOT_BLOCK,
    HIDE_NOTIFICATION_CONTENT,
    ENABLE_DEFAULT_TIMER,
    ENABLE_WIPE_ON_RESTART,
    CHANGE_PUSH,
    OPEN_CHATS,
}

data class Finding(
    val id: String,
    val severity: Severity,
    val title: String,
    val detail: String,
    val fix: Fix? = null,
    val fixLabel: String? = null,
)

data class AuditReport(val findings: List<Finding>) {
    val score: Int = (100 - findings.sumOf { it.severity.weight }).coerceIn(0, 100)

    val headline: String
        get() = when {
            findings.any { it.severity == Severity.CRITICAL } -> "At risk"
            findings.any { it.severity == Severity.WARNING } -> "Needs attention"
            else -> "Looking good"
        }
}

/**
 * On-device security and privacy audit (PLAN.md §11.7). Everything runs locally, and nothing is reported anywhere.
 */
object SecurityAudit {
    /**
     * Android support table, by API level. Google ships security bulletins for roughly the four latest releases.
     * As of late 2026: API 36 (16) and 35 (15) are fully supported, 34 (14) is supported but nearing its end,
     * 33 (13) is at or past end of life, and 32 and older are unsupported.
     */
    private fun androidSupport(sdk: Int): Severity = when {
        sdk >= 35 -> Severity.OK
        sdk == 34 -> Severity.INFO
        sdk == 33 -> Severity.WARNING
        else -> Severity.CRITICAL
    }

    fun run(ctx: Context, unverifiedContacts: Long?): AuditReport {
        val out = mutableListOf<Finding>()
        val prefs = Graph.prefs

        // --- OS patch level ---
        val patch = runCatching { LocalDate.parse(Build.VERSION.SECURITY_PATCH) }.getOrNull()
        if (patch != null) {
            val days = ChronoUnit.DAYS.between(patch, LocalDate.now())
            out += when {
                days > 180 -> Finding(
                    "patch", Severity.CRITICAL, "Security updates are badly out of date",
                    "Your last security patch is from ${Build.VERSION.SECURITY_PATCH} ($days days ago). Known exploits for this device are public.",
                    Fix.SYSTEM_UPDATE, "Check for updates",
                )
                days > 90 -> Finding(
                    "patch", Severity.WARNING, "Security updates are behind",
                    "Your last security patch is from ${Build.VERSION.SECURITY_PATCH} ($days days ago).",
                    Fix.SYSTEM_UPDATE, "Check for updates",
                )
                else -> Finding("patch", Severity.OK, "Security patches are recent", "Patch level ${Build.VERSION.SECURITY_PATCH}.")
            }
        }

        // --- Android version support ---
        val support = androidSupport(Build.VERSION.SDK_INT)
        out += when (support) {
            Severity.OK -> Finding("os", Severity.OK, "Android ${Build.VERSION.RELEASE} is supported", "This version still receives security fixes.")
            Severity.INFO -> Finding(
                "os", Severity.INFO, "Android ${Build.VERSION.RELEASE} support ends soon",
                "Plan an upgrade: this version will stop receiving security fixes.",
            )
            Severity.WARNING -> Finding(
                "os", Severity.WARNING, "Android ${Build.VERSION.RELEASE} is end of life",
                "This version no longer gets full security fixes. Consider updating or a supported custom OS.",
                Fix.SYSTEM_UPDATE, "Check for updates",
            )
            else -> Finding(
                "os", Severity.CRITICAL, "Android ${Build.VERSION.RELEASE} is unsupported",
                "This Android version hasn't had security fixes for a long time. Your device can be compromised remotely.",
                Fix.SYSTEM_UPDATE, "Check for updates",
            )
        }

        // --- Push distributor ---
        val dist = PushHub.current(ctx)
        val host = prefs.pushHost.orEmpty()
        val googleHost = host.endsWith("googleapis.com") || host.contains("fcm") || host.endsWith("google.com")
        when {
            prefs.pushStatus != "ok" -> out += Finding(
                "push", Severity.CRITICAL, "Notifications aren't set up",
                "Without a push service you won't receive messages.", Fix.CHANGE_PUSH, "Set up",
            )
            dist in PushHub.GOOGLE_DISTRIBUTORS || googleHost -> out += Finding(
                "push", Severity.WARNING, "Notifications go through Google",
                "Message contents stay encrypted, but Google can see when you receive messages. A self-hosted or community ntfy server avoids this.",
                Fix.CHANGE_PUSH, "Change",
            )
            host.endsWith("mozilla.com") -> out += Finding(
                "push", Severity.INFO, "Notifications go through Mozilla",
                "Contents are encrypted, and Mozilla only sees delivery timing.",
            )
            else -> out += Finding("push", Severity.OK, "Notifications avoid big tech", "Delivered via ${dist?.let { PushHub.label(ctx, it) } ?: "your push app"}.")
        }
        if (dist != null) {
            val pm = ctx.getSystemService(PowerManager::class.java)
            if (!pm.isIgnoringBatteryOptimizations(dist)) {
                out += Finding(
                    "battery", Severity.INFO, "Messages may arrive late",
                    "Battery optimisation can delay your push app. Allow ${PushHub.label(ctx, dist)} to run unrestricted.",
                    Fix.BATTERY_SETTINGS, "Open settings",
                )
            }
        }

        // --- Screen lock ---
        val km = ctx.getSystemService(KeyguardManager::class.java)
        out += if (!km.isDeviceSecure) {
            Finding(
                "screenlock", Severity.CRITICAL, "No screen lock",
                "Anyone holding your phone can open it. Set a PIN or password so hardware encryption can protect your data.",
                Fix.SECURITY_SETTINGS, "Set screen lock",
            )
        } else {
            Finding("screenlock", Severity.OK, "Screen lock is on", "Your device storage key is protected by your lock screen.")
        }

        // --- Storage encryption ---
        val dpm = ctx.getSystemService(DevicePolicyManager::class.java)
        val enc = dpm.storageEncryptionStatus
        if (enc != DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_PER_USER && enc != DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE) {
            out += Finding(
                "encryption", Severity.WARNING, "Device storage isn't fully encrypted",
                "GoldfishSend encrypts its own data, but other apps' data may be readable.",
            )
        }

        // --- Developer options / ADB ---
        val dev = Settings.Global.getInt(ctx.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1
        val adb = Settings.Global.getInt(ctx.contentResolver, Settings.Global.ADB_ENABLED, 0) == 1
        if (adb) {
            out += Finding(
                "adb", Severity.WARNING, "USB debugging is on",
                "A connected computer could control your phone. Turn it off when you're not using it.",
                Fix.DEVELOPER_SETTINGS, "Open developer options",
            )
        } else if (dev) {
            out += Finding(
                "devopts", Severity.INFO, "Developer options are enabled",
                "These expose advanced settings that can weaken security.", Fix.DEVELOPER_SETTINGS, "Open developer options",
            )
        }

        // --- Root / bootloader ---
        val boot = getprop("ro.boot.verifiedbootstate")
        val flashLocked = getprop("ro.boot.flash.locked")
        val rooted = listOf("/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/app/Superuser.apk", "/data/adb/magisk")
            .any { File(it).exists() } || Build.TAGS?.contains("test-keys") == true
        when {
            rooted -> out += Finding(
                "root", Severity.CRITICAL, "This device appears to be rooted",
                "Root access lets other apps bypass Android's security, including reading GoldfishSend's memory.",
            )
            boot == "orange" || flashLocked == "0" -> out += Finding(
                "bootloader", Severity.WARNING, "The bootloader is unlocked",
                "Someone with physical access could modify the system to capture your data. Relock it if you can.",
            )
            boot == "yellow" -> out += Finding(
                "bootloader", Severity.INFO, "Custom verified OS",
                "Your OS is verified with a custom key (for example GrapheneOS). That's fine if you installed it yourself.",
            )
            boot == "green" -> out += Finding("bootloader", Severity.OK, "Verified boot is on", "The OS is verified at every start.")
        }

        // --- Accessibility services ---
        val am = ctx.getSystemService(AccessibilityManager::class.java)
        val services = am.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
            .filter { it.resolveInfo?.serviceInfo?.applicationInfo?.let { ai -> ai.flags and ApplicationInfo.FLAG_SYSTEM == 0 } ?: true }
        if (services.isNotEmpty()) {
            val names = services.mapNotNull { it.resolveInfo?.loadLabel(ctx.packageManager)?.toString() }.take(3).joinToString()
            out += Finding(
                "a11y", Severity.WARNING, "Apps can read your screen",
                "Accessibility services (${names.ifEmpty { "${services.size}" }}) can see everything on screen, including messages.",
                Fix.ACCESSIBILITY_SETTINGS, "Review",
            )
        }

        // --- Keyboard ---
        out += keyboardFindings(ctx)

        // --- Hardware key storage ---
        val strongBox = ctx.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        out += if (strongBox && Graph.vault.usesStrongBox) {
            Finding("strongbox", Severity.OK, "Keys are in a secure chip", "Your master key is held in StrongBox hardware.")
        } else {
            Finding(
                "strongbox", Severity.INFO, "No dedicated security chip",
                "Keys are protected by the processor's trusted environment instead of a separate secure element.",
            )
        }

        // --- App settings ---
        if (!Graph.vault.hasPassphrase) {
            out += Finding(
                "applock", Severity.WARNING, "App lock is off",
                "Anyone who can unlock your phone can read your chats. A passphrase also adds a second layer to your encryption.",
                Fix.SET_PASSPHRASE, "Set passphrase",
            )
        }
        if (prefs.notificationContent != NotificationContent.NONE) {
            out += Finding(
                "notif", Severity.WARNING, "Notifications show details",
                "Names or messages appear in notifications, where other apps and people nearby can see them.",
                Fix.HIDE_NOTIFICATION_CONTENT, "Hide details",
            )
        }
        if (!prefs.screenshotProtection) {
            out += Finding(
                "flagsecure", Severity.WARNING, "Screenshots are allowed",
                "Screenshots and screen recordings can capture your chats, and the recent-apps view shows them.",
                Fix.ENABLE_SCREENSHOT_BLOCK, "Block screenshots",
            )
        }
        if (prefs.defaultTimerSecs <= 0) {
            out += Finding(
                "timer", Severity.INFO, "Messages are kept forever",
                "New chats don't use disappearing messages.", Fix.ENABLE_DEFAULT_TIMER, "Use 1 week",
            )
        }
        if (!prefs.wipeOnReboot) {
            out += Finding(
                "reboot", Severity.INFO, "Messages survive a restart",
                "Optionally erase all messages whenever your phone restarts. That's useful if your phone could be seized.",
                Fix.ENABLE_WIPE_ON_RESTART, "Turn on",
            )
        }
        if ((unverifiedContacts ?: 0) > 0) {
            out += Finding(
                "unverified", Severity.INFO, "$unverifiedContacts unverified contact${if (unverifiedContacts == 1L) "" else "s"}",
                "Contacts added by link haven't been checked in person. Compare safety numbers to be sure.",
                Fix.OPEN_CHATS, "Review",
            )
        }
        if (!prefs.serverUrl.startsWith("https://")) {
            out += Finding(
                "tls", Severity.CRITICAL, "Server connection isn't encrypted",
                "Your server address doesn't use HTTPS. Message contents stay end-to-end encrypted, but metadata is exposed.",
            )
        }
        return AuditReport(out.sortedBy { it.severity.ordinal })
    }

    private fun getprop(name: String): String? = try {
        val p = ProcessBuilder("getprop", name).redirectErrorStream(true).start()
        p.inputStream.bufferedReader().readText().trim().ifEmpty { null }.also { p.waitFor() }
    } catch (e: Exception) {
        null
    }

    /**
     * The default keyboard sees every keystroke, so a closed-source one gets a warning, and a known cloud keyboard
     * gets a critical finding. Other enabled keyboards that aren't trusted are listed as info, because switching
     * to them is one tap away.
     */
    private fun keyboardFindings(ctx: Context): List<Finding> {
        val pm = ctx.packageManager
        val findings = mutableListOf<Finding>()
        val current = Settings.Secure.getString(ctx.contentResolver, Settings.Secure.DEFAULT_INPUT_METHOD)?.substringBefore('/')

        fun classify(pkg: String): KeyboardTrust.Result {
            val system = runCatching {
                pm.getApplicationInfo(pkg, 0).flags and ApplicationInfo.FLAG_SYSTEM != 0
            }.getOrDefault(false)
            return KeyboardTrust.classify(pkg, installerOf(pm, pkg), system)
        }

        fun label(pkg: String, result: KeyboardTrust.Result): String = result.name
            ?: runCatching { pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString() }.getOrDefault(pkg)

        if (current != null) {
            val r = classify(current)
            val name = label(current, r)
            findings += when (r.verdict) {
                KeyboardTrust.Verdict.OPEN_SOURCE -> Finding(
                    "ime", Severity.OK, "Open-source keyboard",
                    if (r.viaFdroid) "$name was installed from F-Droid, which only distributes open-source apps." else "$name is open source.",
                )
                KeyboardTrust.Verdict.SOURCE_AVAILABLE -> Finding(
                    "ime", Severity.INFO, "Source-available keyboard: $name",
                    listOfNotNull(r.note, "It sees everything you type.").joinToString(" "),
                    Fix.INPUT_METHOD_SETTINGS, "Keyboard settings",
                )
                KeyboardTrust.Verdict.CLOSED_SOURCE_CLOUD -> Finding(
                    "ime", Severity.CRITICAL, "Your keyboard sends what you type: $name",
                    listOfNotNull(r.note, "Your messages pass through it before they're encrypted.", KeyboardTrust.ALTERNATIVES).joinToString(" "),
                    Fix.GET_OPEN_SOURCE_KEYBOARD, "Get an open-source keyboard",
                )
                KeyboardTrust.Verdict.CLOSED_SOURCE -> Finding(
                    "ime", Severity.WARNING, "Closed-source keyboard: $name",
                    listOfNotNull(
                        r.note ?: "$name is closed source.",
                        "Nobody can check what it does with what you type, including your messages before they're encrypted.",
                        KeyboardTrust.ALTERNATIVES,
                    ).joinToString(" "),
                    Fix.GET_OPEN_SOURCE_KEYBOARD, "Get an open-source keyboard",
                )
                KeyboardTrust.Verdict.UNKNOWN -> Finding(
                    "ime", Severity.WARNING, "Keyboard may be closed source: $name",
                    "GoldfishSend couldn't confirm that $name is open source, and it sees everything you type. " +
                        "Keyboards installed from F-Droid are recognised automatically. ${KeyboardTrust.ALTERNATIVES}",
                    Fix.GET_OPEN_SOURCE_KEYBOARD, "Get an open-source keyboard",
                )
            }
        }

        val imm = ctx.getSystemService(InputMethodManager::class.java)
        val others = runCatching { imm.enabledInputMethodList }.getOrDefault(emptyList())
            .map { it.packageName }
            .distinct()
            .filter { it != current }
            .mapNotNull { pkg ->
                val r = classify(pkg)
                if (r.verdict == KeyboardTrust.Verdict.OPEN_SOURCE) null else label(pkg, r)
            }
        if (others.isNotEmpty()) {
            findings += Finding(
                "ime-enabled", Severity.INFO, "Other keyboards can be switched to",
                "${others.joinToString()} ${if (others.size == 1) "is" else "are"} enabled but not confirmed open source. " +
                    "Turn off keyboards you don't use.",
                Fix.INPUT_METHOD_SETTINGS, "Keyboard settings",
            )
        }
        return findings
    }

    private fun installerOf(pm: PackageManager, pkg: String): String? = runCatching {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            pm.getInstallSourceInfo(pkg).installingPackageName
        } else {
            @Suppress("DEPRECATION")
            pm.getInstallerPackageName(pkg)
        }
    }.getOrNull()
}
