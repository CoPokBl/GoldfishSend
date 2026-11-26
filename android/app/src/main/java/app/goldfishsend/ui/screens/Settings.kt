package app.goldfishsend.ui.screens

import app.goldfishsend.ui.components.rememberReAuth
import androidx.compose.material.icons.rounded.Autorenew
import androidx.compose.material.icons.rounded.Link
import androidx.compose.material.icons.rounded.Emergency
import androidx.compose.material.icons.rounded.NotificationsOff
import androidx.compose.material.icons.rounded.VisibilityOff
import androidx.compose.material.icons.rounded.TheaterComedy
import app.goldfishsend.ui.components.PinEntryDialog
import app.goldfishsend.security.AppLock
import app.goldfishsend.core.PanicResponse
import app.goldfishsend.core.DuressAction
import android.content.Intent
import android.net.Uri
import android.os.Build
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.AccountCircle
import androidx.compose.material.icons.rounded.Badge
import androidx.compose.material.icons.rounded.BrightnessMedium
import androidx.compose.material.icons.rounded.ContentPaste
import androidx.compose.material.icons.rounded.DarkMode
import androidx.compose.material.icons.rounded.DeleteForever
import androidx.compose.material.icons.rounded.DeleteSweep
import androidx.compose.material.icons.rounded.DoneAll
import androidx.compose.material.icons.rounded.Dns
import androidx.compose.material.icons.rounded.Fingerprint
import androidx.compose.material.icons.rounded.HourglassBottom
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.Key
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.LockClock
import androidx.compose.material.icons.rounded.NotificationsActive
import androidx.compose.material.icons.rounded.Palette
import androidx.compose.material.icons.rounded.PhonelinkLock
import androidx.compose.material.icons.rounded.RestartAlt
import androidx.compose.material.icons.rounded.Screenshot
import androidx.compose.material.icons.rounded.Memory
import androidx.compose.material.icons.rounded.Shuffle
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material.icons.rounded.Timer
import androidx.compose.material.icons.rounded.VpnLock
import androidx.compose.material.icons.rounded.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.LargeTopAppBar
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.rememberTopAppBarState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import app.goldfishsend.BuildConfig
import app.goldfishsend.core.Graph
import app.goldfishsend.core.NotificationContent
import app.goldfishsend.core.Session
import app.goldfishsend.core.Shredder
import app.goldfishsend.core.TIMER_CHOICES
import app.goldfishsend.core.ThemeMode
import app.goldfishsend.core.launchSafe
import app.goldfishsend.core.timerLabel
import app.goldfishsend.net.ApiException
import app.goldfishsend.net.ServerApi
import app.goldfishsend.push.PushHub
import app.goldfishsend.security.Wiper
import app.goldfishsend.ui.components.ChoiceDialog
import app.goldfishsend.ui.components.ConfirmDialog
import app.goldfishsend.ui.components.FieldKind
import app.goldfishsend.ui.components.SecureTextField
import app.goldfishsend.ui.components.SectionHeader
import app.goldfishsend.ui.components.SettingRow
import app.goldfishsend.ui.components.SwitchRow
import app.goldfishsend.ui.components.biometricAvailable
import app.goldfishsend.ui.components.promptBiometric
import app.goldfishsend.ui.components.promptBiometricOnly
import app.goldfishsend.proto.Rand
import app.goldfishsend.ui.components.rememberQuery
import app.goldfishsend.ui.components.BusyDialog
import app.goldfishsend.ui.components.ButtonKind
import app.goldfishsend.ui.components.ProgressButton
import app.goldfishsend.ui.components.ProgressRow
import app.goldfishsend.ui.components.rememberWork
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

private enum class Picker { NOTIF, CLIPBOARD, DEFAULT_TIMER, TIMER_START, LOCK_TIMEOUT, FAILED, INACTIVITY, DURESS_ACTION, PANIC, ROTATION }

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(s: Session, openPassphrase: () -> Unit) {
    val ctx = LocalContext.current
    val activity = ctx as FragmentActivity
    val scope = rememberCoroutineScope()
    // This profile's settings. A decoy session has its own copy of every one (DecoyPrefs): changes there look real and
    // stay in the decoy, and nothing here reads or writes the real profile's from a decoy.
    val p = s.prefs
    val v by p.version.collectAsState()
    val vault = Graph.vault
    val name by rememberQuery(s) { it.repo.displayName }
    var picker by remember { mutableStateOf<Picker?>(null) }
    var editName by remember { mutableStateOf(false) }
    var editServer by remember { mutableStateOf(false) }
    var pushPicker by remember { mutableStateOf(false) }
    var networkSettings by remember { mutableStateOf(false) }
    var duress by remember { mutableStateOf(false) }
    // Security-relevant changes need the current secret (or the phone's screen lock) first.
    val reauth = rememberReAuth(s, activity)
    var hiddenPinDialog by remember { mutableStateOf(false) }
    var disconnectPanic by remember { mutableStateOf(false) }
    // Feature flags live inside the profile's encrypted DB, so a decoy session sees (and sets) its own.
    val duressOn by rememberQuery(s, v) { q -> q.repo.kvString(AppLock.KV_DURESS_ON) == "1" }
    val hiddenOn by rememberQuery(s, v) { q -> q.repo.kvString(AppLock.KV_HIDDEN_ON) == "1" }
    val notifyHidden by rememberQuery(s, v) { q -> q.repo.kvString(AppLock.KV_NOTIFY_HIDDEN) == "1" }
    var secretsChanged by remember { androidx.compose.runtime.mutableIntStateOf(0) }
    // Sealed in the vault (or the decoy's DB): read off the main thread.
    val duressAction by rememberQuery(s, secretsChanged) { q -> q.secrets.duressAction }
    var confirmWipeMessages by remember { mutableStateOf(false) }
    val wiping = rememberWork()
    var confirmPanic by remember { mutableStateOf(false) }
    val scroll = TopAppBarDefaults.exitUntilCollapsedScrollBehavior(rememberTopAppBarState())
    // Reading v makes this recompose on any preference change.
    @Suppress("UNUSED_EXPRESSION") v

    Scaffold(
        modifier = Modifier.nestedScroll(scroll.nestedScrollConnection),
        topBar = { LargeTopAppBar(title = { Text("Settings") }, scrollBehavior = scroll) },
        contentWindowInsets = androidx.compose.foundation.layout.WindowInsets(0),
    ) { pad ->
        LazyColumn(Modifier.padding(top = pad.calculateTopPadding()).fillMaxSize(), contentPadding = PaddingValues(bottom = 32.dp)) {
            item {
                SectionHeader("Profile")
                SettingRow("Your name", name ?: "Not set · only shared with contacts", Icons.Rounded.AccountCircle, onClick = { editName = true })
            }
            item {
                SectionHeader("Appearance")
                Column(Modifier.padding(horizontal = 24.dp, vertical = 8.dp)) {
                    SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                        ThemeMode.entries.forEachIndexed { i, m ->
                            SegmentedButton(
                                selected = p.themeMode == m,
                                onClick = { p.themeMode = m },
                                shape = SegmentedButtonDefaults.itemShape(i, ThemeMode.entries.size),
                            ) { Text(m.name.lowercase().replaceFirstChar { it.uppercase() }) }
                        }
                    }
                }
                if (Build.VERSION.SDK_INT >= 31) {
                    SwitchRow("Dynamic colour", "Match your wallpaper (Material You)", Icons.Rounded.Palette, p.dynamicColor) { p.dynamicColor = it }
                }
                SwitchRow("Pure black", "Darker dark theme for OLED screens", Icons.Rounded.DarkMode, p.amoled) { p.amoled = it }
            }
            item {
                SectionHeader("Privacy")
                SettingRow(
                    "Notification content",
                    when (p.notificationContent) {
                        NotificationContent.NONE -> "Show nothing"
                        NotificationContent.NAME -> "Name only"
                        NotificationContent.NAME_AND_MESSAGE -> "Name and message"
                    },
                    Icons.Rounded.NotificationsActive,
                    onClick = { picker = Picker.NOTIF },
                )
                SwitchRow(
                    "Silent while locked",
                    "No notification for messages that arrive while GoldfishSend is locked. Until you unlock, it can't tell " +
                        "which chat a message is for, so this is what keeps hidden chats silent then too.",
                    Icons.Rounded.NotificationsOff,
                    p.quietWhileLocked,
                ) { p.quietWhileLocked = it }
                SwitchRow("Read receipts", "Let contacts know when you've read their messages", Icons.Rounded.DoneAll, p.readReceipts) { p.readReceipts = it }
                SwitchRow("Block screenshots", "Also hides chats in the recent-apps view", Icons.Rounded.Screenshot, p.screenshotProtection) { p.screenshotProtection = it }
                SettingRow(
                    "Clear clipboard",
                    if (p.clipboardClearSecs == 0) "Never" else "After ${p.clipboardClearSecs} seconds",
                    Icons.Rounded.ContentPaste,
                    onClick = { picker = Picker.CLIPBOARD },
                )
                SwitchRow(
                    "Clear clipboard on lock",
                    "A copied message also goes when GoldfishSend locks. With an immediate lock you can't paste it into another app.",
                    Icons.Rounded.ContentPaste,
                    p.clipboardClearOnLock,
                ) { p.clipboardClearOnLock = it }
            }
            item {
                SectionHeader("Disappearing messages")
                SettingRow("Default timer for new chats", timerLabel(p.defaultTimerSecs), Icons.Rounded.Timer, onClick = { picker = Picker.DEFAULT_TIMER })
                SettingRow(
                    "Timer starts",
                    if (p.timerStartsOnRead) "When I read a message" else "When a message arrives",
                    Icons.Rounded.HourglassBottom,
                    onClick = { picker = Picker.TIMER_START },
                )
            }
            item {
                SectionHeader("App lock")
                SettingRow(
                    "Unlock method",
                    when (vault.unlockMethod) {
                        app.goldfishsend.crypto.UnlockMethod.NONE -> "Off · anyone who can unlock your phone can read chats"
                        app.goldfishsend.crypto.UnlockMethod.SCREEN_LOCK -> "Phone screen lock"
                        app.goldfishsend.crypto.UnlockMethod.APP_SECRET -> if (vault.secretIsPin) "App PIN (own keypad)" else "Passphrase"
                    },
                    Icons.Rounded.Key,
                    onClick = openPassphrase,
                )
                if (vault.requiresUserUnlock) {
                    SwitchRow(
                        "Clear memory when locking",
                        "Overwrites leftover message text in the app's memory after it locks",
                        Icons.Rounded.Memory,
                        p.wipeMemoryOnLock,
                    ) { p.wipeMemoryOnLock = it }
                    SettingRow(
                        "Auto-lock",
                        lockLabel(p.lockTimeoutSecs),
                        Icons.Rounded.LockClock,
                        onClick = { picker = Picker.LOCK_TIMEOUT },
                    )
                    SwitchRow("Lock when screen turns off", null, Icons.Rounded.Lock, p.lockOnScreenOff) { p.lockOnScreenOff = it }
                }
                if (vault.hasPassphrase) {
                    if (vault.secretIsPin) {
                        SwitchRow(
                            "Scramble keypad",
                            "Shuffle the digits each time, so watching your fingers or smudges doesn't reveal your PIN",
                            Icons.Rounded.Shuffle,
                            p.scramblePinPad,
                        ) { p.scramblePinPad = it }
                    }
                    val bioAvailable = remember { biometricAvailable(activity) }
                    SwitchRow(
                        "Fingerprint unlock",
                        if (bioAvailable) "Unlock with biometrics instead of typing" else "No strong biometrics set up on this phone",
                        Icons.Rounded.Fingerprint,
                        checked = p.biometricUnlock && (s.decoy || vault.hasBiometric),
                        enabled = bioAvailable,
                    ) { on ->
                        if (s.decoy) {
                            // The decoy's own setting. The prompt is the same, but the real biometric key and its copy of
                            // the master key are never touched (and the decoy's key never goes near them).
                            if (!on) {
                                p.biometricUnlock = false
                            } else {
                                promptBiometricOnly(activity, "Enable fingerprint unlock", onSuccess = { p.biometricUnlock = true })
                            }
                        } else if (!on) {
                            vault.disableBiometric()
                            p.biometricUnlock = false
                        } else {
                            val cipher = runCatching { vault.biometricEncryptCipher() }.getOrNull() ?: return@SwitchRow
                            promptBiometric(activity, "Enable fingerprint unlock", cipher, onSuccess = { c ->
                                val mk = s.masterKeyCopy()
                                vault.enableBiometric(mk, c)
                                mk.fill(0)
                                p.biometricUnlock = true
                            })
                        }
                    }
                    SettingRow(
                        "Erase after failed attempts",
                        if (p.maxFailedAttempts == 0) "Off" else "After ${p.maxFailedAttempts} wrong ${if (vault.secretIsPin) "PINs" else "passphrases"}",
                        Icons.Rounded.Warning,
                        onClick = { reauth.require("Changing when everything is erased.") { picker = Picker.FAILED } },
                    )
                    SettingRow(
                        "Duress PIN",
                        if (duressOn == true) {
                            "On · " + when (duressAction) {
                                null -> ""
                                DuressAction.WIPE_ALL -> "silently erases everything"
                                DuressAction.DECOY -> "opens a separate decoy profile"
                            }
                        } else {
                            "Off · a second PIN for when you're forced to unlock"
                        },
                        Icons.Rounded.PhonelinkLock,
                        onClick = { reauth.require("Changing the duress PIN.") { duress = true } },
                    )
                    if (duressOn == true) {
                        SettingRow(
                            "When the duress PIN is entered",
                            when (duressAction) {
                                null -> ""
                                DuressAction.WIPE_ALL -> "Erase everything"
                                DuressAction.DECOY -> "Open a decoy profile. Your real chats stay locked and untouched."
                            },
                            Icons.Rounded.TheaterComedy,
                            onClick = { reauth.require("Changing what the duress PIN does.") { picker = Picker.DURESS_ACTION } },
                        )
                    }
                }
            }
            item {
                SectionHeader("Hidden chats")
                SettingRow(
                    "Hidden chats",
                    if (hiddenOn == true) "On · long-press \"Chats\" and enter your hidden-chats PIN to show them" else "Off · keep chosen chats out of the list behind a separate PIN",
                    Icons.Rounded.VisibilityOff,
                    onClick = { reauth.require("Changing hidden chats.") { hiddenPinDialog = true } },
                )
                if (hiddenOn == true) {
                    SwitchRow(
                        "Notify for hidden chats",
                        "A notification with no name or text. Off means hidden chats stay silent while unlocked; to keep " +
                            "them silent while locked too, turn on \"Silent while locked\".",
                        Icons.Rounded.NotificationsOff,
                        notifyHidden == true,
                    ) { on ->
                        scope.launch(Dispatchers.IO) {
                            s.repo.kvPutString(AppLock.KV_NOTIFY_HIDDEN, if (on) "1" else null)
                            s.db.notifyChanged()
                        }
                    }
                }
            }
            item {
                SectionHeader("Panic button")
                SettingRow(
                    "Response to a panic app",
                    when (p.panicResponse) {
                        PanicResponse.OFF -> "Off"
                        PanicResponse.LOCK -> "Lock GoldfishSend"
                        PanicResponse.WIPE_MESSAGES -> "Lock and erase all messages"
                        PanicResponse.WIPE_EVERYTHING -> "Erase everything"
                    },
                    Icons.Rounded.Emergency,
                    onClick = { reauth.require("Changing the panic response.") { picker = Picker.PANIC } },
                )
                val trigger = p.panicTrigger
                SettingRow(
                    "Connected panic app",
                    if (trigger == null) {
                        "None · connect one from a panic app such as Ripple. Only a connected app can erase."
                    } else {
                        runCatching { ctx.packageManager.getApplicationLabel(ctx.packageManager.getApplicationInfo(trigger, 0)).toString() }
                            .getOrDefault(trigger) + " · tap to disconnect"
                    },
                    Icons.Rounded.Link,
                    onClick = { if (trigger != null) reauth.require("Disconnecting the panic app.") { disconnectPanic = true } },
                )
            }
            item {
                SectionHeader("Contacts and keys")
                SettingRow(
                    "Rotate mailboxes",
                    if (p.mailboxRotationDays == 0) "Never" else "Every ${p.mailboxRotationDays} days · limits how long the server can link your traffic",
                    Icons.Rounded.Autorenew,
                    onClick = { picker = Picker.ROTATION },
                )
            }
            item {
                SectionHeader("Automatic erasing")
                SwitchRow(
                    "Erase messages on restart",
                    "All messages are destroyed whenever your phone reboots",
                    Icons.Rounded.RestartAlt,
                    p.wipeOnReboot,
                ) { v -> reauth.require("Changing erase settings.") { p.wipeOnReboot = v } }
                SettingRow(
                    "Erase everything if unused",
                    if (p.inactivityWipeDays == 0) "Off" else "If not unlocked for ${p.inactivityWipeDays} days",
                    Icons.Rounded.DeleteSweep,
                    onClick = { reauth.require("Changing erase settings.") { picker = Picker.INACTIVITY } },
                )
            }
            item {
                SectionHeader("Network")
                SettingRow(
                    "Push service",
                    pushChoice(ctx, s)?.let { PushHub.label(ctx, it) } ?: "Not set up",
                    Icons.Rounded.NotificationsActive,
                    onClick = { pushPicker = true },
                )
                SettingRow("Connection", connectionSummary(s), Icons.Rounded.VpnLock, onClick = { reauth.require("Changing how GoldfishSend connects.") { networkSettings = true } })
                // Switching servers moves new mailboxes (and what they reveal) to another operator: confirm it's the owner.
                SettingRow("Server", p.serverUrl, Icons.Rounded.Dns, onClick = { reauth.require("Changing your server.") { editServer = true } })
            }
            item {
                SectionHeader("Danger zone")
                SettingRow("Erase all messages", "Contacts are kept", Icons.Rounded.DeleteSweep, onClick = { confirmWipeMessages = true })
                SettingRow(
                    "Panic wipe",
                    "Destroy all keys, contacts and messages now. Tip: add the \"Panic wipe\" tile to Quick Settings.",
                    Icons.Rounded.DeleteForever,
                    onClick = { confirmPanic = true },
                )
            }
            item {
                SectionHeader("About")
                SettingRow("GoldfishSend ${BuildConfig.VERSION_NAME}", "Free software under the AGPL-3.0 licence", Icons.Rounded.Info)
                SettingRow("Encryption", "Signal protocol (PQXDH + Double Ratchet) · SQLCipher · Android Keystore", Icons.Rounded.Shield)
            }
        }
    }

    if (networkSettings) {
        NetworkSettingsDialog(s) { networkSettings = false }
    }
    when (picker) {
        Picker.NOTIF -> ChoiceDialog(
            "Notification content",
            listOf(NotificationContent.NONE to "Show nothing", NotificationContent.NAME to "Name only", NotificationContent.NAME_AND_MESSAGE to "Name and message"),
            p.notificationContent, { picker = null },
        ) { p.notificationContent = it }
        Picker.CLIPBOARD -> ChoiceDialog(
            "Clear clipboard", listOf(0 to "Never", 15 to "15 seconds", 30 to "30 seconds", 60 to "1 minute", 300 to "5 minutes"),
            p.clipboardClearSecs, { picker = null },
        ) { p.clipboardClearSecs = it }
        Picker.DEFAULT_TIMER -> ChoiceDialog(
            "Default timer", TIMER_CHOICES.map { it to timerLabel(it) }, p.defaultTimerSecs, { picker = null },
        ) { p.defaultTimerSecs = it }
        Picker.TIMER_START -> ChoiceDialog(
            "Timer starts", listOf(true to "When I read a message", false to "When a message arrives"), p.timerStartsOnRead, { picker = null },
        ) { p.timerStartsOnRead = it }
        Picker.LOCK_TIMEOUT -> ChoiceDialog(
            "Auto-lock", listOf(0, 30, 60, 300, 900, 3600).map { it to lockLabel(it) }, p.lockTimeoutSecs, { picker = null },
        ) { p.lockTimeoutSecs = it }
        Picker.FAILED -> ChoiceDialog(
            "Erase after failed attempts", listOf(0 to "Off", 5 to "5 attempts", 10 to "10 attempts", 20 to "20 attempts"),
            p.maxFailedAttempts, { picker = null },
        ) { p.maxFailedAttempts = it }
        Picker.INACTIVITY -> ChoiceDialog(
            "Erase everything if unused", listOf(0 to "Off", 3 to "3 days", 7 to "7 days", 14 to "14 days", 30 to "30 days", 90 to "90 days"),
            p.inactivityWipeDays, { picker = null },
        ) { p.inactivityWipeDays = it }
        Picker.DURESS_ACTION -> ChoiceDialog(
            "When the duress PIN is entered",
            listOf(
                DuressAction.WIPE_ALL to "Erase everything",
                DuressAction.DECOY to "Open a separate decoy profile (your real chats stay locked)",
            ),
            duressAction ?: DuressAction.WIPE_ALL, { picker = null },
        ) { a ->
            scope.launch {
                withContext(Dispatchers.IO) { s.secrets.duressAction = a }
                secretsChanged++
            }
        }
        Picker.PANIC -> ChoiceDialog(
            "Response to a panic app",
            listOf(
                PanicResponse.OFF to "Off",
                PanicResponse.LOCK to "Lock GoldfishSend",
                PanicResponse.WIPE_MESSAGES to "Lock and erase all messages",
                PanicResponse.WIPE_EVERYTHING to "Erase everything",
            ),
            p.panicResponse, { picker = null },
        ) { p.panicResponse = it }
        Picker.ROTATION -> ChoiceDialog(
            "Rotate mailboxes", listOf(0 to "Never", 7 to "Every 7 days", 14 to "Every 14 days", 30 to "Every 30 days", 90 to "Every 90 days"),
            p.mailboxRotationDays, { picker = null },
        ) { p.mailboxRotationDays = it }
        null -> Unit
    }

    if (editName) {
        var text by remember { mutableStateOf(name.orEmpty()) }
        AlertDialog(
            onDismissRequest = { editName = false },
            title = { Text("Your name") },
            text = {
                Column {
                    Text("Shared with new contacts when you connect.", color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Spacer(Modifier.height(12.dp))
                    SecureTextField(text, { text = it }, Modifier.fillMaxWidth(), hint = "Name")
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    editName = false
                    scope.launch(Dispatchers.IO) { s.repo.displayName = text.take(64) }
                }) { Text("Save") }
            },
            dismissButton = { TextButton(onClick = { editName = false }) { Text("Cancel") } },
        )
    }
    if (editServer) {
        ServerDialog(s) { editServer = false }
    }
    if (pushPicker) {
        PushPickerDialog(s) { pushPicker = false }
    }
    if (duress) {
        DuressDialog(s, duressOn == true) {
            duress = false
            secretsChanged++
        }
    }
    if (hiddenPinDialog) {
        HiddenChatsDialog(s, hiddenOn == true) { hiddenPinDialog = false }
    }
    if (disconnectPanic) {
        ConfirmDialog(
            "Disconnect panic app?", "It will only be able to lock GoldfishSend, never erase it.", "Disconnect", false,
            { disconnectPanic = false },
        ) { p.panicTrigger = null }
    }
    if (confirmWipeMessages) {
        ConfirmDialog("Erase all messages?", "Every message in every chat is destroyed. This can't be undone.", "Erase", true, { confirmWipeMessages = false }) {
            wiping.run {
                withContext(Dispatchers.IO) {
                    if (s.decoy) {
                        // The decoy's own messages. The real ones (and their key) belong to the real profile. Its own root
                        // is replaced too, as the real profile's would be.
                        s.repo.wipeAllMessages()
                        runCatching { Shredder.rotate(s) }
                        s.db.notifyChanged()
                    } else {
                        Wiper.wipeMessages()
                    }
                }
            }
        }
    }
    BusyDialog(wiping.busy, "Erasing messages…")
    if (confirmPanic) {
        ConfirmDialog(
            "Panic wipe?",
            "All keys, contacts and messages are destroyed immediately. Your contacts won't be able to reach you. This can't be undone.",
            "Wipe everything", true, { confirmPanic = false },
        ) { Wiper.wipeEverything(ctx, killProcess = true) }
    }
}

private fun lockLabel(secs: Int): String = when (secs) {
    0 -> "Immediately"
    30 -> "After 30 seconds"
    60 -> "After 1 minute"
    300 -> "After 5 minutes"
    900 -> "After 15 minutes"
    3600 -> "After 1 hour"
    else -> "After $secs seconds"
}

/** The push app shown for this profile: a decoy's own pick if it made one, otherwise the device's. */
fun pushChoice(ctx: android.content.Context, s: Session): String? =
    (if (s.decoy) s.prefs.decoyPushDistributor else null) ?: PushHub.current(ctx)

@Composable
fun PushPickerDialog(s: Session, onDismiss: () -> Unit) {
    val ctx = LocalContext.current
    val dists = remember { PushHub.distributors(ctx) }
    val current = remember { pushChoice(ctx, s) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Push service") },
        text = {
            Column {
                if (dists.isEmpty()) {
                    Text("No push app is installed. Install ntfy or Sunup, then come back.")
                    TextButton(onClick = { ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://f-droid.org/packages/io.heckel.ntfy/"))) }) {
                        Text("Get ntfy")
                    }
                    TextButton(onClick = {
                        ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://f-droid.org/packages/org.unifiedpush.distributor.sunup/")))
                    }) { Text("Get Sunup") }
                } else {
                    for (d in dists) {
                        Row(Modifier.fillMaxWidth()) {
                            TextButton(onClick = {
                                if (s.decoy) {
                                    // The decoy's own choice. The device's push registration belongs to the real profile.
                                    s.prefs.decoyPushDistributor = d.packageName
                                } else {
                                    PushHub.select(ctx, d.packageName)
                                    // Every instance again with the new push app. Each mailbox then moves to its new
                                    // endpoint on its own, a few minutes apart (Mailboxes.onNewEndpoint).
                                    Graph.scope.launchSafe { PushHub.register(ctx, s) }
                                }
                                onDismiss()
                            }) {
                                Text(d.label + if (d.packageName == current) "  ✓" else "")
                            }
                        }
                    }
                }
            }
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text("Close") } },
    )
}

/**
 * Why the server can't be changed while there are chats: every contact and group reaches us through a mailbox on this
 * server, and mailboxes can't live on two servers at once, so switching would cut them off without telling them.
 */
private const val SERVER_IN_USE =
    "Your contacts and groups reach you through this server, and they can't be moved to another one. To switch servers, delete your chats first."

@Composable
private fun ServerDialog(s: Session, onDismiss: () -> Unit) {
    val ctx = LocalContext.current
    val work = rememberWork()
    val p = s.prefs
    var url by remember { mutableStateOf(p.serverUrl) }
    var fingerprint by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    val hasContacts by rememberQuery(s) { it.repo.contacts().isNotEmpty() }
    AlertDialog(
        onDismissRequest = { if (!work.busy) onDismiss() },
        title = { Text("Server") },
        text = {
            Column {
                if (hasContacts == true) {
                    Text(SERVER_IN_USE, color = MaterialTheme.colorScheme.onSurfaceVariant)
                } else {
                    Text("Advanced: only change this if you run your own GoldfishSend server.", color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Spacer(Modifier.height(12.dp))
                    SecureTextField(url, { url = it; error = null }, Modifier.fillMaxWidth(), hint = "https://", kind = FieldKind.URI)
                    Spacer(Modifier.height(8.dp))
                    SecureTextField(fingerprint, { fingerprint = it; error = null }, Modifier.fillMaxWidth(), hint = "Server fingerprint (optional)")
                    error?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
                    ProgressRow(work.busy, "Checking the server…")
                }
            }
        },
        confirmButton = {
            ProgressButton(busy = work.busy, enabled = hasContacts == false, kind = ButtonKind.TEXT, onClick = {
                if (!ServerApi.isValidServer(url)) {
                    error = "Use a secure https:// address."
                    return@ProgressButton
                }
                val typed = fingerprint.trim()
                val fp = if (typed.isEmpty()) null else app.goldfishsend.net.Gateway.parseFingerprintInput(typed)
                if (typed.isNotEmpty() && fp == null) {
                    error = "That isn't a server fingerprint. Check it with the server's operator."
                    return@ProgressButton
                }
                val target = url.trim().trimEnd('/')
                work.run {
                    if (s.decoy) {
                        // The decoy is offline: it never contacts a server (one could link it to the real profile), and it
                        // never touches the real profile's server settings. It fails the way an unreachable server does.
                        kotlinx.coroutines.delay(1200L + Rand.int(1500))
                        error = "Couldn't reach that server."
                        return@run
                    }
                    // Verify the server before switching: against the typed fingerprint, the built-in one, or the key it
                    // presents now (remembered from here on).
                    var learned: String? = null
                    val expected = fp ?: app.goldfishsend.core.Prefs.builtInServerKey(target)
                    val result = withContext(Dispatchers.IO) {
                        runCatching {
                            Graph.api(target, app.goldfishsend.net.ServerPin(expected, onFirstUse = { learned = it })).info()
                        }
                    }
                    result.exceptionOrNull()?.let { e ->
                        error = if ((e as? ApiException)?.code == "server_identity_changed") {
                            "That server's fingerprint doesn't match. Check it with the server's operator."
                        } else {
                            "Couldn't reach that server."
                        }
                        return@run
                    }
                    val switched = withContext(Dispatchers.IO) {
                        // Nothing more is made on the old server: a mailbox finishing now would be taken for one on the new.
                        app.goldfishsend.core.Mailboxes.stopFill()
                        // Drop our mailboxes on the old server; new ones are created on the new server. They're deleted
                        // there too (retried until it confirms), and an outstanding invite's prekeys go with them. Checked
                        // again here, under the lock a new contact is made under: a chat's mailbox is never dropped, since
                        // its contact or group would lose the way to reach us without being told.
                        val ok = s.lock.withLock {
                            s.db.tx {
                                if (s.repo.contacts().isNotEmpty()) {
                                    return@tx false
                                }
                                val boxes = s.repo.allMailboxes()
                                for (m in boxes.filter { it.contactId == null }) {
                                    m.inviteSpkId?.let { s.signal.removeSignedPreKey(it) }
                                    m.inviteKyberId?.let { s.signal.removeKyberPreKey(it) }
                                }
                                s.repo.doomMailboxes(boxes, Graph.prefs.serverUrl, Graph.prefs.serverKey)
                                true
                            }
                        }
                        if (ok) {
                            app.goldfishsend.core.Invites.forgetCachedQr()
                            // Registered with the old server's push key: new mailboxes get instances made for the new one.
                            PushHub.dropUnused(s)
                        }
                        ok
                    }
                    if (!switched) {
                        error = SERVER_IN_USE
                        return@run
                    }
                    Graph.prefs.serverUrl = target
                    val tofu = learned
                    if (fp == null && tofu != null) {
                        // Only trusted on first use: a key built in for this server later takes over (see Prefs.serverKey).
                        Graph.prefs.learnServerKey(tofu)
                    } else {
                        Graph.prefs.serverKey = fp
                    }
                    Graph.prefs.serverKeyChanged = null
                    Graph.scope.launchSafe { PushHub.register(ctx, s) }
                    Graph.scope.launchSafe { app.goldfishsend.core.OwnerOps.kick(s) }
                    onDismiss()
                }
            }) { Text("Save") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

/**
 * Sets or removes the duress PIN, on GoldfishSend's own keypad. It goes through the profile's own secrets: in a decoy
 * session that's the decoy's, so it works there like the real thing (same checks, same cost) and changes nothing real.
 */
@Composable
private fun DuressDialog(s: Session, on: Boolean, onDismiss: () -> Unit) {
    val work = rememberWork()
    val secrets = s.secrets
    // Setting or removing it runs Argon2 (and for the real profile deletes the decoy): the dialog stays, busy, until done.
    fun save(block: () -> Unit) {
        work.run {
            withContext(Dispatchers.Default) { block() }
            onDismiss()
        }
    }
    PinEntryDialog(
        "Duress PIN",
        "If someone forces you to unlock GoldfishSend, enter this PIN instead of your real one. You choose what it does afterwards: " +
            "erase everything, or open a separate decoy profile. The duress PIN can never decrypt your real chats.",
        onDismiss = onDismiss,
        minLength = 4,
        removeLabel = if (on) "Remove" else null,
        busy = work.busy,
        busyText = "Saving…",
        onRemove = {
            save {
                secrets.setDuress(null)
                s.repo.kvPutString(AppLock.KV_DURESS_ON, null)
                s.db.notifyChanged()
            }
        },
        validate = { pin ->
            // Must differ from this profile's app secret and hidden-chats PIN (a decoy's are its own).
            val copy = pin.copyOf()
            val clash = runCatching { secrets.checkSecret(copy) }.getOrDefault(false) || secrets.isHiddenPin(pin)
            copy.fill('\u0000')
            if (clash) "This must be different from your other PINs." else null
        },
    ) { pin ->
        save {
            // For the real profile, a verifier only: the duress PIN can't decrypt anything real. A new PIN also starts a
            // fresh decoy profile.
            secrets.setDuress(pin)
            pin.fill('\u0000')
            s.repo.kvPutString(AppLock.KV_DURESS_ON, "1")
            s.db.notifyChanged()
        }
    }
}

/** Sets or removes the hidden-chats PIN (the profile's own, as for [DuressDialog]). Removing it un-hides every hidden chat. */
@Composable
private fun HiddenChatsDialog(s: Session, on: Boolean, onDismiss: () -> Unit) {
    val work = rememberWork()
    val secrets = s.secrets
    fun save(block: () -> Unit) {
        work.run {
            withContext(Dispatchers.Default) { block() }
            onDismiss()
        }
    }
    PinEntryDialog(
        if (on) "Change hidden-chats PIN" else "Hidden chats",
        "Choose a PIN for hidden chats. Hide a chat from its contact info. To see hidden chats, long-press \"Chats\" and enter this PIN. " +
            "They're hidden again when GoldfishSend locks.",
        onDismiss = onDismiss,
        removeLabel = if (on) "Turn off" else null,
        busy = work.busy,
        busyText = "Saving…",
        onRemove = {
            save {
                secrets.setHiddenPin(null)
                for (id in s.repo.hiddenContactIds()) {
                    s.repo.setHidden(id, false)
                }
                s.repo.kvPutString(AppLock.KV_HIDDEN_ON, null)
                s.db.notifyChanged()
            }
        },
        validate = { pin ->
            val copy = pin.copyOf()
            val clash = runCatching { secrets.checkSecret(copy) }.getOrDefault(false) || secrets.isDuress(pin)
            copy.fill('\u0000')
            if (clash) "This must be different from your other PINs." else null
        },
    ) { pin ->
        save {
            secrets.setHiddenPin(pin)
            pin.fill('\u0000')
            s.repo.kvPutString(AppLock.KV_HIDDEN_ON, "1")
            s.db.notifyChanged()
        }
    }
}
