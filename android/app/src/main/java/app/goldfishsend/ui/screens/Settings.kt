package app.goldfishsend.ui.screens

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
import app.goldfishsend.core.TIMER_CHOICES
import app.goldfishsend.core.ThemeMode
import app.goldfishsend.core.launchSafe
import app.goldfishsend.core.timerLabel
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
import app.goldfishsend.ui.components.rememberQuery
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private enum class Picker { NOTIF, CLIPBOARD, DEFAULT_TIMER, TIMER_START, LOCK_TIMEOUT, FAILED, INACTIVITY }

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(s: Session, openPassphrase: () -> Unit) {
    val ctx = LocalContext.current
    val activity = ctx as FragmentActivity
    val scope = rememberCoroutineScope()
    val v by Graph.prefs.version.collectAsState()
    val p = Graph.prefs
    val vault = Graph.vault
    val name by rememberQuery(s) { it.repo.displayName }
    var picker by remember { mutableStateOf<Picker?>(null) }
    var editName by remember { mutableStateOf(false) }
    var editServer by remember { mutableStateOf(false) }
    var pushPicker by remember { mutableStateOf(false) }
    var networkSettings by remember { mutableStateOf(false) }
    var duress by remember { mutableStateOf(false) }
    var confirmWipeMessages by remember { mutableStateOf(false) }
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
                SwitchRow("Read receipts", "Let contacts know when you've read their messages", Icons.Rounded.DoneAll, p.readReceipts) { p.readReceipts = it }
                SwitchRow("Block screenshots", "Also hides chats in the recent-apps view", Icons.Rounded.Screenshot, p.screenshotProtection) { p.screenshotProtection = it }
                SettingRow(
                    "Clear clipboard",
                    if (p.clipboardClearSecs == 0) "Never" else "After ${p.clipboardClearSecs} seconds",
                    Icons.Rounded.ContentPaste,
                    onClick = { picker = Picker.CLIPBOARD },
                )
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
                    if (vault.hasPassphrase) "Change passphrase" else "Set a passphrase",
                    if (vault.hasPassphrase) "Required to open GoldfishSend" else "Off · anyone who can unlock your phone can read chats",
                    Icons.Rounded.Key,
                    onClick = openPassphrase,
                )
                if (vault.hasPassphrase) {
                    val bioAvailable = remember { biometricAvailable(activity) }
                    SwitchRow(
                        "Fingerprint unlock",
                        if (bioAvailable) "Unlock with biometrics instead of typing" else "No strong biometrics set up on this phone",
                        Icons.Rounded.Fingerprint,
                        checked = p.biometricUnlock && vault.hasBiometric,
                        enabled = bioAvailable,
                    ) { on ->
                        if (!on) {
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
                        "Auto-lock",
                        lockLabel(p.lockTimeoutSecs),
                        Icons.Rounded.LockClock,
                        onClick = { picker = Picker.LOCK_TIMEOUT },
                    )
                    SwitchRow("Lock when screen turns off", null, Icons.Rounded.Lock, p.lockOnScreenOff) { p.lockOnScreenOff = it }
                    SettingRow(
                        "Erase after failed attempts",
                        if (p.maxFailedAttempts == 0) "Off" else "After ${p.maxFailedAttempts} wrong passphrases",
                        Icons.Rounded.Warning,
                        onClick = { picker = Picker.FAILED },
                    )
                    SettingRow(
                        "Duress PIN",
                        if (vault.hasDuress) "Set · entering it silently erases everything" else "Off · a second PIN that erases everything when entered",
                        Icons.Rounded.PhonelinkLock,
                        onClick = { duress = true },
                    )
                }
            }
            item {
                SectionHeader("Automatic erasing")
                SwitchRow(
                    "Erase messages on restart",
                    "All messages are destroyed whenever your phone reboots",
                    Icons.Rounded.RestartAlt,
                    p.wipeOnReboot,
                ) { p.wipeOnReboot = it }
                SettingRow(
                    "Erase everything if unused",
                    if (p.inactivityWipeDays == 0) "Off" else "If not unlocked for ${p.inactivityWipeDays} days",
                    Icons.Rounded.DeleteSweep,
                    onClick = { picker = Picker.INACTIVITY },
                )
            }
            item {
                SectionHeader("Network")
                SettingRow(
                    "Push service",
                    PushHub.current(ctx)?.let { PushHub.label(ctx, it) } ?: "Not set up",
                    Icons.Rounded.NotificationsActive,
                    onClick = { pushPicker = true },
                )
                SettingRow("Connection", connectionSummary(), Icons.Rounded.VpnLock, onClick = { networkSettings = true })
                SettingRow("Server", p.serverUrl, Icons.Rounded.Dns, onClick = { editServer = true })
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
        NetworkSettingsDialog { networkSettings = false }
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
        PushPickerDialog { pushPicker = false }
    }
    if (duress) {
        DuressDialog { duress = false }
    }
    if (confirmWipeMessages) {
        ConfirmDialog("Erase all messages?", "Every message in every chat is destroyed. This can't be undone.", "Erase", true, { confirmWipeMessages = false }) {
            scope.launch(Dispatchers.IO) { Wiper.wipeMessages() }
        }
    }
    if (confirmPanic) {
        ConfirmDialog(
            "Panic wipe?",
            "All keys, contacts and messages are destroyed immediately. Your contacts won't be able to reach you. This can't be undone.",
            "Wipe everything", true, { confirmPanic = false },
        ) { Wiper.wipeEverything(ctx) }
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

@Composable
fun PushPickerDialog(onDismiss: () -> Unit) {
    val ctx = LocalContext.current
    val dists = remember { PushHub.distributors(ctx) }
    val current = remember { PushHub.current(ctx) }
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
                                PushHub.select(ctx, d.packageName)
                                Graph.scope.launchSafe { PushHub.register(ctx) }
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

@Composable
private fun ServerDialog(s: Session, onDismiss: () -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var url by remember { mutableStateOf(Graph.prefs.serverUrl) }
    var error by remember { mutableStateOf<String?>(null) }
    val hasContacts by rememberQuery(s) { it.repo.contacts().isNotEmpty() }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Server") },
        text = {
            Column {
                if (hasContacts == true) {
                    Text(
                        "Your existing contacts reach you through this server. To switch, remove your contacts first.",
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                } else {
                    Text("Advanced: only change this if you run your own GoldfishSend server.", color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Spacer(Modifier.height(12.dp))
                    SecureTextField(url, { url = it; error = null }, Modifier.fillMaxWidth(), hint = "https://", kind = FieldKind.URI)
                    error?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
                }
            }
        },
        confirmButton = {
            TextButton(enabled = hasContacts == false, onClick = {
                if (!ServerApi.isValidServer(url)) {
                    error = "Use a secure https:// address."
                    return@TextButton
                }
                scope.launch {
                    val ok = withContext(Dispatchers.IO) {
                        runCatching { Graph.api(url.trim().trimEnd('/')).info() }.isSuccess
                    }
                    if (!ok) {
                        error = "Couldn't reach that server."
                        return@launch
                    }
                    withContext(Dispatchers.IO) {
                        // Drop pooled mailboxes on the old server; new ones are created on the new server.
                        for (m in s.repo.allMailboxes()) {
                            s.repo.deleteMailboxRow(m.id)
                        }
                    }
                    Graph.prefs.serverUrl = url.trim().trimEnd('/')
                    Graph.scope.launchSafe { PushHub.register(ctx) }
                    onDismiss()
                }
            }) { Text("Save") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun DuressDialog(onDismiss: () -> Unit) {
    val scope = rememberCoroutineScope()
    var pin by remember { mutableStateOf("") }
    val vault = Graph.vault
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Duress PIN") },
        text = {
            Column {
                Text(
                    "If someone forces you to unlock GoldfishSend, enter this PIN instead of your passphrase. Everything is silently erased, and the app looks freshly installed.",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(12.dp))
                SecureTextField(pin, { pin = it }, Modifier.fillMaxWidth(), hint = "Duress PIN (4+ digits)", kind = FieldKind.NUMBER_PASSWORD)
            }
        },
        confirmButton = {
            TextButton(enabled = pin.length >= 4, onClick = {
                val chars = pin.toCharArray()
                pin = ""
                scope.launch(Dispatchers.Default) {
                    vault.setDuress(chars)
                    chars.fill('\u0000')
                }
                onDismiss()
            }) { Text("Save") }
        },
        dismissButton = {
            Row {
                if (vault.hasDuress) {
                    TextButton(onClick = {
                        vault.setDuress(null)
                        onDismiss()
                    }) { Text("Remove", color = MaterialTheme.colorScheme.error) }
                }
                TextButton(onClick = onDismiss) { Text("Cancel") }
            }
        },
    )
}
