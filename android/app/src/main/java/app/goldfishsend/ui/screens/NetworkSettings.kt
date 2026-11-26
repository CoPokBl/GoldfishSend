package app.goldfishsend.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material.icons.rounded.Key
import androidx.compose.material.icons.rounded.VpnLock
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import app.goldfishsend.core.Graph
import app.goldfishsend.core.NetPrefs
import app.goldfishsend.core.PinMismatch
import app.goldfishsend.core.Session
import app.goldfishsend.net.Gateway
import app.goldfishsend.net.NetStack
import app.goldfishsend.security.ClipboardGuard
import app.goldfishsend.net.PinPolicy
import app.goldfishsend.net.ProxyMode
import app.goldfishsend.net.TorManager
import app.goldfishsend.ui.components.SectionHeader
import app.goldfishsend.ui.components.SettingRow
import androidx.compose.foundation.layout.size
import app.goldfishsend.ui.components.Spinner
import app.goldfishsend.ui.components.SwitchRow

/**
 * What the Connection screen shows and changes. The real profile (and onboarding) uses the device's network settings. A
 * decoy session has its own copy, kept in its own settings: switching there looks the same, but the real connection mode,
 * pins and Tor stay exactly as they were, and the real profile's pinned servers (which say who it talks to) never show.
 */
private interface ConnectionSettings {
    var mode: ProxyMode
    var pinServers: Boolean

    fun pins(): Map<String, Set<String>>

    fun blockedKeys(hostKey: String): Set<String>

    fun forget(hostKey: String)
}

private class DeviceConnection(private val ctx: android.content.Context) : ConnectionSettings {
    override var mode: ProxyMode
        get() = NetPrefs.proxyMode
        set(m) {
            NetPrefs.proxyMode = m
            NetStack.apply(ctx)
            Graph.resetHttp()
        }

    override var pinServers: Boolean
        get() = NetPrefs.pinServers
        set(v) {
            NetPrefs.pinServers = v
            Graph.resetHttp()
        }

    override fun pins() = NetPrefs.allPins()

    override fun blockedKeys(hostKey: String) = NetPrefs.blockedKeys(hostKey)

    override fun forget(hostKey: String) {
        NetPrefs.forgetPins(hostKey)
        Graph.resetHttp()
    }
}

/** The decoy never connects anywhere, so it never records a pin. */
private class DecoyConnection(private val p: app.goldfishsend.core.Prefs) : ConnectionSettings {
    override var mode: ProxyMode
        get() = p.decoyProxyMode?.let { runCatching { ProxyMode.valueOf(it) }.getOrNull() } ?: ProxyMode.DIRECT
        set(m) {
            p.decoyProxyMode = m.name
        }

    override var pinServers: Boolean
        get() = p.decoyPinServers
        set(v) {
            p.decoyPinServers = v
        }

    override fun pins() = emptyMap<String, Set<String>>()

    override fun blockedKeys(hostKey: String) = emptySet<String>()

    override fun forget(hostKey: String) = Unit
}

private fun connection(ctx: android.content.Context, s: Session?): ConnectionSettings =
    if (s?.decoy == true) DecoyConnection(s.prefs) else DeviceConnection(ctx)

/** One-line summary for the Settings row (and onboarding, with no session yet). */
@Composable
fun connectionSummary(s: Session? = null): String {
    val c = connection(LocalContext.current, s)
    return when (c.mode) {
        ProxyMode.DIRECT -> "Direct connection"
        ProxyMode.EMBEDDED_TOR -> "Built-in Tor"
        ProxyMode.ORBOT -> "Tor through Orbot"
    } + if (c.pinServers) " · TLS keys pinned" else ""
}

private fun modeTitle(m: ProxyMode) = when (m) {
    ProxyMode.DIRECT -> "Direct"
    ProxyMode.EMBEDDED_TOR -> "Built-in Tor"
    ProxyMode.ORBOT -> "Orbot"
}

private fun modeDetail(m: ProxyMode) = when (m) {
    ProxyMode.DIRECT -> "Fastest. Servers can see your IP address."
    ProxyMode.EMBEDDED_TOR -> "Hides your IP address from servers. Slower to connect, and uses more battery."
    ProxyMode.ORBOT -> "Uses the Orbot app's Tor connection. Orbot must be running."
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NetworkSettingsDialog(s: Session? = null, onDismiss: () -> Unit) {
    val ctx = LocalContext.current
    val conn = remember(s) { connection(ctx, s) }
    val netVersion by NetPrefs.version.collectAsState()
    val p = s?.prefs ?: Graph.prefs
    val prefsVersion by p.version.collectAsState()
    val realTor by TorManager.state.collectAsState()
    // A decoy that chose built-in Tor can only show a running Tor if the device runs it anyway; it never starts one.
    val tor = if (s?.decoy == true && NetPrefs.proxyMode != ProxyMode.EMBEDDED_TOR) TorManager.State.Failed(null) else realTor
    var forget by remember { mutableStateOf<String?>(null) }
    var trust by remember { mutableStateOf<Pair<String, String>?>(null) }
    // Reading the versions recomposes on every change.
    @Suppress("UNUSED_EXPRESSION") netVersion
    @Suppress("UNUSED_EXPRESSION") prefsVersion

    Dialog(onDismissRequest = onDismiss, properties = DialogProperties(usePlatformDefaultWidth = false)) {
        Scaffold(
            topBar = {
                TopAppBar(
                    title = { Text("Connection") },
                    navigationIcon = {
                        IconButton(onClick = onDismiss) { Icon(Icons.AutoMirrored.Rounded.ArrowBack, "Back") }
                    },
                )
            },
        ) { pad ->
            Column(
                Modifier
                    .padding(pad)
                    .fillMaxSize()
                    .verticalScroll(rememberScrollState()),
            ) {
                SectionHeader("How to reach servers")
                for (m in ProxyMode.entries) {
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .selectable(selected = conn.mode == m, role = Role.RadioButton) {
                                if (conn.mode != m) {
                                    conn.mode = m
                                }
                            }
                            .padding(horizontal = 24.dp, vertical = 10.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        RadioButton(selected = conn.mode == m, onClick = null)
                        Spacer(Modifier.width(16.dp))
                        Column {
                            Text(modeTitle(m), style = MaterialTheme.typography.bodyLarge)
                            Text(modeDetail(m), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                    }
                }
                if (conn.mode == ProxyMode.EMBEDDED_TOR) {
                    val status = when (val t = tor) {
                        is TorManager.State.Ready -> "Connected through Tor."
                        TorManager.State.Starting -> "Connecting to Tor… Nothing is sent until Tor is ready."
                        is TorManager.State.Failed -> "Tor couldn't connect. Nothing is sent until it does. Check your internet connection."
                        TorManager.State.Off -> "Starting Tor…"
                    }
                    val connecting = tor == TorManager.State.Starting || tor == TorManager.State.Off
                    SettingRow("Tor status", status, Icons.Rounded.VpnLock, trailing = if (connecting) ({ Spinner(Modifier.size(20.dp)) }) else null)
                }
                if (conn.mode != ProxyMode.DIRECT) {
                    Text(
                        "Tor covers your connections to GoldfishSend servers. Notifications still arrive through your push " +
                            "service (for example ntfy), which can see when you get a message but never what it says.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(horizontal = 24.dp, vertical = 8.dp),
                    )
                }

                SectionHeader("Server identity")
                val own = p.serverKey
                Column(Modifier.fillMaxWidth().padding(horizontal = 24.dp, vertical = 8.dp)) {
                    Text(runCatching { java.net.URI(p.serverUrl).host }.getOrNull() ?: p.serverUrl, style = MaterialTheme.typography.bodyLarge)
                    Text(
                        own?.let { Gateway.displayFingerprint(it) } ?: "Recorded the first time the app connects.",
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = if (own != null) FontFamily.Monospace else null,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    if (own != null) {
                        TextButton(onClick = { ClipboardGuard.copy(ctx, Gateway.displayFingerprint(own)) }) { Text("Copy") }
                    }
                }
                Text(
                    "GoldfishSend always checks this identity key and encrypts every request to it, whatever the connection. " +
                        "Compare it with the fingerprint your server's operator publishes.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = 24.dp, vertical = 4.dp),
                )

                SectionHeader("TLS keys (optional)")
                SwitchRow(
                    "Pin TLS keys",
                    "An extra layer on top of the identity check: also remember each server's TLS certificate key and refuse to " +
                        "connect if it changes. You'll be asked what to do whenever a server renews its certificate with a new key.",
                    Icons.Rounded.Key,
                    conn.pinServers,
                ) {
                    conn.pinServers = it
                }
                val pins = conn.pins()
                if (conn.pinServers && pins.isEmpty()) {
                    Text(
                        "Keys are recorded the next time the app connects to each server.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(horizontal = 24.dp, vertical = 8.dp),
                    )
                }
                for ((hostKey, set) in pins.toSortedMap()) {
                    Column(Modifier.fillMaxWidth().padding(horizontal = 24.dp, vertical = 8.dp)) {
                        Text(hostKey.removeSuffix(":443"), style = MaterialTheme.typography.bodyLarge)
                        for (pin in set) {
                            Text(
                                PinPolicy.displayFingerprint(pin),
                                style = MaterialTheme.typography.bodySmall,
                                fontFamily = FontFamily.Monospace,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        val blocked = conn.blockedKeys(hostKey)
                        for (b in blocked) {
                            Spacer(Modifier.height(4.dp))
                            Text(
                                "Blocked new key: ${PinPolicy.displayFingerprint(b)}",
                                style = MaterialTheme.typography.bodySmall,
                                fontFamily = FontFamily.Monospace,
                                color = MaterialTheme.colorScheme.error,
                            )
                        }
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            blocked.firstOrNull()?.let { b -> TextButton(onClick = { trust = hostKey to b }) { Text("Trust new key") } }
                            TextButton(onClick = { forget = hostKey }) { Text("Forget") }
                        }
                    }
                }
                Text(
                    "Compare a fingerprint with the one your server's operator publishes. Operators can print it with the command in the server README.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = 24.dp, vertical = 12.dp),
                )
            }
        }
    }

    forget?.let { hostKey ->
        AlertDialog(
            onDismissRequest = { forget = null },
            title = { Text("Forget this server's key?") },
            text = { Text("The next connection to ${hostKey.removeSuffix(":443")} will record whatever key it presents.") },
            confirmButton = {
                TextButton(onClick = {
                    conn.forget(hostKey)
                    forget = null
                }) { Text("Forget") }
            },
            dismissButton = { TextButton(onClick = { forget = null }) { Text("Cancel") } },
        )
    }
    trust?.let { (hostKey, pin) -> ConfirmTrustDialog(hostKey, pin) { trust = null } }
}

/**
 * Shown over the whole app as soon as a pinned server presents a different key. Not in a decoy session: the pins are the
 * real profile's (and so is the decision), so the question waits for the real profile.
 */
@Composable
fun PinMismatchDialog() {
    val session by Graph.session.collectAsState()
    if (session?.decoy == true) {
        return
    }
    val m by NetPrefs.mismatch.collectAsState()
    var confirm by remember { mutableStateOf<PinMismatch?>(null) }
    m?.let { mismatch ->
        if (confirm == null) {
            val host = mismatch.hostKey.removeSuffix(":443")
            AlertDialog(
                onDismissRequest = { },
                title = { Text("This server's identity changed") },
                text = {
                    Column {
                        Text(
                            "GoldfishSend stopped connecting to $host because its key isn't the one it remembered. Nothing was sent.\n\n" +
                                "This happens when the server's operator replaces the key, but it can also mean someone is " +
                                "intercepting your connection. Only trust the new key if the operator confirms the change.",
                        )
                        Spacer(Modifier.height(12.dp))
                        Text("Remembered", style = MaterialTheme.typography.labelMedium)
                        for (e in mismatch.expected) {
                            Text(PinPolicy.displayFingerprint(e), fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
                        }
                        Spacer(Modifier.height(8.dp))
                        Text("Now", style = MaterialTheme.typography.labelMedium)
                        Text(PinPolicy.displayFingerprint(mismatch.presented), fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
                    }
                },
                confirmButton = { TextButton(onClick = { NetPrefs.keepBlocked(mismatch.hostKey, mismatch.presented) }) { Text("Keep blocked") } },
                dismissButton = { TextButton(onClick = { confirm = mismatch }) { Text("Trust new key") } },
            )
        }
    }
    confirm?.let { c -> ConfirmTrustDialog(c.hostKey, c.presented) { confirm = null } }
}

@Composable
private fun ConfirmTrustDialog(hostKey: String, pin: String, onDone: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDone,
        title = { Text("Trust the new key?") },
        text = {
            Text(
                "Only continue if ${hostKey.removeSuffix(":443")}'s operator told you the key changed and the fingerprint matches:\n\n" +
                    PinPolicy.displayFingerprint(pin),
            )
        },
        confirmButton = {
            TextButton(onClick = {
                NetPrefs.trustNewKey(hostKey, pin)
                Graph.resetHttp()
                onDone()
            }) { Text("Trust") }
        },
        dismissButton = { TextButton(onClick = onDone) { Text("Cancel") } },
    )
}
