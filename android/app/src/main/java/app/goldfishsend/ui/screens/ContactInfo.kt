package app.goldfishsend.ui.screens

import androidx.compose.material.icons.rounded.Dns
import androidx.compose.material.icons.rounded.VisibilityOff
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material.icons.rounded.Block
import androidx.compose.material.icons.rounded.DeleteSweep
import androidx.compose.material.icons.rounded.Edit
import androidx.compose.material.icons.rounded.Timer
import androidx.compose.material.icons.rounded.Verified
import androidx.compose.material.icons.rounded.VerifiedUser
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import app.goldfishsend.core.Graph
import app.goldfishsend.core.Messenger
import app.goldfishsend.core.Session
import app.goldfishsend.core.TIMER_CHOICES
import app.goldfishsend.core.timerLabel
import app.goldfishsend.ui.components.Avatar
import app.goldfishsend.ui.components.ChoiceDialog
import app.goldfishsend.ui.components.ConfirmDialog
import app.goldfishsend.ui.components.SecureTextField
import app.goldfishsend.ui.components.SettingRow
import app.goldfishsend.ui.components.SwitchRow
import app.goldfishsend.ui.components.rememberQuery
import androidx.activity.compose.LocalActivity
import androidx.fragment.app.FragmentActivity
import app.goldfishsend.ui.components.blockWhenObscured
import app.goldfishsend.ui.components.rememberReAuth
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import app.goldfishsend.ui.components.BusyDialog
import app.goldfishsend.ui.components.ProgressButton
import app.goldfishsend.ui.components.ProgressRow
import app.goldfishsend.ui.components.rememberWork
import kotlinx.coroutines.launch
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.fingerprint.NumericFingerprintGenerator

/** Signal-style safety number: 60 digits, identical on both phones. */
internal fun safetyNumber(s: Session, remote: ByteArray): String? = runCatching {
    val local = s.signal.identityKeyPair.publicKey
    val remoteKey = IdentityKey(remote)
    NumericFingerprintGenerator(5200)
        .createFor(2, local.serialize(), local, remoteKey.serialize(), remoteKey)
        .displayableFingerprint.displayText
}.getOrNull()

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ContactInfoScreen(s: Session, contactId: Long, back: () -> Unit, onDeleted: () -> Unit) {
    val scope = rememberCoroutineScope()
    val contact by rememberQuery(s, contactId) { it.repo.contact(contactId) }
    // Null while it's computed (it takes a moment), empty when there's nothing to compare yet.
    val safety by rememberQuery(s, contact?.identityKey?.size) { q -> contact?.identityKey?.let { safetyNumber(q, it) }.orEmpty() }
    var rename by remember { mutableStateOf(false) }
    var timer by remember { mutableStateOf(false) }
    var confirmDelete by remember { mutableStateOf(false) }
    var confirmClear by remember { mutableStateOf(false) }
    var confirmAccept by remember { mutableStateOf(false) }
    val activity = LocalActivity.current as FragmentActivity
    val reauth = rememberReAuth(s, activity)
    val trusting = rememberWork()
    val accepting = rememberWork()
    val erasing = rememberWork()
    val deleting = rememberWork()
    val c = contact ?: return
    val newSafety by rememberQuery(s, c.pendingIdentity?.size) { q -> c.pendingIdentity?.let { safetyNumber(q, it) } }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { },
                navigationIcon = { IconButton(onClick = back) { Icon(Icons.AutoMirrored.Rounded.ArrowBack, "Back") } },
            )
        },
    ) { pad ->
        Column(
            Modifier
                .padding(pad)
                .fillMaxSize()
                .verticalScroll(rememberScrollState()),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Avatar(c.name, c.id, 96.dp)
            Spacer(Modifier.height(16.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(c.name, style = MaterialTheme.typography.headlineSmall)
                IconButton(onClick = { rename = true }) { Icon(Icons.Rounded.Edit, "Rename") }
            }
            AssistChip(
                onClick = {},
                label = {
                    Text(
                        when {
                            c.pendingIdentity != null -> "Safety number changed"
                            c.verified -> "Verified"
                            else -> "Not verified"
                        },
                    )
                },
                leadingIcon = {
                    Icon(
                        if (c.verified) Icons.Rounded.Verified else Icons.Rounded.VerifiedUser, null,
                        tint = if (c.verified) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                },
            )
            Spacer(Modifier.height(16.dp))

            c.pendingServerKey?.let { presented ->
                Surface(
                    color = MaterialTheme.colorScheme.errorContainer,
                    shape = MaterialTheme.shapes.large,
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
                ) {
                    Column(Modifier.padding(20.dp)) {
                        Text("Can't verify ${c.name}'s server", style = MaterialTheme.typography.titleMedium)
                        Spacer(Modifier.height(6.dp))
                        Text(
                            "Its identity key changed. $SERVER_IDENTITY_EXPLANATION Messages to ${c.name} wait until this is sorted " +
                                "out. It also resolves by itself if ${c.name} tells your app about the new key.",
                            style = MaterialTheme.typography.bodyMedium,
                        )
                        Spacer(Modifier.height(12.dp))
                        FingerprintPair(c.outServerKey, presented)
                        Spacer(Modifier.height(12.dp))
                        ProgressButton(
                            onClick = {
                                reauth.require("Trusting a new server identity.") {
                                    trusting.run {
                                        withContext(Dispatchers.IO) {
                                            s.repo.trustPendingServerKey(contactId, presented)
                                            s.db.notifyChanged()
                                            app.goldfishsend.core.Outbox.kick()
                                        }
                                    }
                                }
                            },
                            busy = trusting.busy,
                            modifier = Modifier.blockWhenObscured(),
                        ) { Text("Trust new identity") }
                    }
                }
                Spacer(Modifier.height(12.dp))
            }

            if (c.pendingIdentity != null) {
                Surface(
                    color = MaterialTheme.colorScheme.errorContainer,
                    shape = MaterialTheme.shapes.large,
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
                ) {
                    Column(Modifier.padding(20.dp)) {
                        Text("${c.name}'s safety number changed", style = MaterialTheme.typography.titleMedium)
                        Spacer(Modifier.height(6.dp))
                        Text(
                            "This usually means they reinstalled GoldfishSend or got a new phone, but it could also mean someone " +
                                "is pretending to be them. Messages are paused. Compare the new number below with ${c.name}, in person " +
                                "or on a call, before accepting.",
                            style = MaterialTheme.typography.bodyMedium,
                        )
                        Spacer(Modifier.height(12.dp))
                        if (newSafety == null) {
                            ProgressRow(true, "Calculating the new safety number…")
                        }
                        newSafety?.chunked(5)?.chunked(4)?.forEach { row ->
                            Row(horizontalArrangement = Arrangement.spacedBy(14.dp)) {
                                for (g in row) {
                                    Text(g, fontFamily = FontFamily.Monospace, fontSize = 16.sp, letterSpacing = 1.sp)
                                }
                            }
                        }
                        Spacer(Modifier.height(12.dp))
                        ProgressButton(onClick = { confirmAccept = true }, busy = accepting.busy) { Text("Accept new safety number") }
                    }
                }
                Spacer(Modifier.height(12.dp))
            }

            Surface(
                color = MaterialTheme.colorScheme.surfaceContainer,
                shape = MaterialTheme.shapes.large,
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
            ) {
                Column(Modifier.padding(20.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                    Text("Safety number", style = MaterialTheme.typography.titleMedium)
                    Spacer(Modifier.height(4.dp))
                    Text(
                        "Compare this with the number on ${c.name}'s phone. If they match, your chat is private.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        textAlign = TextAlign.Center,
                    )
                    Spacer(Modifier.height(12.dp))
                    val digits = safety?.chunked(5).orEmpty()
                    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        for (row in digits.chunked(4)) {
                            Row(horizontalArrangement = Arrangement.spacedBy(14.dp)) {
                                for (g in row) {
                                    Text(g, fontFamily = FontFamily.Monospace, fontSize = 18.sp, letterSpacing = 1.sp)
                                }
                            }
                        }
                    }
                    if (safety == null) {
                        ProgressRow(true, "Calculating…")
                    } else if (safety == "") {
                        Text("Available once you've exchanged a message.", style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
            Spacer(Modifier.height(8.dp))
            Column(Modifier.fillMaxWidth()) {
                SwitchRow(
                    "Mark as verified",
                    "Only after comparing safety numbers in person or over a call",
                    Icons.Rounded.Verified,
                    checked = c.verified,
                    onChange = { v -> scope.launch(Dispatchers.IO) { s.repo.setVerified(contactId, v); s.db.notifyChanged() } },
                )
                val hiddenOn by rememberQuery(s) { q -> !q.decoy && q.repo.kvString(app.goldfishsend.security.AppLock.KV_HIDDEN_ON) == "1" }
                if (hiddenOn == true) {
                    SwitchRow(
                        "Hide this chat",
                        "Keeps it out of the chat list until you enter your hidden-chats PIN",
                        Icons.Rounded.VisibilityOff,
                        checked = c.hidden,
                        onChange = { v -> scope.launch(Dispatchers.IO) { s.repo.setHidden(contactId, v); s.db.notifyChanged() } },
                    )
                }
                // Their server is their own choice: showing it lets you notice an unexpected one.
                SettingRow(
                    "Their server",
                    (c.outServer?.let { runCatching { java.net.URI(it).host }.getOrNull() } ?: "Not known yet") +
                        (c.outServerKey?.let { "\nIdentity " + app.goldfishsend.net.Gateway.displayFingerprint(it) } ?: ""),
                    Icons.Rounded.Dns,
                )
                SettingRow(
                    "Disappearing messages",
                    timerLabel(c.timerSecs),
                    Icons.Rounded.Timer,
                    onClick = { timer = true },
                )
                SettingRow("Clear chat", "Delete all messages in this chat from this phone", Icons.Rounded.DeleteSweep, onClick = { confirmClear = true })
                SettingRow("Block and delete", "Removes this contact. They won't be able to message you.", Icons.Rounded.Block, onClick = { confirmDelete = true })
            }
            Spacer(Modifier.height(32.dp))
        }
    }

    if (rename) {
        var name by remember { mutableStateOf(c.name) }
        AlertDialog(
            onDismissRequest = { rename = false },
            title = { Text("Name") },
            text = { SecureTextField(name, { name = it }, Modifier.fillMaxWidth(), hint = "Name") },
            confirmButton = {
                TextButton(enabled = name.isNotBlank(), onClick = {
                    rename = false
                    scope.launch(Dispatchers.IO) { s.repo.renameContact(contactId, name.trim().take(64)); s.db.notifyChanged() }
                }) { Text("Save") }
            },
            dismissButton = { TextButton(onClick = { rename = false }) { Text("Cancel") } },
        )
    }
    if (timer) {
        ChoiceDialog("Disappearing messages", TIMER_CHOICES.map { it to timerLabel(it) }, c.timerSecs, { timer = false }) { secs ->
            scope.launch(Dispatchers.IO) { Messenger.setTimer(s, contactId, secs) }
        }
    }
    if (confirmClear) {
        ConfirmDialog("Clear chat?", "All messages in this chat will be permanently erased from this phone.", "Clear", true, { confirmClear = false }) {
            erasing.run {
                withContext(Dispatchers.IO) { Messenger.clearChat(s, contactId) }
            }
        }
    }
    if (confirmAccept) {
        ConfirmDialog(
            "Accept the new safety number?",
            "Only do this if you've confirmed with ${c.name} that the new number is theirs. They'll be marked as not verified.",
            "Accept", false, { confirmAccept = false },
        ) { accepting.run { withContext(Dispatchers.IO) { app.goldfishsend.core.Messenger.acceptIdentityChange(s, contactId) } } }
    }
    if (confirmDelete) {
        ConfirmDialog(
            "Block and delete ${c.name}?",
            "The chat and all its messages will be erased, and ${c.name} won't be able to reach you anymore.",
            "Block and delete", true, { confirmDelete = false },
        ) {
            deleting.run {
                withContext(Dispatchers.IO) { Messenger.deleteContact(s, contactId) }
                onDeleted()
            }
        }
    }
    BusyDialog(erasing.busy, "Clearing the chat…")
    BusyDialog(deleting.busy, "Deleting ${c.name}…", hint = "Telling the server to delete their inbox.")
}
