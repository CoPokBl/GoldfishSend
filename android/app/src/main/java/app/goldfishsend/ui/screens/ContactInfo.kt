package app.goldfishsend.ui.screens

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
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.fingerprint.NumericFingerprintGenerator

/** Signal-style safety number: 60 digits, identical on both phones. */
private fun safetyNumber(s: Session, remote: ByteArray): String? = runCatching {
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
    val safety by rememberQuery(s, contact?.identityKey?.size) { q -> contact?.identityKey?.let { safetyNumber(q, it) } }
    var rename by remember { mutableStateOf(false) }
    var timer by remember { mutableStateOf(false) }
    var confirmDelete by remember { mutableStateOf(false) }
    var confirmClear by remember { mutableStateOf(false) }
    val c = contact ?: return

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
                label = { Text(if (c.verified) "Verified" else "Not verified") },
                leadingIcon = {
                    Icon(
                        if (c.verified) Icons.Rounded.Verified else Icons.Rounded.VerifiedUser, null,
                        tint = if (c.verified) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                },
            )
            Spacer(Modifier.height(16.dp))

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
            scope.launch(Dispatchers.IO) { s.repo.clearConversation(contactId); s.db.notifyChanged() }
        }
    }
    if (confirmDelete) {
        ConfirmDialog(
            "Block and delete ${c.name}?",
            "The chat and all its messages will be erased, and ${c.name} won't be able to reach you anymore.",
            "Block and delete", true, { confirmDelete = false },
        ) {
            scope.launch(Dispatchers.IO) {
                Messenger.deleteContact(s, contactId)
                launch(Dispatchers.Main) { onDeleted() }
            }
        }
    }
}
