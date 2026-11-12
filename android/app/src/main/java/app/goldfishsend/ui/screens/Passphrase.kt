package app.goldfishsend.ui.screens

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import app.goldfishsend.core.Graph
import app.goldfishsend.core.Session
import app.goldfishsend.ui.components.ConfirmDialog
import app.goldfishsend.ui.components.FieldKind
import app.goldfishsend.ui.components.SecureTextField
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Set, change or remove the app passphrase. MK never changes: only its wrapping does. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PassphraseScreen(s: Session, back: () -> Unit) {
    val scope = rememberCoroutineScope()
    val has = Graph.vault.hasPassphrase
    var pass by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var confirmRemove by remember { mutableStateOf(false) }

    fun save(newPass: CharArray?) {
        busy = true
        scope.launch {
            withContext(Dispatchers.Default) {
                val mk = s.masterKeyCopy()
                Graph.vault.changePassphrase(mk, newPass)
                mk.fill(0)
                newPass?.fill('\u0000')
            }
            if (newPass == null) {
                Graph.prefs.biometricUnlock = false
            }
            back()
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(if (has) "Change passphrase" else "Set a passphrase") },
                navigationIcon = { IconButton(onClick = back) { Icon(Icons.AutoMirrored.Rounded.ArrowBack, "Back") } },
            )
        },
    ) { pad ->
        Column(
            Modifier
                .padding(pad)
                .fillMaxSize()
                .imePadding()
                .padding(24.dp),
        ) {
            Text(
                "Your passphrase is stretched with Argon2 and combined with a key locked inside your phone's secure hardware. " +
                    "Without it, your chats can't be decrypted, even by someone who copies the app's data.",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(20.dp))
            SecureTextField(pass, { pass = it }, Modifier.fillMaxWidth(), hint = "New passphrase", kind = FieldKind.PASSWORD)
            Spacer(Modifier.height(10.dp))
            SecureTextField(confirm, { confirm = it }, Modifier.fillMaxWidth(), hint = "Confirm passphrase", kind = FieldKind.PASSWORD)
            Spacer(Modifier.height(6.dp))
            Text(
                when {
                    confirm.isNotEmpty() && confirm != pass -> "Passphrases don't match"
                    pass.isNotEmpty() && pass.length < 6 -> "Use at least 6 characters. Longer is stronger."
                    else -> " "
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
            )
            Spacer(Modifier.height(16.dp))
            Button(
                enabled = !busy && pass.length >= 6 && pass == confirm,
                onClick = { save(pass.toCharArray().also { pass = ""; confirm = "" }) },
                modifier = Modifier.fillMaxWidth().height(52.dp),
            ) {
                if (busy) CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp) else Text("Save")
            }
            if (has) {
                Spacer(Modifier.height(8.dp))
                TextButton(onClick = { confirmRemove = true }, modifier = Modifier.fillMaxWidth()) {
                    Text("Remove passphrase", color = MaterialTheme.colorScheme.error)
                }
            }
        }
    }
    if (confirmRemove) {
        ConfirmDialog(
            "Remove passphrase?",
            "Anyone who can unlock your phone will be able to open GoldfishSend. Fingerprint unlock and the duress PIN are turned off too.",
            "Remove", true, { confirmRemove = false },
        ) { save(null) }
    }
}
