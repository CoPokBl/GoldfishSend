package app.goldfishsend.ui.components

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import app.goldfishsend.core.Graph
import androidx.compose.runtime.rememberCoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * A PIN dialog on GoldfishSend's own keypad. With [confirm], the PIN must be entered twice. [validate] may reject a PIN
 * by returning a message (for example "Can't be the same as your app PIN"); it runs off the main thread, since checks
 * against other PINs run Argon2, and the pad shows "Checking…" meanwhile. While [busy] (the caller is working with the
 * PIN), the pad shows [busyText] and takes no input. [onDone] receives a CharArray it must wipe.
 */
@Composable
fun PinEntryDialog(
    title: String,
    message: String,
    onDismiss: () -> Unit,
    minLength: Int = 6,
    confirm: Boolean = true,
    removeLabel: String? = null,
    onRemove: (() -> Unit)? = null,
    validate: (suspend (CharArray) -> String?)? = null,
    busy: Boolean = false,
    busyText: String = "Checking…",
    onDone: (CharArray) -> Unit,
) {
    val pin = remember { PinBuffer() }
    val scope = rememberCoroutineScope()
    var first by remember { mutableStateOf<CharArray?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var checking by remember { mutableStateOf(false) }
    val working = busy || checking

    /** Runs [validate] on [entered], then [then] if it passed. A rejected PIN is wiped. */
    fun validated(entered: CharArray, then: () -> Unit) {
        val v = validate ?: return then()
        checking = true
        scope.launch {
            val problem = withContext(Dispatchers.Default) { v(entered) }
            checking = false
            if (problem != null) {
                entered.fill('\u0000')
                error = problem
            } else {
                then()
            }
        }
    }

    fun submit() {
        if (working) {
            return
        }
        val entered = pin.take()
        if (!confirm) {
            validated(entered) { onDone(entered) }
            return
        }
        val f = first
        if (f == null) {
            validated(entered) {
                first = entered
                error = null
            }
        } else if (f.contentEquals(entered)) {
            f.fill('\u0000')
            first = null
            onDone(entered)
        } else {
            f.fill('\u0000')
            entered.fill('\u0000')
            first = null
            error = "The PINs didn't match. Try again."
        }
    }

    AlertDialog(
        onDismissRequest = {
            if (!working) {
                first?.fill('\u0000')
                onDismiss()
            }
        },
        title = { Text(title) },
        text = {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text(
                    error ?: if (first != null) "Enter it again to confirm." else message,
                    color = if (error != null) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center,
                )
                Spacer(Modifier.height(16.dp))
                PinPad(
                    pin, onSubmit = ::submit, scrambled = Graph.prefs.scramblePinPad, minLength = minLength,
                    busyText = if (working) (if (checking) "Checking…" else busyText) else null,
                )
            }
        },
        confirmButton = {},
        dismissButton = {
            if (onRemove != null && removeLabel != null) {
                TextButton(onClick = onRemove, enabled = !working) { Text(removeLabel, color = MaterialTheme.colorScheme.error) }
            }
            TextButton(onClick = {
                first?.fill('\u0000')
                onDismiss()
            }, enabled = !working) { Text("Cancel") }
        },
    )
}
