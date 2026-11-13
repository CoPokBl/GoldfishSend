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

/**
 * A PIN dialog on GoldfishSend's own keypad. With [confirm], the PIN must be entered twice. [validate] may reject a PIN
 * by returning a message (for example "Can't be the same as your app PIN"). [onDone] receives a CharArray it must wipe.
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
    validate: (CharArray) -> String? = { null },
    onDone: (CharArray) -> Unit,
) {
    val pin = remember { PinBuffer() }
    var first by remember { mutableStateOf<CharArray?>(null) }
    var error by remember { mutableStateOf<String?>(null) }

    fun submit() {
        val entered = pin.take()
        if (!confirm) {
            val problem = validate(entered)
            if (problem != null) {
                entered.fill('\u0000')
                error = problem
            } else {
                onDone(entered)
            }
            return
        }
        val f = first
        if (f == null) {
            val problem = validate(entered)
            if (problem != null) {
                entered.fill('\u0000')
                error = problem
                return
            }
            first = entered
            error = null
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
            first?.fill('\u0000')
            onDismiss()
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
                PinPad(pin, onSubmit = ::submit, scrambled = Graph.prefs.scramblePinPad, minLength = minLength)
            }
        },
        confirmButton = {},
        dismissButton = {
            if (onRemove != null && removeLabel != null) {
                TextButton(onClick = onRemove) { Text(removeLabel, color = MaterialTheme.colorScheme.error) }
            }
            TextButton(onClick = {
                first?.fill('\u0000')
                onDismiss()
            }) { Text("Cancel") }
        },
    )
}
