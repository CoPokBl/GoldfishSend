package app.goldfishsend.security

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.selection.selectable
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import app.goldfishsend.core.Graph
import app.goldfishsend.core.PanicResponse
import app.goldfishsend.core.Session
import app.goldfishsend.ui.components.blockWhenObscured
import app.goldfishsend.ui.components.rememberReAuth
import app.goldfishsend.ui.theme.GoldfishTheme
import kotlinx.coroutines.launch

/**
 * PanicKit responder (https://guardianproject.info/code/panickit/). A trigger app (for example Ripple) lists GoldfishSend
 * as a responder.
 *
 * - CONNECT: the trigger app asks to be trusted. The user approves it here and picks the response. Only the approved
 *   package may later cause anything destructive. Its identity comes from getCallingActivity(), which the trigger app
 *   can't spoof because it has to start us with startActivityForResult. This changes the same settings as the panic
 *   section of Settings, so it's guarded the same way: only while the app is unlocked, after confirming it's the user
 *   ([rememberReAuth]), with tapjacking protection, and in a decoy session only the decoy's own settings are shown or
 *   changed.
 * - TRIGGER: always locks (harmless, so any trigger may cause it). Erasing happens only if the caller is the approved
 *   trigger app and the user chose an erasing response.
 * - DISCONNECT: the approved app removes itself, while the app is unlocked (a locked GoldfishSend changes nothing, and a
 *   decoy only its own copy). Ignoring it is harmless: a trigger app doesn't send to a responder it has disconnected.
 *
 * Nothing happens unless the user has set a response (OFF by default). No permissions are needed.
 *
 * Connecting and disconnecting change the open profile's settings: while a decoy session is open, the decoy's own copy,
 * so a coercer can't quietly disarm (or re-point) the real profile's panic response. A trigger always acts on the real
 * profile's settings.
 */
class PanicResponderActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (Graph.uiPrefs.screenshotProtection) {
            window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
        val caller = callingActivity?.packageName
        when (intent?.action) {
            ACTION_TRIGGER -> {
                trigger(caller)
                finishAndRemoveTask()
            }
            ACTION_DISCONNECT -> lifecycleScope.launch {
                // The open profile's settings: in a decoy, only the decoy's own copy changes.
                val s = Graph.session.value ?: Graph.tryAutoUnlock()
                if (s != null && caller != null && caller == s.prefs.panicTrigger) {
                    s.prefs.panicTrigger = null
                    setResult(RESULT_OK)
                }
                finish()
            }
            ACTION_CONNECT -> connect(caller)
            else -> finish()
        }
    }

    private fun trigger(caller: String?) {
        val prefs = Graph.prefs
        val response = prefs.panicResponse
        if (response == PanicResponse.OFF) {
            return
        }
        Graph.lock()
        val trusted = caller != null && caller == prefs.panicTrigger
        if (!trusted) {
            return
        }
        when (response) {
            PanicResponse.WIPE_MESSAGES -> Wiper.wipeMessages()
            PanicResponse.WIPE_EVERYTHING -> Wiper.wipeEverything(applicationContext)
            else -> Unit
        }
    }

    private fun connect(caller: String?) {
        if (caller == null) {
            // Not started with startActivityForResult, so we can't tell who's asking.
            finish()
            return
        }
        val label = runCatching { packageManager.getApplicationLabel(packageManager.getApplicationInfo(caller, 0)).toString() }
            .getOrDefault(caller)
        lifecycleScope.launch {
            // Without an app lock a cold start hasn't opened the database yet. With one, nothing is opened here.
            val s = Graph.session.value ?: Graph.tryAutoUnlock()
            setContent {
                val p = s?.prefs ?: Graph.prefs
                GoldfishTheme(p.themeMode, p.amoled, p.dynamicColor) {
                    // Connecting changes the open profile's settings, so it needs the app unlocked.
                    if (s == null) {
                        UnlockFirst(label)
                    } else {
                        Connect(s, caller, label)
                    }
                }
            }
        }
    }

    @Composable
    private fun UnlockFirst(label: String) {
        AlertDialog(
            onDismissRequest = ::cancel,
            title = { Text("Unlock GoldfishSend first") },
            text = { Text("To let $label trigger GoldfishSend, unlock GoldfishSend, then connect it again from $label.") },
            confirmButton = { TextButton(onClick = ::cancel) { Text("OK") } },
        )
    }

    @Composable
    private fun Connect(s: Session, caller: String, label: String) {
        val reauth = rememberReAuth(s, this)
        val values = listOf(PanicResponse.LOCK, PanicResponse.WIPE_MESSAGES, PanicResponse.WIPE_EVERYTHING)
        val options = listOf("Lock GoldfishSend", "Lock and erase all messages", "Erase everything")
        // The open profile's own setting: a decoy's copy never shows the real one.
        var choice by remember { mutableStateOf(preselect(s.prefs.panicResponse)) }
        var asking by remember { mutableStateOf(true) }
        if (!asking) {
            return
        }
        AlertDialog(
            onDismissRequest = ::cancel,
            title = { Text("Let $label trigger GoldfishSend?") },
            text = {
                Column {
                    for ((v, text) in values.zip(options)) {
                        // Guarded too: an overlay mustn't pick a different response than the one the user sees.
                        Row(
                            Modifier
                                .fillMaxWidth()
                                .blockWhenObscured()
                                .selectable(selected = v == choice, role = Role.RadioButton) { choice = v }
                                .padding(vertical = 10.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            RadioButton(selected = v == choice, onClick = null)
                            Spacer(Modifier.width(16.dp))
                            Text(text, style = MaterialTheme.typography.bodyLarge)
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        asking = false
                        reauth.require("Connecting a panic app.", cancel = ::cancel) {
                            // A decoy session changes only its own copy, as the panic section of its Settings does.
                            s.prefs.panicTrigger = caller
                            s.prefs.panicResponse = choice
                            setResult(RESULT_OK)
                            finish()
                        }
                    },
                    modifier = Modifier.blockWhenObscured(),
                ) { Text("Allow") }
            },
            dismissButton = { TextButton(onClick = ::cancel) { Text("Cancel") } },
        )
    }

    private fun cancel() {
        setResult(RESULT_CANCELED)
        finish()
    }

    companion object {
        const val ACTION_TRIGGER = "info.guardianproject.panic.action.TRIGGER"
        const val ACTION_CONNECT = "info.guardianproject.panic.action.CONNECT"
        const val ACTION_DISCONNECT = "info.guardianproject.panic.action.DISCONNECT"

        /** The response first selected: the open profile's current one ([current]), or Lock while it's off. */
        internal fun preselect(current: PanicResponse): PanicResponse =
            if (current == PanicResponse.OFF) PanicResponse.LOCK else current
    }
}
