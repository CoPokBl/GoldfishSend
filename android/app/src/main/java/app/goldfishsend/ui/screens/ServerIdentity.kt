package app.goldfishsend.ui.screens

import androidx.activity.compose.LocalActivity
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import app.goldfishsend.core.Graph
import app.goldfishsend.core.Mailboxes
import app.goldfishsend.core.Session
import app.goldfishsend.core.launchSafe
import app.goldfishsend.net.Gateway
import app.goldfishsend.ui.components.blockWhenObscured
import app.goldfishsend.ui.components.rememberReAuth

/** Shared explanation for a server whose identity key changed. */
const val SERVER_IDENTITY_EXPLANATION =
    "This can mean the server was replaced, or that someone is intercepting your connection. Nothing was sent to it. " +
        "Only trust the new identity if the server's operator confirms the change and the fingerprint matches."

/** Remembered and new fingerprints, for comparing by eye. */
@Composable
fun FingerprintPair(remembered: String?, now: String) {
    Column {
        if (remembered != null) {
            Text("Remembered", style = MaterialTheme.typography.labelMedium)
            Text(Gateway.displayFingerprint(remembered), fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
            Spacer(Modifier.height(8.dp))
        }
        Text("Now", style = MaterialTheme.typography.labelMedium)
        Text(Gateway.displayFingerprint(now), fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
    }
}

/**
 * Shown over the app when our own server presents a different identity key. "Not now" hides it for this key until the app
 * restarts; the Security tab keeps a non-dismissible alert, and the app doesn't use the new key until the user trusts it.
 */
@Composable
fun ServerIdentityChangedDialog(s: Session) {
    val version by Graph.prefs.version.collectAsState()
    @Suppress("UNUSED_EXPRESSION") version
    val presented = Graph.prefs.serverKeyChanged ?: return
    if (s.decoy) {
        return
    }
    if (ServerIdentityState.snoozed == presented) {
        return
    }
    val activity = LocalActivity.current as? FragmentActivity ?: return
    val reauth = rememberReAuth(s, activity)
    AlertDialog(
        onDismissRequest = { },
        title = { Text("Your server's identity changed") },
        text = {
            Column {
                Text(SERVER_IDENTITY_EXPLANATION)
                Spacer(Modifier.height(12.dp))
                FingerprintPair(Graph.prefs.serverKey, presented)
            }
        },
        confirmButton = {
            TextButton(onClick = { ServerIdentityState.snoozed = presented }) { Text("Not now") }
        },
        dismissButton = {
            TextButton(
                onClick = {
                    reauth.require("Trusting a new server identity.") {
                        s.scope.launchSafe { Mailboxes.trustNewServerKey(s, presented) }
                    }
                },
                modifier = Modifier.blockWhenObscured(),
            ) { Text("Trust new identity") }
        },
    )
}

/** Process-wide "not now" for the dialog, so it doesn't reappear on every screen change. The Security tab reopens it. */
object ServerIdentityState {
    var snoozed by mutableStateOf<String?>(null)
}
