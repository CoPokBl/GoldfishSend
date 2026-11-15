package app.goldfishsend.ui.components

import android.app.KeyguardManager
import android.os.Build
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.Stable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import app.goldfishsend.core.Graph
import app.goldfishsend.core.Session
import app.goldfishsend.crypto.UnlockMethod
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Re-authentication before security-relevant changes (unlock method, duress PIN, erasing, panic response, connection
 * mode). Someone who picks up an unlocked phone can't quietly weaken GoldfishSend's protection.
 *
 * - App PIN or passphrase: the current secret, on GoldfishSend's own keypad (or the passphrase field).
 * - Phone screen lock, or no app lock: the system prompt (phone PIN, pattern, password or strong biometric). With no
 *   screen lock on the phone at all there's nothing to check against, so the change goes ahead.
 * - In a decoy session (opened with the duress PIN), the check passes, as it would for the real owner. The dialogs
 *   themselves refuse anything harmful.
 */
@Stable
class ReAuth internal constructor(
    private val s: Session,
    private val activity: FragmentActivity,
    private val scope: CoroutineScope,
) {
    internal var pending by mutableStateOf<(() -> Unit)?>(null)
    internal var onCancel: () -> Unit = {}
    internal var reason by mutableStateOf("")
    internal var error by mutableStateOf<String?>(null)
    internal var checking by mutableStateOf(false)

    fun require(why: String, cancel: () -> Unit = {}, action: () -> Unit) {
        if (s.decoy) {
            action()
            return
        }
        onCancel = cancel
        when (Graph.vault.unlockMethod) {
            UnlockMethod.APP_SECRET -> {
                reason = why
                error = null
                pending = action
            }
            else -> systemPrompt(why, cancel, action)
        }
    }

    internal fun cancel() {
        pending = null
        onCancel()
    }

    private fun systemPrompt(why: String, cancel: () -> Unit, action: () -> Unit) {
        val km = activity.getSystemService(KeyguardManager::class.java)
        if (!km.isDeviceSecure) {
            action()
            return
        }
        val prompt = BiometricPrompt(
            activity,
            ContextCompat.getMainExecutor(activity),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    action()
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    cancel()
                }
            },
        )
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Confirm it's you")
            .setSubtitle(why)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            info.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL)
        } else {
            @Suppress("DEPRECATION")
            info.setDeviceCredentialAllowed(true)
        }
        prompt.authenticate(info.build())
    }

    internal fun check(secret: CharArray) {
        val action = pending ?: return
        if (checking) {
            secret.fill('\u0000')
            return
        }
        checking = true
        scope.launch {
            val ok = withContext(Dispatchers.Default) {
                try {
                    Graph.vault.unlockWithPassphrase(secret)?.also { it.fill(0) } != null
                } catch (e: Exception) {
                    false
                } finally {
                    secret.fill('\u0000')
                }
            }
            checking = false
            if (pending !== action) {
                // Cancelled while the secret was being checked.
                return@launch
            }
            if (ok) {
                pending = null
                action()
            } else {
                error = "That's not right. Try again."
            }
        }
    }
}

@Composable
fun rememberReAuth(s: Session, activity: FragmentActivity): ReAuth {
    val scope = rememberCoroutineScope()
    val r = remember(s) { ReAuth(s, activity, scope) }
    ReAuthDialog(r)
    return r
}

@Composable
private fun ReAuthDialog(r: ReAuth) {
    if (r.pending == null) {
        return
    }
    if (Graph.vault.secretIsPin) {
        PinEntryDialog(
            "Confirm it's you",
            r.error ?: "${r.reason} Enter your app PIN.",
            onDismiss = { r.cancel() },
            minLength = 4,
            confirm = false,
            busy = r.checking,
        ) { pin -> r.check(pin) }
        return
    }
    var pass by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = { r.cancel() },
        title = { Text("Confirm it's you") },
        text = {
            Column {
                Text(r.error ?: "${r.reason} Enter your passphrase.", color = if (r.error != null) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant)
                Spacer(Modifier.height(12.dp))
                SecureTextField(pass, { pass = it }, Modifier.fillMaxWidth(), hint = "Passphrase", kind = FieldKind.PASSWORD)
            }
        },
        confirmButton = {
            ProgressButton(
                onClick = {
                    val chars = pass.toCharArray()
                    pass = ""
                    r.check(chars)
                },
                busy = r.checking,
                enabled = pass.isNotEmpty(),
                kind = ButtonKind.TEXT,
            ) { Text("Confirm") }
        },
        dismissButton = { TextButton(onClick = { r.cancel() }) { Text("Cancel") } },
    )
}
