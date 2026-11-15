package app.goldfishsend.ui.screens

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Fingerprint
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledTonalIconButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import app.goldfishsend.R
import app.goldfishsend.core.Graph
import app.goldfishsend.security.AppLock
import app.goldfishsend.security.UnlockResult
import app.goldfishsend.ui.components.FieldKind
import app.goldfishsend.ui.components.SecureTextField
import app.goldfishsend.ui.components.biometricAvailable
import app.goldfishsend.ui.components.promptBiometric
import app.goldfishsend.ui.components.promptScreenLock
import app.goldfishsend.ui.components.PinBuffer
import app.goldfishsend.ui.components.PinPad
import app.goldfishsend.ui.components.ConfirmDialog
import android.view.inputmethod.EditorInfo
import kotlinx.coroutines.launch
import androidx.activity.compose.LocalActivity
import app.goldfishsend.ui.ContentReady

@Composable
fun LockScreen() {
    val activity = LocalActivity.current as FragmentActivity
    val scope = rememberCoroutineScope()
    var pass by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val vault = Graph.vault
    val screenLock = vault.hasScreenLock
    val pinMode = !screenLock && vault.secretIsPin
    val pin = remember { PinBuffer() }
    var keyLost by remember { mutableStateOf(false) }
    var confirmReset by remember { mutableStateOf(false) }
    val bioEnabled = !screenLock && Graph.prefs.biometricUnlock && vault.hasBiometric && biometricAvailable(activity)

    fun tryScreenLock() {
        val cipher = try {
            vault.screenLockDecryptCipher()
        } catch (e: Exception) {
            error = "Your phone's secure storage isn't available right now. Try again in a moment."
            return
        } ?: run {
            keyLost = true
            return
        }
        promptScreenLock(activity, "Unlock GoldfishSend", cipher, onSuccess = { c ->
            val mk = vault.unwrapWithScreenLock(c)
            if (mk != null) {
                busy = true
                scope.launch { AppLock.unlockWithMasterKey(mk) }
            } else {
                error = "Couldn't unlock. Try again."
            }
        }, onError = { msg -> if (msg != null) error = msg })
    }

    fun tryBiometric() {
        val cipher = Graph.vault.biometricDecryptCipher() ?: run {
            error = "Fingerprint unlock was reset. Use your passphrase."
            return
        }
        promptBiometric(activity, "Unlock GoldfishSend", cipher, onSuccess = { c ->
            val mk = Graph.vault.unwrapWithBiometric(c)
            if (mk != null) {
                busy = true
                scope.launch { AppLock.unlockWithMasterKey(mk) }
            }
        }, onError = { msg -> if (msg != null) error = msg })
    }

    fun submit() {
        if ((if (pinMode) pin.length == 0 else pass.isEmpty()) || busy) {
            return
        }
        busy = true
        error = null
        val chars = if (pinMode) pin.take() else pass.toCharArray()
        pass = ""
        scope.launch {
            when (val r = AppLock.unlock(chars)) {
                UnlockResult.Ok, UnlockResult.Wiped -> Unit
                is UnlockResult.Wrong -> {
                    val what = if (pinMode) "PIN" else "passphrase"
                    error = if (r.attemptsLeft != null && r.attemptsLeft <= 3) {
                        "Wrong $what. ${r.attemptsLeft} attempt${if (r.attemptsLeft == 1) "" else "s"} left before everything is erased."
                    } else {
                        "Wrong $what"
                    }
                    busy = false
                }
                UnlockResult.DeviceLocked -> {
                    error = "Unlock your phone first."
                    busy = false
                }
            }
        }
    }

    ContentReady()
    LaunchedEffect(Unit) {
        when {
            screenLock -> tryScreenLock()
            bioEnabled -> tryBiometric()
        }
    }

    Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        Column(
            Modifier
                .fillMaxSize()
                .safeDrawingPadding()
                .imePadding()
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
        ) {
            Box(
                Modifier
                    .size(96.dp)
                    .background(MaterialTheme.colorScheme.primaryContainer, CircleShape),
                contentAlignment = Alignment.Center,
            ) { Image(painterResource(R.drawable.ic_launcher_foreground), null, Modifier.size(130.dp)) }
            Spacer(Modifier.height(24.dp))
            Text("GoldfishSend is locked", style = MaterialTheme.typography.headlineSmall)
            Spacer(Modifier.height(24.dp))
            if (screenLock) {
                Text(
                    if (keyLost) {
                        "Your phone's screen lock was removed or reset, so the key protecting GoldfishSend no longer exists. Your chats can't be recovered."
                    } else {
                        "Use your phone's screen lock to open GoldfishSend."
                    },
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center,
                )
                Spacer(Modifier.height(8.dp))
                Text(error ?: "", color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium, textAlign = TextAlign.Center)
                Spacer(Modifier.height(16.dp))
                if (keyLost) {
                    Button(onClick = { confirmReset = true }, modifier = Modifier.fillMaxWidth().height(52.dp)) { Text("Start over") }
                } else {
                    Button(onClick = ::tryScreenLock, enabled = !busy, modifier = Modifier.fillMaxWidth().height(52.dp)) {
                        if (busy) {
                            CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary)
                        } else {
                            Text("Unlock")
                        }
                    }
                }
            } else if (pinMode) {
                Text(error ?: "Enter your PIN", color = if (error != null) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant, textAlign = TextAlign.Center)
                Spacer(Modifier.height(16.dp))
                // The duress PIN may be shorter than the real PIN, so the pad accepts anything 4 digits or longer.
                PinPad(pin, onSubmit = ::submit, scrambled = Graph.prefs.scramblePinPad, minLength = 4, enabled = !busy)
            } else {
            SecureTextField(
                pass, { pass = it; error = null },
                Modifier.fillMaxWidth(),
                hint = "Passphrase",
                kind = FieldKind.PASSWORD,
                imeAction = EditorInfo.IME_ACTION_GO,
                onImeAction = ::submit,
                requestFocus = !bioEnabled,
            )
            Spacer(Modifier.height(8.dp))
            Text(
                error ?: "",
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodyMedium,
                textAlign = TextAlign.Center,
                modifier = Modifier.height(40.dp),
            )
            Button(onClick = ::submit, enabled = !busy && pass.isNotEmpty(), modifier = Modifier.fillMaxWidth().height(52.dp)) {
                if (busy) {
                    CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary)
                } else {
                    Text("Unlock")
                }
            }
            }
            if (bioEnabled) {
                Spacer(Modifier.height(16.dp))
                FilledTonalIconButton(onClick = ::tryBiometric, modifier = Modifier.size(56.dp)) {
                    Icon(Icons.Rounded.Fingerprint, "Unlock with fingerprint")
                }
            }
        }
    }
    if (confirmReset) {
        ConfirmDialog(
            "Start over?",
            "Everything in GoldfishSend is erased and you'll set it up again. Your contacts will need to add you again.",
            "Erase and start over", true, { confirmReset = false },
        ) { app.goldfishsend.security.Wiper.wipeEverything(Graph.app) }
    }
}

/** Shown briefly while a passphrase-less install unlocks itself with the device key. */
@Composable
fun UnlockingSplash() {
    var failed by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) {
        val s = Graph.tryAutoUnlock()
        if (s == null) {
            failed = true
        } else {
            AppLock.afterUnlock(s)
        }
    }
    if (failed) {
        ContentReady()
    }
    Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            if (failed) {
                Text("Unlock your phone to continue", style = MaterialTheme.typography.titleMedium)
            } else {
                CircularProgressIndicator()
            }
        }
    }
}
