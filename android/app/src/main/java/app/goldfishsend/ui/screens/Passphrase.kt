package app.goldfishsend.ui.screens

import androidx.compose.runtime.LaunchedEffect
import app.goldfishsend.ui.components.rememberReAuth
import androidx.activity.compose.LocalActivity
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import app.goldfishsend.core.Graph
import app.goldfishsend.core.Session
import app.goldfishsend.crypto.KeyVault
import app.goldfishsend.crypto.UnlockMethod
import app.goldfishsend.ui.components.ConfirmDialog
import app.goldfishsend.ui.components.FieldKind
import app.goldfishsend.ui.components.PinBuffer
import app.goldfishsend.ui.components.PinPad
import app.goldfishsend.ui.components.ProgressButton
import app.goldfishsend.ui.components.ProgressRow
import app.goldfishsend.ui.components.SecureTextField
import app.goldfishsend.ui.components.promptScreenLock
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private enum class Choice { NONE, SCREEN_LOCK, PIN, PASSPHRASE }

private enum class Step { CHOOSE, PIN_NEW, PIN_CONFIRM, PASSPHRASE }

/**
 * Chooses how GoldfishSend is unlocked. MK never changes, only how it's wrapped:
 * - No app lock: opens whenever the phone is unlocked.
 * - Phone screen lock: the system prompt (PIN, pattern, password, fingerprint). The OS handles it, so we never see it.
 * - App PIN: typed on GoldfishSend's own keypad, so the keyboard app never sees it. Supports the duress PIN and erasing.
 * - Passphrase (advanced): alphanumeric, typed with the system keyboard.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PassphraseScreen(s: Session, back: () -> Unit) {
    val activity = LocalActivity.current as FragmentActivity
    val scope = rememberCoroutineScope()
    val vault = Graph.vault
    val current = when (vault.unlockMethod) {
        UnlockMethod.NONE -> Choice.NONE
        UnlockMethod.SCREEN_LOCK -> Choice.SCREEN_LOCK
        UnlockMethod.APP_SECRET -> if (vault.secretIsPin) Choice.PIN else Choice.PASSPHRASE
    }
    val screenLockSupported = remember { vault.screenLockSupported() }
    var step by remember { mutableStateOf(Step.CHOOSE) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var confirmNone by remember { mutableStateOf(false) }
    var confirmScreenLock by remember { mutableStateOf(false) }
    val pin = remember { PinBuffer() }
    var firstPin by remember { mutableStateOf<CharArray?>(null) }
    var pass by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    // Reached from Settings and from the Security tab: either way, confirm it's the owner before anything changes.
    val reauth = rememberReAuth(s, activity)
    var authed by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) {
        reauth.require("Changing how GoldfishSend unlocks.", cancel = back) { authed = true }
    }
    // A change in progress finishes before leaving (it's crash-safe either way, but the result would go unseen).
    androidx.activity.compose.BackHandler(busy) { }

    /** Every change generates a new master key and rekeys the database (KeyVault: master-key rotation). */
    fun saveSecret(secret: CharArray?, isPin: Boolean) {
        if (s.decoy) {
            // Pretend: a decoy session must never change how the real data is protected.
            secret?.fill('\u0000')
            back()
            return
        }
        busy = true
        scope.launch {
            try {
                withContext(Dispatchers.Default) {
                    Graph.changeUnlock(s, if (secret == null) KeyVault.Target.None else KeyVault.Target.Secret(secret, isPin))
                }
                back()
            } catch (e: Exception) {
                busy = false
                error = "Couldn't change the unlock method. Nothing was changed. Try again."
            } finally {
                secret?.fill('\u0000')
            }
        }
    }

    fun enableScreenLock() {
        if (s.decoy) {
            back()
            return
        }
        val cipher = runCatching { vault.screenLockEncryptCipher() }.getOrElse {
            error = "Your phone's screen lock couldn't be used. Make sure a PIN, pattern or password is set."
            return
        }
        promptScreenLock(activity, "Confirm your screen lock", cipher, onSuccess = { c ->
            busy = true
            scope.launch {
                try {
                    withContext(Dispatchers.Default) { Graph.changeUnlock(s, KeyVault.Target.ScreenLock(c)) }
                    back()
                } catch (e: Exception) {
                    busy = false
                    error = "Couldn't switch to your screen lock. Nothing was changed. Try again."
                }
            }
        }, onError = { msg -> if (msg != null) error = msg })
    }

    fun pick(choice: Choice) {
        error = null
        when (choice) {
            Choice.NONE -> if (current != Choice.NONE) confirmNone = true
            Choice.SCREEN_LOCK -> if (current != Choice.SCREEN_LOCK) confirmScreenLock = true
            Choice.PIN -> step = Step.PIN_NEW
            Choice.PASSPHRASE -> step = Step.PASSPHRASE
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Unlock method") },
                navigationIcon = {
                    IconButton(enabled = !busy, onClick = {
                        if (step == Step.CHOOSE) back() else {
                            firstPin?.fill('\u0000')
                            firstPin = null
                            pin.clear()
                            step = Step.CHOOSE
                        }
                    }) { Icon(Icons.AutoMirrored.Rounded.ArrowBack, "Back") }
                },
            )
        },
    ) { pad ->
        Column(
            Modifier.padding(pad).fillMaxSize().imePadding().verticalScroll(rememberScrollState()).padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            if (authed) when (step) {
                Step.CHOOSE -> {
                    Option(
                        "No app lock", "GoldfishSend opens whenever your phone is unlocked.",
                        current == Choice.NONE, enabled = !busy,
                    ) { pick(Choice.NONE) }
                    Option(
                        "Phone screen lock",
                        if (screenLockSupported) {
                            "Use your phone's PIN, pattern, password or fingerprint. Your phone handles it, and GoldfishSend never sees it. " +
                                "Erasing after failed attempts and the duress PIN aren't available with this method."
                        } else {
                            "Needs Android 11 or newer and a screen lock set on your phone."
                        },
                        current == Choice.SCREEN_LOCK, enabled = screenLockSupported && !busy,
                    ) { pick(Choice.SCREEN_LOCK) }
                    Option(
                        "App PIN",
                        "Typed on GoldfishSend's own keypad, so your keyboard app never sees it. It also protects your data with " +
                            "its own key, and supports the duress PIN and erasing after failed attempts.",
                        current == Choice.PIN, enabled = !busy,
                    ) { pick(Choice.PIN) }
                    Option(
                        "Passphrase (advanced)",
                        "Letters and numbers, typed with your keyboard app. That's stronger than a PIN, but your keyboard sees what you type.",
                        current == Choice.PASSPHRASE, enabled = !busy,
                    ) { pick(Choice.PASSPHRASE) }
                    error?.let {
                        Spacer(Modifier.height(12.dp))
                        Text(it, color = MaterialTheme.colorScheme.error)
                    }
                    ProgressRow(busy, "Re-encrypting your data…", Modifier.fillMaxWidth(), hint = "This takes a few seconds.")
                }
                Step.PIN_NEW, Step.PIN_CONFIRM -> {
                    Text(
                        if (step == Step.PIN_NEW) "Choose a PIN of at least 6 digits" else "Enter the same PIN again",
                        style = MaterialTheme.typography.titleMedium,
                        textAlign = TextAlign.Center,
                    )
                    Spacer(Modifier.height(6.dp))
                    Text(error ?: "Longer is stronger.", color = if (error != null) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant)
                    Spacer(Modifier.height(20.dp))
                    PinPad(pin, scrambled = Graph.prefs.scramblePinPad, busyText = if (busy) "Saving…" else null, onSubmit = {
                        if (step == Step.PIN_NEW) {
                            firstPin = pin.take()
                            error = null
                            step = Step.PIN_CONFIRM
                        } else {
                            val second = pin.take()
                            val first = firstPin
                            if (first != null && first.contentEquals(second)) {
                                first.fill('\u0000')
                                firstPin = null
                                saveSecret(second, isPin = true)
                            } else {
                                second.fill('\u0000')
                                first?.fill('\u0000')
                                firstPin = null
                                error = "The PINs didn't match. Try again."
                                step = Step.PIN_NEW
                            }
                        }
                    })
                    ProgressRow(busy, "Re-encrypting your data…", hint = "This takes a few seconds.")
                }
                Step.PASSPHRASE -> {
                    Text(
                        "Your passphrase is stretched with Argon2 and combined with a key locked inside your phone's secure hardware.",
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
                            pass.isNotEmpty() && pass.length < 8 -> "Use at least 8 characters. Longer is stronger."
                            else -> " "
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                    Spacer(Modifier.height(16.dp))
                    ProgressButton(
                        busy = busy,
                        enabled = pass.length >= 8 && pass == confirm,
                        onClick = { saveSecret(pass.toCharArray().also { pass = ""; confirm = "" }, isPin = false) },
                        modifier = Modifier.fillMaxWidth().height(52.dp),
                    ) { Text("Save") }
                    ProgressRow(busy, "Re-encrypting your data…", hint = "This takes a few seconds.")
                }
            }
        }
    }
    if (confirmNone) {
        ConfirmDialog(
            "Turn off app lock?",
            "Anyone who can unlock your phone will be able to open GoldfishSend. Fingerprint unlock and the duress PIN are turned off too.",
            "Turn off", true, { confirmNone = false },
        ) { saveSecret(null, isPin = false) }
    }
    if (confirmScreenLock) {
        ConfirmDialog(
            "Use your phone's screen lock?",
            "GoldfishSend's data will be locked to your phone's screen lock. If you ever remove or reset your phone's screen lock, " +
                "your chats can't be recovered. The duress PIN and fingerprint shortcut are turned off.",
            "Continue", false, { confirmScreenLock = false },
        ) { enableScreenLock() }
    }
}

@Composable
private fun Option(title: String, detail: String, selected: Boolean, enabled: Boolean = true, onClick: () -> Unit) {
    Surface(
        color = if (selected) MaterialTheme.colorScheme.secondaryContainer else MaterialTheme.colorScheme.surfaceContainerLow,
        shape = MaterialTheme.shapes.large,
        modifier = Modifier.fillMaxWidth().padding(vertical = 5.dp)
            .selectable(selected = selected, enabled = enabled, role = Role.RadioButton, onClick = onClick),
    ) {
        Row(Modifier.padding(16.dp), verticalAlignment = Alignment.Top, horizontalArrangement = Arrangement.Start) {
            RadioButton(selected = selected, onClick = null, enabled = enabled)
            Spacer(Modifier.width(12.dp))
            Column {
                Text(title, style = MaterialTheme.typography.titleSmall,
                    color = if (enabled) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurfaceVariant)
                Spacer(Modifier.height(2.dp))
                Text(detail, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}
