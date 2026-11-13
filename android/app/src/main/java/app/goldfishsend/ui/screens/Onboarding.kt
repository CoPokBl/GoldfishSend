package app.goldfishsend.ui.screens

import android.Manifest
import android.content.Intent
import android.net.Uri
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.NotificationsActive
import androidx.compose.material.icons.rounded.NoAccounts
import androidx.compose.material.icons.rounded.Timer
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.LifecycleResumeEffect
import app.goldfishsend.R
import app.goldfishsend.core.Graph
import app.goldfishsend.net.ApiException
import app.goldfishsend.net.ServerApi
import app.goldfishsend.push.Distributor
import app.goldfishsend.push.PushHub
import app.goldfishsend.security.AppLock
import app.goldfishsend.ui.components.FieldKind
import app.goldfishsend.ui.components.SecureTextField
import app.goldfishsend.work.MaintenanceWorker
import androidx.compose.foundation.Image
import androidx.compose.ui.res.painterResource
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** First run: welcome → push app → name & optional passphrase → setup. Four calm steps, no jargon. */
@Composable
fun OnboardingFlow() {
    var step by remember { mutableIntStateOf(0) }
    var name by remember { mutableStateOf("") }
    var passphrase by remember { mutableStateOf("") }
    Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        AnimatedContent(
            targetState = step,
            transitionSpec = {
                (slideInHorizontally { it / 3 } + fadeIn()) togetherWith (slideOutHorizontally { -it / 3 } + fadeOut())
            },
            label = "onboarding",
        ) { s ->
            when (s) {
                0 -> Welcome { step = 1 }
                1 -> PushStep { step = 2 }
                2 -> ProfileStep(name, { name = it }, passphrase, { passphrase = it }) { step = 3 }
                else -> FinishStep(name, passphrase) { step = 1 }
            }
        }
    }
}

@Composable
private fun StepScaffold(content: @Composable () -> Unit, bottom: @Composable () -> Unit) {
    Column(
        Modifier
            .fillMaxSize()
            .safeDrawingPadding()
            .imePadding()
            .padding(horizontal = 24.dp),
    ) {
        Column(
            Modifier
                .weight(1f)
                .verticalScroll(rememberScrollState())
                .padding(top = 32.dp),
        ) { content() }
        Column(Modifier.padding(vertical = 16.dp)) { bottom() }
    }
}

@Composable
private fun Logo() {
    Box(
        Modifier
            .size(88.dp)
            .background(MaterialTheme.colorScheme.primaryContainer, CircleShape),
        contentAlignment = Alignment.Center,
    ) {
        Image(painterResource(R.drawable.ic_launcher_foreground), null, Modifier.size(120.dp))
    }
}

@Composable
private fun Bullet(icon: ImageVector, title: String, text: String) {
    Row(Modifier.padding(vertical = 10.dp), verticalAlignment = Alignment.Top) {
        Box(
            Modifier
                .size(40.dp)
                .background(MaterialTheme.colorScheme.secondaryContainer, CircleShape),
            contentAlignment = Alignment.Center,
        ) { Icon(icon, null, tint = MaterialTheme.colorScheme.onSecondaryContainer) }
        Spacer(Modifier.width(16.dp))
        Column {
            Text(title, style = MaterialTheme.typography.titleMedium)
            Text(text, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun Welcome(next: () -> Unit) {
    StepScaffold(
        content = {
            Logo()
            Spacer(Modifier.height(24.dp))
            Text("GoldfishSend", style = MaterialTheme.typography.headlineLarge)
            Text(
                "Private messages that forget.",
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(24.dp))
            Bullet(Icons.Rounded.NoAccounts, "No account, no phone number", "Add people by scanning a code. Nobody can look you up.")
            Bullet(Icons.Rounded.Lock, "End-to-end encrypted", "Only you and the person you're talking to can read messages, with post-quantum protection.")
            Bullet(Icons.Rounded.Timer, "Nothing kept", "The server forgets each message as soon as it's delivered, and chats can disappear on their own.")
        },
        bottom = {
            Button(onClick = next, modifier = Modifier.fillMaxWidth().height(52.dp)) { Text("Get started") }
        },
    )
}

@Composable
private fun PushStep(next: () -> Unit) {
    val ctx = LocalContext.current
    var dists by remember { mutableStateOf(PushHub.distributors(ctx)) }
    var selected by remember { mutableStateOf(PushHub.current(ctx)) }
    var advanced by remember { mutableStateOf(false) }
    var server by remember { mutableStateOf(Graph.prefs.serverUrl) }
    var serverError by remember { mutableStateOf<String?>(null) }
    var networkSettings by remember { mutableStateOf(false) }
    LifecycleResumeEffect(Unit) {
        dists = PushHub.distributors(ctx)
        if (dists.size == 1) {
            selected = dists[0].packageName
        }
        onPauseOrDispose { }
    }
    StepScaffold(
        content = {
            Icon(Icons.Rounded.NotificationsActive, null, Modifier.size(48.dp), tint = MaterialTheme.colorScheme.primary)
            Spacer(Modifier.height(16.dp))
            Text("Notifications", style = MaterialTheme.typography.headlineMedium)
            Spacer(Modifier.height(8.dp))
            when {
                dists.isEmpty() -> {
                    Text(
                        "GoldfishSend uses a separate, open push app to wake your phone when a message arrives, so no Google account is needed. " +
                            "Install one of these, then come back:",
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(Modifier.height(16.dp))
                    PushAppCard("ntfy", "Popular and reliable. Use the public server or your own.") {
                        ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://f-droid.org/packages/io.heckel.ntfy/")))
                    }
                    PushAppCard("Sunup", "Lightweight. Uses Mozilla's push service.") {
                        ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://f-droid.org/packages/org.unifiedpush.distributor.sunup/")))
                    }
                }
                dists.size == 1 -> {
                    Text("You're all set. Messages will arrive through:", color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Spacer(Modifier.height(16.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Rounded.CheckCircle, null, tint = MaterialTheme.colorScheme.primary)
                        Spacer(Modifier.width(12.dp))
                        Text(dists[0].label, style = MaterialTheme.typography.titleMedium)
                    }
                }
                else -> {
                    Text("Choose which app delivers your notifications:", color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Spacer(Modifier.height(8.dp))
                    for (d in dists) {
                        DistributorRow(d, selected == d.packageName) { selected = d.packageName }
                    }
                }
            }
            Spacer(Modifier.height(24.dp))
            TextButton(onClick = { advanced = !advanced }) { Text(if (advanced) "Hide advanced" else "Advanced") }
            AnimatedVisibility(advanced) {
                Column {
                    Text("Server", style = MaterialTheme.typography.labelLarge)
                    Spacer(Modifier.height(6.dp))
                    SecureTextField(server, { server = it; serverError = null }, Modifier.fillMaxWidth(), hint = "https://", kind = FieldKind.URI)
                    serverError?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
                    Spacer(Modifier.height(8.dp))
                    // Tor (built-in or Orbot) and key pinning, needed before setup for an .onion server.
                    TextButton(onClick = { networkSettings = true }) { Text("Connection: ${connectionSummary()}") }
                }
            }
            if (networkSettings) {
                NetworkSettingsDialog { networkSettings = false }
            }
        },
        bottom = {
            if (dists.isEmpty()) {
                OutlinedButton(onClick = { dists = PushHub.distributors(ctx) }, modifier = Modifier.fillMaxWidth().height(52.dp)) {
                    Text("I've installed one")
                }
            } else {
                Button(
                    enabled = selected != null,
                    onClick = {
                        if (!ServerApi.isValidServer(server)) {
                            advanced = true
                            serverError = "That doesn't look like a secure server address (https://… or a Tor .onion address)."
                            return@Button
                        }
                        Graph.prefs.serverUrl = server.trim().trimEnd('/')
                        PushHub.select(ctx, selected!!)
                        next()
                    },
                    modifier = Modifier.fillMaxWidth().height(52.dp),
                ) { Text("Continue") }
            }
        },
    )
}

@Composable
private fun PushAppCard(name: String, text: String, onClick: () -> Unit) {
    Surface(
        onClick = onClick,
        shape = MaterialTheme.shapes.medium,
        color = MaterialTheme.colorScheme.surfaceContainerHigh,
        modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
    ) {
        Column(Modifier.padding(16.dp)) {
            Text("Get $name", style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.primary)
            Text(text, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun DistributorRow(d: Distributor, selected: Boolean, onClick: () -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        RadioButton(selected = selected, onClick = onClick)
        Spacer(Modifier.width(8.dp))
        Column {
            Text(d.label, style = MaterialTheme.typography.titleMedium)
            if (d.packageName in PushHub.GOOGLE_DISTRIBUTORS) {
                Text("Uses Google's servers", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
            }
        }
    }
}

@Composable
private fun ProfileStep(
    name: String,
    onName: (String) -> Unit,
    passphrase: String,
    onPassphrase: (String) -> Unit,
    next: () -> Unit,
) {
    var confirm by remember { mutableStateOf("") }
    var usePassphrase by remember { mutableStateOf(passphrase.isNotEmpty()) }
    val mismatch = usePassphrase && confirm.isNotEmpty() && confirm != passphrase
    StepScaffold(
        content = {
            Text("About you", style = MaterialTheme.typography.headlineMedium)
            Spacer(Modifier.height(8.dp))
            Text(
                "Your name is only shared with people you add. It's optional.",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(16.dp))
            SecureTextField(name, onName, Modifier.fillMaxWidth(), hint = "Your name (optional)")
            Spacer(Modifier.height(32.dp))
            Text("App passphrase", style = MaterialTheme.typography.titleLarge)
            Spacer(Modifier.height(6.dp))
            Text(
                "Lock GoldfishSend with its own passphrase. It's mixed into your encryption keys, so your chats stay safe even if someone gets past your phone's lock. You can add it later.",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.bodyMedium,
            )
            Spacer(Modifier.height(12.dp))
            if (!usePassphrase) {
                OutlinedButton(onClick = { usePassphrase = true }) { Text("Add a passphrase") }
            } else {
                SecureTextField(passphrase, onPassphrase, Modifier.fillMaxWidth(), hint = "Passphrase", kind = FieldKind.PASSWORD)
                Spacer(Modifier.height(8.dp))
                SecureTextField(confirm, { confirm = it }, Modifier.fillMaxWidth(), hint = "Confirm passphrase", kind = FieldKind.PASSWORD)
                if (mismatch) {
                    Text("Passphrases don't match", color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                } else if (passphrase.isNotEmpty() && passphrase.length < 6) {
                    Text("Use at least 6 characters", color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodySmall)
                }
                TextButton(onClick = {
                    usePassphrase = false
                    onPassphrase("")
                    confirm = ""
                }) { Text("Skip for now") }
            }
        },
        bottom = {
            Button(
                enabled = !usePassphrase || (passphrase.length >= 6 && confirm == passphrase),
                onClick = {
                    if (!usePassphrase) {
                        onPassphrase("")
                    }
                    next()
                },
                modifier = Modifier.fillMaxWidth().height(52.dp),
            ) { Text("Continue") }
        },
    )
}

@Composable
private fun FinishStep(name: String, passphrase: String, back: () -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var status by remember { mutableStateOf("Creating your keys…") }
    var error by remember { mutableStateOf<String?>(null) }
    var attempt by remember { mutableIntStateOf(0) }
    val notifPermission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { }

    LaunchedEffect(Unit) {
        if (Build.VERSION.SDK_INT >= 33) {
            notifPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }
    LaunchedEffect(attempt) {
        error = null
        try {
            if (Graph.session.value == null) {
                status = "Creating your keys…"
                val mk = withContext(Dispatchers.Default) {
                    Graph.vault.setup(passphrase.takeIf { it.isNotEmpty() }?.toCharArray())
                }
                val s = Graph.openSession(mk)
                withContext(Dispatchers.IO) {
                    s.repo.displayName = name.ifBlank { null }
                    s.signal.identityKeyPair
                }
            }
            status = "Connecting notifications…"
            PushHub.register(ctx)
            // Wait briefly for the push app to hand us an endpoint. It's fine if it's slow, because setup continues in the background.
            for (i in 0 until 40) {
                if (Graph.prefs.pushStatus == "ok" || Graph.prefs.pushStatus == "failed") {
                    break
                }
                delay(250)
            }
            if (Graph.prefs.pushStatus == "failed") {
                error = "Your push app couldn't register. Open it to check it's working, then try again."
                return@LaunchedEffect
            }
            Graph.prefs.onboarded = true
            MaintenanceWorker.schedule(ctx)
            Graph.session.value?.let { AppLock.afterUnlock(it) }
        } catch (e: ApiException) {
            error = e.human
        } catch (e: Exception) {
            error = "Something went wrong while setting up. Please try again."
        }
    }
    StepScaffold(
        content = {
            Spacer(Modifier.height(80.dp))
            Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
                if (error == null) {
                    CircularProgressIndicator(Modifier.size(56.dp))
                    Spacer(Modifier.height(24.dp))
                    Text(status, style = MaterialTheme.typography.titleMedium, textAlign = TextAlign.Center)
                } else {
                    Text("Almost there", style = MaterialTheme.typography.headlineSmall)
                    Spacer(Modifier.height(12.dp))
                    Text(error!!, textAlign = TextAlign.Center, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        },
        bottom = {
            if (error != null) {
                Button(onClick = { attempt++ }, modifier = Modifier.fillMaxWidth().height(52.dp)) { Text("Try again") }
                Spacer(Modifier.height(8.dp))
                OutlinedButton(onClick = back, modifier = Modifier.fillMaxWidth().height(52.dp)) { Text("Change push app or server") }
                TextButton(
                    onClick = {
                        scope.launch {
                            Graph.prefs.onboarded = true
                            MaintenanceWorker.schedule(ctx)
                            Graph.session.value?.let { AppLock.afterUnlock(it) }
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Continue anyway") }
            }
        },
    )
}
