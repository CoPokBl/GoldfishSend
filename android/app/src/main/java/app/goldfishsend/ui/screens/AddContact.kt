package app.goldfishsend.ui.screens

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material.icons.rounded.ContentPaste
import androidx.compose.material.icons.rounded.QrCode2
import androidx.compose.material.icons.rounded.QrCodeScanner
import androidx.compose.material.icons.rounded.Share
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import app.goldfishsend.core.Graph
import app.goldfishsend.core.InviteException
import app.goldfishsend.core.Invites
import app.goldfishsend.core.Session
import app.goldfishsend.db.Mailbox
import app.goldfishsend.net.ApiException
import app.goldfishsend.proto.InviteLink
import app.goldfishsend.ui.components.FieldKind
import app.goldfishsend.ui.components.QrImage
import app.goldfishsend.ui.components.QrScanner
import app.goldfishsend.ui.components.SecureTextField
import app.goldfishsend.ui.components.rememberQuery
import app.goldfishsend.ui.components.rememberTicker
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Human-readable reason for any invite/setup failure. Never a stack trace or an HTTP code. */
private fun Throwable.friendly(): String = when (this) {
    is InviteException -> human
    is ApiException -> human
    else -> "Something went wrong. Please try again."
}

/**
 * Accepts an invite and returns the new contact id, or a friendly error.
 * Shared by the scanner, "Paste link" and gfsend:// deep links.
 */
suspend fun acceptInvite(s: Session, raw: String, viaQr: Boolean): Result<Long> = withContext(Dispatchers.IO) {
    val link = InviteLink.parse(raw) ?: return@withContext Result.failure(InviteException("That's not a GoldfishSend code."))
    try {
        Result.success(Invites.accept(s, link, viaQr))
    } catch (e: Exception) {
        Result.failure(InviteException(e.friendly()))
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AddContactScreen(s: Session, back: () -> Unit, openChat: (Long) -> Unit) {
    var mode by remember { mutableIntStateOf(0) }
    val snackbar = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()
    var pasteOpen by remember { mutableStateOf(false) }
    var accepting by remember { mutableStateOf(false) }

    fun accept(raw: String, viaQr: Boolean) {
        if (accepting) {
            return
        }
        accepting = true
        scope.launch {
            acceptInvite(s, raw, viaQr)
                .onSuccess(openChat)
                .onFailure {
                    accepting = false
                    snackbar.showSnackbar(it.message ?: "Something went wrong.")
                    if (viaQr) {
                        mode = 0
                        delay(50)
                        mode = 1
                    }
                }
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Add contact") },
                navigationIcon = { IconButton(onClick = back) { Icon(Icons.AutoMirrored.Rounded.ArrowBack, "Back") } },
                actions = { IconButton(onClick = { pasteOpen = true }) { Icon(Icons.Rounded.ContentPaste, "Paste link") } },
            )
        },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { pad ->
        Column(
            Modifier
                .padding(pad)
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Spacer(Modifier.height(8.dp))
            SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                SegmentedButton(
                    selected = mode == 0, onClick = { mode = 0 },
                    shape = SegmentedButtonDefaults.itemShape(0, 2),
                    icon = { Icon(Icons.Rounded.QrCode2, null, Modifier.size(18.dp)) },
                ) { Text("My code") }
                SegmentedButton(
                    selected = mode == 1, onClick = { mode = 1 },
                    shape = SegmentedButtonDefaults.itemShape(1, 2),
                    icon = { Icon(Icons.Rounded.QrCodeScanner, null, Modifier.size(18.dp)) },
                ) { Text("Scan") }
            }
            Spacer(Modifier.height(24.dp))
            AnimatedContent(mode, transitionSpec = { fadeIn() togetherWith fadeOut() }, label = "mode") { m ->
                if (m == 0) {
                    MyCode(s, openChat, snackbar)
                } else {
                    ScanPane(accepting) { accept(it, viaQr = true) }
                }
            }
        }
    }

    if (pasteOpen) {
        var text by remember { mutableStateOf("") }
        AlertDialog(
            onDismissRequest = { pasteOpen = false },
            title = { Text("Paste invite link") },
            text = {
                Column {
                    Text("Paste the link your contact shared with you.", color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Spacer(Modifier.height(12.dp))
                    SecureTextField(text, { text = it }, Modifier.fillMaxWidth(), hint = "gfsend://invite#…", kind = FieldKind.URI)
                }
            },
            confirmButton = {
                TextButton(enabled = text.isNotBlank(), onClick = {
                    pasteOpen = false
                    accept(text, viaQr = false)
                }) { Text("Add") }
            },
            dismissButton = { TextButton(onClick = { pasteOpen = false }) { Text("Cancel") } },
        )
    }
}

@Composable
private fun MyCode(s: Session, openChat: (Long) -> Unit, snackbar: SnackbarHostState) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var invite by remember { mutableStateOf<Invites.Created?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var generation by remember { mutableIntStateOf(0) }
    var sharing by remember { mutableStateOf(false) }
    val now by rememberTicker(true)

    LaunchedEffect(generation) {
        error = null
        while (invite == null) {
            try {
                invite = withContext(Dispatchers.IO) { Invites.create(s, Mailbox.PURPOSE_QR) }
            } catch (e: Exception) {
                error = e.friendly()
                // Retries automatically. The first run may still be preparing in the background.
                delay(4000)
            }
        }
    }
    // Refresh the code shortly before it expires.
    val inv = invite
    if (inv != null && now > inv.expiresAt - 30_000) {
        LaunchedEffect(inv) {
            invite = null
            generation++
        }
    }
    // When someone scans our code, their hello binds the mailbox, so jump straight into the chat.
    val bound by rememberQuery(s, inv?.mailboxId) { q -> inv?.let { q.repo.mailbox(it.mailboxId)?.contactId } }
    LaunchedEffect(bound) {
        bound?.let(openChat)
    }

    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Box(
            Modifier
                .fillMaxWidth(0.82f)
                .aspectRatio(1f)
                .clip(MaterialTheme.shapes.extraLarge)
                .background(Color.White)
                .border(1.dp, MaterialTheme.colorScheme.outlineVariant, MaterialTheme.shapes.extraLarge)
                .padding(20.dp),
            contentAlignment = Alignment.Center,
        ) {
            if (inv != null) {
                QrImage(inv.link.toUri(), Modifier.fillMaxSize())
            } else {
                CircularProgressIndicator(color = Color(0xFF9A4A00))
            }
        }
        Spacer(Modifier.height(16.dp))
        Text(
            when {
                inv != null -> "Ask your contact to scan this with GoldfishSend"
                error != null -> error!!
                else -> "Preparing your code…"
            },
            textAlign = TextAlign.Center,
            style = MaterialTheme.typography.bodyLarge,
        )
        if (inv != null) {
            val left = ((inv.expiresAt - now) / 1000).coerceAtLeast(0)
            Text(
                "Works once · refreshes in ${left / 60}:${"%02d".format(left % 60)}",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Spacer(Modifier.height(24.dp))
        OutlinedButton(
            enabled = !sharing,
            onClick = {
                sharing = true
                scope.launch {
                    try {
                        val link = withContext(Dispatchers.IO) { Invites.create(s, Mailbox.PURPOSE_LINK) }
                        val send = Intent(Intent.ACTION_SEND).apply {
                            type = "text/plain"
                            putExtra(Intent.EXTRA_TEXT, "Let's chat privately on GoldfishSend. This link works once, for 24 hours:\n${link.link.toUri()}")
                        }
                        ctx.startActivity(Intent.createChooser(send, "Share invite link"))
                    } catch (e: Exception) {
                        snackbar.showSnackbar(e.friendly())
                    } finally {
                        sharing = false
                    }
                }
            },
            modifier = Modifier.fillMaxWidth().height(52.dp),
        ) {
            Icon(Icons.Rounded.Share, null)
            Spacer(Modifier.width(8.dp))
            Text("Share a link instead")
        }
        Spacer(Modifier.height(8.dp))
        Text(
            "Scanning in person is safest: it also verifies you're talking to the right person.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
    }
}

@Composable
private fun ScanPane(accepting: Boolean, onCode: (String) -> Unit) {
    val ctx = LocalContext.current
    var granted by remember {
        mutableStateOf(ContextCompat.checkSelfPermission(ctx, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED)
    }
    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted = it }
    LaunchedEffect(Unit) {
        if (!granted) {
            launcher.launch(Manifest.permission.CAMERA)
        }
    }
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Box(
            Modifier
                .fillMaxWidth(0.82f)
                .aspectRatio(1f)
                .clip(MaterialTheme.shapes.extraLarge)
                .background(MaterialTheme.colorScheme.surfaceContainerHighest),
            contentAlignment = Alignment.Center,
        ) {
            when {
                accepting -> Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    CircularProgressIndicator()
                    Spacer(Modifier.height(12.dp))
                    Text("Connecting…")
                }
                granted -> QrScanner(Modifier.fillMaxSize(), onResult = onCode)
                else -> Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.padding(24.dp)) {
                    Text("Camera access is needed to scan codes.", textAlign = TextAlign.Center)
                    Spacer(Modifier.height(12.dp))
                    Button(onClick = { launcher.launch(Manifest.permission.CAMERA) }) { Text("Allow camera") }
                }
            }
        }
        Spacer(Modifier.height(16.dp))
        Text("Point your camera at your contact's code", style = MaterialTheme.typography.bodyLarge, textAlign = TextAlign.Center)
        Row(Modifier.padding(top = 4.dp), horizontalArrangement = Arrangement.Center) {
            Text(
                "Nothing is shared until you scan.",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
