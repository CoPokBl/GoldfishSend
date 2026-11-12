package app.goldfishsend.ui.screens

import android.content.Intent
import android.net.Uri
import android.provider.Settings
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.Error
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.Warning
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.LargeTopAppBar
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.rememberTopAppBarState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.LifecycleResumeEffect
import app.goldfishsend.core.Graph
import app.goldfishsend.core.NotificationContent
import app.goldfishsend.core.Session
import app.goldfishsend.security.AuditReport
import app.goldfishsend.security.Finding
import app.goldfishsend.security.Fix
import app.goldfishsend.security.SecurityAudit
import app.goldfishsend.security.Severity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

private val Amber = Color(0xFFE8A33D)
private val Green = Color(0xFF3FA66B)

@Composable
private fun severityColor(s: Severity): Color = when (s) {
    Severity.CRITICAL -> MaterialTheme.colorScheme.error
    Severity.WARNING -> Amber
    Severity.INFO -> MaterialTheme.colorScheme.primary
    Severity.OK -> Green
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SecurityScreen(s: Session, openPassphrase: () -> Unit, openChats: () -> Unit) {
    val ctx = LocalContext.current
    val prefsVersion by Graph.prefs.version.collectAsState()
    val dbVersion by s.db.changes.collectAsState()
    var resumes by remember { mutableIntStateOf(0) }
    var pushPicker by remember { mutableStateOf(false) }
    LifecycleResumeEffect(Unit) {
        resumes++
        onPauseOrDispose { }
    }
    val report by produceState<AuditReport?>(null, prefsVersion, dbVersion, resumes) {
        value = withContext(Dispatchers.IO) { SecurityAudit.run(ctx, runCatching { s.repo.unverifiedCount() }.getOrNull()) }
    }
    val scroll = TopAppBarDefaults.exitUntilCollapsedScrollBehavior(rememberTopAppBarState())

    fun open(intent: Intent) {
        runCatching { ctx.startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) }.onFailure {
            ctx.startActivity(Intent(Settings.ACTION_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        }
    }

    fun apply(fix: Fix) {
        val p = Graph.prefs
        when (fix) {
            Fix.SYSTEM_UPDATE -> open(Intent("android.settings.SYSTEM_UPDATE_SETTINGS"))
            Fix.SECURITY_SETTINGS -> open(Intent(Settings.ACTION_SECURITY_SETTINGS))
            Fix.DEVELOPER_SETTINGS -> open(Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS))
            Fix.ACCESSIBILITY_SETTINGS -> open(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))
            Fix.INPUT_METHOD_SETTINGS -> open(Intent(Settings.ACTION_INPUT_METHOD_SETTINGS))
            Fix.BATTERY_SETTINGS -> open(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
            Fix.SET_PASSPHRASE -> openPassphrase()
            Fix.ENABLE_SCREENSHOT_BLOCK -> p.screenshotProtection = true
            Fix.HIDE_NOTIFICATION_CONTENT -> p.notificationContent = NotificationContent.NONE
            Fix.ENABLE_DEFAULT_TIMER -> p.defaultTimerSecs = 7 * 86400L
            Fix.ENABLE_WIPE_ON_RESTART -> p.wipeOnReboot = true
            Fix.CHANGE_PUSH -> pushPicker = true
            Fix.OPEN_CHATS -> openChats()
        }
    }

    Scaffold(
        modifier = Modifier.nestedScroll(scroll.nestedScrollConnection),
        topBar = { LargeTopAppBar(title = { Text("Security") }, scrollBehavior = scroll) },
        contentWindowInsets = androidx.compose.foundation.layout.WindowInsets(0),
    ) { pad ->
        val r = report
        if (r == null) {
            Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) { CircularProgressIndicator() }
            return@Scaffold
        }
        val issues = r.findings.filter { it.severity != Severity.OK }
        val good = r.findings.filter { it.severity == Severity.OK }
        LazyColumn(
            Modifier.padding(top = pad.calculateTopPadding()).fillMaxSize(),
            contentPadding = PaddingValues(start = 16.dp, end = 16.dp, bottom = 24.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            item { ScoreCard(r, issues.size) }
            if (issues.isNotEmpty()) {
                item { Label("Recommendations") }
                items(issues, key = { it.id }) { f -> FindingCard(f) { f.fix?.let(::apply) } }
            }
            if (good.isNotEmpty()) {
                item { Label("All good") }
                items(good, key = { it.id }) { f -> FindingCard(f, null) }
            }
            item {
                Text(
                    "Checks run on this phone only. Nothing is sent anywhere.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(8.dp),
                )
            }
        }
    }
    if (pushPicker) {
        PushPickerDialog { pushPicker = false }
    }
}

@Composable
private fun Label(text: String) {
    Text(
        text,
        style = MaterialTheme.typography.labelLarge,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(start = 8.dp, top = 12.dp),
    )
}

@Composable
private fun ScoreCard(r: AuditReport, issues: Int) {
    val color = when {
        r.findings.any { it.severity == Severity.CRITICAL } -> MaterialTheme.colorScheme.error
        r.findings.any { it.severity == Severity.WARNING } -> Amber
        else -> Green
    }
    Surface(color = MaterialTheme.colorScheme.surfaceContainer, shape = MaterialTheme.shapes.extraLarge, modifier = Modifier.fillMaxWidth()) {
        Row(Modifier.padding(24.dp), verticalAlignment = Alignment.CenterVertically) {
            Box(contentAlignment = Alignment.Center) {
                CircularProgressIndicator(
                    progress = { r.score / 100f },
                    modifier = Modifier.size(84.dp),
                    color = color,
                    strokeWidth = 8.dp,
                    trackColor = color.copy(alpha = 0.18f),
                )
                Text("${r.score}", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
            }
            Spacer(Modifier.width(20.dp))
            Column {
                Text(r.headline, style = MaterialTheme.typography.titleLarge)
                Text(
                    if (issues == 0) "Nothing needs your attention." else "$issues thing${if (issues == 1) "" else "s"} you can improve",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun FindingCard(f: Finding, onFix: (() -> Unit)?) {
    val icon = when (f.severity) {
        Severity.CRITICAL -> Icons.Rounded.Error
        Severity.WARNING -> Icons.Rounded.Warning
        Severity.INFO -> Icons.Rounded.Info
        Severity.OK -> Icons.Rounded.CheckCircle
    }
    Surface(color = MaterialTheme.colorScheme.surfaceContainerLow, shape = MaterialTheme.shapes.large, modifier = Modifier.fillMaxWidth()) {
        Row(Modifier.padding(16.dp), verticalAlignment = Alignment.Top) {
            Icon(icon, f.severity.name, tint = severityColor(f.severity), modifier = Modifier.padding(top = 2.dp))
            Spacer(Modifier.width(14.dp))
            Column(Modifier.weight(1f)) {
                Text(f.title, style = MaterialTheme.typography.titleSmall)
                Spacer(Modifier.height(2.dp))
                Text(f.detail, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                if (onFix != null && f.fix != null) {
                    Spacer(Modifier.height(10.dp))
                    FilledTonalButton(onClick = onFix) { Text(f.fixLabel ?: "Fix") }
                }
            }
        }
    }
}
