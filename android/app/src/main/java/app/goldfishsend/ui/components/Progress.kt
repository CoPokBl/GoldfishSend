package app.goldfishsend.ui.components

import android.os.SystemClock
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.Stable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import app.goldfishsend.core.Mailboxes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * When a progress indicator is on screen. It appears only once the work has run for [showAfterMs] (fast operations
 * never flash a spinner), and once shown it stays for at least [minVisibleMs] (no one-frame blink when the work
 * finishes just after it appeared).
 */
class IndicatorTiming(private val showAfterMs: Long = SHOW_AFTER_MS, private val minVisibleMs: Long = MIN_VISIBLE_MS) {
    var visible = false
        private set
    private var activeSince = -1L
    private var shownAt = 0L

    /** Feeds the work's state at [now]. Returns when to call again, or null if nothing changes until [active] does. */
    fun update(active: Boolean, now: Long): Long? {
        if (active) {
            if (activeSince < 0) {
                activeSince = now
            }
            if (visible) {
                return null
            }
            if (now - activeSince >= showAfterMs) {
                visible = true
                shownAt = now
                return null
            }
            return activeSince + showAfterMs
        }
        activeSince = -1L
        if (!visible) {
            return null
        }
        if (now - shownAt >= minVisibleMs) {
            visible = false
            return null
        }
        return shownAt + minVisibleMs
    }

    companion object {
        const val SHOW_AFTER_MS = 150L
        const val MIN_VISIBLE_MS = 300L
    }
}

/** Whether to show progress for work that is [active] right now, following [IndicatorTiming]. */
@Composable
fun rememberShowProgress(active: Boolean): Boolean {
    val timing = remember { IndicatorTiming() }
    var visible by remember { mutableStateOf(false) }
    LaunchedEffect(active) {
        while (true) {
            val now = SystemClock.uptimeMillis()
            val next = timing.update(active, now)
            visible = timing.visible
            delay((next ?: break) - now)
        }
    }
    return visible
}

/**
 * Work started from the UI, at most one at a time: [run] ignores a second tap while the first is still going, so nothing
 * is submitted twice. [busy] drives the button's spinner or a progress bar.
 */
@Stable
class Work internal constructor(private val scope: CoroutineScope) {
    var busy by mutableStateOf(false)
        private set

    fun run(block: suspend CoroutineScope.() -> Unit): Boolean {
        if (busy) {
            return false
        }
        busy = true
        scope.launch {
            try {
                block()
            } finally {
                busy = false
            }
        }
        return true
    }
}

@Composable
fun rememberWork(): Work {
    val scope = rememberCoroutineScope()
    return remember(scope) { Work(scope) }
}

enum class ButtonKind { FILLED, TONAL, OUTLINED, TEXT }

/**
 * A button for work that takes a moment. While [busy] it's disabled (no double submits), and a spinner replaces its
 * label in place, keeping the button's size.
 */
@Composable
fun ProgressButton(
    onClick: () -> Unit,
    busy: Boolean,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    kind: ButtonKind = ButtonKind.FILLED,
    content: @Composable RowScope.() -> Unit,
) {
    val spinning = rememberShowProgress(busy)
    val on = enabled && !busy && !spinning
    val inner: @Composable RowScope.() -> Unit = {
        Box(contentAlignment = Alignment.Center) {
            Row(Modifier.alpha(if (spinning) 0f else 1f), verticalAlignment = Alignment.CenterVertically) { content() }
            if (spinning) {
                Spinner(Modifier.size(20.dp))
            }
        }
    }
    when (kind) {
        ButtonKind.FILLED -> Button(onClick, modifier, enabled = on, content = inner)
        ButtonKind.TONAL -> FilledTonalButton(onClick, modifier, enabled = on, content = inner)
        ButtonKind.OUTLINED -> OutlinedButton(onClick, modifier, enabled = on, content = inner)
        ButtonKind.TEXT -> TextButton(onClick, modifier, enabled = on, content = inner)
    }
}

/** The small indeterminate spinner used inside buttons, rows and bubbles. */
@Composable
fun Spinner(modifier: Modifier = Modifier, color: Color = MaterialTheme.colorScheme.primary, description: String = "Working") {
    CircularProgressIndicator(
        // A size in the caller's modifier comes first and wins.
        modifier.size(16.dp).semantics { contentDescription = description },
        color = color,
        strokeWidth = 2.dp,
        trackColor = Color.Transparent,
    )
}

/**
 * A thin bar for work in progress on the whole screen: lay it over the bottom edge of the top app bar. With
 * [progress] it shows how far the work is, otherwise it's indeterminate.
 */
@Composable
fun TopProgressBar(active: Boolean, modifier: Modifier = Modifier, progress: Float? = null) {
    val show = rememberShowProgress(active)
    AnimatedVisibility(show, modifier.fillMaxWidth(), enter = fadeIn(), exit = fadeOut()) {
        if (progress != null) {
            LinearProgressIndicator(progress = { progress }, Modifier.fillMaxWidth().height(3.dp).semantics { contentDescription = "Working" })
        } else {
            LinearProgressIndicator(Modifier.fillMaxWidth().height(3.dp).semantics { contentDescription = "Working" })
        }
    }
}

/** A spinner and a line of text (and an optional hint below it), shown while [active]. */
@Composable
fun ProgressRow(active: Boolean, text: String, modifier: Modifier = Modifier, hint: String? = null) {
    val show = rememberShowProgress(active)
    AnimatedVisibility(show, modifier, enter = expandVertically() + fadeIn(), exit = shrinkVertically() + fadeOut()) {
        Column(Modifier.padding(vertical = 8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Spinner()
                Text(text, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            if (hint != null) {
                Text(
                    hint,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(start = 28.dp, top = 2.dp),
                )
            }
        }
    }
}

/**
 * A small modal "Erasing…" card for work that has to finish before anything else happens (wipes, deleting a contact).
 * It can't be dismissed: the work runs to completion either way.
 */
@Composable
fun BusyDialog(active: Boolean, text: String, hint: String? = null) {
    if (!rememberShowProgress(active)) {
        return
    }
    Dialog(onDismissRequest = {}, properties = DialogProperties(dismissOnBackPress = false, dismissOnClickOutside = false)) {
        Surface(shape = MaterialTheme.shapes.extraLarge, color = MaterialTheme.colorScheme.surfaceContainerHigh) {
            Column(Modifier.padding(24.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                    Spinner(Modifier.size(24.dp))
                    Text(text, style = MaterialTheme.typography.bodyLarge)
                }
                if (hint != null) {
                    Text(
                        hint,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.padding(top = 12.dp),
                    )
                }
            }
        }
    }
}

/** Progress of a background proof of work (a new mailbox), or the wait for the server's confirmation after it. */
@Composable
fun MailboxProgressBar(modifier: Modifier = Modifier) {
    val p by Mailboxes.progress.collectAsState()
    TopProgressBar(p != null, modifier, progress = p?.solved)
}
