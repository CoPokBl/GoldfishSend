package app.goldfishsend.ui.components

import androidx.compose.material.icons.rounded.Groups
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Done
import androidx.compose.material.icons.rounded.DoneAll
import androidx.compose.material.icons.rounded.ErrorOutline
import androidx.compose.material.icons.rounded.Schedule
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.State
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import app.goldfishsend.core.Session
import app.goldfishsend.db.MsgStatus
import java.text.DateFormat
import java.util.Calendar
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

/** Re-runs [query] off the main thread whenever the DB changes (or [keys] change). */
@Composable
fun <T> rememberQuery(s: Session, vararg keys: Any?, query: (Session) -> T): State<T?> {
    val changes by s.db.changes.collectAsState()
    return produceState<T?>(null, changes, *keys) {
        value = withContext(Dispatchers.IO) { runCatching { query(s) }.getOrNull() }
    }
}

/** A clock that ticks every [periodMs] while [active]. Used for disappearing-message countdowns. */
@Composable
fun rememberTicker(active: Boolean, periodMs: Long = 1000): State<Long> = produceState(System.currentTimeMillis(), active) {
    while (active) {
        value = System.currentTimeMillis()
        delay(periodMs)
    }
}

private val avatarPalette = listOf(
    Color(0xFFE57373), Color(0xFFF06292), Color(0xFFBA68C8), Color(0xFF7986CB), Color(0xFF4FC3F7),
    Color(0xFF4DB6AC), Color(0xFF81C784), Color(0xFFFFB74D), Color(0xFFA1887F), Color(0xFF90A4AE),
)

/** A stable color per group member (identity key), from the avatar palette. */
fun memberColor(member: String): Color = avatarPalette[Math.floorMod(member.hashCode(), avatarPalette.size)]

/** A group's avatar: the palette circle with a group icon. */
@Composable
fun GroupAvatar(seed: Long, size: Dp = 48.dp) {
    val c = avatarPalette[Math.floorMod(seed, avatarPalette.size.toLong()).toInt()]
    Box(
        Modifier.size(size).background(c.copy(alpha = 0.22f), CircleShape),
        contentAlignment = Alignment.Center,
    ) {
        androidx.compose.material3.Icon(
            androidx.compose.material.icons.Icons.Rounded.Groups, null,
            tint = c, modifier = Modifier.size(size * 0.55f),
        )
    }
}

@Composable
fun Avatar(name: String, seed: Long, size: Dp = 48.dp) {
    val c = avatarPalette[(seed % avatarPalette.size).toInt().let { if (it < 0) -it else it }]
    Box(
        Modifier.size(size).background(c.copy(alpha = 0.22f), CircleShape),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            name.trim().firstOrNull()?.uppercase() ?: "?",
            color = c,
            fontWeight = FontWeight.SemiBold,
            fontSize = (size.value * 0.42f).sp,
        )
    }
}

@Composable
fun StatusTicks(status: Int, tint: Color, modifier: Modifier = Modifier) {
    val (icon, desc) = when (status) {
        MsgStatus.QUEUED -> Icons.Rounded.Schedule to "Sending"
        MsgStatus.SENT -> Icons.Rounded.Done to "Sent"
        MsgStatus.DELIVERED -> Icons.Rounded.DoneAll to "Delivered"
        MsgStatus.READ -> Icons.Rounded.DoneAll to "Read"
        else -> Icons.Rounded.ErrorOutline to "Not sent"
    }
    val color = when (status) {
        MsgStatus.READ -> MaterialTheme.colorScheme.primary
        MsgStatus.FAILED -> MaterialTheme.colorScheme.error
        else -> tint
    }
    Icon(icon, desc, modifier.size(15.dp), tint = color)
}

/** Today's time ("14:05") or the date. Formatted for every visible chat row and bubble, so the formatters are reused. */
fun shortTime(ts: Long): String = TimeFormats.short(ts)

fun fullTime(ts: Long): String = TimeFormats.full(ts)

/** The time of day ("14:05"), whatever the day: chat bubbles, under a day separator. */
fun clockTime(ts: Long): String = TimeFormats.clock(ts)

/** Day separator labels in the current locale, and the current time zone's day of [ts]. */
fun dayLabels(): app.goldfishsend.ui.DayLabels = TimeFormats.dayLabels()

fun localDay(ts: Long): Long = app.goldfishsend.ui.ChatRows.epochDay(ts, TimeZone.getDefault())

/**
 * Creating a DateFormat and two Calendars per call cost more than the rest of a chat row; this keeps them until the
 * locale, time zone or day changes.
 */
private object TimeFormats {
    private var locale: Locale? = null
    private var zone: String? = null
    private lateinit var time: DateFormat
    private lateinit var date: DateFormat
    private lateinit var dateTime: DateFormat
    private var todayStart = 0L
    private var todayEnd = 0L

    @Synchronized
    fun short(ts: Long): String {
        refresh(System.currentTimeMillis())
        return (if (ts in todayStart until todayEnd) time else date).format(Date(ts))
    }

    @Synchronized
    fun clock(ts: Long): String {
        refresh(System.currentTimeMillis())
        return time.format(Date(ts))
    }

    private var labels: app.goldfishsend.ui.DayLabels? = null

    @Synchronized
    fun dayLabels(): app.goldfishsend.ui.DayLabels {
        refresh(System.currentTimeMillis())
        return labels ?: run {
            val l = locale!!
            fun pattern(skeleton: String) =
                java.time.format.DateTimeFormatter.ofPattern(android.text.format.DateFormat.getBestDateTimePattern(l, skeleton), l)
            app.goldfishsend.ui.DayLabels(l, pattern("MMMMd"), pattern("yMMMMd")).also { labels = it }
        }
    }

    @Synchronized
    fun full(ts: Long): String {
        refresh(System.currentTimeMillis())
        return dateTime.format(Date(ts))
    }

    private fun refresh(now: Long) {
        val l = Locale.getDefault()
        val tz = TimeZone.getDefault()
        if (l != locale || tz.id != zone) {
            locale = l
            zone = tz.id
            time = DateFormat.getTimeInstance(DateFormat.SHORT)
            date = DateFormat.getDateInstance(DateFormat.SHORT)
            dateTime = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT)
            labels = null
            todayEnd = 0L
        }
        if (now !in todayStart until todayEnd) {
            val c = Calendar.getInstance(tz, l).apply {
                timeInMillis = now
                set(Calendar.HOUR_OF_DAY, 0)
                set(Calendar.MINUTE, 0)
                set(Calendar.SECOND, 0)
                set(Calendar.MILLISECOND, 0)
            }
            todayStart = c.timeInMillis
            c.add(Calendar.DAY_OF_YEAR, 1)
            todayEnd = c.timeInMillis
        }
    }
}

fun countdown(msLeft: Long): String {
    val s = (msLeft / 1000).coerceAtLeast(0)
    return when {
        s < 60 -> "${s}s"
        s < 3600 -> "${s / 60}m"
        s < 86400 -> "${s / 3600}h"
        else -> "${s / 86400}d"
    }
}

@Composable
fun SectionHeader(text: String) {
    Text(
        text,
        style = MaterialTheme.typography.labelLarge,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(start = 24.dp, end = 24.dp, top = 24.dp, bottom = 4.dp),
    )
}

@Composable
fun SettingRow(
    title: String,
    subtitle: String? = null,
    icon: ImageVector? = null,
    enabled: Boolean = true,
    trailing: (@Composable () -> Unit)? = null,
    onClick: (() -> Unit)? = null,
) {
    ListItem(
        headlineContent = { Text(title) },
        supportingContent = subtitle?.let { { Text(it, maxLines = 3, overflow = TextOverflow.Ellipsis) } },
        leadingContent = icon?.let { { Icon(it, null, tint = MaterialTheme.colorScheme.onSurfaceVariant) } },
        trailingContent = trailing,
        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
        modifier = Modifier
            .let { if (onClick != null && enabled) it.clickable(onClick = onClick) else it }
            .padding(horizontal = 8.dp),
    )
}

@Composable
fun SwitchRow(title: String, subtitle: String? = null, icon: ImageVector? = null, checked: Boolean, enabled: Boolean = true, onChange: (Boolean) -> Unit) {
    SettingRow(
        title = title,
        subtitle = subtitle,
        icon = icon,
        enabled = enabled,
        trailing = { Switch(checked = checked, onCheckedChange = onChange, enabled = enabled) },
        onClick = { onChange(!checked) },
    )
}

@Composable
fun <T> ChoiceDialog(title: String, options: List<Pair<T, String>>, selected: T, onDismiss: () -> Unit, onSelect: (T) -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            Column {
                for ((v, label) in options) {
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .selectable(selected = v == selected, role = Role.RadioButton) {
                                onSelect(v)
                                onDismiss()
                            }
                            .padding(vertical = 10.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        RadioButton(selected = v == selected, onClick = null)
                        Spacer(Modifier.width(16.dp))
                        Text(label, style = MaterialTheme.typography.bodyLarge)
                    }
                }
            }
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text("Close") } },
    )
}

@Composable
fun ConfirmDialog(title: String, text: String, confirm: String, destructive: Boolean = false, onDismiss: () -> Unit, onConfirm: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = { Text(text) },
        confirmButton = {
            TextButton(
                onClick = {
                    onDismiss()
                    onConfirm()
                },
                modifier = Modifier.blockWhenObscured(),
            ) {
                Text(confirm, color = if (destructive) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary)
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

/** Thin status line used for background work ("Getting ready…"), never protocol jargon. */
@Composable
fun StatusLine(visible: Boolean, text: String, action: String? = null, onAction: (() -> Unit)? = null) {
    AnimatedVisibility(visible, enter = expandVertically() + fadeIn(), exit = shrinkVertically() + fadeOut()) {
        Row(
            Modifier
                .fillMaxWidth()
                .background(MaterialTheme.colorScheme.secondaryContainer)
                .padding(horizontal = 20.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            if (action == null) {
                CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onSecondaryContainer)
            }
            Text(
                text,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSecondaryContainer,
                modifier = Modifier.weight(1f),
            )
            if (action != null && onAction != null) {
                TextButton(onClick = onAction) { Text(action) }
            }
        }
    }
}

@Composable
fun OnEvery(periodMs: Long, block: suspend () -> Unit) {
    LaunchedEffect(Unit) {
        while (true) {
            block()
            delay(periodMs)
        }
    }
}
