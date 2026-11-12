package app.goldfishsend.core

import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch

/** Launches work whose failure must never crash the app; errors are logged without sensitive detail. */
fun CoroutineScope.launchSafe(block: suspend CoroutineScope.() -> Unit): Job = launch {
    try {
        block()
    } catch (e: kotlinx.coroutines.CancellationException) {
        throw e
    } catch (e: Exception) {
        Log.w("GoldfishSend", "task failed: ${e.javaClass.simpleName}")
    }
}

fun formatTimer(secs: Long): String = when {
    secs <= 0 -> "Off"
    secs < 60 -> "${secs}s"
    secs < 3600 -> "${secs / 60} min"
    secs < 86400 -> "${secs / 3600} h"
    secs < 7 * 86400 -> "${secs / 86400} d"
    else -> "${secs / (7 * 86400)} wk"
}

val TIMER_CHOICES = listOf(0L, 30L, 300L, 3600L, 8 * 3600L, 86400L, 7 * 86400L, 28 * 86400L)

fun timerLabel(secs: Long): String = when (secs) {
    0L -> "Off"
    30L -> "30 seconds"
    300L -> "5 minutes"
    3600L -> "1 hour"
    8 * 3600L -> "8 hours"
    86400L -> "1 day"
    7 * 86400L -> "1 week"
    28 * 86400L -> "4 weeks"
    else -> formatTimer(secs)
}
