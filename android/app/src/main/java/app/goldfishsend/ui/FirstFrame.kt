package app.goldfishsend.ui

import androidx.activity.compose.ReportDrawnWhen
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect

/**
 * MainActivity holds its first frame (showing the splash) until the first screen has its content, for at most
 * [MAX_HOLD_MS]. A start without app lock then goes from the splash straight to the chat list, instead of a spinner while
 * the database opens, a fade, an empty list, and then the chats.
 */
object FirstFrame {
    const val MAX_HOLD_MS = 1000L

    @Volatile
    var ready = false

    /** Set once the first frame is on screen. Until then, screen changes aren't animated (nobody would see them). */
    @Volatile
    var drawn = false
}

/**
 * Marks the screen as showing real content: releases the held first frame, and reports the activity fully drawn
 * (timeToFullDisplay in the startup benchmarks).
 */
@Composable
fun ContentReady(ready: Boolean = true) {
    ReportDrawnWhen { ready }
    if (ready) {
        SideEffect { FirstFrame.ready = true }
    }
}
