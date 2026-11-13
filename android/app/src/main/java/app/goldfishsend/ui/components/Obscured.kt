package app.goldfishsend.ui.components

import android.view.MotionEvent
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.pointer.pointerInteropFilter

/**
 * Tapjacking protection for destructive and trust decisions (erase, accept, verify). Touches that arrive while another
 * app's window covers ours are swallowed, like View.filterTouchesWhenObscured, but only for the guarded control, so
 * screen filters and chat bubbles keep working everywhere else. No permission is needed.
 */
@OptIn(ExperimentalComposeUiApi::class)
fun Modifier.blockWhenObscured(): Modifier = this.pointerInteropFilter { ev ->
    isObscured(ev.flags)
}

/** True when Android marks the touch as passing through (or partially under) another window. */
internal fun isObscured(flags: Int): Boolean =
    (flags and MotionEvent.FLAG_WINDOW_IS_OBSCURED) != 0 || (flags and MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED) != 0
