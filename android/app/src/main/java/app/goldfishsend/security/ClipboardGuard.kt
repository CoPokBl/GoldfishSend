package app.goldfishsend.security

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import app.goldfishsend.core.Graph

/** Copies text marked as sensitive (hidden from clipboard previews) and clears it automatically. */
object ClipboardGuard {
    private val handler = Handler(Looper.getMainLooper())

    fun copy(ctx: Context, text: String) {
        val cm = ctx.getSystemService(ClipboardManager::class.java)
        val clip = ClipData.newPlainText("message", text)
        clip.description.extras = PersistableBundle().apply {
            if (Build.VERSION.SDK_INT >= 33) {
                putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
            } else {
                putBoolean("android.content.extra.IS_SENSITIVE", true)
            }
        }
        cm.setPrimaryClip(clip)
        val secs = Graph.prefs.clipboardClearSecs
        if (secs > 0) {
            handler.removeCallbacksAndMessages(null)
            handler.postDelayed({ clear(ctx, text) }, secs * 1000L)
        }
    }

    private fun clear(ctx: Context, text: String) {
        val cm = ctx.getSystemService(ClipboardManager::class.java)
        // Only clear if the clipboard still holds what we put there.
        val current = runCatching { cm.primaryClip?.getItemAt(0)?.text?.toString() }.getOrNull()
        if (current == null || current == text) {
            runCatching { cm.clearPrimaryClip() }
        }
    }
}
