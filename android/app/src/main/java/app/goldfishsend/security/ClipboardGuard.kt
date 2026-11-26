package app.goldfishsend.security

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.Worker
import androidx.work.WorkerParameters
import androidx.work.workDataOf
import app.goldfishsend.core.Graph
import app.goldfishsend.proto.B64
import app.goldfishsend.proto.Rand
import java.util.concurrent.TimeUnit

/**
 * Copies text marked as sensitive (hidden from clipboard previews) and clears it automatically:
 * - after the chosen delay, by an in-process timer, with a WorkManager job as the fallback in case the process dies first
 *   (Android kills background apps freely, and the timer goes with it);
 * - when the app locks, if the user turned that on ([app.goldfishsend.core.Prefs.clipboardClearOnLock]);
 * - on a wipe ([Wiper]).
 *
 * Each copy carries a random mark in its description, so a clear leaves alone whatever the user copied since. Reading
 * the description (never the text) also avoids Android's "pasted from your clipboard" notice.
 */
object ClipboardGuard {
    private const val MARK = "app.goldfishsend.clip"
    private const val WORK = "clipboard-clear"
    internal const val KEY_MARK = "mark"

    private val handler = Handler(Looper.getMainLooper())

    /**
     * The mark of our copy that's still on the clipboard as far as we know, or null. Kept in the settings (it's random,
     * and says nothing about the text), so a process that died before the app locked still clears it at the next start.
     */
    private var pending: String?
        get() = Graph.prefs.clipboardMark
        set(v) {
            Graph.prefs.clipboardMark = v
        }

    fun copy(ctx: Context, text: String) {
        val app = ctx.applicationContext
        val cm = app.getSystemService(ClipboardManager::class.java)
        val mark = B64.enc(Rand.bytes(12))
        val clip = ClipData.newPlainText("message", text)
        clip.description.extras = PersistableBundle().apply {
            if (Build.VERSION.SDK_INT >= 33) {
                putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
            } else {
                putBoolean("android.content.extra.IS_SENSITIVE", true)
            }
            putString(MARK, mark)
        }
        cm.setPrimaryClip(clip)
        handler.removeCallbacksAndMessages(null)
        pending = mark
        val secs = Graph.prefs.clipboardClearSecs
        if (secs > 0) {
            handler.postDelayed({ clear(app, mark) }, secs * 1000L)
            // Survives the process. It only holds the random mark, never anything of the text.
            val req = OneTimeWorkRequestBuilder<ClipboardClearWorker>()
                .setInitialDelay(secs.toLong(), TimeUnit.SECONDS)
                .setInputData(workDataOf(KEY_MARK to mark))
                .build()
            runCatching { WorkManager.getInstance(app).enqueueUniqueWork(WORK, ExistingWorkPolicy.REPLACE, req) }
        } else {
            runCatching { WorkManager.getInstance(app).cancelUniqueWork(WORK) }
        }
    }

    /** The app just locked, or a new process started (which starts locked): clear our copy if the user asked for that. */
    fun onLock(ctx: Context) {
        val mark = pending ?: return
        if (Graph.prefs.clipboardClearOnLock) {
            clear(ctx, mark)
        }
    }

    /** Clears the clipboard if it still holds the copy marked [mark]. */
    internal fun clear(ctx: Context, mark: String) {
        val app = ctx.applicationContext
        val cm = app.getSystemService(ClipboardManager::class.java)
        // Null if there's no clip, or if Android won't show it to us (an app in the background can't look).
        val desc = runCatching { cm.primaryClipDescription }.getOrNull()
        if (shouldClear(desc != null, desc?.extras?.getString(MARK), mark)) {
            runCatching { cm.clearPrimaryClip() }
        }
        if (pending == mark) {
            pending = null
            handler.removeCallbacksAndMessages(null)
            runCatching { WorkManager.getInstance(app).cancelUniqueWork(WORK) }
        }
    }

    /**
     * Whether to clear: if the clip carries our [ours] mark, or if we can't see it at all. Then it's cleared regardless,
     * as the user asked for the copy to go; at worst that also clears something copied since.
     */
    internal fun shouldClear(seen: Boolean, current: String?, ours: String): Boolean = !seen || current == ours
}

/** The fallback for [ClipboardGuard]'s timer, if the process was killed before it fired. */
class ClipboardClearWorker(ctx: Context, params: WorkerParameters) : Worker(ctx, params) {
    override fun doWork(): Result {
        inputData.getString(ClipboardGuard.KEY_MARK)?.let { ClipboardGuard.clear(applicationContext, it) }
        return Result.success()
    }
}
