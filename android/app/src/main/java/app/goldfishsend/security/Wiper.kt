package app.goldfishsend.security

import android.content.Context
import android.provider.Settings
import androidx.work.WorkManager
import app.goldfishsend.core.Graph
import app.goldfishsend.core.LockedInbox
import app.goldfishsend.core.Mailboxes
import app.goldfishsend.core.Notifier
import app.goldfishsend.db.Db
import app.goldfishsend.push.PushHub
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull

/** Destruction paths. Keys are always destroyed first, so data is unrecoverable even if file deletion is interrupted. */
object Wiper {
    /** Erases all messages. While locked this works by destroying the message root key (instant crypto-shred). */
    fun wipeMessages() {
        val s = Graph.session.value
        if (s != null) {
            s.repo.wipeAllMessages()
            s.db.notifyChanged()
        } else {
            Graph.vault.destroyMessageKey()
        }
        Notifier.cancelAll(Graph.app)
    }

    /** Restart detection: BOOT_COMPLETED *and* a BOOT_COUNT comparison at every start, so a reboot can't be missed. */
    fun checkBoot(ctx: Context, fromBootBroadcast: Boolean) {
        val count = Settings.Global.getInt(ctx.contentResolver, Settings.Global.BOOT_COUNT, -1)
        val prefs = Graph.prefs
        val rebooted = fromBootBroadcast || (count != -1 && prefs.lastBootCount != -1 && count != prefs.lastBootCount)
        if (count != -1) {
            prefs.lastBootCount = count
        }
        if (rebooted && prefs.wipeOnReboot && prefs.onboarded) {
            Graph.vault.destroyMessageKey()
        }
    }

    /** Dead-man switch: wipe everything if the app hasn't been unlocked for N days. */
    fun checkInactivity(ctx: Context) {
        val days = Graph.prefs.inactivityWipeDays
        if (days <= 0 || !Graph.prefs.onboarded) {
            return
        }
        if (System.currentTimeMillis() - Graph.prefs.lastUnlockAt > days * 86_400_000L) {
            wipeEverything(ctx)
        }
    }

    /**
     * Panic wipe: destroy every key, delete the DB, the locked inbox and settings, and unregister push.
     * Inbound mailboxes are then deleted on the server on a best-effort basis, from a snapshot taken before the keys went.
     */
    @OptIn(kotlinx.coroutines.DelicateCoroutinesApi::class)
    fun wipeEverything(ctx: Context) {
        val s = Graph.session.value
        val remote = s?.let { runCatching { it.repo.allMailboxes().map(Mailboxes::item) }.getOrNull() }.orEmpty()
        val server = Graph.prefs.serverUrl
        Graph.lock()
        Graph.vault.destroyAll()
        Db.deleteFiles(ctx)
        LockedInbox.clear()
        PushHub.unregister(ctx)
        Notifier.cancelAll(ctx)
        runCatching { WorkManager.getInstance(ctx).cancelAllWork() }
        Graph.prefs.clear()
        if (remote.isNotEmpty()) {
            GlobalScope.launch {
                withTimeoutOrNull(15_000) {
                    runCatching {
                        val api = Graph.api(server)
                        for (batch in remote.chunked(100)) {
                            api.delete(batch)
                        }
                    }
                }
            }
        }
    }
}
