package app.goldfishsend.security

import android.content.Context
import android.provider.Settings
import androidx.work.WorkManager
import app.goldfishsend.core.Graph
import app.goldfishsend.core.LockedInbox
import app.goldfishsend.core.Mailboxes
import app.goldfishsend.core.NetPrefs
import app.goldfishsend.net.TorManager
import app.goldfishsend.core.Notifier
import app.goldfishsend.db.Db
import app.goldfishsend.push.PushHub
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull

/** Destruction paths. Keys are always destroyed first, so data is unrecoverable even if file deletion is interrupted. */
object Wiper {
    /**
     * Erases all messages, including pushes waiting in the locked inbox. While locked this works by destroying the message
     * root key (an instant crypto-shred) and the per-expiry bucket keys. The inbox key pair is replaced at the next unlock,
     * so remnants of old sealed pushes can never be opened again.
     */
    fun wipeMessages() {
        val s = Graph.session.value
        LockedInbox.clear()
        if (s != null) {
            s.repo.wipeAllMessages()
            LockedInbox.rotateKeys(s)
            s.db.notifyChanged()
        } else {
            Graph.vault.destroyMessageKey()
            Graph.prefs.inboxRotatePending = true
        }
        app.goldfishsend.crypto.BucketKeys.destroyAll()
        Notifier.cancelAll(Graph.app)
    }

    /**
     * Restart detection: BOOT_COMPLETED *and* a BOOT_COUNT comparison at every start, so a reboot can't be missed. The
     * handled boot count is persisted, so the same boot is never handled twice (which would shred messages received since).
     */
    fun checkBoot(ctx: Context, fromBootBroadcast: Boolean) {
        val count = Settings.Global.getInt(ctx.contentResolver, Settings.Global.BOOT_COUNT, -1)
        val prefs = Graph.prefs
        val rebooted = if (count != -1) {
            prefs.lastBootCount != -1 && count != prefs.lastBootCount
        } else {
            // No boot counter on this device: the broadcast is the only signal.
            fromBootBroadcast
        }
        if (count != -1) {
            prefs.lastBootCount = count
        }
        if (rebooted && prefs.wipeOnReboot && prefs.onboarded) {
            wipeMessages()
        }
    }

    /** Records that the user is here (interactive unlock, or the app is in the foreground while unlocked). */
    fun recordPresence(ctx: Context = Graph.app) {
        Graph.prefs.presence = Presence.Mark(
            System.currentTimeMillis(),
            android.os.SystemClock.elapsedRealtime(),
            Settings.Global.getInt(ctx.contentResolver, Settings.Global.BOOT_COUNT, -1),
        )
    }

    /** Dead-man switch: wipe everything if the user hasn't been present for N days. Background wake-ups don't count. */
    fun checkInactivity(ctx: Context) {
        val days = Graph.prefs.inactivityWipeDays
        if (days <= 0 || !Graph.prefs.onboarded) {
            return
        }
        val last = Graph.prefs.presence
        if (last == null) {
            // First run with the feature (or an upgrade): start the clock now rather than erasing.
            recordPresence(ctx)
            return
        }
        val boot = Settings.Global.getInt(ctx.contentResolver, Settings.Global.BOOT_COUNT, -1)
        if (Presence.shouldWipe(last, days, System.currentTimeMillis(), android.os.SystemClock.elapsedRealtime(), boot)) {
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
        // Store the connection mode explicitly, so the best-effort deletes below still go through Tor or Orbot
        // after the main preferences (which hold the legacy Orbot flag) are cleared. Network state goes last.
        NetPrefs.proxyMode = NetPrefs.proxyMode
        Graph.prefs.clear()
        val wipeNetwork = {
            NetPrefs.clear()
            TorManager.deleteState(ctx)
            Graph.resetHttp()
        }
        if (remote.isNotEmpty()) {
            GlobalScope.launch {
                try {
                    withTimeoutOrNull(15_000) {
                        runCatching {
                            val api = Graph.api(server)
                            for (batch in remote.chunked(100)) {
                                api.delete(batch)
                            }
                        }
                    }
                } finally {
                    wipeNetwork()
                }
            }
        } else {
            wipeNetwork()
        }
    }
}
