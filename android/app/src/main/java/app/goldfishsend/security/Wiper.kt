package app.goldfishsend.security

import android.content.Context
import android.provider.Settings
import androidx.work.WorkManager
import app.goldfishsend.core.Graph
import app.goldfishsend.core.LockedInbox
import app.goldfishsend.core.Mailboxes
import app.goldfishsend.core.NetPrefs
import app.goldfishsend.core.Shredder
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
     * so remnants of old sealed pushes can never be opened again. While unlocked the rows are deleted and the message root
     * key is replaced too, so stale copies of them left in flash can't be opened either.
     */
    fun wipeMessages() {
        val s = Graph.realSession
        LockedInbox.clear()
        if (s != null) {
            s.repo.wipeAllMessages()
            // If it can't happen now (the phone itself is locked), it's still pending and happens at the next chance.
            runCatching { Shredder.rotate(s) }
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
        if (count != -1 && count != prefs.lastBootCount) {
            prefs.lastBootCount = count
        }
        if (rebooted && prefs.wipeOnReboot && prefs.onboarded) {
            wipeMessages()
        }
    }

    /**
     * Records that the user is here (interactive unlock, or the app is in the foreground while unlocked). The inactivity
     * limit is checked first ([Presence.onPresent]): once it has passed, being here erases instead of resetting the clock.
     */
    fun recordPresence(ctx: Context = Graph.app) {
        if (!checkInactivity(ctx)) {
            mark(ctx)
        }
    }

    private fun mark(ctx: Context) {
        Graph.prefs.presence = Presence.Mark(
            System.currentTimeMillis(),
            android.os.SystemClock.elapsedRealtime(),
            Settings.Global.getInt(ctx.contentResolver, Settings.Global.BOOT_COUNT, -1),
        )
    }

    /**
     * Dead-man switch: wipe everything if the user hasn't been present for N days. Background wake-ups don't count.
     * Returns true if it wiped.
     */
    fun checkInactivity(ctx: Context): Boolean {
        val days = Graph.prefs.inactivityWipeDays
        if (days <= 0 || !Graph.prefs.onboarded) {
            return false
        }
        val last = Graph.prefs.presence
        if (last == null) {
            // First run with the feature (or an upgrade): start the clock now rather than erasing.
            mark(ctx)
            return false
        }
        val boot = Settings.Global.getInt(ctx.contentResolver, Settings.Global.BOOT_COUNT, -1)
        val now = Presence.onPresent(last, days, System.currentTimeMillis(), android.os.SystemClock.elapsedRealtime(), boot)
        if (now == Presence.OnPresent.WIPE) {
            wipeEverything(ctx)
            return true
        }
        return false
    }

    /**
     * Panic wipe: destroy every key, delete the DB, the locked inbox and settings, and unregister push.
     * Inbound mailboxes are then deleted on the server on a best-effort basis, from a snapshot taken before the keys went.
     */
    @OptIn(kotlinx.coroutines.DelicateCoroutinesApi::class)
    fun wipeEverything(ctx: Context, killProcess: Boolean = false) {
        val s = Graph.realSession
        val remote = s?.let { runCatching { it.repo.allMailboxes().map(Mailboxes::item) }.getOrNull() }.orEmpty()
        val server = Graph.prefs.serverUrl
        // Captured before the settings go: the deletes still verify the server's identity. Without a pin they're skipped
        // (they'd only reveal the secrets to whoever answers).
        val serverKey = Graph.prefs.serverKey
        // Every wipe, not only the panic ones that end the process: nothing started before it may go on talking to a
        // server (perhaps no longer through Tor, once the settings are gone) or write settings back afterwards.
        Graph.stopBackground()
        Graph.lock()
        Graph.vault.destroyAll()
        app.goldfishsend.crypto.BucketKeys.destroyAll()
        // Anything copied from a chat goes too.
        runCatching {
            val cm = ctx.getSystemService(android.content.ClipboardManager::class.java)
            cm.clearPrimaryClip()
        }
        Db.deleteFiles(ctx)
        Db.deleteFiles(ctx, Db.DECOY_NAME)
        LockedInbox.clear()
        PushHub.unregister(ctx)
        Notifier.cancelAll(ctx)
        // Again, for anything enqueued while the above ran.
        runCatching { WorkManager.getInstance(ctx).cancelAllWork() }
        // Store the connection mode explicitly, so the best-effort deletes below still go through Tor or Orbot
        // after the main preferences (which hold the legacy Orbot flag) are cleared. Network state goes last.
        NetPrefs.proxyMode = NetPrefs.proxyMode
        Graph.prefs.clear()
        val wipeNetwork = {
            NetPrefs.clear()
            TorManager.deleteState(ctx)
            Graph.resetHttp()
            if (killProcess) {
                // Panic wipe: nothing of this process (decrypted strings, caches) survives in memory.
                android.os.Process.killProcess(android.os.Process.myPid())
            }
        }
        if (remote.isNotEmpty() && serverKey != null) {
            GlobalScope.launch {
                try {
                    withTimeoutOrNull(15_000) {
                        // One mailbox per request, each on its own connection, as every owner request goes. There's no
                        // time left to spread them out, so the server sees them arrive together: it learns which
                        // mailboxes were ours only as they stop existing.
                        val api = Graph.ownerApi(server, app.goldfishsend.net.ServerPin(serverKey))
                        for (item in remote) {
                            runCatching { api.delete(item) }
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
