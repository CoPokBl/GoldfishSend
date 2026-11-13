package app.goldfishsend.work

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import app.goldfishsend.core.Graph
import app.goldfishsend.core.Mailboxes
import app.goldfishsend.core.Messenger
import app.goldfishsend.core.Outbox
import app.goldfishsend.core.Sweeper
import app.goldfishsend.core.launchSafe
import app.goldfishsend.security.Wiper
import java.util.concurrent.TimeUnit

/** Durable outbox delivery when the process isn't running. */
class OutboxWorker(ctx: Context, params: WorkerParameters) : CoroutineWorker(ctx, params) {
    override suspend fun doWork(): Result {
        // Locked with a passphrase: nothing we can do, and the unlock path kicks the outbox again.
        val s = Graph.realSession ?: Graph.tryAutoUnlock() ?: return Result.success()
        return try {
            Outbox.runAndSchedule(s)
            Result.success()
        } catch (e: Exception) {
            Result.retry()
        }
    }
}

/**
 * Periodic housekeeping: the inactivity wipe (works while locked), plus expiry sweep, mailbox refresh,
 * pool top-up, cleanup and re-sending unreceipted messages when unlocked.
 */
class MaintenanceWorker(ctx: Context, params: WorkerParameters) : CoroutineWorker(ctx, params) {
    override suspend fun doWork(): Result {
        Wiper.checkInactivity(applicationContext)
        if (!Graph.prefs.onboarded) {
            return Result.success()
        }
        runCatching { Sweeper.sweepLocked() }
        val s = Graph.realSession ?: Graph.tryAutoUnlock() ?: return Result.success()
        runCatching { Sweeper.sweep(s) }
        runCatching { Mailboxes.cleanup(s) }
        runCatching { Mailboxes.refreshAll(s) }
        runCatching { Mailboxes.ensurePool(s) }
        runCatching { Mailboxes.rotateContacts(s) }
        runCatching { app.goldfishsend.core.Groups.maintain(s) }
        runCatching { Messenger.resendUnreceipted(s) }
        runCatching { s.repo.vacuumIfNeeded() }
        return Result.success()
    }

    companion object {
        fun schedule(ctx: Context) {
            val req = PeriodicWorkRequestBuilder<MaintenanceWorker>(6, TimeUnit.HOURS).build()
            WorkManager.getInstance(ctx).enqueueUniquePeriodicWork("maintenance", ExistingPeriodicWorkPolicy.KEEP, req)
        }
    }
}

/** Disappearing-message alarm. */
class ExpiryReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val pending = goAsync()
        Graph.scope.launchSafe {
            try {
                val s = Graph.realSession ?: Graph.tryAutoUnlock()
                if (s != null) {
                    Sweeper.sweep(s)
                } else {
                    Sweeper.sweepLocked()
                }
            } finally {
                pending.finish()
            }
        }
    }
}

/** Device restart: optional message wipe (BOOT_COUNT is also checked at every app start). */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED) {
            Wiper.checkBoot(context, fromBootBroadcast = true)
            Wiper.checkInactivity(context)
            MaintenanceWorker.schedule(context)
        }
    }
}

/** Quick Settings panic tile: one tap destroys every key and all data. */
class PanicTileService : TileService() {
    override fun onStartListening() {
        qsTile?.apply {
            state = if (Graph.prefs.onboarded) Tile.STATE_ACTIVE else Tile.STATE_UNAVAILABLE
            label = "Panic wipe"
            updateTile()
        }
    }

    override fun onClick() {
        if (!Graph.prefs.onboarded) {
            return
        }
        Wiper.wipeEverything(applicationContext, killProcess = true)
        qsTile?.apply {
            state = Tile.STATE_UNAVAILABLE
            updateTile()
        }
    }
}
