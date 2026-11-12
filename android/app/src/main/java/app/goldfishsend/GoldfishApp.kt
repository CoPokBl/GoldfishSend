package app.goldfishsend

import android.app.Application
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import androidx.core.content.ContextCompat
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import app.goldfishsend.core.AppVisibility
import app.goldfishsend.core.Graph
import app.goldfishsend.core.Notifier
import app.goldfishsend.core.launchSafe
import app.goldfishsend.security.AppLock
import app.goldfishsend.security.Wiper
import app.goldfishsend.work.MaintenanceWorker

class GoldfishApp : Application() {
    override fun onCreate() {
        super.onCreate()
        Graph.init(this)
        Notifier.ensureChannel(this)
        // Order matters: the restart and inactivity wipes must run before anything can open the DB.
        Wiper.checkBoot(this, fromBootBroadcast = false)
        Wiper.checkInactivity(this)

        ProcessLifecycleOwner.get().lifecycle.addObserver(object : DefaultLifecycleObserver {
            override fun onStart(owner: LifecycleOwner) {
                AppVisibility.foreground = true
                AppLock.onForeground()
                Wiper.checkInactivity(this@GoldfishApp)
            }

            override fun onStop(owner: LifecycleOwner) {
                AppVisibility.foreground = false
                AppLock.onBackground()
            }
        })

        ContextCompat.registerReceiver(
            this,
            object : BroadcastReceiver() {
                override fun onReceive(context: Context, intent: Intent) {
                    AppLock.onScreenOff()
                }
            },
            IntentFilter(Intent.ACTION_SCREEN_OFF),
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )

        if (Graph.prefs.onboarded) {
            MaintenanceWorker.schedule(this)
            if (!Graph.vault.hasPassphrase) {
                Graph.scope.launchSafe {
                    Graph.tryAutoUnlock()?.let { AppLock.afterUnlock(it) }
                }
            }
        }
    }
}
