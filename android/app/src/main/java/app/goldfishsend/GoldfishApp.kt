package app.goldfishsend

import android.app.Application
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.StrictMode
import androidx.core.content.ContextCompat
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import app.goldfishsend.core.AppVisibility
import app.goldfishsend.core.Graph
import app.goldfishsend.core.Notifier
import app.goldfishsend.core.ReceiveGuard
import app.goldfishsend.core.launchSafe
import app.goldfishsend.security.AppLock
import app.goldfishsend.security.Wiper
import app.goldfishsend.work.MaintenanceWorker

class GoldfishApp : Application() {
    override fun onCreate() {
        super.onCreate()
        if (BuildConfig.DEBUG) {
            // Logs (tag StrictMode) disk, network and slow calls on the main thread, which make the UI stutter.
            StrictMode.setThreadPolicy(StrictMode.ThreadPolicy.Builder().detectAll().penaltyLog().build())
        }
        Graph.init(this)
        ReceiveGuard.log = { android.util.Log.w("GoldfishSend", it) }
        Notifier.ensureChannel(this)
        // Order matters: the restart and inactivity wipes must run before anything can open the DB.
        Wiper.checkBoot(this, fromBootBroadcast = false)
        Wiper.checkInactivity(this)
        // Starts built-in Tor if the user turned it on (off by default).
        app.goldfishsend.net.NetStack.apply(this)

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
            // Older installs: make sure the duress and hidden-chat slots hold decoy data, so their presence can't be told.
            runCatching { Graph.vault.ensureDecoySlots() }
            MaintenanceWorker.schedule(this)
            if (!Graph.vault.requiresUserUnlock) {
                Graph.scope.launchSafe {
                    Graph.tryAutoUnlock()?.let { AppLock.afterUnlock(it) }
                }
            }
        }
    }
}
