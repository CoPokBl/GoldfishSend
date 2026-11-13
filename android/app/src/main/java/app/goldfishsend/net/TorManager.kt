package app.goldfishsend.net

import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.ServiceConnection
import android.os.IBinder
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import java.io.File
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import org.torproject.jni.TorService

/**
 * Runs Tor inside the app process (Guardian Project tor-android). The app binds to the library's in-process,
 * non-exported TorService. A bound service needs no foreground-service permission, and Tor lives exactly as long as
 * the app process does. Status broadcasts are package-scoped by the library, so other apps can't see them.
 */
object TorManager {
    sealed interface State {
        data object Off : State

        data object Starting : State

        data class Ready(val socksPort: Int) : State

        data class Failed(val reason: String?) : State
    }

    private val _state = MutableStateFlow<State>(State.Off)
    val state: StateFlow<State> = _state

    @Volatile
    private var service: TorService? = null
    private var connection: ServiceConnection? = null
    private var receiver: BroadcastReceiver? = null
    private var appContext: Context? = null

    /** Extra settings, applied on top of the library defaults (SOCKSPort auto, a control socket in the app dir). */
    private const val TORRC = """# Written by GoldfishSend.
ClientOnly 1
# Refuse SOCKS requests that carry a raw IP address. Hostnames are resolved by Tor, so there are no DNS leaks.
SafeSocks 1
TestSocks 0
AvoidDiskWrites 1
"""

    val socksPort: Int
        get() = (_state.value as? State.Ready)?.socksPort ?: 0

    @Synchronized
    fun start(ctx: Context) {
        if (connection != null) {
            return
        }
        val app = ctx.applicationContext
        appContext = app
        _state.value = State.Starting
        runCatching {
            val torrc = TorService.getTorrc(app)
            if (!torrc.exists() || torrc.readText() != TORRC) {
                torrc.parentFile?.mkdirs()
                torrc.writeText(TORRC)
            }
        }

        val r = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                when (intent.action) {
                    TorService.ACTION_STATUS -> when (intent.getStringExtra(TorService.EXTRA_STATUS)) {
                        TorService.STATUS_ON -> refresh()
                        TorService.STATUS_STARTING -> _state.value = State.Starting
                        TorService.STATUS_STOPPING, TorService.STATUS_OFF ->
                            if (connection != null) _state.value = State.Starting else _state.value = State.Off
                    }
                    TorService.ACTION_ERROR -> _state.value = State.Failed(intent.getStringExtra(Intent.EXTRA_TEXT))
                }
            }
        }
        receiver = r
        LocalBroadcastManager.getInstance(app).registerReceiver(
            r,
            IntentFilter().apply {
                addAction(TorService.ACTION_STATUS)
                addAction(TorService.ACTION_ERROR)
            },
        )

        val c = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
                service = (binder as? TorService.LocalBinder)?.service
                refresh()
            }

            override fun onServiceDisconnected(name: ComponentName?) {
                service = null
                _state.value = State.Starting
            }
        }
        connection = c
        app.bindService(Intent(app, TorService::class.java), c, Context.BIND_AUTO_CREATE)
    }

    @Synchronized
    fun stop() {
        val app = appContext ?: return
        connection?.let { runCatching { app.unbindService(it) } }
        receiver?.let { LocalBroadcastManager.getInstance(app).unregisterReceiver(it) }
        connection = null
        receiver = null
        service = null
        _state.value = State.Off
    }

    /** Re-reads readiness from the service: a SOCKS port is open and a circuit is established. */
    fun refresh() {
        val s = service ?: return
        val port = runCatching { s.socksPort }.getOrDefault(0)
        val circuit = runCatching { s.getInfo("status/circuit-established") }.getOrNull()?.trim() == "1"
        if (port > 0 && circuit) {
            _state.value = State.Ready(port)
        } else if (_state.value !is State.Failed) {
            _state.value = State.Starting
        }
    }

    /**
     * Blocks the calling (network) thread until Tor is ready, for up to [timeoutMs].
     * @return the SOCKS port, or 0 on timeout.
     */
    fun awaitReady(timeoutMs: Long): Int {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            socksPort.takeIf { it > 0 }?.let { return it }
            refresh()
            socksPort.takeIf { it > 0 }?.let { return it }
            Thread.sleep(250)
        }
        return 0
    }

    /** Deletes Tor's state (guards, cached consensus), so a wiped phone shows no trace of Tor use by this app. */
    fun deleteState(ctx: Context) {
        stop()
        runCatching { ctx.getDir(TorService::class.java.simpleName, Context.MODE_PRIVATE).deleteRecursively() }
        runCatching { File(ctx.cacheDir, TorService::class.java.simpleName).deleteRecursively() }
    }
}
