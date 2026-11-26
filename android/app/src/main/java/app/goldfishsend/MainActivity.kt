package app.goldfishsend

import android.content.Intent
import android.os.Bundle
import android.os.SystemClock
import android.view.View
import android.view.ViewTreeObserver
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import app.goldfishsend.core.Graph
import app.goldfishsend.proto.InviteLink
import app.goldfishsend.ui.AppRoot
import app.goldfishsend.ui.FirstFrame
import app.goldfishsend.ui.screens.ChatListPreload
import app.goldfishsend.ui.theme.GoldfishTheme
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.launch

class MainActivity : FragmentActivity() {
    private val pendingLink = MutableStateFlow<String?>(null)

    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        applySecureFlag()
        lifecycleScope.launch {
            // The open session's settings: a decoy has its own.
            Graph.session.flatMapLatest { (it?.prefs ?: Graph.prefs).version }.collect { applySecureFlag() }
        }
        handleIntent(intent)
        if (savedInstanceState == null) {
            holdFirstFrame()
            // Without app lock, the database is opening in the background already (GoldfishApp): load the chat list
            // while the activity and its first composition are being set up.
            if (Graph.prefs.onboarded && !Graph.vault.requiresUserUnlock) {
                lifecycleScope.launch { Graph.tryAutoUnlock()?.let { ChatListPreload.start(it) } }
            }
        } else {
            FirstFrame.ready = true
            FirstFrame.drawn = true
        }
        setContent {
            val session by Graph.session.collectAsState()
            val p = session?.prefs ?: Graph.prefs
            val v by p.version.collectAsState()
            v.let {
                GoldfishTheme(p.themeMode, p.amoled, p.dynamicColor) {
                    AppRoot(pendingLink)
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleIntent(intent)
    }

    /**
     * Invite links are never acted on automatically: AppRoot asks the user first (after unlock). The intent is replaced by
     * a clean one with no data and no extras, so the invite secret isn't kept in the activity, and Navigation can't act on
     * deep-link extras.
     */
    private fun handleIntent(intent: Intent?) {
        val data = intent?.dataString
        if (data != null && (InviteLink.parse(data) != null || InviteLink.isOutdated(data))) {
            pendingLink.value = data
        }
        if (intent != null && (intent.data != null || intent.extras != null)) {
            setIntent(Intent(this, MainActivity::class.java))
        }
    }

    /** Keeps the splash on screen until the first screen has its content (see [FirstFrame]). */
    private fun holdFirstFrame() {
        FirstFrame.ready = false
        FirstFrame.drawn = false
        val content = findViewById<View>(android.R.id.content)
        val deadline = SystemClock.uptimeMillis() + FirstFrame.MAX_HOLD_MS
        content.viewTreeObserver.addOnPreDrawListener(object : ViewTreeObserver.OnPreDrawListener {
            override fun onPreDraw(): Boolean {
                if (!FirstFrame.ready && SystemClock.uptimeMillis() < deadline) {
                    return false
                }
                content.viewTreeObserver.removeOnPreDrawListener(this)
                FirstFrame.drawn = true
                return true
            }
        })
    }

    /** FLAG_SECURE blocks screenshots and screen recording, and blanks the recent-apps preview. It's on by default. */
    private fun applySecureFlag() {
        if (Graph.uiPrefs.screenshotProtection) {
            window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        } else {
            window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
    }
}
