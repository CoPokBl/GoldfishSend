package app.goldfishsend

import android.content.Intent
import android.os.Bundle
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
import app.goldfishsend.ui.theme.GoldfishTheme
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch

class MainActivity : FragmentActivity() {
    private val pendingLink = MutableStateFlow<String?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        applySecureFlag()
        lifecycleScope.launch {
            Graph.prefs.version.collect { applySecureFlag() }
        }
        handleIntent(intent)
        setContent {
            val v by Graph.prefs.version.collectAsState()
            val p = Graph.prefs
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

    private fun handleIntent(intent: Intent?) {
        val data = intent?.dataString ?: return
        if (InviteLink.parse(data) != null) {
            pendingLink.value = data
        }
        // Don't keep the invite secret in the activity's intent.
        intent.data = null
    }

    /** FLAG_SECURE blocks screenshots and screen recording, and blanks the recent-apps preview. It's on by default. */
    private fun applySecureFlag() {
        if (Graph.prefs.screenshotProtection) {
            window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        } else {
            window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
    }
}
