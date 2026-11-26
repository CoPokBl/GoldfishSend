package app.goldfishsend.security

import android.app.Activity
import android.app.AlertDialog
import android.os.Bundle
import app.goldfishsend.core.Graph
import app.goldfishsend.core.PanicResponse

/**
 * PanicKit responder (https://guardianproject.info/code/panickit/). A trigger app (for example Ripple) lists GoldfishSend
 * as a responder.
 *
 * - CONNECT: the trigger app asks to be trusted. The user approves it here and picks the response. Only the approved
 *   package may later cause anything destructive. Its identity comes from getCallingActivity(), which the trigger app
 *   can't spoof because it has to start us with startActivityForResult.
 * - TRIGGER: always locks (harmless, so any trigger may cause it). Erasing happens only if the caller is the approved
 *   trigger app and the user chose an erasing response.
 * - DISCONNECT: the approved app removes itself.
 *
 * Nothing happens unless the user has set a response (OFF by default). No permissions are needed.
 *
 * Connecting and disconnecting change the open profile's settings: while a decoy session is open, the decoy's own copy,
 * so a coercer can't quietly disarm (or re-point) the real profile's panic response. A trigger always acts on the real
 * profile's settings.
 */
class PanicResponderActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val prefs = Graph.uiPrefs
        val caller = callingActivity?.packageName
        when (intent?.action) {
            ACTION_TRIGGER -> {
                trigger(caller)
                finishAndRemoveTask()
            }
            ACTION_DISCONNECT -> {
                if (caller != null && caller == prefs.panicTrigger) {
                    prefs.panicTrigger = null
                    setResult(RESULT_OK)
                }
                finish()
            }
            ACTION_CONNECT -> connect(caller)
            else -> finish()
        }
    }

    private fun trigger(caller: String?) {
        val prefs = Graph.prefs
        val response = prefs.panicResponse
        if (response == PanicResponse.OFF) {
            return
        }
        Graph.lock()
        val trusted = caller != null && caller == prefs.panicTrigger
        if (!trusted) {
            return
        }
        when (response) {
            PanicResponse.WIPE_MESSAGES -> Wiper.wipeMessages()
            PanicResponse.WIPE_EVERYTHING -> Wiper.wipeEverything(applicationContext, killProcess = true)
            else -> Unit
        }
    }

    private fun connect(caller: String?) {
        if (caller == null) {
            // Not started with startActivityForResult, so we can't tell who's asking.
            finish()
            return
        }
        val label = runCatching { packageManager.getApplicationLabel(packageManager.getApplicationInfo(caller, 0)).toString() }
            .getOrDefault(caller)
        val options = arrayOf("Lock GoldfishSend", "Lock and erase all messages", "Erase everything")
        val values = arrayOf(PanicResponse.LOCK, PanicResponse.WIPE_MESSAGES, PanicResponse.WIPE_EVERYTHING)
        val prefs = Graph.uiPrefs
        var choice = values.indexOf(prefs.panicResponse).coerceAtLeast(0)
        AlertDialog.Builder(this)
            .setTitle("Let $label trigger GoldfishSend?")
            .setSingleChoiceItems(options, choice) { _, which -> choice = which }
            .setPositiveButton("Allow") { _, _ ->
                prefs.panicTrigger = caller
                prefs.panicResponse = values[choice]
                setResult(RESULT_OK)
                finish()
            }
            .setNegativeButton("Cancel") { _, _ ->
                setResult(RESULT_CANCELED)
                finish()
            }
            .setOnCancelListener {
                setResult(RESULT_CANCELED)
                finish()
            }
            .show()
    }

    companion object {
        const val ACTION_TRIGGER = "info.guardianproject.panic.action.TRIGGER"
        const val ACTION_CONNECT = "info.guardianproject.panic.action.CONNECT"
        const val ACTION_DISCONNECT = "info.guardianproject.panic.action.DISCONNECT"
    }
}
