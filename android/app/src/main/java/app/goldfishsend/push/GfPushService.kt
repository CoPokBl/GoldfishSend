package app.goldfishsend.push

import app.goldfishsend.core.Graph
import app.goldfishsend.core.Messenger
import app.goldfishsend.core.PushEndpointData
import app.goldfishsend.core.launchSafe
import org.unifiedpush.android.connector.FailedReason
import org.unifiedpush.android.connector.PushService
import org.unifiedpush.android.connector.data.PushEndpoint
import org.unifiedpush.android.connector.data.PushMessage

/** Receives UnifiedPush events. The connector has already done RFC 8291 decryption with keys it generated. */
class GfPushService : PushService() {
    override fun onNewEndpoint(endpoint: PushEndpoint, instance: String) {
        if (instance != PushHub.INSTANCE) {
            return
        }
        val keys = endpoint.pubKeySet ?: run {
            // Without Web Push keys the server can't encrypt to us, so refuse to proceed.
            Graph.prefs.pushStatus = "failed"
            return
        }
        PushHub.onEndpoint(PushEndpointData(endpoint.url, keys.pubKey, keys.auth))
    }

    override fun onMessage(message: PushMessage, instance: String) {
        if (instance != PushHub.INSTANCE || !message.decrypted) {
            return
        }
        val content = message.content
        Graph.scope.launchSafe { Messenger.onPushPayload(content) }
    }

    override fun onRegistrationFailed(reason: FailedReason, instance: String) {
        Graph.prefs.pushStatus = "failed"
    }

    override fun onUnregistered(instance: String) {
        Graph.prefs.pushStatus = "none"
    }
}
