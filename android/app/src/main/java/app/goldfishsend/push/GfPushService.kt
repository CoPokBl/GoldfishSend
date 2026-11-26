package app.goldfishsend.push

import app.goldfishsend.core.Graph
import app.goldfishsend.core.Messenger
import app.goldfishsend.core.PushEndpointData
import app.goldfishsend.core.launchSafe
import org.unifiedpush.android.connector.FailedReason
import org.unifiedpush.android.connector.PushService
import org.unifiedpush.android.connector.data.PushEndpoint
import org.unifiedpush.android.connector.data.PushMessage

/**
 * Receives UnifiedPush events, for every instance (one per mailbox, see [PushHub]). The connector has already done
 * RFC 8291 decryption with the keys it generated for that instance.
 */
class GfPushService : PushService() {
    override fun onNewEndpoint(endpoint: PushEndpoint, instance: String) {
        val keys = endpoint.pubKeySet ?: run {
            // Without Web Push keys the server can't encrypt to us, so refuse to proceed.
            PushHub.onRegistrationFailed(instance)
            return
        }
        PushHub.onEndpoint(instance, PushEndpointData(endpoint.url, keys.pubKey, keys.auth))
    }

    override fun onMessage(message: PushMessage, instance: String) {
        if (!message.decrypted) {
            return
        }
        val content = message.content
        Graph.scope.launchSafe { Messenger.onPushPayload(content, instance) }
    }

    override fun onRegistrationFailed(reason: FailedReason, instance: String) {
        PushHub.onRegistrationFailed(instance)
    }

    override fun onUnregistered(instance: String) {
        PushHub.onUnregistered(instance)
    }
}
