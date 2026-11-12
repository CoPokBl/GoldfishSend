package app.goldfishsend.push

import android.content.Context
import app.goldfishsend.core.Graph
import app.goldfishsend.core.LockedInbox
import app.goldfishsend.core.Mailboxes
import app.goldfishsend.core.PushEndpointData
import app.goldfishsend.core.launchSafe
import app.goldfishsend.proto.ProtoJson
import org.unifiedpush.android.connector.UnifiedPush

data class Distributor(val packageName: String, val label: String)

/** UnifiedPush integration. The user only ever sees "Notifications via <app>". */
object PushHub {
    const val INSTANCE = "default"

    /** Distributors that route through Google's servers (flagged by the Security tab). */
    val GOOGLE_DISTRIBUTORS = setOf(
        "org.unifiedpush.distributor.fcm",
        "org.unifiedpush.distributor.fcm.gcm",
    )

    fun distributors(ctx: Context): List<Distributor> =
        UnifiedPush.getDistributors(ctx).filter { it != ctx.packageName }.map { Distributor(it, label(ctx, it)) }

    fun label(ctx: Context, pkg: String): String = try {
        val pm = ctx.packageManager
        @Suppress("DEPRECATION") pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString()
    } catch (e: Exception) {
        pkg
    }

    fun current(ctx: Context): String? = UnifiedPush.getAckDistributor(ctx) ?: UnifiedPush.getSavedDistributor(ctx)

    fun select(ctx: Context, pkg: String) {
        UnifiedPush.saveDistributor(ctx, pkg)
    }

    /** Fetches the server's VAPID key and registers with the selected distributor. The endpoint arrives in [GfPushService]. */
    suspend fun register(ctx: Context) {
        val info = Graph.api().info()
        Graph.prefs.pushStatus = "pending"
        UnifiedPush.register(ctx, INSTANCE, "GoldfishSend", info.vapidPublicKey)
    }

    fun unregister(ctx: Context) {
        runCatching { UnifiedPush.unregister(ctx, INSTANCE) }
        runCatching { UnifiedPush.removeDistributor(ctx) }
    }

    fun onEndpoint(data: PushEndpointData) {
        Graph.prefs.pushStatus = "ok"
        Graph.prefs.pushHost = runCatching { java.net.URI(data.url).host }.getOrNull()
        Graph.scope.launchSafe {
            val s = Graph.session.value ?: Graph.tryAutoUnlock()
            if (s == null) {
                LockedInbox.put(
                    LockedInbox.KIND_ENDPOINT,
                    ProtoJson.encodeToString(PushEndpointData.serializer(), data).toByteArray(),
                )
            } else {
                Mailboxes.onNewEndpoint(s, data)
            }
        }
    }
}
