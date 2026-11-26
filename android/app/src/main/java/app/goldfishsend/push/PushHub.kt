package app.goldfishsend.push

import android.content.Context
import app.goldfishsend.core.Graph
import app.goldfishsend.core.LockedInbox
import app.goldfishsend.core.Mailboxes
import app.goldfishsend.core.PushEndpointData
import app.goldfishsend.core.Session
import app.goldfishsend.core.launchSafe
import app.goldfishsend.proto.ProtoJson
import app.goldfishsend.proto.Rand
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.Serializable
import org.unifiedpush.android.connector.UnifiedPush

data class Distributor(val packageName: String, val label: String)

/** An endpoint change that arrived while locked, kept in the [LockedInbox] until the next unlock. */
@Serializable
data class InstanceEndpoint(val instance: String, val endpoint: PushEndpointData)

/**
 * UnifiedPush integration. The user only ever sees "Notifications via <app>".
 *
 * Every mailbox has its own UnifiedPush instance, so its own endpoint and Web Push keys: the server sees a different
 * endpoint for each contact's and each group's mailbox, and for each new mailbox a rotation brings, and can't link them
 * by it. A spare instance is registered ahead of the next mailbox ([fresh]). Once a mailbox is gone its instance is
 * unregistered ([sweep]) and never reused, because the server has seen its endpoint.
 */
object PushHub {
    /** How long a new instance may take to get its endpoint from the distributor. */
    private const val REGISTER_TIMEOUT_MS = 60_000L

    /** Distributors that route through Google's servers (flagged by the Security tab). */
    val GOOGLE_DISTRIBUTORS = setOf(
        "org.unifiedpush.distributor.fcm",
        "org.unifiedpush.distributor.fcm.gcm",
    )

    /** Instances waiting for their first endpoint. Null: the distributor refused it. */
    private val waiters = ConcurrentHashMap<String, CompletableDeferred<PushEndpointData?>>()

    /** Instances we unregistered ourselves, whose "unregistered" callback is expected. */
    private val dropped = ConcurrentHashMap.newKeySet<String>()

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

    /** A random name, so nothing about the mailbox shows in it. */
    internal fun newInstanceName(): String = "m" + Rand.bytes(8).joinToString("") { "%02x".format(it) }

    private fun newSpare(s: Session): String = newInstanceName().also { s.repo.addPushInstance(it) }

    /** Our server's VAPID key, which every registration needs. */
    private suspend fun vapid(): String = Graph.api().info().vapidPublicKey

    /**
     * Registers every instance with the selected distributor again: at setup, after choosing another push app, or when
     * the user asks. With none yet, a spare is registered for the first mailbox. Endpoints arrive in [GfPushService];
     * one that changed makes that mailbox move to it ([Mailboxes.onNewEndpoint]).
     */
    suspend fun register(ctx: Context, s: Session) {
        if (s.decoy) {
            return
        }
        val key = vapid()
        Graph.prefs.pushStatus = "pending"
        val names = s.repo.pushInstances().map { it.name }.ifEmpty { listOf(newSpare(s)) }
        for (n in names) {
            UnifiedPush.register(ctx, n, "GoldfishSend", key)
        }
    }

    /** Registers one instance again (the server says it can't reach its endpoint any more). */
    suspend fun reregister(instance: String) {
        UnifiedPush.register(Graph.app, instance, "GoldfishSend", vapid())
    }

    /**
     * An instance and its endpoint for a new mailbox: the spare, registered now if it has no endpoint yet. Null if no
     * push app is chosen, or the distributor refused the registration (some limit how many an app may have) or didn't
     * answer in time. The spare stays for the next try.
     */
    suspend fun fresh(s: Session): Pair<String, PushEndpointData>? {
        if (s.decoy || current(Graph.app) == null) {
            return null
        }
        val spare = s.repo.spareInstance()
        spare?.endpoint?.let { return spare.name to decode(it) }
        val name = spare?.name ?: newSpare(s)
        val waiter = CompletableDeferred<PushEndpointData?>()
        waiters[name] = waiter
        try {
            UnifiedPush.register(Graph.app, name, "GoldfishSend", vapid())
            val ep = withTimeoutOrNull(REGISTER_TIMEOUT_MS) { waiter.await() } ?: return null
            return name to ep
        } finally {
            waiters.remove(name, waiter)
        }
    }

    fun decode(json: String): PushEndpointData = ProtoJson.decodeFromString(PushEndpointData.serializer(), json)

    fun encode(ep: PushEndpointData): String = ProtoJson.encodeToString(PushEndpointData.serializer(), ep)

    /**
     * Unregisters the instances whose mailbox is gone (deleted, blocked, replaced and drained), so nothing can wake us
     * through their endpoints any more. Safe to call often.
     */
    fun sweep(s: Session) {
        if (s.decoy) {
            return
        }
        for (n in s.repo.takeOrphanInstances()) {
            dropped += n
            runCatching { UnifiedPush.unregister(Graph.app, n) }
        }
    }

    /**
     * Unregisters every instance no mailbox is on, spares included: switching servers, whose push (VAPID) key the spare
     * was registered with.
     */
    fun dropUnused(s: Session) {
        for (n in s.repo.takeInstancesWithoutMailbox()) {
            dropped += n
            runCatching { UnifiedPush.unregister(Graph.app, n) }
        }
    }

    /** An endpoint arrived for an instance we don't have (its mailbox is gone): unregister it too. */
    fun dropStray(instance: String) {
        dropped += instance
        runCatching { UnifiedPush.unregister(Graph.app, instance) }
    }

    /** Every instance, and the distributor choice (the wipe). */
    fun unregister(ctx: Context) {
        runCatching { UnifiedPush.removeDistributor(ctx) }
    }

    // --- events from GfPushService ---

    fun onEndpoint(instance: String, data: PushEndpointData) {
        Graph.prefs.pushStatus = "ok"
        Graph.prefs.pushHost = runCatching { java.net.URI(data.url).host }.getOrNull()
        Graph.scope.launchSafe {
            val s = Graph.realSession ?: Graph.tryAutoUnlock()
            if (s == null) {
                LockedInbox.putEndpoint(instance, ProtoJson.encodeToString(InstanceEndpoint.serializer(), InstanceEndpoint(instance, data)).toByteArray())
            } else {
                Mailboxes.onNewEndpoint(s, instance, data)
            }
        }
    }

    /** Called once [instance]'s endpoint is stored, for a mailbox creation waiting on it. */
    internal fun endpointStored(instance: String, data: PushEndpointData) {
        waiters[instance]?.complete(data)
    }

    fun onRegistrationFailed(instance: String) {
        Graph.prefs.pushStatus = "failed"
        waiters[instance]?.complete(null)
    }

    fun onUnregistered(instance: String) {
        if (dropped.remove(instance)) {
            return
        }
        // The distributor dropped it (the push app was removed, or its registrations reset). The last endpoint is kept:
        // registering again brings a new one, and the mailbox moves to it if it changed.
        waiters[instance]?.complete(null)
        Graph.prefs.pushStatus = "none"
    }
}
