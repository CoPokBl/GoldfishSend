package app.goldfishsend.core

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import app.goldfishsend.MainActivity
import app.goldfishsend.R

/** Message notifications. By default they reveal nothing: no name, no content, and nothing on the lock screen. */
object Notifier {
    private const val CHANNEL = "messages"
    private const val ID = 1

    fun ensureChannel(ctx: Context) {
        val ch = NotificationChannel(CHANNEL, "Messages", NotificationManager.IMPORTANCE_HIGH).apply {
            description = "New message alerts"
            lockscreenVisibility = Notification.VISIBILITY_SECRET
            setShowBadge(true)
        }
        ctx.getSystemService(NotificationManager::class.java).createNotificationChannel(ch)
    }

    fun newMessage(ctx: Context, contactName: String?, body: String?) {
        if (ContextCompat.checkSelfPermission(ctx, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED &&
            android.os.Build.VERSION.SDK_INT >= 33
        ) {
            return
        }
        val mode = Graph.prefs.notificationContent
        val title = when (mode) {
            NotificationContent.NONE -> "GoldfishSend"
            else -> contactName ?: "GoldfishSend"
        }
        val text = when (mode) {
            NotificationContent.NAME_AND_MESSAGE -> body ?: "New message"
            else -> "New message"
        }
        val pi = PendingIntent.getActivity(
            ctx, 0, Intent(ctx, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val public = NotificationCompat.Builder(ctx, CHANNEL)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle("GoldfishSend")
            .setContentText("New message")
            .build()
        val n = NotificationCompat.Builder(ctx, CHANNEL)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(title)
            .setContentText(text)
            .setContentIntent(pi)
            .setAutoCancel(true)
            .setCategory(NotificationCompat.CATEGORY_MESSAGE)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setVisibility(NotificationCompat.VISIBILITY_SECRET)
            .setPublicVersion(public)
            .setOnlyAlertOnce(false)
            .build()
        try {
            NotificationManagerCompat.from(ctx).notify(ID, n)
        } catch (e: SecurityException) {
            // Notification permission revoked.
        }
    }

    fun cancel(ctx: Context) {
        NotificationManagerCompat.from(ctx).cancel(ID)
    }

    fun cancelAll(ctx: Context) {
        NotificationManagerCompat.from(ctx).cancelAll()
    }
}
