package app.goldfishsend.core

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import app.goldfishsend.crypto.BucketKeys
import app.goldfishsend.work.ExpiryReceiver

/**
 * Disappearing-message enforcement. Expired rows are already hidden at query time. This removes them (crypto-shred)
 * and arms an alarm for the next expiry.
 */
object Sweeper {
    fun sweep(s: Session) {
        val now = System.currentTimeMillis()
        val n = s.repo.deleteExpired(now)
        BucketKeys.shredExpired(now)
        (s.messages.bucketStore as? BucketKeys.DbStore)?.pruneRows(now)
        if (n > 0) {
            s.db.notifyChanged()
            // Expired messages may still have a notification showing their text.
            Notifier.cancel(Graph.app)
        }
        schedule(s)
    }

    /**
     * Locked: the DB is closed, but finished expiry buckets can still be destroyed through the Keystore. Re-arms the alarm
     * for the next bucket end.
     */
    fun sweepLocked() {
        val now = System.currentTimeMillis()
        if (BucketKeys.shredExpired(now) > 0) {
            Notifier.cancel(Graph.app)
        }
        arm(BucketKeys.nextBucketEnd())
    }

    fun schedule(s: Session) {
        val ctx = Graph.app
        val am = ctx.getSystemService(Context.ALARM_SERVICE) as AlarmManager
        val pi = PendingIntent.getBroadcast(
            ctx, 1, Intent(ctx, ExpiryReceiver::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        arm(s.repo.nextExpiry())
    }

    private fun arm(next: Long?) {
        val ctx = Graph.app
        val am = ctx.getSystemService(Context.ALARM_SERVICE) as AlarmManager
        val pi = PendingIntent.getBroadcast(
            ctx, 1, Intent(ctx, ExpiryReceiver::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        if (next == null) {
            am.cancel(pi)
            return
        }
        val at = maxOf(next, System.currentTimeMillis() + 1_000)
        if (Build.VERSION.SDK_INT < 31 || am.canScheduleExactAlarms()) {
            am.setExactAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, at, pi)
        } else {
            am.setAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, at, pi)
        }
    }
}
