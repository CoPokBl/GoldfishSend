package app.goldfishsend.core

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import app.goldfishsend.work.ExpiryReceiver

/**
 * Disappearing-message enforcement. Expired rows are already hidden at query time. This removes them (crypto-shred)
 * and arms an alarm for the next expiry.
 */
object Sweeper {
    fun sweep(s: Session) {
        val n = s.repo.deleteExpired(System.currentTimeMillis())
        if (n > 0) {
            s.db.notifyChanged()
        }
        schedule(s)
    }

    fun schedule(s: Session) {
        val ctx = Graph.app
        val am = ctx.getSystemService(Context.ALARM_SERVICE) as AlarmManager
        val pi = PendingIntent.getBroadcast(
            ctx, 1, Intent(ctx, ExpiryReceiver::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val next = s.repo.nextExpiry()
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
