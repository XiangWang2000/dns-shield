package io.github.xiangwang2000.dnsshield.service

import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import androidx.core.content.ContextCompat

/**
 * Keeps a started FGS record independent of Android's binding to VpnService.
 * A dead VPN can be removed from its process record during unbind before AMS
 * schedules sticky restarts. This service has no VPN binding, timer or worker.
 */
class VpnRecoveryService : Service() {
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val requestedState = VpnUserIntentStore(
            getSharedPreferences(VPN_SERVICE_PREFERENCES, Context.MODE_PRIVATE)
        ).snapshot()

        // Started normally by the already-foreground VPN, so a rejected request
        // can finish without a foreground-promotion obligation.
        if ((requestedState.hasExplicitChoice && !requestedState.desiredEnabled) ||
            VpnService.prepare(this) != null) {
            stopSelfResult(startId)
            return START_NOT_STICKY
        }
        DnsVpnService.createVpnNotificationChannel(this)
        val currentNotification = if (intent != null) {
            getSystemService(NotificationManager::class.java).activeNotifications
                .firstOrNull { it.id == DnsVpnService.NOTIFICATION_ID }?.notification
        } else null
        val notification = currentNotification
            ?: DnsVpnService.createVpnNotification(this, "DNS Shield 正在啟動防護…")
        try {
            if (Build.VERSION.SDK_INT >= 34) {
                startForeground(
                    DnsVpnService.NOTIFICATION_ID,
                    notification,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED
                )
            } else {
                startForeground(DnsVpnService.NOTIFICATION_ID, notification)
            }
        } catch (exception: SecurityException) {
            // Authorization can disappear between prepare() and promotion.
            if (VpnService.prepare(this) == null) throw exception
            stopSelfResult(startId)
            return START_NOT_STICKY
        }

        if (intent == null) {
            // The VPN service rechecks both persisted choice and system Always-on.
            ContextCompat.startForegroundService(
                this,
                Intent(this, DnsVpnService::class.java).setAction(VpnService.SERVICE_INTERFACE)
            )
        }
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null
}
