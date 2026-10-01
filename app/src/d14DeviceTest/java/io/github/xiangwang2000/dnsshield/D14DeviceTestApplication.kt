package io.github.xiangwang2000.dnsshield

import android.app.Application
import android.os.SystemClock

/** Captures the first app lifecycle timestamp for D14 cold-process measurements. */
class D14DeviceTestApplication : Application() {
    override fun onCreate() {
        processCreatedAtElapsedRealtimeNanos = SystemClock.elapsedRealtimeNanos()
        super.onCreate()
    }

    companion object {
        @Volatile
        var processCreatedAtElapsedRealtimeNanos: Long = 0L
            private set
    }
}
