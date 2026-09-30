package io.github.xiangwang2000.dnsshield

import android.app.Activity
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.Process
import android.util.Log

/** Terminates the isolated app without an active instrumentation or shell signal. */
class D15ProcessDeathActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        check(packageName.endsWith(".d15test"))
        val processId = Process.myPid()
        Log.i("D15ProcessDeath", "Scheduled self SIGKILL for pid=$processId in 5000ms")
        Handler(Looper.getMainLooper()).postDelayed({
            Log.i("D15ProcessDeath", "Sending self SIGKILL for pid=$processId")
            Process.killProcess(processId)
        }, 5_000)
        finish()
    }
}
