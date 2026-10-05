package io.github.xiangwang2000.dnsshield

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.Process
import android.os.SystemClock
import android.util.Log
import io.github.xiangwang2000.dnsshield.service.VPN_SERVICE_PREFERENCES
import io.github.xiangwang2000.dnsshield.service.VpnUserIntentStore
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.flow.first
import io.github.xiangwang2000.dnsshield.service.DnsVpnService
import io.github.xiangwang2000.dnsshield.service.VpnLifecycleState
import java.io.File

/** Writes an explicit D15 intent and immediately terminates the isolated app process. */
class D15ProcessDeathActivity : Activity() {
    companion object {
        const val EXTRA_INTENT_OPERATION = "intent_operation"
        const val OPERATION_SERVICE_STOP = "service_stop"
        const val OPERATION_TERMINATE_STOPPED = "terminate_stopped"
        const val OPERATION_EXPLICIT_STOP = "explicit_stop"
        const val OPERATION_AUTHORIZATION_REVOKE = "authorization_revoke"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        check(packageName.endsWith(".d15test"))

        val operation = intent.getStringExtra(EXTRA_INTENT_OPERATION)
        if (operation == null) {
            val processId = Process.myPid()
            Log.i("D15ProcessDeath", "Scheduled self SIGKILL for pid=$processId in 5000ms")
            Handler(Looper.getMainLooper()).postDelayed({
                Log.i("D15ProcessDeath", "Sending self SIGKILL for pid=$processId")
                Process.killProcess(processId)
            }, 5_000)
            finish()
            return
        }
        if (operation == OPERATION_SERVICE_STOP || operation == OPERATION_TERMINATE_STOPPED) {
            if (operation == OPERATION_SERVICE_STOP) {
                check(DnsVpnService.lifecycleStateFlow.value == VpnLifecycleState.RUNNING)
                startService(Intent(this, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_STOP))
            } else {
                check(DnsVpnService.lifecycleStateFlow.value == VpnLifecycleState.STOPPED)
            }
            // Remove the activity record before SIGKILL so Android cannot relaunch this test action.
            finish()
            Thread({
                try {
                    runBlocking {
                        withTimeout(15_000) {
                            DnsVpnService.lifecycleStateFlow.first { it == VpnLifecycleState.STOPPED }
                        }
                    }
                    val xml = File(applicationInfo.dataDir, "shared_prefs/$VPN_SERVICE_PREFERENCES.xml")
                        .readText(Charsets.UTF_8)
                    check(xml.contains("name=\"desired_enabled\" value=\"false\""))
                    check(xml.contains("name=\"has_explicit_choice\" value=\"true\""))
                    Log.i("D15ProcessDeath", "Actual service STOP/revoke completed with durable false intent; operation=$operation; immediate self SIGKILL pid=${Process.myPid()}")
                    Process.killProcess(Process.myPid())
                } catch (exception: Exception) {
                    Log.e("D15ProcessDeath", "Service STOP/revoke was not durably confirmed; no SIGKILL", exception)
                    runOnUiThread { finish() }
                }
            }, "D15-service-stop-confirmation").start()
            return
        }
        if (operation != OPERATION_EXPLICIT_STOP && operation != OPERATION_AUTHORIZATION_REVOKE) {
            Log.e("D15ProcessDeath", "Unsupported intent operation=$operation; process remains alive")
            finish()
            return
        }

        val store = VpnUserIntentStore(
            getSharedPreferences(VPN_SERVICE_PREFERENCES, Context.MODE_PRIVATE)
        )
        val intentWrite = if (operation == OPERATION_EXPLICIT_STOP) {
            store.stageExplicitStop()
        } else {
            store.stageAuthorizationRevoke()
        }
        val processId = Process.myPid()
        finish()
        Thread({
            val persistStartedAt = SystemClock.elapsedRealtime()
            val result = runCatching { runBlocking { store.persist(intentWrite) } }
            val persistDurationMs = SystemClock.elapsedRealtime() - persistStartedAt
            Handler(Looper.getMainLooper()).post {
                if (result.getOrNull() != true) {
                    Log.e(
                        "D15ProcessDeath",
                        "Intent operation=$operation was not persisted; persistDurationMs=$persistDurationMs; process remains alive",
                        result.exceptionOrNull()
                    )
                    finish()
                    return@post
                }

                Log.i(
                    "D15ProcessDeath",
                    "Persisted direct store operation=$operation (not system onRevoke); persistDurationMs=$persistDurationMs; sending self SIGKILL for pid=$processId"
                )
                Process.killProcess(processId)
            }
        }, "D15-intent-persistence").start()
    }
}
