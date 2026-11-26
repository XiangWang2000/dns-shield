package io.github.xiangwang2000.dnsshield

import android.app.Activity
import android.net.VpnService
import android.os.Bundle

/** Opens the system VPN consent flow for the isolated D04 device-test package. */
class D04VpnConsentActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val request = VpnService.prepare(this)
        if (request == null) {
            setResult(RESULT_OK)
            finish()
        } else {
            startActivityForResult(request, REQUEST_VPN_CONSENT)
        }
    }

    @Deprecated("The VPN consent activity returns a result through the platform API.")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: android.content.Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_VPN_CONSENT && resultCode == RESULT_OK && VpnService.prepare(this) == null) {
            setResult(RESULT_OK)
        } else {
            setResult(RESULT_CANCELED)
        }
        finish()
    }

    private companion object {
        const val REQUEST_VPN_CONSENT = 4041
    }
}
