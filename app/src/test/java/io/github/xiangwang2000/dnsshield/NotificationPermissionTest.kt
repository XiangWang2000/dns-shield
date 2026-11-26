package io.github.xiangwang2000.dnsshield

import android.os.Build
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class NotificationPermissionTest {
    @Test
    fun olderReleasesNeverAskForTheRuntimePermission() {
        assertFalse(requiresNotificationPermission(Build.VERSION_CODES.Q, permissionGranted = false))
        assertFalse(requiresNotificationPermission(Build.VERSION_CODES.S_V2, permissionGranted = false))
    }

    @Test
    fun android13AndAboveSkipTheRequestOnceGranted() {
        assertFalse(requiresNotificationPermission(Build.VERSION_CODES.TIRAMISU, permissionGranted = true))
        assertFalse(requiresNotificationPermission(Build.VERSION_CODES.UPSIDE_DOWN_CAKE, permissionGranted = true))
    }

    @Test
    fun android13AndAboveRequestThePermissionWhileItIsMissing() {
        assertTrue(requiresNotificationPermission(Build.VERSION_CODES.TIRAMISU, permissionGranted = false))
        assertTrue(requiresNotificationPermission(Build.VERSION_CODES.UPSIDE_DOWN_CAKE, permissionGranted = false))
    }
}
