package io.github.xiangwang2000.dnsshield.update

import android.app.Application
import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.xiangwang2000.dnsshield.BuildConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AppUpdateViewModelInstrumentedTest {
    @Test
    fun interruptedInstallWarningOnlyMatchesCurrentVersion() {
        val application = InstrumentationRegistry.getInstrumentation().targetContext.applicationContext as Application
        val preferences = application.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)
        val containedPreviousMarker = preferences.contains(INSTALL_STARTED_VERSION_CODE)
        val previousMarker = preferences.getInt(INSTALL_STARTED_VERSION_CODE, 0)

        try {
            assertTrue(preferences.edit().remove(INSTALL_STARTED_VERSION_CODE).commit())
            val withoutMarker = AppUpdateViewModel(application).state.value
            assertEquals(UpdatePhase.Idle, withoutMarker.phase)
            assertNull(withoutMarker.message)

            assertTrue(
                preferences.edit()
                    .putInt(INSTALL_STARTED_VERSION_CODE, BuildConfig.VERSION_CODE - 1)
                    .commit()
            )
            val markerFromPreviousVersion = AppUpdateViewModel(application).state.value
            assertEquals(UpdatePhase.Idle, markerFromPreviousVersion.phase)
            assertNull(markerFromPreviousVersion.message)

            assertTrue(
                preferences.edit()
                    .putInt(INSTALL_STARTED_VERSION_CODE, BuildConfig.VERSION_CODE)
                    .commit()
            )
            val markerFromCurrentVersion = AppUpdateViewModel(application).state.value
            assertEquals(UpdatePhase.Idle, markerFromCurrentVersion.phase)
            assertEquals(INTERRUPTED_INSTALL_MESSAGE, markerFromCurrentVersion.message)
        } finally {
            val editor = preferences.edit()
            if (containedPreviousMarker) {
                editor.putInt(INSTALL_STARTED_VERSION_CODE, previousMarker)
            } else {
                editor.remove(INSTALL_STARTED_VERSION_CODE)
            }
            editor.commit()
        }
    }

    private companion object {
        const val PREFERENCES_NAME = "app_updates"
        const val INSTALL_STARTED_VERSION_CODE = "install_started_from_version_code"
        const val INTERRUPTED_INSTALL_MESSAGE = "上次安裝更新已中斷，請重新檢查更新。"
    }
}
