package io.github.xiangwang2000.dnsshield.service

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class VpnUserIntentInstrumentedTest {
    private lateinit var context: Context
    private val preferencesName = "vpn_user_intent_persistence_test"

    @Before
    fun setUp() {
        context = InstrumentationRegistry.getInstrumentation().targetContext
        context.deleteSharedPreferences(preferencesName)
    }

    @After
    fun tearDown() {
        context.deleteSharedPreferences(preferencesName)
    }

    @Test
    fun explicitStopIsWrittenToThePreferencesFileBeforeReturning(): Unit = runBlocking {
        val preferences = context.getSharedPreferences(preferencesName, Context.MODE_PRIVATE)
        assertTrue(
            preferences.edit()
                .putBoolean(VPN_DESIRED_ENABLED_KEY, true)
                .putBoolean(VPN_EXPLICIT_CHOICE_KEY, false)
                .commit()
        )

        val store = VpnUserIntentStore(preferences)
        assertTrue(store.persist(store.stageExplicitStop()))

        val preferencesFile = File(
            context.applicationInfo.dataDir,
            "shared_prefs/$preferencesName.xml"
        )
        val xml = preferencesFile.readText(Charsets.UTF_8)
        assertTrue(xml.contains("name=\"$VPN_DESIRED_ENABLED_KEY\" value=\"false\""))
        assertTrue(xml.contains("name=\"$VPN_EXPLICIT_CHOICE_KEY\" value=\"true\""))
    }
}
