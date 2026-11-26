package io.github.xiangwang2000.dnsshield.viewmodel

import io.github.xiangwang2000.dnsshield.data.BypassedApp
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AppListStateTest {
    private val apps = listOf(
        AppInfo(packageName = "org.example.mail", appName = "Mail", isBypassed = true),
        AppInfo(packageName = "org.example.maps", appName = "Maps", isBypassed = false),
        AppInfo(packageName = "com.example.chat", appName = "Chat", isBypassed = false)
    )

    @Test
    fun blankQueryKeepsEveryAppInOrder() {
        assertEquals(apps, filterApps(apps, ""))
        assertEquals(apps, filterApps(apps, "   "))
    }

    @Test
    fun queryMatchesAppNameCaseInsensitively() {
        assertEquals(listOf(apps[0]), filterApps(apps, "mAil"))
    }

    @Test
    fun queryMatchesPackageNameWithoutChangingOrder() {
        assertEquals(listOf(apps[0], apps[1]), filterApps(apps, "org.example"))
        assertEquals(listOf(apps[2]), filterApps(apps, "com.example"))
    }

    @Test
    fun bypassFlagsFollowTheSavedListInsteadOfThePreviousSnapshot() {
        val saved = listOf(BypassedApp(packageName = "org.example.maps", appName = "Maps"))

        val merged = applyBypassState(apps, saved)

        assertEquals(listOf(false, true, false), merged.map { it.isBypassed })
        assertEquals(apps.map { it.packageName }, merged.map { it.packageName })
        assertEquals(apps.map { it.appName }, merged.map { it.appName })
    }

    @Test
    fun missingSavedListClearsEveryBypassFlag() {
        assertTrue(applyBypassState(apps, null).none { it.isBypassed })
        assertTrue(applyBypassState(apps, emptyList()).none { it.isBypassed })
    }

    @Test
    fun pendingChangeCoversAddedAndRemovedExclusions() {
        val installed = setOf("org.example.mail", "org.example.maps", "com.example.chat")

        assertTrue(
            hasVisibleBypassChange(
                saved = setOf("org.example.mail", "org.example.maps"),
                applied = setOf("org.example.mail"),
                isInstalled = installed::contains
            )
        )
        assertTrue(
            hasVisibleBypassChange(
                saved = setOf("org.example.mail"),
                applied = setOf("org.example.mail", "com.example.chat"),
                isInstalled = installed::contains
            )
        )
    }

    @Test
    fun pendingChangeIgnoresPackagesThatAreNoLongerInstalled() {
        assertFalse(
            hasVisibleBypassChange(
                saved = setOf("org.example.mail"),
                applied = setOf("org.example.mail", "org.example.uninstalled"),
                isInstalled = setOf("org.example.mail")::contains
            )
        )
    }

    @Test
    fun identicalExclusionSetsHaveNoPendingChange() {
        assertFalse(
            hasVisibleBypassChange(
                saved = setOf("org.example.mail"),
                applied = setOf("org.example.mail"),
                isInstalled = { true }
            )
        )
    }
}
