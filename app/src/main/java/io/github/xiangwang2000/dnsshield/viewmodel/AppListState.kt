package io.github.xiangwang2000.dnsshield.viewmodel

import io.github.xiangwang2000.dnsshield.data.BypassedApp

/** Pure state transforms shared by the installed-app list and its pending-change prompt. */

internal fun applyBypassState(apps: List<AppInfo>, saved: List<BypassedApp>?): List<AppInfo> {
    val bypassedPackages = saved.orEmpty().mapTo(mutableSetOf()) { it.packageName }
    return apps.map { app -> app.copy(isBypassed = app.packageName in bypassedPackages) }
}

internal fun filterApps(apps: List<AppInfo>, query: String): List<AppInfo> =
    if (query.isBlank()) {
        apps
    } else {
        apps.filter {
            it.appName.contains(query, ignoreCase = true) ||
                it.packageName.contains(query, ignoreCase = true)
        }
    }

internal fun hasVisibleBypassChange(
    saved: Set<String>,
    applied: Set<String>,
    isInstalled: (String) -> Boolean
): Boolean = ((saved - applied) + (applied - saved)).any(isInstalled)
