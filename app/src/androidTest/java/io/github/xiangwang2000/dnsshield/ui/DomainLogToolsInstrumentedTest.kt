package io.github.xiangwang2000.dnsshield.ui

import android.accessibilityservice.AccessibilityService
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.os.Build
import android.os.Bundle
import android.os.SystemClock
import android.view.accessibility.AccessibilityNodeInfo
import android.view.accessibility.AccessibilityWindowInfo
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Scaffold
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.xiangwang2000.dnsshield.MainActivity
import io.github.xiangwang2000.dnsshield.service.DnsDecision
import io.github.xiangwang2000.dnsshield.service.DnsDecisionEvent
import io.github.xiangwang2000.dnsshield.service.DnsDecisionReason
import io.github.xiangwang2000.dnsshield.ui.theme.MyApplicationTheme
import io.github.xiangwang2000.dnsshield.viewmodel.DomainRuleUndoToken
import java.io.File
import java.util.concurrent.atomic.AtomicInteger
import org.junit.After
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class DomainLogToolsInstrumentedTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private var activity: MainActivity? = null

    @After
    fun finishActivity() {
        activity?.let { current -> instrumentation.runOnMainSync { current.finish() } }
    }

    @Test
    fun searchFiltersClearAndCopyFullDomainWithoutAddingAllowRule() {
        val allowCalls = AtomicInteger()
        val state = render(emptyList(), allowCalls)
        val clipboard = clipboardManager()
        val originalClip = clipboard.primaryClip
        try {
            assertTrue(hasText("目前沒有近期網域判斷"))
            assertTrue(hasText("網域被封鎖，或符合自訂允許規則時，結果會顯示在這裡。"))
            capture("domain-no-events.png")

            val events = listOf(
                DnsDecisionEvent(3, "updates.other.net", DnsDecision.BLOCK, DnsDecisionReason.PROTECTION_LIST, 3_000L),
                DnsDecisionEvent(1, "Ads.example.com", DnsDecision.BLOCK, DnsDecisionReason.PROTECTION_LIST, 2_000L),
                DnsDecisionEvent(2, "ads.news.example.com", DnsDecision.ALLOW, DnsDecisionReason.USER_RULE, 1_000L)
            )
            instrumentation.runOnMainSync { state.value = events }
            waitUntil { findNode("blocked_events") != null }

            assertSelected("domain_filter_all")
            setText("domain_log_search", "ADS")
            hideKeyboardIfOpen()
            waitUntil {
                hasText("Ads.example.com") &&
                    hasText("ads.news.example.com") &&
                    findNode("decision_event_3") == null
            }
            capture("domain-search-all.png")

            click("domain_filter_blocked")
            assertSelected("domain_filter_blocked")
            waitUntil { hasText("Ads.example.com") && findNode("decision_event_2") == null }
            capture("domain-search-blocked.png")

            click("domain_filter_allowed")
            assertSelected("domain_filter_allowed")
            waitUntil { hasText("ads.news.example.com") && findNode("decision_event_1") == null }

            setText("domain_log_search", "missing")
            hideKeyboardIfOpen()
            waitUntil { hasText("找不到符合條件的網域") }
            assertFalse("A non-empty event list with no matches has its own state", hasText("目前沒有近期網域判斷"))

            click("clear_domain_search")
            hideKeyboardIfOpen()
            waitUntil { hasText("ads.news.example.com") && findNode("clear_domain_search") == null }
            assertSelected("domain_filter_allowed")

            click("domain_filter_all")
            assertSelected("domain_filter_all")
            clickVisible("copy_domain_2", "blocked_events")
            val fullDomain = "ads.news.example.com"
            waitUntil { clipboardText(clipboard) == fullDomain }
            assertEquals(fullDomain, clipboardText(clipboard))
            assertEquals("Copying must not create an allow rule", 0, allowCalls.get())
            capture("domain-copy-full.png")
        } finally {
            restoreClipboard(clipboard, originalClip)
        }
    }

    private fun render(
        initialEvents: List<DnsDecisionEvent>,
        allowCalls: AtomicInteger
    ): MutableState<List<DnsDecisionEvent>> {
        val state = mutableStateOf(initialEvents)
        val intent = Intent(instrumentation.targetContext, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
        activity = instrumentation.startActivitySync(intent) as MainActivity
        val current = requireNotNull(activity)
        instrumentation.runOnMainSync {
            current.setContent {
                MyApplicationTheme {
                    Scaffold(modifier = Modifier.fillMaxSize()) { insets ->
                        Box(
                            modifier = Modifier
                                .fillMaxSize()
                                .padding(insets)
                                .semantics { testTagsAsResourceId = true }
                        ) {
                            LogsTab(
                                logs = emptyList(),
                                blockedEvents = state.value,
                                onClearLogs = {},
                                onAllowBlockedDomain = { domain ->
                                    allowCalls.incrementAndGet()
                                    DomainRuleUndoToken(domain, false, "test-revision", null)
                                },
                                onUndoDomainRule = { false },
                                userDomainRules = emptyList()
                            )
                        }
                    }
                }
            }
        }
        waitUntil { findNode("domain_log_search") != null }
        return state
    }

    private fun setText(tag: String, value: String) {
        val arguments = Bundle().apply {
            putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, value)
        }
        assertTrue("Cannot enter text in " + tag, requireNode(tag).performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, arguments))
        waitUntil { textIn(requireNode(tag)).contains(value) }
    }

    private fun hideKeyboardIfOpen() {
        val keyboardOpen = instrumentation.uiAutomation.windows.any {
            it.type == AccessibilityWindowInfo.TYPE_INPUT_METHOD
        }
        if (keyboardOpen) {
            instrumentation.uiAutomation.performGlobalAction(AccessibilityService.GLOBAL_ACTION_BACK)
            SystemClock.sleep(150)
        }
    }

    private fun click(tag: String) {
        assertTrue("Cannot click " + tag, requireNode(tag).performAction(AccessibilityNodeInfo.ACTION_CLICK))
        SystemClock.sleep(150)
    }

    private fun clickVisible(tag: String, scrollTag: String) {
        val deadline = SystemClock.uptimeMillis() + 7000
        while (SystemClock.uptimeMillis() < deadline) {
            val target = findNode(tag)
            if (target?.isVisibleToUser == true) {
                if (target.performAction(AccessibilityNodeInfo.ACTION_CLICK)) return
            } else {
                // Accessibility scrolling is asynchronous; a rejected repeat must not reverse it.
                requireNode(scrollTag).performAction(AccessibilityNodeInfo.ACTION_SCROLL_FORWARD)
            }
            SystemClock.sleep(100)
        }
        capture("unreachable-" + tag + ".png")
        fail("Cannot reach and click " + tag + " in " + scrollTag)
    }

    private fun assertSelected(tag: String) {
        waitUntil { findNode(tag)?.let { hasSelectedState(it) } == true }
        assertTrue("Filter does not expose selected semantics: " + tag, hasSelectedState(requireNode(tag)))
    }

    private fun hasSelectedState(node: AccessibilityNodeInfo): Boolean {
        if (!node.refresh()) return false
        val checked = if (Build.VERSION.SDK_INT >= 36) {
            node.checked == AccessibilityNodeInfo.CHECKED_STATE_TRUE
        } else {
            legacyChecked(node)
        }
        return node.isSelected || (node.isCheckable && checked)
    }

    // The Boolean accessor is required on API 24-35; API 36+ uses getChecked().
    @Suppress("DEPRECATION")
    private fun legacyChecked(node: AccessibilityNodeInfo): Boolean = node.isChecked

    private fun clipboardManager(): ClipboardManager =
        instrumentation.targetContext.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager

    private fun clipboardText(clipboard: ClipboardManager): String? =
        clipboard.primaryClip?.getItemAt(0)?.text?.toString()

    private fun restoreClipboard(clipboard: ClipboardManager, originalClip: ClipData?) {
        if (originalClip != null) {
            clipboard.setPrimaryClip(originalClip)
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            clipboard.clearPrimaryClip()
        } else {
            clipboard.setPrimaryClip(ClipData.newPlainText("", ""))
        }
    }

    private fun capture(name: String) {
        val baseDirectory = requireNotNull(instrumentation.targetContext.getExternalFilesDir(null))
        val directory = File(baseDirectory, "ui-additions-20261028")
        check(directory.isDirectory || directory.mkdirs())
        val screenshot = requireNotNull(instrumentation.uiAutomation.takeScreenshot())
        try {
            File(directory, name).outputStream().use { output ->
                assertTrue(screenshot.compress(Bitmap.CompressFormat.PNG, 100, output))
            }
        } finally {
            screenshot.recycle()
        }
    }

    private fun hasText(expected: String): Boolean {
        val root = instrumentation.uiAutomation.rootInActiveWindow ?: return false
        fun contains(node: AccessibilityNodeInfo): Boolean =
            node.text?.toString() == expected ||
                (0 until node.childCount).any { index ->
                    node.getChild(index)?.let { contains(it) } == true
                }
        return contains(root)
    }

    private fun findNode(tag: String): AccessibilityNodeInfo? {
        val root = instrumentation.uiAutomation.rootInActiveWindow ?: return null
        fun find(node: AccessibilityNodeInfo): AccessibilityNodeInfo? {
            if (node.viewIdResourceName == tag) return node
            for (index in 0 until node.childCount) {
                node.getChild(index)?.let { child -> find(child)?.let { return it } }
            }
            return null
        }
        return find(root)
    }

    private fun requireNode(tag: String): AccessibilityNodeInfo {
        waitUntil { findNode(tag) != null }
        return findNode(tag) ?: throw AssertionError("Missing accessible UI node: " + tag)
    }

    private fun textIn(node: AccessibilityNodeInfo): String = buildString {
        node.text?.let { append(it) }
        for (index in 0 until node.childCount) node.getChild(index)?.let { append(textIn(it)) }
    }

    private fun waitUntil(condition: () -> Boolean) {
        val deadline = SystemClock.uptimeMillis() + 7000
        while (SystemClock.uptimeMillis() < deadline) {
            if (condition()) return
            SystemClock.sleep(100)
        }
        assertTrue("UI condition timed out", condition())
    }
}