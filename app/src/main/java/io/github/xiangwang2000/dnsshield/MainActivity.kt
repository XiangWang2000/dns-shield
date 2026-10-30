package io.github.xiangwang2000.dnsshield

import android.app.Activity
import android.net.VpnService
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.DialogProperties
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import io.github.xiangwang2000.dnsshield.blocking.DomainPolicyDiagnostics
import io.github.xiangwang2000.dnsshield.blocking.DomainRuleAction
import io.github.xiangwang2000.dnsshield.blocking.PublicSuffixResolverStatus
import io.github.xiangwang2000.dnsshield.blocking.RuleBlocklistSource
import io.github.xiangwang2000.dnsshield.blocking.RulePolicyStatus
import io.github.xiangwang2000.dnsshield.data.DnsServer
import io.github.xiangwang2000.dnsshield.data.UserDomainRuleEntity
import io.github.xiangwang2000.dnsshield.service.DnsDecisionEvent
import io.github.xiangwang2000.dnsshield.service.UnderlyingNetworkConnectivity
import io.github.xiangwang2000.dnsshield.service.DnsDiagnosticsSnapshot
import io.github.xiangwang2000.dnsshield.service.DnsVpnService
import io.github.xiangwang2000.dnsshield.service.DohEndpointConfiguration
import io.github.xiangwang2000.dnsshield.service.VpnLifecycleState
import io.github.xiangwang2000.dnsshield.service.isIpv4Literal
import io.github.xiangwang2000.dnsshield.ui.DomainRulesTab
import io.github.xiangwang2000.dnsshield.ui.ExemptAppsTab
import io.github.xiangwang2000.dnsshield.ui.LogsTab
import io.github.xiangwang2000.dnsshield.ui.theme.*
import io.github.xiangwang2000.dnsshield.viewmodel.DomainRuleUndoToken
import io.github.xiangwang2000.dnsshield.viewmodel.DnsShieldUiState
import io.github.xiangwang2000.dnsshield.viewmodel.DnsVpnViewModel
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    override fun onStart() {
        super.onStart()
        DnsVpnService.setUiForeground(true)
    }

    override fun onStop() {
        DnsVpnService.setUiForeground(false)
        super.onStop()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.dark(android.graphics.Color.TRANSPARENT),
            navigationBarStyle = SystemBarStyle.dark(android.graphics.Color.TRANSPARENT)
        )
        setContent {
            MyApplicationTheme {
                Scaffold(
                    modifier = Modifier
                        .fillMaxSize()
                        .testTag("main_scaffold"),
                    containerColor = MaterialTheme.colorScheme.background
                ) { innerPadding ->
                    DnsShieldDashboard(
                        modifier = Modifier.padding(innerPadding)
                    )
                }
            }
        }
    }

    override fun onTrimMemory(level: Int) {
        super.onTrimMemory(level)
        if (level >= android.content.ComponentCallbacks2.TRIM_MEMORY_UI_HIDDEN) {
            try {
                io.github.xiangwang2000.dnsshield.viewmodel.AppIconCache.clear()
            } catch (e: Exception) {
                android.util.Log.w("MainActivity", "Failed to clear AppIconCache", e)
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DnsShieldDashboard(
    modifier: Modifier = Modifier,
    viewModel: DnsVpnViewModel = viewModel()
) {
    val context = LocalContext.current
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()

    // Register Launcher for VpnService Intent confirmation (System Permission Interceptor)
    val vpnPrepareLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult(),
        onResult = { result ->
            if (result.resultCode == Activity.RESULT_OK) {
                // Permission granted, safely trigger VPN toggle action
                viewModel.toggleVpn(context)
            } else {
                Toast.makeText(context, "同意 Android 的 VPN 連線要求後，才能開啟 DNS 防護。", Toast.LENGTH_SHORT).show()
            }
        }
    )

    // Clear, clean, authorized action handler for toggling the VPN protection layer
    val handleToggleVpn = {
        when (uiState.vpnLifecycleState) {
            VpnLifecycleState.RUNNING,
            VpnLifecycleState.STARTING -> viewModel.toggleVpn(context)
            VpnLifecycleState.STOPPING -> Unit
            VpnLifecycleState.STOPPED,
            VpnLifecycleState.FAILED -> {
                try {
                    val vpnIntent = VpnService.prepare(context)
                    if (vpnIntent != null) {
                        vpnPrepareLauncher.launch(vpnIntent)
                    } else {
                        viewModel.toggleVpn(context)
                    }
                } catch (e: Exception) {
                    android.util.Log.e("MainActivity", "Failed to prepare/launch VPN service", e)
                    Toast.makeText(context, "無法開啟 VPN，請稍後重試。${e.localizedMessage.orEmpty()}", Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    DnsShieldScreen(
        uiState = uiState,
        onToggleVpn = handleToggleVpn,
        onSelectDns = { viewModel.selectDnsServer(it) },
        onAddCustomDns = { name, pri, sec, allowPlaintext, primaryDoh, primaryBootstrap, secondaryDoh, secondaryBootstrap ->
            viewModel.addCustomDnsServer(
                name,
                pri,
                sec,
                allowPlaintext,
                primaryDoh,
                primaryBootstrap,
                secondaryDoh,
                secondaryBootstrap
            )
        },
        onDeleteDns = { viewModel.deleteDnsServer(it) },
        onSetPlaintextFallback = { server, allow -> viewModel.setPlaintextFallback(server, allow) },
        onSearchChange = { viewModel.setSearchQuery(it) },
        onToggleBypass = { pkg, name, active -> viewModel.toggleAppBypass(pkg, name, active) },
        onInfoCardDismiss = { viewModel.setInfoCardVisible(false) },
        onInfoCardRestore = { viewModel.setInfoCardVisible(true) },
        onClearLogs = { viewModel.clearVpnLogs() },
        onRestartVpn = { viewModel.restartVpn(context) },
        onLoadAppsIfNeeded = { viewModel.refreshInstalledAppsIfNeeded() },
        onRetryLoadApps = { viewModel.refreshInstalledApps() },
        onDomainRuleSearchChange = viewModel::setDomainRuleSearchQuery,
        onSaveDomainRule = viewModel::saveDomainRule,
        onDeleteDomainRule = viewModel::deleteDomainRule,
        onAllowBlockedDomain = viewModel::allowBlockedDomain,
        onUndoDomainRule = viewModel::undoDomainRule,
        onDismissResolverNotice = viewModel::dismissResolverNotice,
        modifier = modifier
    )
}

@Composable
fun DnsShieldScreen(
    uiState: DnsShieldUiState,
    onToggleVpn: () -> Unit,
    onSelectDns: (Int) -> Unit,
    onAddCustomDns: suspend (String, String, String?, Boolean, String?, String?, String?, String?) -> String?,
    onDeleteDns: (DnsServer) -> Unit,
    onSetPlaintextFallback: (DnsServer, Boolean) -> Unit,
    onSearchChange: (String) -> Unit,
    onToggleBypass: (String, String, Boolean) -> Unit,
    onInfoCardDismiss: () -> Unit,
    onInfoCardRestore: () -> Unit,
    onClearLogs: () -> Unit,
    onRestartVpn: () -> Unit,
    onLoadAppsIfNeeded: () -> Unit,
    onDomainRuleSearchChange: (String) -> Unit,
    onSaveDomainRule: suspend (String, DomainRuleAction, Boolean) -> String?,
    onDeleteDomainRule: suspend (UserDomainRuleEntity) -> Unit,
    onAllowBlockedDomain: suspend (String) -> DomainRuleUndoToken,
    onUndoDomainRule: suspend (DomainRuleUndoToken) -> Boolean,
    modifier: Modifier = Modifier,
    onDismissResolverNotice: () -> Unit = {},
    onRetryLoadApps: () -> Unit = {}
) {
    var selectedTab by rememberSaveable { mutableIntStateOf(0) }
    var showAddDnsDialog by rememberSaveable { mutableStateOf(false) }
    BoxWithConstraints(
        modifier = modifier.fillMaxSize().imePadding()
            .background(MaterialTheme.colorScheme.background)
            .semantics { testTagsAsResourceId = true }
    ) {
        val compactHeight = maxHeight < 480.dp
        val useRail = maxWidth >= 600.dp || (compactHeight && maxWidth >= 480.dp)
        Row(Modifier.fillMaxSize()) {
            if (useRail) DashboardTabs(selectedTab, { selectedTab = it }, useRail = true, compactHeight = compactHeight)
            Column(Modifier.weight(1f)) {
                AppHeader(uiState.vpnLifecycleState, uiState.networkConnectivity)
                Box(Modifier.weight(1f).widthIn(max = 840.dp).fillMaxWidth().align(Alignment.CenterHorizontally)) {
                    when (selectedTab) {
                        0 -> ControlCenterTab(
                            uiState = uiState,
                            onToggleVpn = onToggleVpn,
                            onShowLogs = { selectedTab = 3 },
                            onSelectDns = onSelectDns,
                            onAddDnsClicked = { showAddDnsDialog = true },
                            onDeleteDns = onDeleteDns,
                            onSetPlaintextFallback = onSetPlaintextFallback,
                            onDismissResolverNotice = onDismissResolverNotice
                        )
                        1 -> {
                            LaunchedEffect(Unit) { onLoadAppsIfNeeded() }
                            ExemptAppsTab(
                                appSearchQuery = uiState.appSearchQuery,
                                onSearchChange = onSearchChange,
                                filteredApps = uiState.filteredApps,
                                isLoading = uiState.isLoadingApps,
                                appLoadError = uiState.appLoadError,
                                onRetryLoadApps = onRetryLoadApps,
                                onToggleBypass = onToggleBypass,
                                infoCardVisible = uiState.infoCardVisible,
                                onInfoCardVisibleChange = { visible ->
                                    if (visible) onInfoCardRestore() else onInfoCardDismiss()
                                }
                            )
                        }
                        2 -> DomainRulesTab(
                            rules = uiState.userDomainRules,
                            searchQuery = uiState.domainRuleSearchQuery,
                            onSearchChange = onDomainRuleSearchChange,
                            onSaveRule = onSaveDomainRule,
                            onDeleteRule = onDeleteDomainRule
                        )
                        3 -> LogsTab(
                            logs = uiState.logs,
                            blockedEvents = uiState.blockedEvents,
                            userDomainRules = uiState.userDomainRules,
                            onClearLogs = onClearLogs,
                            onAllowBlockedDomain = onAllowBlockedDomain,
                            onUndoDomainRule = onUndoDomainRule
                        )
                    }
                }
                // Reserve real space so pending changes cannot cover list items.
                ApplyRestartBanner(
                    visible = uiState.vpnSettingsModified,
                    onRestart = onRestartVpn,
                    enabled = uiState.vpnLifecycleState == VpnLifecycleState.RUNNING,
                    modifier = Modifier.widthIn(max = 840.dp).align(Alignment.CenterHorizontally)
                )
                if (!useRail) DashboardTabs(selectedTab, { selectedTab = it })
            }
        }
    }
    if (showAddDnsDialog) {
        AddDnsDialog(onDismiss = { showAddDnsDialog = false }, onConfirm = onAddCustomDns)
    }
}

private fun protectionStatusLabel(
    state: VpnLifecycleState,
    networkConnectivity: UnderlyingNetworkConnectivity
): String = when (state) {
    VpnLifecycleState.STOPPED -> "防護已關閉"
    VpnLifecycleState.STARTING -> "正在啟動防護…"
    VpnLifecycleState.RUNNING -> when (networkConnectivity) {
        UnderlyingNetworkConnectivity.OFFLINE -> "等待網路"
        UnderlyingNetworkConnectivity.UNKNOWN -> "確認網路中"
        UnderlyingNetworkConnectivity.CONNECTING -> "確認網路連線中"
        UnderlyingNetworkConnectivity.CAPTIVE_PORTAL -> "網路需要登入"
        UnderlyingNetworkConnectivity.ONLINE -> "DNS 防護中"
    }
    VpnLifecycleState.STOPPING -> "正在停止防護…"
    VpnLifecycleState.FAILED -> "防護發生錯誤"
}

@Composable
private fun protectionStatusColor(
    state: VpnLifecycleState,
    networkConnectivity: UnderlyingNetworkConnectivity
): Color = when (state) {
    VpnLifecycleState.RUNNING -> if (networkConnectivity == UnderlyingNetworkConnectivity.ONLINE) {
        MaterialTheme.colorScheme.primary
    } else MaterialTheme.colorScheme.tertiary
    VpnLifecycleState.FAILED -> MaterialTheme.colorScheme.error
    VpnLifecycleState.STARTING, VpnLifecycleState.STOPPING -> MaterialTheme.colorScheme.secondary
    VpnLifecycleState.STOPPED -> MaterialTheme.colorScheme.onSurfaceVariant
}

@Composable
fun AppHeader(
    lifecycleState: VpnLifecycleState,
    networkConnectivity: UnderlyingNetworkConnectivity = UnderlyingNetworkConnectivity.UNKNOWN
) {
    Row(
        Modifier.fillMaxWidth().background(MaterialTheme.colorScheme.surface)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Icon(Icons.Default.Shield, contentDescription = null, tint = protectionStatusColor(lifecycleState, networkConnectivity))
        Text("DNS Shield", modifier = Modifier.weight(1f), style = MaterialTheme.typography.titleMedium,
            maxLines = 1, overflow = TextOverflow.Ellipsis)
        Text(
            protectionStatusLabel(lifecycleState, networkConnectivity),
            modifier = Modifier.testTag("protection_header_status").semantics { liveRegion = LiveRegionMode.Polite },
            style = MaterialTheme.typography.labelMedium,
            color = protectionStatusColor(lifecycleState, networkConnectivity)
        )
    }
}

@Composable
fun ProtectionStatusCard(
    lifecycleState: VpnLifecycleState,
    queryCount: Long,
    blockedAds: Long,
    onToggleVpn: () -> Unit,
    onShowLogs: () -> Unit,
    networkConnectivity: UnderlyingNetworkConnectivity = UnderlyingNetworkConnectivity.UNKNOWN
) {
    val actionLabel = when (lifecycleState) {
        VpnLifecycleState.STOPPED -> "開啟防護"
        VpnLifecycleState.STARTING -> "取消啟動"
        VpnLifecycleState.RUNNING -> "關閉防護"
        VpnLifecycleState.STOPPING -> "正在停止…"
        VpnLifecycleState.FAILED -> "重試開啟防護"
    }
    Card(
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        shape = RoundedCornerShape(20.dp),
        modifier = Modifier.fillMaxWidth().testTag("protection_status_card")
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Icon(
                    if (lifecycleState == VpnLifecycleState.FAILED) Icons.Default.ErrorOutline else Icons.Default.Shield,
                    contentDescription = null, tint = protectionStatusColor(lifecycleState, networkConnectivity), modifier = Modifier.size(24.dp)
                )
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(
                        protectionStatusLabel(lifecycleState, networkConnectivity),
                        style = MaterialTheme.typography.titleMedium,
                        modifier = Modifier.testTag("protection_status_label").semantics { heading() }
                    )
                    Text(
                        when (lifecycleState) {
                            VpnLifecycleState.RUNNING -> when (networkConnectivity) {
                                UnderlyingNetworkConnectivity.OFFLINE -> "防護已啟用，等待網路連線。連線恢復後會自動繼續處理 DNS 查詢。"
                                UnderlyingNetworkConnectivity.UNKNOWN -> "防護已啟用，正在確認目前使用的網路。"
                                UnderlyingNetworkConnectivity.CONNECTING -> "防護已啟用，正在確認網路是否可連線。"
                                UnderlyingNetworkConnectivity.CAPTIVE_PORTAL -> "防護已啟用，請先完成 Wi-Fi 或網路的登入。"
                                UnderlyingNetworkConnectivity.ONLINE -> "正在處理經由本機 VPN 的系統 DNS 查詢。"
                            }
                            VpnLifecycleState.STARTING -> "正在建立本機 VPN 連線。"
                            VpnLifecycleState.STOPPING -> "請稍候，正在結束 VPN 連線。"
                            VpnLifecycleState.FAILED -> "請重試，或查看運作記錄中的錯誤原因。"
                            VpnLifecycleState.STOPPED -> "開啟後套用 DNS 設定與網域規則。"
                        },
                        modifier = Modifier.testTag("protection_status_description"),
                        style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
            Button(
                onClick = onToggleVpn,
                enabled = lifecycleState != VpnLifecycleState.STOPPING,
                modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("power_button"),
                colors = if (lifecycleState == VpnLifecycleState.RUNNING) {
                    ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
                        contentColor = MaterialTheme.colorScheme.onSurface
                    )
                } else ButtonDefaults.buttonColors()
            ) {
                if (lifecycleState == VpnLifecycleState.STOPPING) {
                    CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                } else {
                    Icon(Icons.Default.PowerSettingsNew, contentDescription = null, modifier = Modifier.size(20.dp))
                }
                Spacer(Modifier.width(8.dp))
                Text(actionLabel)
            }
            if (lifecycleState == VpnLifecycleState.FAILED) {
                TextButton(onClick = onShowLogs, modifier = Modifier.fillMaxWidth()) { Text("查看運作記錄") }
            }
            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                StatCard("DNS 請求", queryCount.toString(), Modifier.weight(1f).testTag("stat_query_count"))
                StatCard("封鎖請求", blockedAds.toString(), Modifier.weight(1f).testTag("stat_blocked_ads"))
            }
            Text(
                "累計次數，App 程序結束後重設。",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.testTag("statistics_scope")
            )
        }
    }
}

@Composable
fun DashboardTabs(
    selectedTab: Int,
    onTabSelected: (Int) -> Unit,
    useRail: Boolean = false,
    compactHeight: Boolean = false
) {
    val labels = listOf("防護", "排除 App", "網域規則", "運作記錄")
    val icons = listOf(Icons.Default.Shield, Icons.Default.AppBlocking, Icons.Default.Dns, Icons.Default.History)
    val tags = listOf("tab_control", "tab_exempt", "tab_domain_rules", "tab_logs")
    val navigationLabels = if (LocalDensity.current.fontScale >= 1.6f) {
        listOf("防護", "排除\nApp", "網域\n規則", "運作\n記錄")
    } else labels
    if (useRail) {
        NavigationRail(
            modifier = Modifier.fillMaxHeight().verticalScroll(rememberScrollState()),
            containerColor = MaterialTheme.colorScheme.surface,
            windowInsets = WindowInsets(0)
        ) {
            Spacer(Modifier.height(12.dp))
            labels.forEachIndexed { index, label ->
                NavigationRailItem(
                    selected = selectedTab == index, onClick = { onTabSelected(index) },
                    icon = { Icon(icons[index], contentDescription = if (compactHeight) label else null) },
                    label = if (compactHeight) null else { { Text(label, style = MaterialTheme.typography.labelMedium) } },
                    modifier = Modifier.testTag(tags[index])
                )
            }
        }
    } else {
        NavigationBar(containerColor = MaterialTheme.colorScheme.surface, windowInsets = WindowInsets(0)) {
            labels.forEachIndexed { index, label ->
                NavigationBarItem(
                    selected = selectedTab == index, onClick = { onTabSelected(index) },
                    icon = { Icon(icons[index], contentDescription = null) },
                    label = { Text(navigationLabels[index], style = MaterialTheme.typography.labelMedium, textAlign = TextAlign.Center) },
                    modifier = Modifier.testTag(tags[index])
                )
            }
        }
    }
}

@Composable
fun ApplyRestartBanner(visible: Boolean, onRestart: () -> Unit, modifier: Modifier = Modifier, enabled: Boolean = true) {
    if (!visible) return
    Surface(
        color = MaterialTheme.colorScheme.tertiaryContainer,
        contentColor = MaterialTheme.colorScheme.onTertiaryContainer,
        modifier = modifier.fillMaxWidth().testTag("apply_restart_banner")
    ) {
        Row(
            Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text("排除名單已儲存，重啟防護後生效。", style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
            TextButton(onClick = onRestart, enabled = enabled, modifier = Modifier.heightIn(min = 48.dp).testTag("apply_restart_button")) {
                Text("重啟套用", color = MaterialTheme.colorScheme.onTertiaryContainer)
            }
        }
    }
}

@Composable
fun StatCard(title: String, value: String, modifier: Modifier = Modifier) {
    Column(modifier.semantics(mergeDescendants = true) {}, verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(title, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
    }
}

@Composable
fun ControlCenterTab(
    uiState: DnsShieldUiState,
    onToggleVpn: () -> Unit,
    onShowLogs: () -> Unit,
    onSelectDns: (Int) -> Unit,
    onAddDnsClicked: () -> Unit,
    onDeleteDns: (DnsServer) -> Unit,
    onSetPlaintextFallback: (DnsServer, Boolean) -> Unit,
    onDismissResolverNotice: () -> Unit
) {
    var deleteCandidate by remember { mutableStateOf<DnsServer?>(null) }
    LazyColumn(
        modifier = Modifier.fillMaxSize().testTag("control_center_list"),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item {
            ProtectionStatusCard(
                uiState.vpnLifecycleState, uiState.queryCount, uiState.blockedAds,
                onToggleVpn, onShowLogs, uiState.networkConnectivity
            )
        }
        uiState.resolverNotice?.let { notice ->
            item {
                Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)) {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text("DNS 設定提醒", style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.onErrorContainer)
                        Text(
                            notice, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onErrorContainer,
                            modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite }.testTag("resolver_notice")
                        )
                        TextButton(onClick = onDismissResolverNotice) { Text("知道了", color = MaterialTheme.colorScheme.onErrorContainer) }
                    }
                }
            }
        }
        if (uiState.rulePolicyStatus.let {
            it.degradationReason != null || it.reloadError != null || it.publicSuffixStatus is PublicSuffixResolverStatus.Rejected
        }) item { RulePolicyWarning(uiState.rulePolicyStatus) }
        item {
            Column(Modifier.padding(top = 4.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("DNS 解析器", style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f).semantics { heading() })
                    FilledTonalButton(onClick = onAddDnsClicked, modifier = Modifier.heightIn(min = 48.dp).testTag("add_dns_button")) {
                        Icon(Icons.Default.Add, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(4.dp))
                        Text("新增")
                    }
                }
                Text(
                    if (uiState.activeDnsServer == null) "正在載入 DNS 設定…" else "已選 DNS：${uiState.activeDnsServer.name}",
                    style = MaterialTheme.typography.bodyMedium, modifier = Modifier.testTag("stat_active_dns"),
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                if (uiState.vpnLifecycleState == VpnLifecycleState.RUNNING) {
                    Text(
                        if (uiState.activeDns.isBlank() || uiState.activeDns == "None") "防護服務尚未回報套用的 DNS。"
                        else "服務已套用：${uiState.activeDns}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.testTag("service_applied_dns")
                    )
                }
            }
        }
        if (uiState.vpnLifecycleState == VpnLifecycleState.RUNNING) item {
            Column(Modifier.fillMaxWidth().testTag("dns_transport_status"), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(
                    "最近一次上游查詢的傳輸方式",
                    style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    uiState.dnsTransportStatus, style = MaterialTheme.typography.bodyMedium,
                    color = when {
                        uiState.dnsTransportStatus.contains("SERVFAIL") || uiState.dnsTransportStatus.contains("不可用") -> MaterialTheme.colorScheme.error
                        uiState.dnsTransportStatus.contains("明文") -> MaterialTheme.colorScheme.tertiary
                        else -> MaterialTheme.colorScheme.onSurface
                    }
                )
            }
        }
        items(uiState.dnsServers, key = { it.id }) { server ->
            DnsServerCard(
                server, isActive = server.id == uiState.activeDnsServer?.id, onSelect = { onSelectDns(server.id) },
                onSetPlaintextFallback = { onSetPlaintextFallback(server, it) }, onDelete = { deleteCandidate = server }
            )
        }
        item { RuleStatusCard(uiState.rulePolicyStatus) }
        item { DnsDiagnosticsCard(uiState.diagnostics) }
        item {
            DisclosureCard("防護範圍與限制", "防護經由本機 VPN 的系統 DNS 查詢。") {
                Text("僅攔截送往本機 VPN DNS 的 IPv4 UDP／TCP 53 查詢。App 直接指定其他 DNS 位址、使用自帶的 DoH／DoT，或透過 IPv6 DNS 查詢時，都不會被攔截。一般網路流量仍走原本網路。", style = MaterialTheme.typography.bodyMedium)
                Text("DoH 使用 HTTPS 加密；未加密備援使用 UDP/53，回應過大時可能改用 TCP/53。DNS Shield 不在本機驗證 DNSSEC，也無法只封鎖同一網域中的廣告內容。", style = MaterialTheme.typography.bodyMedium)
            }
        }
    }
    deleteCandidate?.let { server ->
        AlertDialog(
            onDismissRequest = { deleteCandidate = null },
            title = { Text("刪除 DNS 設定？") },
            text = { Text("將刪除「${server.name}」。若這是目前選用的 DNS，系統會改用另一組設定。") },
            confirmButton = { TextButton(onClick = { deleteCandidate = null; onDeleteDns(server) }) { Text("刪除", color = MaterialTheme.colorScheme.error) } },
            dismissButton = { TextButton(onClick = { deleteCandidate = null }) { Text("保留") } }
        )
    }
}

@Composable
private fun DnsServerCard(
    server: DnsServer, isActive: Boolean, onSelect: () -> Unit,
    onSetPlaintextFallback: (Boolean) -> Unit, onDelete: () -> Unit
) {
    OutlinedCard(
        border = androidx.compose.foundation.BorderStroke(
            if (isActive) 2.dp else 1.dp,
            if (isActive) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outlineVariant
        ),
        colors = CardDefaults.outlinedCardColors(containerColor = MaterialTheme.colorScheme.surface),
        modifier = Modifier.fillMaxWidth().testTag("dns_server_card_${server.id}")
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Row(
                Modifier.weight(1f).selectable(selected = isActive, role = Role.RadioButton, onClick = onSelect)
                    .padding(12.dp).testTag("select_dns_${server.id}"),
                verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                RadioButton(selected = isActive, onClick = null)
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(server.name, style = MaterialTheme.typography.titleSmall)
                    Text(buildString { append(server.primaryIp); server.secondaryIp?.let { append(" · "); append(it) } },
                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    if (isActive || server.isCustom) {
                        Text(if (isActive) "已選用" else "自訂 DNS",
                            style = MaterialTheme.typography.labelMedium,
                            color = if (isActive) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }
            if (server.isCustom) {
                IconButton(onClick = onDelete, modifier = Modifier.testTag("delete_dns_${server.id}")) {
                    Icon(Icons.Default.DeleteOutline, contentDescription = "刪除 ${server.name} 的 DNS 設定")
                }
            }
        }
        if (isActive) {
            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            Row(
                Modifier.fillMaxWidth().toggleable(value = server.allowPlaintextFallback, role = Role.Switch, onValueChange = onSetPlaintextFallback)
                    .padding(16.dp).testTag("dns_plaintext_fallback_${server.id}"),
                verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text("允許未加密備援", style = MaterialTheme.typography.titleSmall)
                    Text(if (server.allowPlaintextFallback) "DoH 失敗時改用未加密 DNS。"
                        else "僅使用加密 DNS；DoH 失敗時會回報解析錯誤。",
                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                Switch(checked = server.allowPlaintextFallback, onCheckedChange = null)
            }
            var showEndpoints by rememberSaveable(server.id) { mutableStateOf(false) }
            TextButton(
                onClick = { showEndpoints = !showEndpoints },
                modifier = Modifier.padding(horizontal = 8.dp).testTag("dns_endpoint_details_" + server.id).semantics { stateDescription = if (showEndpoints) "已展開" else "已收合" }
            ) { Text(if (showEndpoints) "收合連線設定" else "查看連線設定") }
            if (showEndpoints) {
                val endpoints = listOfNotNull(
                    DohEndpointConfiguration.endpoint(server.primaryDohUrl, server.primaryDohBootstrapIps, server.primaryIp)?.let { "主要" to it },
                    DohEndpointConfiguration.endpoint(
                        server.secondaryDohUrl, server.secondaryDohBootstrapIps, server.secondaryIp.orEmpty()
                    )?.let { "備援" to it }
                )
                val distinctEndpoints = endpoints.distinctBy { (_, endpoint) -> endpoint.url to endpoint.bootstrapAddresses }
                val sharesEndpoint = endpoints.size > 1 && distinctEndpoints.size == 1
                Column(Modifier.padding(start = 16.dp, end = 16.dp, bottom = 16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (distinctEndpoints.isEmpty()) {
                        Text(
                            if (server.allowPlaintextFallback) "未設定 DoH，這組 DNS 會使用未加密傳輸。"
                            else "未設定可用的 DoH，僅加密模式下查詢會失敗。",
                            style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.tertiary
                        )
                    }
                    if (sharesEndpoint) {
                        Text("主要與備援共用同一個 DoH 服務。", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    distinctEndpoints.forEach { (label, endpoint) ->
                        val endpointLabel = if (sharesEndpoint) "DoH" else "$label DoH"
                        Text("$endpointLabel：${endpoint.url}", style = MaterialTheme.typography.bodySmall)
                        if (endpoint.bootstrapAddresses.isNotEmpty()) {
                            Text("連線位址：${endpoint.bootstrapAddresses.joinToString("、")}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun DisclosureCard(title: String, summary: String, modifier: Modifier = Modifier, content: @Composable ColumnScope.() -> Unit) {
    var expanded by rememberSaveable { mutableStateOf(false) }
    Card(modifier = Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Row(
            modifier.fillMaxWidth().clickable(role = Role.Button) { expanded = !expanded }
                .semantics { stateDescription = if (expanded) "已展開" else "已收合" }.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(title, style = MaterialTheme.typography.titleSmall, modifier = Modifier.semantics { heading() })
                Text(summary, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Icon(if (expanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore, contentDescription = null)
        }
        if (expanded) {
            Column(Modifier.padding(start = 16.dp, end = 16.dp, bottom = 16.dp), verticalArrangement = Arrangement.spacedBy(12.dp), content = content)
        }
    }
}

@Composable
private fun DnsDiagnosticsCard(diagnostics: DnsDiagnosticsSnapshot) {
    DisclosureCard("連線診斷", "累積查詢失敗 ${diagnostics.failed} · 待處理 ${diagnostics.pending}", Modifier.testTag("dns_diagnostics_card")) {
        val lines = listOf(
            "收到 ${diagnostics.received} · 解析 ${diagnostics.resolved} · 攔截 ${diagnostics.blocked}",
            "累積查詢失敗 ${diagnostics.failed}（超載 ${diagnostics.overloaded}）· 拒絕 ${diagnostics.rejected}",
            "快取命中 ${diagnostics.cacheHits} · 合併重複查詢 ${diagnostics.coalesced}",
            "上游傳輸：DoH 已排程 ${diagnostics.dohCallsQueued} · UDP 已送出 ${diagnostics.udpAttempts} · TCP ${diagnostics.tcpAttempts}",
            "UDP 備援 ${diagnostics.fallbackAttempts} · 次要 DNS 重試 ${diagnostics.udpRetryAttempts}",
            "待處理 ${diagnostics.pending} · 最高 ${diagnostics.peakPending}",
            if (diagnostics.latency.sampleCount == 0) "查詢延遲：尚無資料"
            else "最近 ${diagnostics.latency.sampleCount} 筆延遲：P50 ${diagnostics.latency.p50Millis} ms · P95 ${diagnostics.latency.p95Millis} ms"
        )
        lines.forEach { Text(it, style = MaterialTheme.typography.bodyMedium) }
        Text("失敗數為累積查詢失敗，不代表目前仍無法連線。統計保存在記憶體，App 程序結束後會重設。", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun RuleStatusCard(status: RulePolicyStatus) {
    val summary = when (status.source) {
        RuleBlocklistSource.NOT_LOADED -> "開啟防護後載入名單"
        RuleBlocklistSource.BUILT_IN -> "使用內建備用規則"
        RuleBlocklistSource.APK_BUNDLED -> listOfNotNull(
            status.sourceName.ifBlank { "App 隨附名單" },
            status.entryCount?.let { "$it 筆規則" },
            status.sourceDate?.takeIf { it.isNotBlank() }?.let { "來源 $it" } ?: "來源日期未知"
        ).joinToString(" · ")
        RuleBlocklistSource.PRIVATE_OVERRIDE -> "使用裝置上的自訂名單"
    }
    DisclosureCard("防護名單", summary, Modifier.testTag("rule_status_card")) {
        DomainPolicyDiagnostics.details(status).forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
        val sourceNote = when (status.source) {
            RuleBlocklistSource.APK_BUNDLED -> "名單隨 App 更新，不會在背景下載。"
            RuleBlocklistSource.PRIVATE_OVERRIDE -> "目前使用裝置上的自訂名單。"
            RuleBlocklistSource.BUILT_IN -> "目前使用 App 內建的備用規則。"
            RuleBlocklistSource.NOT_LOADED -> null
        }
        sourceNote?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.testTag("rule_source_note")) }
    }
}

@Composable
private fun RulePolicyWarning(status: RulePolicyStatus) {
    Surface(
        color = MaterialTheme.colorScheme.tertiaryContainer,
        shape = RoundedCornerShape(12.dp),
        modifier = Modifier.fillMaxWidth().testTag("rule_policy_warning").semantics { liveRegion = LiveRegionMode.Polite }
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("防護名單需要注意", style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.onTertiaryContainer)
            status.degradationReason?.let {
                Text("完整名單無法載入，目前使用備用規則。原因：$it", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onTertiaryContainer)
            }
            status.reloadError?.let {
                Text("規則重新載入失敗，繼續使用目前規則。請重啟防護後再試。", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onTertiaryContainer)
            }
            if (status.publicSuffixStatus is PublicSuffixResolverStatus.Rejected) {
                Text("公共後綴資料無法載入，目前只比對完整網域。", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onTertiaryContainer)
            }
        }
    }
}

@Composable
fun AddDnsDialog(
    onDismiss: () -> Unit,
    onConfirm: suspend (String, String, String?, Boolean, String?, String?, String?, String?) -> String?
) {
    var name by rememberSaveable { mutableStateOf("") }
    var primaryIp by rememberSaveable { mutableStateOf("") }
    var secondaryIp by rememberSaveable { mutableStateOf("") }
    var allowPlaintextFallback by rememberSaveable { mutableStateOf(true) }
    var primaryDohUrl by rememberSaveable { mutableStateOf("") }
    var primaryBootstrapIps by rememberSaveable { mutableStateOf("") }
    var secondaryDohUrl by rememberSaveable { mutableStateOf("") }
    var secondaryBootstrapIps by rememberSaveable { mutableStateOf("") }
    var attempted by rememberSaveable { mutableStateOf(false) }
    var saveError by remember { mutableStateOf<String?>(null) }
    var isSaving by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val formScrollState = rememberScrollState()
    val nameError = if (attempted && name.isBlank()) "請輸入伺服器名稱。" else null
    val primaryError = if (attempted && !isIpv4Literal(primaryIp.trim())) "請輸入有效的 IPv4 位址。" else null
    val secondaryError = if (attempted && secondaryIp.isNotBlank() && !isIpv4Literal(secondaryIp.trim())) "請輸入有效的 IPv4 位址。" else null
    val primaryDohError = if (attempted) DohEndpointConfiguration.validationError(primaryDohUrl, primaryBootstrapIps, !allowPlaintextFallback) else null
    val secondaryDohError = if (attempted) DohEndpointConfiguration.validationError(secondaryDohUrl, secondaryBootstrapIps, !allowPlaintextFallback) else null
    AlertDialog(
        modifier = Modifier.imePadding().semantics { testTagsAsResourceId = true },
        properties = DialogProperties(decorFitsSystemWindows = false),
        onDismissRequest = { if (!isSaving) onDismiss() },
        title = { Text("新增 DNS 解析器") },
        text = {
            Column(Modifier.fillMaxWidth().heightIn(max = 480.dp).verticalScroll(formScrollState), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                saveError?.let {
                    Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite }.testTag("dialog_dns_save_error"))
                }
                DnsFormField(name, { name = it; saveError = null }, "伺服器名稱", "例如：家用 DNS", nameError, isSaving, "dialog_dns_name_input")
                Row(
                    Modifier.fillMaxWidth().toggleable(value = allowPlaintextFallback, enabled = !isSaving, role = Role.Switch) { allowPlaintextFallback = it; saveError = null },
                    verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text("允許未加密備援", style = MaterialTheme.typography.titleSmall)
                        Text(if (allowPlaintextFallback) "DoH 失敗時可改用未加密 DNS。" else "僅使用加密 DNS；DoH 失敗時會回報解析錯誤。",
                            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    Switch(checked = allowPlaintextFallback, onCheckedChange = null, enabled = !isSaving, modifier = Modifier.testTag("dialog_plaintext_fallback_switch"))
                }
                DnsFormField(primaryIp, { primaryIp = it; saveError = null }, "主要 DNS IPv4", "8.8.8.8", primaryError, isSaving, "dialog_dns_primary_input", KeyboardType.Decimal)
                DnsFormField(secondaryIp, { secondaryIp = it; saveError = null }, "備援 DNS IPv4（選填）", "8.8.4.4", secondaryError, isSaving, "dialog_dns_secondary_input", KeyboardType.Decimal)
                Text("DoH 加密連線", style = MaterialTheme.typography.titleSmall)
                Text("Google、Cloudflare、AdGuard、Quad9 的常用 IPv4 位址會自動對應 DoH。其他解析器請填 HTTPS 網址。未設定 DoH 時，只能使用未加密 DNS。",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                DnsFormField(primaryDohUrl, { primaryDohUrl = it; saveError = null }, "主要 DoH 網址（選填）", "https://resolver.example/dns-query", primaryDohError, isSaving, "dialog_dns_doh_input", KeyboardType.Uri)
                DnsFormField(primaryBootstrapIps, { primaryBootstrapIps = it; saveError = null }, "主要 DoH 連線 IPv4（選填）", "203.0.113.53, 203.0.113.54", null, isSaving, "dialog_dns_bootstrap_input")
                Text("連線 IPv4（Bootstrap）用來找到 DoH 伺服器；多個位址請用逗號分隔。僅加密模式下，自訂 DoH 主機名稱必須填寫。",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                DnsFormField(secondaryDohUrl, { secondaryDohUrl = it; saveError = null }, "備援 DoH 網址（選填）", "https://backup.example/dns-query", secondaryDohError, isSaving, "dialog_dns_secondary_doh_input", KeyboardType.Uri)
                DnsFormField(secondaryBootstrapIps, { secondaryBootstrapIps = it; saveError = null }, "備援 DoH 連線 IPv4（選填）", "203.0.113.55", null, isSaving, "dialog_dns_secondary_bootstrap_input")
            }
        },
        confirmButton = {
            TextButton(
                enabled = !isSaving, modifier = Modifier.heightIn(min = 48.dp).testTag("dialog_confirm_button"),
                onClick = {
                    if (isSaving) return@TextButton
                    attempted = true
                    if (name.isBlank() || !isIpv4Literal(primaryIp.trim()) ||
                        (secondaryIp.isNotBlank() && !isIpv4Literal(secondaryIp.trim())) ||
                        DohEndpointConfiguration.validationError(primaryDohUrl, primaryBootstrapIps, !allowPlaintextFallback) != null ||
                        DohEndpointConfiguration.validationError(secondaryDohUrl, secondaryBootstrapIps, !allowPlaintextFallback) != null
                    ) {
                        saveError = "請檢查標示的欄位，再試一次。"
                        scope.launch { formScrollState.scrollTo(0) }
                        return@TextButton
                    }
                    if (!allowPlaintextFallback && !DohEndpointConfiguration.hasUsableEncryptedEndpoint(
                        primaryIp.trim(), secondaryIp.trim().takeIf(String::isNotEmpty),
                        primaryDohUrl.trim().takeIf(String::isNotEmpty), primaryBootstrapIps.trim(),
                        secondaryDohUrl.trim().takeIf(String::isNotEmpty), secondaryBootstrapIps.trim()
                    )) {
                        saveError = "僅加密模式需要可用的 DoH 網址與連線位址，請檢查設定。"
                        scope.launch { formScrollState.scrollTo(0) }
                        return@TextButton
                    }
                    isSaving = true
                    saveError = null
                    scope.launch {
                        try {
                            saveError = onConfirm(name.trim(), primaryIp.trim(), secondaryIp.trim().takeIf(String::isNotEmpty),
                                allowPlaintextFallback, primaryDohUrl.trim().takeIf(String::isNotEmpty),
                                primaryBootstrapIps.trim().takeIf(String::isNotEmpty),
                                secondaryDohUrl.trim().takeIf(String::isNotEmpty), secondaryBootstrapIps.trim().takeIf(String::isNotEmpty))
                            if (saveError == null) onDismiss() else formScrollState.scrollTo(0)
                        } catch (cancelled: CancellationException) { throw cancelled }
                        catch (exception: Exception) {
                            saveError = "無法儲存 DNS 設定，請稍後再試。"
                            formScrollState.scrollTo(0)
                        }
                        finally { isSaving = false }
                    }
                }
            ) { Text(if (isSaving) "儲存中…" else "新增") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss, enabled = !isSaving, modifier = Modifier.heightIn(min = 48.dp).testTag("dialog_cancel_button")) { Text("取消") }
        }
    )
}

@Composable
private fun DnsFormField(
    value: String, onValueChange: (String) -> Unit, label: String, placeholder: String,
    error: String?, isSaving: Boolean, tag: String, keyboardType: KeyboardType = KeyboardType.Text
) {
    OutlinedTextField(
        value = value, onValueChange = onValueChange, label = { Text(label) }, placeholder = { Text(placeholder) },
        enabled = !isSaving, isError = error != null, supportingText = error?.let { { Text(it) } },
        singleLine = true, keyboardOptions = KeyboardOptions(keyboardType = keyboardType),
        modifier = Modifier.fillMaxWidth().testTag(tag)
    )
}
