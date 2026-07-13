package io.github.xiangwang2000.dnsshield

import android.app.Activity
import android.net.VpnService
import android.os.Bundle
import android.widget.ImageView
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.*
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.AltRoute
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import io.github.xiangwang2000.dnsshield.data.DnsServer
import io.github.xiangwang2000.dnsshield.service.DnsVpnService
import io.github.xiangwang2000.dnsshield.ui.theme.*
import io.github.xiangwang2000.dnsshield.viewmodel.AppInfo
import io.github.xiangwang2000.dnsshield.viewmodel.DnsShieldUiState
import io.github.xiangwang2000.dnsshield.viewmodel.DnsVpnViewModel

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
        enableEdgeToEdge()
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
                Toast.makeText(context, "需要 VPN 權限才能啟動安全 DNS 防護", Toast.LENGTH_SHORT).show()
            }
        }
    )

    // Clear, clean, authorized action handler for toggling the VPN protection layer
    val handleToggleVpn = {
        if (uiState.isRunning) {
            viewModel.toggleVpn(context)
        } else {
            try {
                val vpnIntent = VpnService.prepare(context)
                if (vpnIntent != null) {
                    vpnPrepareLauncher.launch(vpnIntent)
                } else {
                    viewModel.toggleVpn(context)
                }
            } catch (e: Exception) {
                android.util.Log.e("MainActivity", "Failed to prepare/launch VPN service", e)
                Toast.makeText(context, "系統 VPN 核心不可用：${e.localizedMessage}", Toast.LENGTH_LONG).show()
            }
        }
    }

    DnsShieldScreen(
        uiState = uiState,
        onToggleVpn = handleToggleVpn,
        onSelectDns = { viewModel.selectDnsServer(it) },
        onAddCustomDns = { name, pri, sec -> viewModel.addCustomDnsServer(name, pri, sec) },
        onDeleteDns = { viewModel.deleteDnsServer(it) },
        onSearchChange = { viewModel.setSearchQuery(it) },
        onToggleBypass = { pkg, name, active -> viewModel.toggleAppBypass(pkg, name, active) },
        onInfoCardDismiss = { viewModel.setInfoCardVisible(false) },
        onInfoCardRestore = { viewModel.setInfoCardVisible(true) },
        onClearLogs = { viewModel.clearVpnLogs() },
        onRestartVpn = { viewModel.restartVpn(context) },
        onLoadAppsIfNeeded = { viewModel.refreshInstalledAppsIfNeeded() },
        modifier = modifier
    )
}

@Composable
fun DnsShieldScreen(
    uiState: DnsShieldUiState,
    onToggleVpn: () -> Unit,
    onSelectDns: (Int) -> Unit,
    onAddCustomDns: (String, String, String?) -> Unit,
    onDeleteDns: (DnsServer) -> Unit,
    onSearchChange: (String) -> Unit,
    onToggleBypass: (String, String, Boolean) -> Unit,
    onInfoCardDismiss: () -> Unit,
    onInfoCardRestore: () -> Unit,
    onClearLogs: () -> Unit,
    onRestartVpn: () -> Unit,
    onLoadAppsIfNeeded: () -> Unit,
    modifier: Modifier = Modifier
) {
    var selectedTab by rememberSaveable { mutableIntStateOf(0) } // 0: 控制中心, 1: 排除名單, 2: 運作日誌
    var showAddDnsDialog by remember { mutableStateOf(false) }

    Box(
        modifier = modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
    ) {
        Column(
            modifier = Modifier.fillMaxSize()
        ) {
            // App Header (Ultra Compact Screen Space Optimization)
            AppHeader(isRunning = uiState.isRunning)

            // Animated Power / Status Banner
            ProtectionStatusCard(
                isRunning = uiState.isRunning,
                queryCount = uiState.queryCount,
                blockedAds = uiState.blockedAds,
                savedBytesText = formatBytes(uiState.savedBytes),
                activeDns = uiState.activeDns,
                onToggleVpn = onToggleVpn
            )

            // Navigation Tabs
            DashboardTabs(
                selectedTab = selectedTab,
                onTabSelected = { selectedTab = it }
            )

            // Tab Content Switcher
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f)
            ) {
                when (selectedTab) {
                    0 -> {
                        ControlCenterTab(
                            dnsServers = uiState.dnsServers,
                            activeDnsServer = uiState.activeDnsServer,
                            onSelectDns = onSelectDns,
                            onAddDnsClicked = { showAddDnsDialog = true },
                            onDeleteDns = onDeleteDns
                        )
                    }
                    1 -> {
                        LaunchedEffect(Unit) {
                            onLoadAppsIfNeeded()
                        }
                        ExemptAppsTab(
                            appSearchQuery = uiState.appSearchQuery,
                            onSearchChange = onSearchChange,
                            filteredApps = uiState.filteredApps,
                            isLoading = uiState.isLoadingApps,
                            onToggleBypass = onToggleBypass,
                            infoCardVisible = uiState.infoCardVisible,
                            onInfoCardVisibleChange = { visible ->
                                if (visible) onInfoCardRestore() else onInfoCardDismiss()
                            }
                        )
                    }
                    2 -> {
                        LogsTab(
                            logs = uiState.logs,
                            onClearLogs = onClearLogs
                        )
                    }
                }
            }
        }

        // Floating Apply-Restart Banner
        ApplyRestartBanner(
            visible = uiState.vpnSettingsModified,
            onRestart = onRestartVpn,
            modifier = Modifier.align(Alignment.BottomCenter)
        )

        // Modal Custom Upstream DNS Config Dialogue
        if (showAddDnsDialog) {
            AddDnsDialog(
                onDismiss = { showAddDnsDialog = false },
                onConfirm = { name, pri, sec ->
                    onAddCustomDns(name, pri, sec)
                    showAddDnsDialog = false
                }
            )
        }
    }
}

@Composable
fun AppHeader(isRunning: Boolean) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.surface)
            .padding(horizontal = 12.dp, vertical = 6.dp)
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector = Icons.Default.Shield,
                contentDescription = "App Logo",
                tint = if (isRunning) CyberEmerald else CyberCrimson,
                modifier = Modifier.size(22.dp)
            )
            Spacer(modifier = Modifier.width(8.dp))
            Column {
                Text(
                    text = "DNS Shield",
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Bold,
                    color = ColorTextPrimary
                )
                Text(
                    text = "本機 DNS 層級安全與廣告阻擋 (僅 IPv4 UDP)",
                    fontSize = 10.sp,
                    color = ColorTextSecondary
                )
            }
        }
    }
}

@Composable
fun ProtectionStatusCard(
    isRunning: Boolean,
    queryCount: Int,
    blockedAds: Int,
    savedBytesText: String,
    activeDns: String,
    onToggleVpn: () -> Unit
) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 6.dp)
            .clip(RoundedCornerShape(12.dp))
            .background(
                Brush.horizontalGradient(
                    colors = if (isRunning) {
                        listOf(CyberEmerald.copy(alpha = 0.10f), DarkSurface)
                    } else {
                        listOf(CyberCrimson.copy(alpha = 0.08f), DarkSurface)
                    }
                )
            )
            .border(
                width = 1.dp,
                color = if (isRunning) CyberEmerald.copy(alpha = 0.20f) else ColorBorder,
                shape = RoundedCornerShape(12.dp)
            )
            .padding(horizontal = 12.dp, vertical = 8.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // Left Action Column: Power Button
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier.width(84.dp)
            ) {
                Box(
                    contentAlignment = Alignment.Center,
                    modifier = Modifier
                        .size(64.dp)
                        .clip(CircleShape)
                        .background(
                            Brush.radialGradient(
                                colors = if (isRunning) {
                                    listOf(CyberEmerald.copy(alpha = 0.22f), Color.Transparent)
                                } else {
                                    listOf(CyberCrimson.copy(alpha = 0.18f), Color.Transparent)
                                }
                            )
                        )
                        .clickable(onClickLabel = "Toggle VPN Protection") {
                            onToggleVpn()
                        }
                        .testTag("power_button")
                ) {
                    Box(
                        contentAlignment = Alignment.Center,
                        modifier = Modifier
                            .size(46.dp)
                            .clip(CircleShape)
                            .background(if (isRunning) CyberEmerald else CyberCrimson)
                    ) {
                        Icon(
                            imageVector = Icons.Default.PowerSettingsNew,
                            contentDescription = "Power Switch Icon",
                            tint = ColorWhite,
                            modifier = Modifier.size(24.dp)
                        )
                    }
                }

                Spacer(modifier = Modifier.height(3.dp))

                Text(
                    text = if (isRunning) "防護中" else "防護關閉",
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Bold,
                    color = if (isRunning) CyberEmerald else ColorTextSecondary
                )
            }

            // Right Status Grid
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    StatCard(
                        title = "DNS 解析",
                        value = "$queryCount 次",
                        icon = Icons.AutoMirrored.Filled.AltRoute,
                        iconTint = CyberSky,
                        modifier = Modifier
                            .weight(1f)
                            .testTag("stat_query_count")
                    )
                    StatCard(
                        title = "當前 DNS",
                        value = activeDns,
                        icon = Icons.Default.Dns,
                        iconTint = CyberEmeraldGlow,
                        modifier = Modifier
                            .weight(1f)
                            .testTag("stat_active_dns")
                    )
                }
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    StatCard(
                        title = "DNS 廣告攔截",
                        value = "$blockedAds 次",
                        icon = Icons.Default.Shield,
                        iconTint = CyberEmerald,
                        modifier = Modifier
                            .weight(1f)
                            .testTag("stat_blocked_ads")
                    )
                    StatCard(
                        title = "預估節省流量",
                        value = savedBytesText,
                        icon = Icons.Default.OfflineBolt,
                        iconTint = CyberAmber,
                        modifier = Modifier
                            .weight(1f)
                            .testTag("stat_saved_traffic")
                    )
                }
            }
        }
    }
}

@Composable
fun DashboardTabs(
    selectedTab: Int,
    onTabSelected: (Int) -> Unit
) {
    SecondaryTabRow(
        selectedTabIndex = selectedTab,
        containerColor = MaterialTheme.colorScheme.surface,
        contentColor = CyberEmerald,
        indicator = {
            TabRowDefaults.SecondaryIndicator(
                modifier = Modifier.tabIndicatorOffset(selectedTab),
                color = CyberEmerald
            )
        },
        divider = { HorizontalDivider(color = ColorBorder) }
    ) {
        Tab(
            selected = selectedTab == 0,
            onClick = { onTabSelected(0) },
            text = { Text("控制中心", fontSize = 14.sp) },
            icon = { Icon(Icons.Default.Tune, contentDescription = null, modifier = Modifier.size(20.dp)) },
            selectedContentColor = CyberEmerald,
            unselectedContentColor = ColorTextSecondary,
            modifier = Modifier.testTag("tab_control")
        )
        Tab(
            selected = selectedTab == 1,
            onClick = { onTabSelected(1) },
            text = { Text("排除名單", fontSize = 14.sp) },
            icon = { Icon(Icons.Default.AppBlocking, contentDescription = null, modifier = Modifier.size(20.dp)) },
            selectedContentColor = CyberEmerald,
            unselectedContentColor = ColorTextSecondary,
            modifier = Modifier.testTag("tab_exempt")
        )
        Tab(
            selected = selectedTab == 2,
            onClick = { onTabSelected(2) },
            text = { Text("運作日誌", fontSize = 14.sp) },
            icon = { Icon(Icons.Default.Terminal, contentDescription = null, modifier = Modifier.size(20.dp)) },
            selectedContentColor = CyberEmerald,
            unselectedContentColor = ColorTextSecondary,
            modifier = Modifier.testTag("tab_logs")
        )
    }
}

@Composable
fun ApplyRestartBanner(
    visible: Boolean,
    onRestart: () -> Unit,
    modifier: Modifier = Modifier
) {
    AnimatedVisibility(
        visible = visible,
        enter = slideInVertically(initialOffsetY = { it }) + fadeIn(),
        exit = slideOutVertically(targetOffsetY = { it }) + fadeOut(),
        modifier = modifier.padding(16.dp)
    ) {
        Card(
            shape = RoundedCornerShape(12.dp),
            colors = CardDefaults.cardColors(
                containerColor = CyberAmber,
                contentColor = Color.Black
            ),
            elevation = CardDefaults.cardElevation(defaultElevation = 8.dp),
            modifier = Modifier
                .fillMaxWidth()
                .testTag("apply_restart_banner")
        ) {
            Row(
                modifier = Modifier.padding(horizontal = 14.dp, vertical = 12.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(
                    modifier = Modifier
                        .size(32.dp)
                        .background(Color.Black.copy(alpha = 0.15f), CircleShape),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = Icons.Default.Sync,
                        contentDescription = "Sync Icon",
                        tint = Color.Black,
                        modifier = Modifier.size(20.dp)
                    )
                }
                Spacer(modifier = Modifier.width(12.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "排除設定已變更",
                        fontSize = 13.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color.Black
                    )
                    Text(
                        text = "請重啟 VPN 服務以套用新名單。",
                        fontSize = 11.sp,
                        color = Color.Black.copy(alpha = 0.85f)
                    )
                }
                Spacer(modifier = Modifier.width(8.dp))
                Button(
                    onClick = onRestart,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = Color.Black,
                        contentColor = CyberAmber
                    ),
                    shape = RoundedCornerShape(8.dp),
                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp),
                    modifier = Modifier
                        .height(34.dp)
                        .testTag("apply_restart_button")
                ) {
                    Text("立即重啟", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                }
            }
        }
    }
}

@Composable
fun StatCard(
    title: String,
    value: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    iconTint: Color,
    modifier: Modifier = Modifier
) {
    Card(
        shape = RoundedCornerShape(8.dp),
        colors = CardDefaults.cardColors(
            containerColor = DarkSurface
        ),
        modifier = modifier
            .border(1.dp, ColorBorder, RoundedCornerShape(8.dp))
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 6.dp)
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = iconTint,
                    modifier = Modifier.size(13.dp)
                )
                Spacer(modifier = Modifier.width(4.dp))
                Text(
                    text = title,
                    fontSize = 10.sp,
                    color = ColorTextSecondary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
            Spacer(modifier = Modifier.height(3.dp))
            Text(
                text = value,
                fontSize = 13.sp,
                fontWeight = FontWeight.Bold,
                color = ColorTextPrimary,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}

@Composable
fun ControlCenterTab(
    dnsServers: List<DnsServer>,
    activeDnsServer: DnsServer?,
    onSelectDns: (Int) -> Unit,
    onAddDnsClicked: () -> Unit,
    onDeleteDns: (DnsServer) -> Unit
) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 12.dp, vertical = 8.dp)
            .testTag("control_center_list"),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "選擇 Upstream 安全 DNS",
                    fontSize = 15.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = ColorTextPrimary
                )
                Button(
                    onClick = onAddDnsClicked,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = CyberEmerald
                    ),
                    shape = RoundedCornerShape(8.dp),
                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp),
                    modifier = Modifier
                        .height(32.dp)
                        .testTag("add_dns_button")
                ) {
                    Icon(Icons.Default.Add, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(4.dp))
                    Text("新增 DNS", fontSize = 12.sp, color = ColorWhite)
                }
            }
        }

        items(dnsServers, key = { it.id }) { server ->
            val isActive = server.id == activeDnsServer?.id
            Card(
                shape = RoundedCornerShape(12.dp),
                colors = CardDefaults.cardColors(
                    containerColor = if (isActive) CyberEmerald.copy(alpha = 0.08f) else DarkSurface
                ),
                modifier = Modifier
                    .fillMaxWidth()
                    .border(
                        width = 1.dp,
                        color = if (isActive) CyberEmerald else ColorBorder,
                        shape = RoundedCornerShape(12.dp)
                    )
                    .clickable { onSelectDns(server.id) }
                    .testTag("dns_server_card_${server.id}")
            ) {
                Row(
                    modifier = Modifier.padding(16.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    RadioButton(
                        selected = isActive,
                        onClick = { onSelectDns(server.id) },
                        colors = RadioButtonDefaults.colors(
                            selectedColor = CyberEmerald,
                            unselectedColor = ColorTextSecondary
                        )
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Column(
                        modifier = Modifier.weight(1f)
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(
                                text = server.name,
                                fontSize = 16.sp,
                                fontWeight = FontWeight.Bold,
                                color = ColorTextPrimary
                            )
                            if (server.isCustom) {
                                Spacer(modifier = Modifier.width(6.dp))
                                Box(
                                    modifier = Modifier
                                        .background(CyberSky.copy(alpha = 0.15f), RoundedCornerShape(4.dp))
                                        .padding(horizontal = 6.dp, vertical = 2.dp)
                                ) {
                                    Text("自訂", fontSize = 10.sp, color = CyberSky, fontWeight = FontWeight.Bold)
                                }
                            }
                        }
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = "主要 IP: ${server.primaryIp}",
                            fontSize = 12.sp,
                            color = ColorTextSecondary
                        )
                        server.secondaryIp?.let {
                            Text(
                                text = "次要 IP: $it",
                                fontSize = 12.sp,
                                color = ColorTextSecondary
                            )
                        }
                    }

                    if (server.isCustom) {
                        IconButton(
                            onClick = { onDeleteDns(server) },
                            modifier = Modifier.testTag("delete_dns_${server.id}")
                        ) {
                            Icon(
                                imageVector = Icons.Default.DeleteOutline,
                                contentDescription = "Delete DNS Config",
                                tint = CyberCrimson
                            )
                        }
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ExemptAppsTab(
    appSearchQuery: String,
    onSearchChange: (String) -> Unit,
    filteredApps: List<AppInfo>,
    isLoading: Boolean,
    onToggleBypass: (String, String, Boolean) -> Unit,
    infoCardVisible: Boolean,
    onInfoCardVisibleChange: (Boolean) -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 12.dp, vertical = 8.dp)
    ) {

        // Dismissible Explanatory Tip using smooth visibility transition
        AnimatedVisibility(
            visible = infoCardVisible,
            enter = fadeIn() + expandVertically(),
            exit = fadeOut() + shrinkVertically()
        ) {
            Card(
                shape = RoundedCornerShape(8.dp),
                colors = CardDefaults.cardColors(
                    containerColor = CyberSky.copy(alpha = 0.08f)
                ),
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 6.dp)
                    .border(1.dp, CyberSky.copy(alpha = 0.2f), RoundedCornerShape(8.dp))
            ) {
                Row(
                    modifier = Modifier.padding(start = 12.dp, top = 6.dp, end = 4.dp, bottom = 6.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        imageVector = Icons.Default.Info,
                        contentDescription = null,
                        tint = CyberSky,
                        modifier = Modifier.size(16.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "勾選加入「排除名單」的應用程式，其所有流量與 DNS 解析將繞過 VPN，不受防護解析或廣告攔截影響。\n排除後，該 App 將完全不受 DNS Shield 管理。",
                        fontSize = 11.sp,
                        color = ColorTextPrimary,
                        modifier = Modifier.weight(1f)
                    )
                    IconButton(
                        onClick = { onInfoCardVisibleChange(false) },
                        modifier = Modifier.size(28.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.Close,
                            contentDescription = "關閉提示",
                            tint = ColorTextSecondary,
                            modifier = Modifier.size(14.dp)
                        )
                    }
                }
            }
        }

        // Search text field
        TextField(
            value = appSearchQuery,
            onValueChange = onSearchChange,
            modifier = Modifier
                .fillMaxWidth()
                .testTag("app_search_input"),
            placeholder = { Text("搜尋已安裝的 App...", color = ColorTextSecondary, fontSize = 13.sp) },
            leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, tint = ColorTextSecondary, modifier = Modifier.size(18.dp)) },
            trailingIcon = {
                if (appSearchQuery.isNotEmpty()) {
                    IconButton(onClick = { onSearchChange("") }) {
                        Icon(Icons.Default.Close, contentDescription = "清除搜尋", tint = ColorTextSecondary, modifier = Modifier.size(18.dp))
                    }
                } else if (!infoCardVisible) {
                    // Restore info card button! Perfect UX discovery loop
                    IconButton(onClick = { onInfoCardVisibleChange(true) }) {
                        Icon(Icons.Default.Info, contentDescription = "顯示說明", tint = CyberSky, modifier = Modifier.size(18.dp))
                    }
                }
            },
            singleLine = true,
            colors = TextFieldDefaults.colors(
                focusedContainerColor = DarkSurface,
                unfocusedContainerColor = DarkSurface,
                focusedIndicatorColor = CyberEmerald,
                unfocusedIndicatorColor = Color.Transparent,
                disabledIndicatorColor = Color.Transparent,
                focusedTextColor = ColorTextPrimary,
                unfocusedTextColor = ColorTextPrimary
            ),
            shape = RoundedCornerShape(10.dp)
        )

        Spacer(modifier = Modifier.height(8.dp))

        if (isLoading) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
                contentAlignment = Alignment.Center
            ) {
                CircularProgressIndicator(color = CyberEmerald)
            }
        } else if (filteredApps.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
                contentAlignment = Alignment.Center
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Icon(
                        imageVector = Icons.Default.FilterListOff,
                        contentDescription = null,
                        modifier = Modifier.size(48.dp),
                        tint = ColorTextSecondary
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = "找不到符合的應用程式",
                        fontSize = 14.sp,
                        color = ColorTextSecondary
                    )
                }
            }
        } else {
            LazyColumn(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f)
                    .testTag("app_exempt_list"),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                items(filteredApps, key = { it.packageName }) { app ->
                    Card(
                        shape = RoundedCornerShape(10.dp),
                        colors = CardDefaults.cardColors(
                            containerColor = DarkSurface
                        ),
                        modifier = Modifier
                            .fillMaxWidth()
                            .border(1.dp, ColorBorder, RoundedCornerShape(10.dp))
                    ) {
                        Row(
                            modifier = Modifier.padding(12.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            // App Icon using optimized async loader
                            AppIconAsync(
                                packageName = app.packageName,
                                modifier = Modifier
                                    .size(40.dp)
                                    .clip(RoundedCornerShape(8.dp))
                            )

                            Spacer(modifier = Modifier.width(12.dp))

                            Column(
                                modifier = Modifier.weight(1f)
                            ) {
                                Text(
                                    text = app.appName,
                                    fontSize = 15.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = ColorTextPrimary,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                                Text(
                                    text = app.packageName,
                                    fontSize = 11.sp,
                                    color = ColorTextSecondary,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                            }

                            Checkbox(
                                checked = app.isBypassed,
                                onCheckedChange = { checked ->
                                    onToggleBypass(app.packageName, app.appName, checked)
                                },
                                colors = CheckboxDefaults.colors(
                                    checkedColor = CyberEmerald,
                                    uncheckedColor = ColorTextSecondary,
                                    checkmarkColor = ColorWhite
                                ),
                                modifier = Modifier.testTag("checkbox_${app.packageName}")
                            )
                        }
                    }
                }
            }
        }
    }
}

// Optimized async app icon loader backed by AppIconCache to reduce repeated PackageManager lookups
@Composable
fun AppIconAsync(packageName: String, modifier: Modifier = Modifier) {
    val context = androidx.compose.ui.platform.LocalContext.current
    var iconDrawable by remember(packageName) {
        mutableStateOf(io.github.xiangwang2000.dnsshield.viewmodel.AppIconCache.get(packageName))
    }

    if (iconDrawable == null) {
        LaunchedEffect(packageName) {
            val drawable = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
                runCatching {
                    context.packageManager.getApplicationIcon(packageName)
                }.getOrNull()
            }
            if (drawable != null) {
                io.github.xiangwang2000.dnsshield.viewmodel.AppIconCache.put(packageName, drawable)
                iconDrawable = drawable
            }
        }
    }

    val currentDrawable = iconDrawable
    if (currentDrawable != null) {
        AndroidView(
            factory = {
                ImageView(it).apply {
                    scaleType = ImageView.ScaleType.FIT_CENTER
                }
            },
            update = { imageView ->
                imageView.setImageDrawable(currentDrawable)
            },
            modifier = modifier
        )
    } else {
        Box(
            modifier = modifier.background(ColorBorder, RoundedCornerShape(8.dp)),
            contentAlignment = Alignment.Center
        ) {
            Icon(Icons.Default.Android, contentDescription = null, tint = ColorTextSecondary)
        }
    }
}

@Composable
fun LogsTab(
    logs: List<String>,
    onClearLogs: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 12.dp, vertical = 8.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = "即時封包解析日誌",
                fontSize = 15.sp,
                fontWeight = FontWeight.SemiBold,
                color = ColorTextPrimary
            )
            IconButton(
                onClick = onClearLogs,
                modifier = Modifier.testTag("clear_logs_button")
            ) {
                Icon(
                    imageVector = Icons.Default.DeleteSweep,
                    contentDescription = "Clear logs",
                    tint = ColorTextSecondary
                )
            }
        }

        Spacer(modifier = Modifier.height(8.dp))

        Box(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f)
                .clip(RoundedCornerShape(12.dp))
                .background(Color(0xFF020617)) // Deep black console
                .border(1.dp, ColorBorder, RoundedCornerShape(12.dp))
                .padding(12.dp)
        ) {
            if (logs.isEmpty()) {
                Box(
                    modifier = Modifier.fillMaxSize(),
                    contentAlignment = Alignment.Center
                ) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Icon(
                            imageVector = Icons.Default.Code,
                            contentDescription = null,
                            modifier = Modifier.size(36.dp),
                            tint = ColorBorder
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = "尚無封包傳輸日誌 (請啟動 VPN)",
                            fontSize = 12.sp,
                            color = ColorTextSecondary,
                            textAlign = TextAlign.Center
                        )
                    }
                }
            } else {
                LazyColumn(
                    modifier = Modifier
                        .fillMaxSize()
                        .testTag("logs_console")
                ) {
                    items(logs) { log ->
                        Text(
                            text = log,
                            color = getLogColor(log),
                            fontSize = 12.sp,
                            fontFamily = FontFamily.Monospace,
                            modifier = Modifier.padding(vertical = 2.dp)
                        )
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AddDnsDialog(
    onDismiss: () -> Unit,
    onConfirm: (name: String, primaryIp: String, secondaryIp: String?) -> Unit
) {
    var name by remember { mutableStateOf("") }
    var primaryIp by remember { mutableStateOf("") }
    var secondaryIp by remember { mutableStateOf("") }

    var nameError by remember { mutableStateOf(false) }
    var primaryError by remember { mutableStateOf(false) }
    var secondaryError by remember { mutableStateOf(false) }

    fun validateIp(ip: String): Boolean {
        val ipv4Regex = """^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$""".toRegex()
        return ip.trim().matches(ipv4Regex)
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("新增自訂安全 DNS Server", color = ColorTextPrimary) },
        text = {
            Column(
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                OutlinedTextField(
                    value = name,
                    onValueChange = {
                        name = it
                        nameError = false
                    },
                    label = { Text("伺服器名稱") },
                    placeholder = { Text("例如: AdGuard Family") },
                    singleLine = true,
                    isError = nameError,
                    supportingText = {
                        if (nameError) {
                            Text("伺服器名稱不可為空")
                        }
                    },
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = CyberEmerald,
                        focusedLabelColor = CyberEmerald,
                        unfocusedTextColor = ColorTextPrimary,
                        focusedTextColor = ColorTextPrimary,
                        errorBorderColor = CyberCrimson
                    ),
                    modifier = Modifier.testTag("dialog_dns_name_input")
                )

                OutlinedTextField(
                    value = primaryIp,
                    onValueChange = {
                        primaryIp = it
                        primaryError = false
                    },
                    label = { Text("主要 DNS IP (必填)") },
                    placeholder = { Text("8.8.8.8") },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
                    singleLine = true,
                    isError = primaryError,
                    supportingText = {
                        if (primaryError) {
                            Text("請輸入有效的 IPv4 位址")
                        }
                    },
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = CyberEmerald,
                        focusedLabelColor = CyberEmerald,
                        unfocusedTextColor = ColorTextPrimary,
                        focusedTextColor = ColorTextPrimary,
                        errorBorderColor = CyberCrimson
                    ),
                    modifier = Modifier.testTag("dialog_dns_primary_input")
                )

                OutlinedTextField(
                    value = secondaryIp,
                    onValueChange = {
                        secondaryIp = it
                        secondaryError = false
                    },
                    label = { Text("次要 DNS IP (選填)") },
                    placeholder = { Text("8.8.4.4") },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
                    singleLine = true,
                    isError = secondaryError,
                    supportingText = {
                        if (secondaryError) {
                            Text("請輸入有效的 IPv4 位址")
                        }
                    },
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = CyberEmerald,
                        focusedLabelColor = CyberEmerald,
                        unfocusedTextColor = ColorTextPrimary,
                        focusedTextColor = ColorTextPrimary,
                        errorBorderColor = CyberCrimson
                    )
                )
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    val trimmedName = name.trim()
                    val trimmedPrimary = primaryIp.trim()
                    val trimmedSecondary = secondaryIp.trim()

                    val isNameValid = trimmedName.isNotEmpty()
                    val isPrimaryValid = validateIp(trimmedPrimary)
                    val isSecondaryValid = trimmedSecondary.isEmpty() || validateIp(trimmedSecondary)

                    nameError = !isNameValid
                    primaryError = !isPrimaryValid
                    secondaryError = !isSecondaryValid

                    if (isNameValid && isPrimaryValid && isSecondaryValid) {
                        onConfirm(
                            trimmedName,
                            trimmedPrimary,
                            trimmedSecondary.takeIf { it.isNotEmpty() }
                        )
                    }
                },
                colors = ButtonDefaults.buttonColors(
                    containerColor = CyberEmerald
                ),
                modifier = Modifier.testTag("dialog_confirm_button")
            ) {
                Text("新增", color = ColorWhite)
            }
        },
        dismissButton = {
            TextButton(
                onClick = onDismiss,
                modifier = Modifier.testTag("dialog_cancel_button")
            ) {
                Text("取消", color = ColorTextSecondary)
            }
        },
        containerColor = DarkSurface
    )
}

// Helper functions for formatting bytes and selecting log colors
fun formatBytes(bytes: Long): String {
    return when {
        bytes < 1024L -> "$bytes B"
        bytes < 1024L * 1024L ->
            String.format(java.util.Locale.US, "%.1f KB", bytes / 1024.0)
        else ->
            String.format(java.util.Locale.US, "%.2f MB", bytes / (1024.0 * 1024.0))
    }
}

fun getLogColor(log: String): Color {
    return when {
        log.contains("🛡️") || log.contains("攔截") -> CyberAmber
        log.contains("✓") || log.contains("成功") -> CyberEmeraldGlow
        log.contains("✗") || log.contains("Err") || log.contains("失敗") -> CyberCrimson
        else -> ColorTextPrimary
    }
}
