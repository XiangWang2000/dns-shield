package io.github.xiangwang2000.dnsshield.ui

import android.content.ClipData
import android.os.Build
import android.widget.ImageView
import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.relocation.BringIntoViewRequester
import androidx.compose.foundation.relocation.bringIntoViewRequester
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Android
import androidx.compose.material.icons.filled.CheckBox
import androidx.compose.material.icons.filled.CheckBoxOutlineBlank
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.DeleteOutline
import androidx.compose.material.icons.filled.DeleteSweep
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.RadioButtonDefaults
import androidx.compose.material3.Snackbar
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.SnackbarResult
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.ClipEntry
import androidx.compose.ui.platform.LocalClipboard
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.viewinterop.AndroidView
import io.github.xiangwang2000.dnsshield.blocking.DomainNameNormalizer
import io.github.xiangwang2000.dnsshield.blocking.DomainRuleAction
import io.github.xiangwang2000.dnsshield.blocking.UserDomainRule
import io.github.xiangwang2000.dnsshield.blocking.UserDomainRuleMatcher
import io.github.xiangwang2000.dnsshield.data.UserDomainRuleEntity
import io.github.xiangwang2000.dnsshield.service.DnsDecision
import io.github.xiangwang2000.dnsshield.service.DnsDecisionEvent
import io.github.xiangwang2000.dnsshield.service.DnsDecisionReason
import io.github.xiangwang2000.dnsshield.ui.theme.ColorBorder
import io.github.xiangwang2000.dnsshield.ui.theme.ColorTextPrimary
import io.github.xiangwang2000.dnsshield.ui.theme.ColorTextSecondary
import io.github.xiangwang2000.dnsshield.ui.theme.CyberAmber
import io.github.xiangwang2000.dnsshield.ui.theme.CyberCrimson
import io.github.xiangwang2000.dnsshield.ui.theme.CyberEmerald
import io.github.xiangwang2000.dnsshield.ui.theme.CyberEmeraldGlow
import io.github.xiangwang2000.dnsshield.ui.theme.CyberSky
import io.github.xiangwang2000.dnsshield.ui.theme.DarkSurface
import io.github.xiangwang2000.dnsshield.viewmodel.AppIconCache
import io.github.xiangwang2000.dnsshield.viewmodel.AppInfo
import io.github.xiangwang2000.dnsshield.viewmodel.DomainRuleUndoToken
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
fun ExemptAppsTab(
    appSearchQuery: String,
    onSearchChange: (String) -> Unit,
    filteredApps: List<AppInfo>,
    isLoading: Boolean,
    onToggleBypass: (String, String, Boolean) -> Unit,
    infoCardVisible: Boolean,
    onInfoCardVisibleChange: (Boolean) -> Unit,
    appLoadError: String? = null,
    onRetryLoadApps: () -> Unit = {}
) {
    var retryRequested by remember(appLoadError, isLoading) { mutableStateOf(false) }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .testTag("app_exempt_list"),
        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item(key = "exempt_apps_heading") {
            Text(
                text = "排除 App",
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.SemiBold,
                color = ColorTextPrimary
            )
        }

        if (infoCardVisible) {
            item(key = "exempt_apps_info") {
                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = MaterialTheme.colorScheme.surfaceVariant,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier.padding(start = 14.dp, top = 8.dp, end = 6.dp, bottom = 8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            imageVector = Icons.Default.Info,
                            contentDescription = null,
                            tint = CyberSky,
                            modifier = Modifier.size(20.dp)
                        )
                        Spacer(Modifier.width(10.dp))
                        Text(
                            text = "勾選後不套用 DNS 設定與網域規則。清單只列出有啟動圖示的 App。",
                            modifier = Modifier.weight(1f),
                            style = MaterialTheme.typography.bodyMedium,
                            color = ColorTextPrimary
                        )
                        IconButton(
                            onClick = { onInfoCardVisibleChange(false) },
                            modifier = Modifier.size(48.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Default.Close,
                                contentDescription = "關閉說明",
                                tint = ColorTextSecondary
                            )
                        }
                    }
                }
            }
        }

        item(key = "exempt_apps_search") {
            OutlinedTextField(
                value = appSearchQuery,
                onValueChange = onSearchChange,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("app_search_input"),
                label = { Text("搜尋 App") },
                placeholder = { Text("輸入名稱或套件名稱") },
                leadingIcon = {
                    Icon(Icons.Default.Search, contentDescription = null)
                },
                trailingIcon = {
                    when {
                        appSearchQuery.isNotEmpty() -> IconButton(
                            onClick = { onSearchChange("") },
                            modifier = Modifier.size(48.dp)
                        ) {
                            Icon(Icons.Default.Close, contentDescription = "清除搜尋")
                        }
                        !infoCardVisible -> IconButton(
                            onClick = { onInfoCardVisibleChange(true) },
                            modifier = Modifier.size(48.dp)
                        ) {
                            Icon(Icons.Default.Info, contentDescription = "顯示說明", tint = CyberSky)
                        }
                    }
                },
                singleLine = true
            )
        }

        if (appLoadError != null && !isLoading) {
            item(key = "exempt_apps_error") {
                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = MaterialTheme.colorScheme.errorContainer,
                    modifier = Modifier.fillMaxWidth().testTag("app_load_error").semantics { liveRegion = LiveRegionMode.Polite }
                ) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Text(
                            text = appLoadError.takeIf { it.isNotBlank() }
                                ?: "無法載入 App 清單，請重試。",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onErrorContainer
                        )
                        Button(
                            onClick = {
                                if (!isLoading && !retryRequested) {
                                    retryRequested = true
                                    onRetryLoadApps()
                                }
                            },
                            enabled = !isLoading && !retryRequested,
                            modifier = Modifier.heightIn(min = 48.dp)
                                .testTag("retry_load_apps_button")
                        ) {
                            Text(
                                if (isLoading || retryRequested) "重新載入中…" else "重新載入"
                            )
                        }
                    }
                }
            }
        }

        when {
            isLoading && filteredApps.isEmpty() -> item(key = "exempt_apps_loading") {
                LoadingMessage("正在載入應用程式清單")
            }

            appLoadError != null && filteredApps.isEmpty() -> Unit

            filteredApps.isEmpty() -> item(key = "exempt_apps_empty") {
                EmptyMessage(
                    icon = Icons.Default.Android,
                    title = if (appSearchQuery.isBlank()) {
                        "目前沒有可顯示的應用程式"
                    } else {
                        "找不到符合的應用程式"
                    },
                    description = if (appSearchQuery.isBlank()) {
                        "清單只顯示有啟動圖示的 App。"
                    } else {
                        "試試其他 App 名稱或套件名稱。"
                    }
                )
            }

            else -> items(filteredApps, key = { it.packageName }) { app ->
                val shape = RoundedCornerShape(12.dp)
                Surface(
                    shape = shape,
                    color = DarkSurface,
                    modifier = Modifier
                        .fillMaxWidth()
                        .border(1.dp, ColorBorder, shape)
                        .toggleable(
                            value = app.isBypassed,
                            role = Role.Checkbox,
                            onValueChange = { checked ->
                                onToggleBypass(app.packageName, app.appName, checked)
                            }
                        )
                        .testTag("checkbox_" + app.packageName)
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .defaultMinSize(minHeight = 72.dp)
                            .padding(horizontal = 14.dp, vertical = 12.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        AppIconAsync(
                            packageName = app.packageName,
                            modifier = Modifier
                                .size(44.dp)
                                .clip(RoundedCornerShape(10.dp))
                        )
                        Spacer(Modifier.width(14.dp))
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = app.appName,
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.SemiBold,
                                color = ColorTextPrimary
                            )
                            Text(
                                text = app.packageName,
                                style = MaterialTheme.typography.bodySmall,
                                color = ColorTextSecondary
                            )
                        }
                        Spacer(Modifier.width(8.dp))
                        Icon(
                            imageVector = if (app.isBypassed) {
                                Icons.Default.CheckBox
                            } else {
                                Icons.Default.CheckBoxOutlineBlank
                            },
                            contentDescription = null,
                            tint = if (app.isBypassed) CyberEmerald else ColorTextSecondary,
                            modifier = Modifier.size(28.dp)
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun AppIconAsync(packageName: String, modifier: Modifier = Modifier) {
    val context = LocalContext.current
    var iconDrawable by remember(packageName) {
        mutableStateOf(AppIconCache.get(packageName))
    }

    if (iconDrawable == null) {
        LaunchedEffect(packageName) {
            val drawable = withContext(Dispatchers.IO) {
                runCatching {
                    context.packageManager.getApplicationIcon(packageName)
                }.getOrNull()
            }
            if (drawable != null) {
                AppIconCache.put(packageName, drawable)
                iconDrawable = drawable
            }
        }
    }

    val currentDrawable = iconDrawable
    if (currentDrawable != null) {
        AndroidView(
            factory = { viewContext ->
                ImageView(viewContext).apply {
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
            modifier = modifier
                .background(ColorBorder, RoundedCornerShape(10.dp)),
            contentAlignment = Alignment.Center
        ) {
            Icon(
                imageVector = Icons.Default.Android,
                contentDescription = null,
                tint = ColorTextSecondary
            )
        }
    }
}

@Composable
fun DomainRulesTab(
    rules: List<UserDomainRuleEntity>,
    searchQuery: String,
    onSearchChange: (String) -> Unit,
    onSaveRule: suspend (String, DomainRuleAction, Boolean) -> String?,
    onDeleteRule: suspend (UserDomainRuleEntity) -> Unit
) {
    var showAddDialog by rememberSaveable { mutableStateOf(false) }
    var domainInput by rememberSaveable { mutableStateOf("") }
    var selectedAction by rememberSaveable { mutableStateOf(DomainRuleAction.ALLOW) }
    var includeSubdomains by rememberSaveable { mutableStateOf(false) }
    var validationError by remember { mutableStateOf<String?>(null) }
    var isSaving by remember { mutableStateOf(false) }
    var pendingDeleteRule by remember { mutableStateOf<UserDomainRuleEntity?>(null) }
    var deleteError by remember { mutableStateOf<String?>(null) }
    var isDeleting by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val snackbarHostState = remember { SnackbarHostState() }
    val dialogScrollState = rememberScrollState()
    LaunchedEffect(validationError) {
        if (validationError != null) dialogScrollState.scrollTo(0)
    }

    val filteredRules = remember(rules, searchQuery) {
        if (searchQuery.isBlank()) {
            rules
        } else {
            val searchTerms = listOfNotNull(
                searchQuery.trim().takeIf { it.isNotEmpty() },
                DomainNameNormalizer.normalize(searchQuery)
            ).distinct()
            rules.filter { rule ->
                searchTerms.any { term -> rule.domain.contains(term, ignoreCase = true) }
            }
        }
    }

    Box(modifier = Modifier.fillMaxSize()) {
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .testTag("domain_rules_list"),
            contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            item(key = "domain_rules_heading") {
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(
                            text = "網域規則",
                            style = MaterialTheme.typography.titleLarge,
                            color = ColorTextPrimary
                        )
                        Button(
                            onClick = {
                                domainInput = ""
                                selectedAction = DomainRuleAction.ALLOW
                                includeSubdomains = false
                                validationError = null
                                showAddDialog = true
                            },
                            modifier = Modifier
                                .defaultMinSize(minHeight = 48.dp)
                                .testTag("add_domain_rule_button")
                        ) {
                            Text("新增")
                        }
                    }
                    Text(
                        text = "使用者規則優先於防護名單；較精確的規則優先。",
                        style = MaterialTheme.typography.bodyMedium,
                        color = ColorTextSecondary
                    )
                }
            }

            item(key = "domain_rules_search") {
                OutlinedTextField(
                    value = searchQuery,
                    onValueChange = onSearchChange,
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("domain_rules_search"),
                    singleLine = true,
                    label = { Text("搜尋網域") },
                    leadingIcon = { Icon(Icons.Default.Search, contentDescription = null) },
                    trailingIcon = if (searchQuery.isNotEmpty()) {
                        {
                            IconButton(
                                onClick = { onSearchChange("") },
                                modifier = Modifier.size(48.dp)
                            ) {
                                Icon(Icons.Default.Close, contentDescription = "清除搜尋")
                            }
                        }
                    } else {
                        null
                    }
                )
            }

            if (filteredRules.isEmpty()) {
                item(key = "domain_rules_empty") {
                    EmptyMessage(
                        icon = Icons.Default.Search,
                        title = if (searchQuery.isBlank()) {
                            "尚未建立網域規則"
                        } else {
                            "找不到符合的網域規則"
                        },
                        description = if (searchQuery.isBlank()) {
                            "新增允許或封鎖規則，管理特定網域的 DNS 解析。"
                        } else {
                            "清除搜尋或試試其他網域名稱。"
                        }
                    )
                }
            } else {
                items(filteredRules, key = { it.id }) { rule ->
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.surface
                        )
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .defaultMinSize(minHeight = 72.dp)
                                .padding(start = 16.dp, end = 8.dp, top = 10.dp, bottom = 10.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(
                                modifier = Modifier.weight(1f),
                                verticalArrangement = Arrangement.spacedBy(4.dp)
                            ) {
                                Text(
                                    text = rule.domain,
                                    style = MaterialTheme.typography.titleSmall,
                                    fontWeight = FontWeight.Medium,
                                    color = ColorTextPrimary
                                )
                                val actionLabel = if (
                                    rule.action.equals("ALLOW", ignoreCase = true)
                                ) "允許" else "封鎖"
                                val scopeLabel = if (rule.includeSubdomains) {
                                    "包含子網域"
                                } else {
                                    "僅此網域"
                                }
                                Text(
                                    text = actionLabel + " · " + scopeLabel,
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = ColorTextSecondary
                                )
                            }
                            IconButton(
                                onClick = {
                                    deleteError = null
                                    pendingDeleteRule = rule
                                },
                                modifier = Modifier
                                    .size(48.dp)
                                    .testTag("delete_domain_rule_" + rule.id)
                            ) {
                                Icon(
                                    imageVector = Icons.Default.DeleteOutline,
                                    contentDescription = "刪除 " + rule.domain,
                                    tint = ColorTextSecondary
                                )
                            }
                        }
                    }
                }
            }
        }

        SnackbarHost(
            hostState = snackbarHostState,
            modifier = Modifier
                .align(Alignment.BottomCenter)
                .padding(12.dp)
        )
    }

    if (showAddDialog) {
        AlertDialog(
            modifier = Modifier.imePadding().semantics { testTagsAsResourceId = true },
            properties = DialogProperties(decorFitsSystemWindows = false),
            onDismissRequest = {
                if (!isSaving) showAddDialog = false
            },
            title = { Text("新增網域規則") },
            text = {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(max = 480.dp)
                        .verticalScroll(dialogScrollState)
                        .testTag("domain_rule_dialog_scroll"),
                    verticalArrangement = Arrangement.spacedBy(14.dp)
                ) {
                    OutlinedTextField(
                        value = domainInput,
                        onValueChange = {
                            domainInput = it
                            validationError = null
                        },
                        enabled = !isSaving,
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("domain_rule_input"),
                        label = { Text("網域名稱") },
                        placeholder = { Text("example.com") },
                        singleLine = true,
                        isError = validationError != null,
                        supportingText = {
                            validationError?.let {
                                Text(it, color = MaterialTheme.colorScheme.error)
                            }
                        },
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri)
                    )

                    Text(
                        text = "處理方式",
                        style = MaterialTheme.typography.titleSmall,
                        color = ColorTextPrimary
                    )
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .selectableGroup(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        RuleActionChoice(
                            label = "允許",
                            selected = selectedAction == DomainRuleAction.ALLOW,
                            selectedColor = CyberEmerald,
                            enabled = !isSaving,
                            modifier = Modifier.weight(1f),
                            onClick = {
                                selectedAction = DomainRuleAction.ALLOW
                                validationError = null
                            }
                        )
                        RuleActionChoice(
                            label = "封鎖",
                            selected = selectedAction == DomainRuleAction.BLOCK,
                            selectedColor = MaterialTheme.colorScheme.error,
                            enabled = !isSaving,
                            modifier = Modifier.weight(1f),
                            onClick = {
                                selectedAction = DomainRuleAction.BLOCK
                                validationError = null
                            }
                        )
                    }

                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .defaultMinSize(minHeight = 56.dp)
                            .toggleable(
                                value = includeSubdomains,
                                enabled = !isSaving,
                                role = Role.Switch,
                                onValueChange = {
                                    includeSubdomains = it
                                    validationError = null
                                }
                            )
                            .testTag("domain_rule_include_subdomains"),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(
                            modifier = Modifier.weight(1f),
                            verticalArrangement = Arrangement.spacedBy(2.dp)
                        ) {
                            Text(
                                text = "包含子網域",
                                style = MaterialTheme.typography.bodyLarge,
                                color = ColorTextPrimary
                            )
                            Text(
                                text = "套用至此網域及其子網域",
                                style = MaterialTheme.typography.bodyMedium,
                                color = ColorTextSecondary
                            )
                        }
                        Switch(
                            checked = includeSubdomains,
                            onCheckedChange = null,
                            enabled = !isSaving
                        )
                    }
                }
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        if (isSaving) return@TextButton
                        isSaving = true
                        validationError = null
                        scope.launch {
                            try {
                                validationError = onSaveRule(
                                    domainInput,
                                    selectedAction,
                                    includeSubdomains
                                )
                                if (validationError == null) {
                                    showAddDialog = false
                                    domainInput = ""
                                    includeSubdomains = false
                                    selectedAction = DomainRuleAction.ALLOW
                                }
                            } catch (exception: CancellationException) {
                                throw exception
                            } catch (exception: Exception) {
                                validationError = "儲存失敗：" +
                                    (exception.localizedMessage ?: "請稍後再試")
                            } finally {
                                isSaving = false
                            }
                        }
                    },
                    enabled = !isSaving,
                    modifier = Modifier.testTag("save_domain_rule_button")
                ) {
                    if (isSaving) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(18.dp),
                            strokeWidth = 2.dp
                        )
                        Spacer(Modifier.width(8.dp))
                        Text("儲存中")
                    } else {
                        Text("儲存")
                    }
                }
            },
            dismissButton = {
                TextButton(
                    onClick = { if (!isSaving) showAddDialog = false },
                    enabled = !isSaving
                ) {
                    Text("取消")
                }
            }
        )
    }

    pendingDeleteRule?.let { rule ->
        AlertDialog(
            modifier = Modifier.imePadding().semantics { testTagsAsResourceId = true },
            properties = DialogProperties(decorFitsSystemWindows = false),
            onDismissRequest = {
                if (!isDeleting) {
                    pendingDeleteRule = null
                    deleteError = null
                }
            },
            title = { Text("刪除網域規則？") },
            text = {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(max = 480.dp)
                        .verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Text("確定要刪除 " + rule.domain + "？")
                    deleteError?.let {
                        Text(
                            text = it,
                            color = MaterialTheme.colorScheme.error,
                            style = MaterialTheme.typography.bodyMedium
                        )
                    }
                }
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        if (isDeleting) return@TextButton
                        scope.launch {
                            isDeleting = true
                            deleteError = null
                            try {
                                onDeleteRule(rule)
                                pendingDeleteRule = null
                                snackbarHostState.showSnackbar("已刪除網域規則")
                            } catch (exception: CancellationException) {
                                throw exception
                            } catch (exception: Exception) {
                                deleteError = "刪除失敗：" +
                                    (exception.localizedMessage ?: "請稍後再試")
                            } finally {
                                isDeleting = false
                            }
                        }
                    },
                    enabled = !isDeleting
                ) {
                    if (isDeleting) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(18.dp),
                            strokeWidth = 2.dp
                        )
                        Spacer(Modifier.width(8.dp))
                        Text("刪除中")
                    } else {
                        Text("刪除")
                    }
                }
            },
            dismissButton = {
                TextButton(
                    onClick = {
                        if (!isDeleting) {
                            pendingDeleteRule = null
                            deleteError = null
                        }
                    },
                    enabled = !isDeleting
                ) {
                    Text("取消")
                }
            }
        )
    }
}

@Composable
private fun RuleActionChoice(
    label: String,
    selected: Boolean,
    selectedColor: Color,
    enabled: Boolean,
    modifier: Modifier = Modifier,
    onClick: () -> Unit
) {
    Row(
        modifier = modifier
            .defaultMinSize(minHeight = 48.dp)
            .selectable(
                selected = selected,
                enabled = enabled,
                role = Role.RadioButton,
                onClick = onClick
            )
            .padding(horizontal = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        RadioButton(
            selected = selected,
            onClick = null,
            enabled = enabled,
            colors = RadioButtonDefaults.colors(selectedColor = selectedColor)
        )
        Text(
            text = label,
            style = MaterialTheme.typography.bodyLarge,
            color = if (selected) selectedColor else ColorTextPrimary
        )
    }
}

private enum class DomainLogFilter { ALL, BLOCKED, ALLOWED }

@Composable
fun LogsTab(
    logs: List<String>,
    blockedEvents: List<DnsDecisionEvent>,
    onClearLogs: () -> Unit,
    onAllowBlockedDomain: suspend (String) -> DomainRuleUndoToken,
    onUndoDomainRule: suspend (DomainRuleUndoToken) -> Boolean,
    userDomainRules: List<UserDomainRuleEntity> = emptyList()
) {
    var showTechnicalLogs by rememberSaveable { mutableStateOf(false) }
    var pendingAllowDomains by remember { mutableStateOf<Set<String>>(emptySet()) }
    val snackbarHostState = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()
    val locale = LocalConfiguration.current.locales[0]
    var domainSearchQuery by rememberSaveable { mutableStateOf("") }
    var selectedDomainFilter by rememberSaveable { mutableStateOf(DomainLogFilter.ALL) }
    val clipboard = LocalClipboard.current
    val context = LocalContext.current
    val searchTerm = domainSearchQuery.trim()
    val filteredEvents = blockedEvents.filter { event ->
        (searchTerm.isEmpty() || event.domain.contains(searchTerm, ignoreCase = true)) &&
            (
                when (selectedDomainFilter) {
                    DomainLogFilter.ALL -> true
                    DomainLogFilter.BLOCKED -> event.decision == DnsDecision.BLOCK
                    DomainLogFilter.ALLOWED -> event.decision == DnsDecision.ALLOW
                }
            )
    }
    val ruleMatcher = remember(userDomainRules) {
        UserDomainRuleMatcher(userDomainRules.mapNotNull { rule ->
            val action = when (rule.action) {
                DomainRuleAction.ALLOW.name -> DomainRuleAction.ALLOW
                DomainRuleAction.BLOCK.name -> DomainRuleAction.BLOCK
                else -> return@mapNotNull null
            }
            UserDomainRule(rule.domain, action, rule.includeSubdomains)
        })
    }

    Column(modifier = Modifier.fillMaxSize()) {
        LazyColumn(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f)
                .testTag(if (showTechnicalLogs) "logs_console" else "blocked_events"),
            contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            item(key = "logs_heading") {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "運作記錄",
                        style = MaterialTheme.typography.titleLarge,
                        color = ColorTextPrimary
                    )
                    if (showTechnicalLogs) {
                        IconButton(
                            onClick = onClearLogs,
                            modifier = Modifier
                                .size(48.dp)
                                .testTag("clear_logs_button")
                        ) {
                            Icon(
                                imageVector = Icons.Default.DeleteSweep,
                                contentDescription = "清除技術記錄",
                                tint = ColorTextSecondary
                            )
                        }
                    }
                }
            }

            item(key = "logs_mode") {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .selectableGroup(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    LogModeChoice(
                        label = "網域判斷",
                        selected = !showTechnicalLogs,
                        modifier = Modifier.weight(1f),
                        onClick = { showTechnicalLogs = false }
                    )
                    LogModeChoice(
                        label = "技術記錄",
                        selected = showTechnicalLogs,
                        modifier = Modifier.weight(1f),
                        onClick = { showTechnicalLogs = true }
                    )
                }
            }

            if (showTechnicalLogs) {
                item(key = "technical_logs_description") {
                    Text(
                        text = "App 在背景時，部分 DNS 記錄會合併為摘要。",
                        style = MaterialTheme.typography.bodyMedium,
                        color = ColorTextSecondary
                    )
                }
                if (logs.isEmpty()) {
                    item(key = "technical_logs_empty") {
                        EmptyMessage(
                            icon = Icons.Default.Code,
                            title = "目前沒有技術記錄",
                            description = "服務產生新的事件後，記錄會顯示在這裡。"
                        )
                    }
                } else {
                    items(logs) { log ->
                        Text(
                            text = log,
                            color = getLogColor(log),
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace,
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 2.dp)
                        )
                    }
                }
            } else {
                item(key = "decision_events_description") {
                    Text(
                        text = "同網域合併顯示最新判斷、時間與記錄次數，最多 100 個網域。只記錄封鎖與自訂允許判斷，App 程序結束後會清除。",
                        style = MaterialTheme.typography.bodyMedium,
                        color = ColorTextSecondary
                    )
                }
                item(key = "decision_event_tools") {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedTextField(
                            value = domainSearchQuery,
                            onValueChange = { domainSearchQuery = it },
                            modifier = Modifier.fillMaxWidth().testTag("domain_log_search"),
                            label = { Text("搜尋網域") },
                            placeholder = { Text("輸入完整或部分網域") },
                            singleLine = true,
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                            trailingIcon = {
                                if (domainSearchQuery.isNotEmpty()) {
                                    IconButton(
                                        onClick = { domainSearchQuery = "" },
                                        modifier = Modifier.size(48.dp).testTag("clear_domain_search")
                                    ) {
                                        Icon(
                                            imageVector = Icons.Default.Close,
                                            contentDescription = "清除網域搜尋",
                                            tint = ColorTextSecondary
                                        )
                                    }
                                }
                            }
                        )
                        FlowRow(
                            modifier = Modifier.fillMaxWidth().selectableGroup(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                            verticalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            FilterChip(
                                selected = selectedDomainFilter == DomainLogFilter.ALL,
                                onClick = { selectedDomainFilter = DomainLogFilter.ALL },
                                label = { Text("全部") },
                                modifier = Modifier.testTag("domain_filter_all")
                            )
                            FilterChip(
                                selected = selectedDomainFilter == DomainLogFilter.BLOCKED,
                                onClick = { selectedDomainFilter = DomainLogFilter.BLOCKED },
                                label = { Text("已封鎖") },
                                modifier = Modifier.testTag("domain_filter_blocked")
                            )
                            FilterChip(
                                selected = selectedDomainFilter == DomainLogFilter.ALLOWED,
                                onClick = { selectedDomainFilter = DomainLogFilter.ALLOWED },
                                label = { Text("已允許") },
                                modifier = Modifier.testTag("domain_filter_allowed")
                            )
                        }
                    }
                }
                if (blockedEvents.isEmpty()) {
                    item(key = "decision_events_empty") {
                        EmptyMessage(
                            icon = Icons.Default.Search,
                            title = "目前沒有近期網域判斷",
                            description = "網域被封鎖，或符合自訂允許規則時，結果會顯示在這裡。"
                        )
                    }
                } else if (filteredEvents.isEmpty()) {
                    item(key = "decision_events_no_results") {
                        Column(modifier = Modifier.fillMaxWidth().testTag("domain_log_no_results")) {
                            EmptyMessage(
                                icon = Icons.Default.Search,
                                title = "找不到符合條件的網域",
                                description = "請修改搜尋文字或切換篩選條件後再試。"
                            )
                        }
                    }
                } else {
                    items(filteredEvents, key = { it.id }) { event ->
                        val isPending = event.domain in pendingAllowDomains
                        val hasAllowRule = ruleMatcher.decisionFor(event.domain) == DomainRuleAction.ALLOW
                        val bringIntoView = remember(event.id) { BringIntoViewRequester() }
                        LaunchedEffect(hasAllowRule, isPending) {
                            if (hasAllowRule && isPending) bringIntoView.bringIntoView()
                        }
                        Card(
                            modifier = Modifier.fillMaxWidth()
                                .testTag("decision_event_" + event.id),
                            colors = CardDefaults.cardColors(
                                containerColor = MaterialTheme.colorScheme.surface
                            )
                        ) {
                            Column(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .defaultMinSize(minHeight = 68.dp)
                                    .padding(start = 16.dp, end = 8.dp, top = 12.dp, bottom = 12.dp),
                                verticalArrangement = Arrangement.spacedBy(6.dp)
                            ) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text(
                                        text = event.domain,
                                        style = MaterialTheme.typography.titleSmall,
                                        fontWeight = FontWeight.Medium,
                                        color = ColorTextPrimary,
                                        modifier = Modifier.weight(1f).testTag("domain_log_text_" + event.id)
                                    )
                                    IconButton(
                                        onClick = {
                                            scope.launch {
                                                try {
                                                    clipboard.setClipEntry(
                                                        ClipEntry(ClipData.newPlainText("完整網域", event.domain))
                                                    )
                                                    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
                                                        Toast.makeText(context, "已複製完整網域", Toast.LENGTH_SHORT).show()
                                                    }
                                                } catch (exception: CancellationException) {
                                                    throw exception
                                                } catch (exception: Exception) {
                                                    Toast.makeText(context, "複製失敗，請再試一次。", Toast.LENGTH_SHORT).show()
                                                }
                                            }
                                        },
                                        modifier = Modifier.size(48.dp).testTag("copy_domain_" + event.id)
                                    ) {
                                        Icon(
                                            imageVector = Icons.Default.ContentCopy,
                                            contentDescription = "複製完整網域 " + event.domain,
                                            tint = ColorTextSecondary
                                        )
                                    }
                                }
                                Column(
                                    modifier = Modifier.fillMaxWidth(),
                                    verticalArrangement = Arrangement.spacedBy(2.dp)
                                ) {
                                    val decisionLabel = if (event.decision == DnsDecision.BLOCK) {
                                        "已封鎖"
                                    } else {
                                        "已允許"
                                    }
                                    val reasonLabel = when (event.reason) {
                                        DnsDecisionReason.USER_RULE -> "使用者規則"
                                        DnsDecisionReason.PROTECTION_LIST -> "防護名單"
                                    }
                                    val time = java.text.SimpleDateFormat(
                                        "yyyy/MM/dd HH:mm:ss",
                                        locale
                                    ).format(java.util.Date(event.occurredAtMillis))
                                    Text(
                                        text = "最新：$decisionLabel · $reasonLabel",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = ColorTextSecondary
                                    )
                                    Text(
                                        text = "最後記錄 " + time + " · 累計 " + event.recordCount + " 次",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = ColorTextSecondary,
                                        modifier = Modifier.testTag("decision_event_summary_" + event.id)
                                    )
                                }

                                if (event.decision == DnsDecision.BLOCK && hasAllowRule) {
                                    Row(
                                        modifier = Modifier.fillMaxWidth()
                                            .bringIntoViewRequester(bringIntoView),
                                        horizontalArrangement = Arrangement.End
                                    ) {
                                        Text(
                                            text = "目前規則：允許",
                                            style = MaterialTheme.typography.bodySmall,
                                            color = CyberEmerald,
                                            modifier = Modifier.testTag("allowed_rule_" + event.id)
                                        )
                                    }
                                } else if (event.decision == DnsDecision.BLOCK) {
                                    Row(
                                        modifier = Modifier.fillMaxWidth()
                                            .bringIntoViewRequester(bringIntoView),
                                        horizontalArrangement = Arrangement.End
                                    ) {
                                        TextButton(
                                            onClick = {
                                                if (event.domain in pendingAllowDomains) return@TextButton
                                                pendingAllowDomains = pendingAllowDomains + event.domain
                                                scope.launch {
                                                    try {
                                                        val token = try {
                                                            onAllowBlockedDomain(event.domain)
                                                        } catch (exception: CancellationException) {
                                                            throw exception
                                                        } catch (exception: Exception) {
                                                            snackbarHostState.showSnackbar(
                                                                "允許失敗：" +
                                                                    (exception.localizedMessage ?: "請稍後再試")
                                                            )
                                                            return@launch
                                                        }

                                                        val result = snackbarHostState.showSnackbar(
                                                            message = "已精確允許 " + event.domain,
                                                            actionLabel = "復原",
                                                            withDismissAction = true
                                                        )
                                                        if (result == SnackbarResult.ActionPerformed) {
                                                            try {
                                                                val restored = onUndoDomainRule(token)
                                                                snackbarHostState.showSnackbar(
                                                                    if (restored) {
                                                                        "已復原規則變更"
                                                                    } else {
                                                                        "規則已再度變更，無法復原"
                                                                    }
                                                                )
                                                            } catch (exception: CancellationException) {
                                                                throw exception
                                                            } catch (exception: Exception) {
                                                                snackbarHostState.showSnackbar(
                                                                    "復原失敗：" +
                                                                        (exception.localizedMessage ?: "請稍後再試")
                                                                )
                                                            }
                                                        }
                                                    } finally {
                                                        pendingAllowDomains = pendingAllowDomains - event.domain
                                                    }
                                                }
                                            },
                                            enabled = !isPending,
                                            modifier = Modifier.heightIn(min = 48.dp)
                                                .testTag("allow_blocked_" + event.id)
                                        ) {
                                            if (isPending) {
                                                CircularProgressIndicator(
                                                    modifier = Modifier.size(18.dp),
                                                    strokeWidth = 2.dp
                                                )
                                                Spacer(Modifier.width(6.dp))
                                                Text("處理中")
                                            } else {
                                                Text("一鍵允許")
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if (snackbarHostState.currentSnackbarData != null) {
            SnackbarHost(
                hostState = snackbarHostState,
                modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp)
            ) { data ->
                Snackbar(
                    actionOnNewLine = data.visuals.actionLabel != null,
                    action = data.visuals.actionLabel?.let { label ->
                        {
                            TextButton(
                                onClick = { data.performAction() },
                                modifier = Modifier.heightIn(min = 48.dp),
                                colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.inversePrimary)
                            ) { Text(label) }
                        }
                    },
                    dismissAction = if (data.visuals.withDismissAction) {
                        {
                            IconButton(onClick = { data.dismiss() }) {
                                Icon(Icons.Default.Close, contentDescription = "關閉通知")
                            }
                        }
                    } else null
                ) {
                    Text(data.visuals.message, maxLines = 3, overflow = TextOverflow.Ellipsis)
                }
            }
        }
    }
}

@Composable
private fun LogModeChoice(
    label: String,
    selected: Boolean,
    modifier: Modifier = Modifier,
    onClick: () -> Unit
) {
    Row(
        modifier = modifier
            .defaultMinSize(minHeight = 48.dp)
            .selectable(
                selected = selected,
                role = Role.RadioButton,
                onClick = onClick
            )
            .padding(horizontal = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        RadioButton(selected = selected, onClick = null)
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium,
            color = if (selected) CyberEmerald else ColorTextPrimary
        )
    }
}

@Composable
private fun LoadingMessage(message: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 24.dp),
        horizontalArrangement = Arrangement.Center,
        verticalAlignment = Alignment.CenterVertically
    ) {
        CircularProgressIndicator(
            modifier = Modifier.size(24.dp),
            color = CyberEmerald,
            strokeWidth = 2.dp
        )
        Spacer(Modifier.width(12.dp))
        Text(message, style = MaterialTheme.typography.bodyLarge, color = ColorTextSecondary)
    }
}

@Composable
private fun EmptyMessage(
    icon: ImageVector,
    title: String,
    description: String
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 28.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = CyberSky,
            modifier = Modifier.size(36.dp)
        )
        Text(
            text = title,
            style = MaterialTheme.typography.titleMedium,
            color = ColorTextPrimary,
            textAlign = TextAlign.Center
        )
        Text(
            text = description,
            style = MaterialTheme.typography.bodyMedium,
            color = ColorTextSecondary,
            textAlign = TextAlign.Center
        )
    }
}

private fun getLogColor(log: String): Color {
    return when {
        log.contains("🛡️") || log.contains("攔截") -> CyberAmber
        log.contains("✓") || log.contains("成功") -> CyberEmeraldGlow
        log.contains("✗") || log.contains("Err") || log.contains("失敗") -> CyberCrimson
        else -> ColorTextPrimary
    }
}
