package com.example.webmil.ui.screens

import android.annotation.SuppressLint
import android.webkit.WebView
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material.icons.rounded.Warning
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import com.example.webmil.browser.WebBrowserManager
import com.example.webmil.browser.model.WebTab
import com.example.webmil.smartcard.tls.SmartCardWebViewClient
import com.example.webmil.ui.SmartCardViewModel
import com.example.webmil.ui.components.BookmarkManagementDialog
import com.example.webmil.ui.components.CardRemovalAlertOverlay
import com.example.webmil.ui.components.SecurityStatusDialog
import com.example.webmil.ui.components.WebAddressBar
import com.example.webmil.ui.components.WebBrowserTabRow

@Composable
fun WebBrowserScreen(
    viewModel: SmartCardViewModel,
    modifier: Modifier = Modifier
) {
    val browserState by viewModel.browserUiState.collectAsState()
    val smartCardUiState by viewModel.uiState.collectAsState()
    val browserManager = viewModel.browserManager

    val activeTab = browserState.activeTab
    val webViewMap = remember { mutableStateMapOf<String, WebView>() }

    Column(modifier = modifier.fillMaxSize()) {
        // 1. Multi-Tab Bar
        WebBrowserTabRow(
            tabs = browserState.tabs,
            activeTabId = browserState.activeTabId,
            onTabSelected = { browserManager.selectTab(it) },
            onTabClosed = { tabId ->
                webViewMap.remove(tabId)?.destroy()
                browserManager.closeTab(tabId)
            },
            onNewTabClick = { browserManager.addTab() }
        )

        // 2. Address Bar & Navigation Controls
        WebAddressBar(
            activeTab = activeTab,
            bookmarks = browserState.bookmarks,
            onNavigate = { url ->
                activeTab?.let { tab ->
                    val formatted = WebBrowserManager.formatUrl(url)
                    browserManager.updateTabUrl(tab.id, formatted)
                    webViewMap[tab.id]?.loadUrl(formatted)
                }
            },
            onBackClick = {
                activeTab?.let { tab ->
                    webViewMap[tab.id]?.goBack()
                }
            },
            onForwardClick = {
                activeTab?.let { tab ->
                    webViewMap[tab.id]?.goForward()
                }
            },
            onRefreshClick = {
                activeTab?.let { tab ->
                    webViewMap[tab.id]?.reload()
                }
            },
            onStopClick = {
                activeTab?.let { tab ->
                    webViewMap[tab.id]?.stopLoading()
                    browserManager.updateTabLoading(tab.id, false)
                }
            },
            onBookmarkToggle = { url, title ->
                viewModel.toggleBookmark(url, title)
            },
            onSecurityClick = {
                browserManager.showSecurityDialog(true)
            },
            onBookmarkManageClick = {
                browserManager.showBookmarkSheet(true)
            }
        )

        // 3. Persistent Security Status Banner below address bar
        RealTimeSecurityBanner(
            activeTab = activeTab,
            sessionAuthorized = viewModel.smartCardManager.isSessionAuthorized(),
            pendingTlsHost = smartCardUiState.pendingTlsHost,
            hasActiveCert = smartCardUiState.activeCertificate != null,
            onBannerClick = { browserManager.showSecurityDialog(true) }
        )

        // 4. WebView Container for Tabs
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f)
        ) {
            browserState.tabs.forEach { tab ->
                val isSelected = tab.id == browserState.activeTabId
                if (isSelected) {
                    SingleWebTabView(
                        tab = tab,
                        viewModel = viewModel,
                        browserManager = browserManager,
                        onWebViewCreated = { webView ->
                            webViewMap[tab.id] = webView
                        }
                    )
                }
            }
        }
    }

    // 5. Real-Time Security Status Dialog
    if (browserState.isSecurityDialogVisible) {
        val currentSecInfo = activeTab?.securityInfo ?: com.example.webmil.browser.model.SslSecurityInfo()
        SecurityStatusDialog(
            securityInfo = currentSecInfo,
            smartCardUiState = smartCardUiState,
            onVerifyPin = { pin -> viewModel.verifyPin(pin) },
            onSelectCertificate = { cert -> viewModel.selectCertificate(cert) },
            onDismiss = { browserManager.showSecurityDialog(false) }
        )
    }

    // 6. DoD & Military Portals Bookmark Management Dialog
    if (browserState.isBookmarkSheetVisible) {
        BookmarkManagementDialog(
            bookmarks = browserState.bookmarks,
            onSelectBookmark = { url ->
                activeTab?.let { tab ->
                    val formatted = WebBrowserManager.formatUrl(url)
                    browserManager.updateTabUrl(tab.id, formatted)
                    webViewMap[tab.id]?.loadUrl(formatted)
                }
            },
            onAddBookmark = { title, url, category ->
                viewModel.addBookmark(url, title, category)
            },
            onDeleteBookmark = { url ->
                viewModel.deleteBookmark(url)
            },
            onDismiss = {
                browserManager.showBookmarkSheet(false)
            }
        )
    }

    // 7. Card Removal Rapid Security Overlay Dialog
    if (smartCardUiState.cardRemovalWarning != null || smartCardUiState.isSessionLocked) {
        CardRemovalAlertOverlay(
            warningMessage = smartCardUiState.cardRemovalWarning ?: "Smart Card removed during active secure session!",
            onEnableSimulation = {
                viewModel.enableSimulationMode()
            },
            onDismiss = {
                viewModel.dismissCardRemovalWarning()
            }
        )
    }
}

@SuppressLint("SetJavaScriptEnabled")
@Composable
fun SingleWebTabView(
    tab: WebTab,
    viewModel: SmartCardViewModel,
    browserManager: WebBrowserManager,
    onWebViewCreated: (WebView) -> Unit
) {
    var mtlsDetected = remember { false }

    val client = remember(tab.id) {
        SmartCardWebViewClient(
            smartCardManager = viewModel.smartCardManager,
            onPageStartedCallback = { url ->
                browserManager.updateTabLoading(tab.id, true)
                url?.let { browserManager.updateTabUrl(tab.id, it) }
            },
            onPageFinishedCallback = { view, _ ->
                browserManager.updateTabLoading(tab.id, false)
                browserManager.updateTabNavigationState(
                    tabId = tab.id,
                    canGoBack = view?.canGoBack() ?: false,
                    canGoForward = view?.canGoForward() ?: false
                )
                view?.title?.let { title ->
                    if (title.isNotBlank()) {
                        browserManager.updateTabTitle(tab.id, title)
                    }
                }
                browserManager.updateTabSslCertificate(
                    tabId = tab.id,
                    certificate = view?.certificate,
                    isMtls = mtlsDetected
                )
            },
            onSslErrorCallback = { sslError ->
                browserManager.updateTabSslCertificate(
                    tabId = tab.id,
                    certificate = null,
                    sslError = sslError?.toString() ?: "SSL Certificate Warning"
                )
            },
            onMtlsRequestedCallback = { _ ->
                mtlsDetected = true
                browserManager.updateTabSslCertificate(
                    tabId = tab.id,
                    certificate = null,
                    isMtls = true
                )
                if (!viewModel.smartCardManager.isSessionAuthorized() || viewModel.uiState.value.activeCertificate == null) {
                    browserManager.showSecurityDialog(true)
                }
            },
            onMtlsAuthenticatedCallback = { _ ->
                mtlsDetected = true
                browserManager.updateTabSslCertificate(
                    tabId = tab.id,
                    certificate = null,
                    isMtls = true
                )
            }
        )
    }

    DisposableEffect(client) {
        viewModel.registerWebViewClient(client)
        onDispose {
            viewModel.unregisterWebViewClient(client)
        }
    }

    AndroidView(
        factory = { context ->
            WebView(context).apply {
                layoutParams = android.view.ViewGroup.LayoutParams(
                    android.view.ViewGroup.LayoutParams.MATCH_PARENT,
                    android.view.ViewGroup.LayoutParams.MATCH_PARENT
                )
                setLayerType(android.view.View.LAYER_TYPE_HARDWARE, null)
                settings.javaScriptEnabled = true
                settings.domStorageEnabled = true
                settings.useWideViewPort = true
                settings.loadWithOverviewMode = true

                webViewClient = client

                loadUrl(tab.url)
                onWebViewCreated(this)
            }
        },
        update = { webView ->
            onWebViewCreated(webView)
            webView.requestLayout()
            webView.invalidate()
        },
        modifier = Modifier.fillMaxSize()
    )
}

@Composable
fun RealTimeSecurityBanner(
    activeTab: WebTab?,
    sessionAuthorized: Boolean,
    pendingTlsHost: String?,
    hasActiveCert: Boolean,
    onBannerClick: () -> Unit
) {
    val secInfo = activeTab?.securityInfo
    val isMtls = secInfo?.isMtlsAuthenticated == true || pendingTlsHost != null
    val isPendingPin = pendingTlsHost != null || !sessionAuthorized || !hasActiveCert

    val bannerBg = when {
        isPendingPin && isMtls -> Color(0xFFFFF3E0) // Light Orange for PIN pending
        isMtls -> Color(0xFFE8F5E9) // Light Green for mTLS OK
        secInfo?.isSecure == true -> Color(0xFFE3F2FD) // Light Blue for HTTPS
        else -> Color(0xFFFBE9E7)
    }

    val bannerTextColor = when {
        isPendingPin && isMtls -> Color(0xFFE65100) // Orange
        isMtls -> Color(0xFF2E7D32) // Green
        secInfo?.isSecure == true -> Color(0xFF1565C0) // Blue
        else -> Color(0xFFC62828) // Red
    }

    val bannerText = when {
        pendingTlsHost != null -> "🔒 Mutual TLS Authentication Requested for $pendingTlsHost. Click to enter PIN."
        isMtls && isPendingPin -> "🔒 Mutual TLS Authentication Requested for ${secInfo?.host ?: "server"}. Click to enter PIN."
        isMtls -> "🛡️ Mutual TLS Active - Authenticated via CAC/PIV Smart Card Certificate"
        secInfo?.isSecure == true -> "🔒 SSL/TLS Encrypted Connection (${secInfo.host})"
        else -> "⚠️ Unencrypted or SSL Warning Connection"
    }

    Surface(
        onClick = onBannerClick,
        color = bannerBg,
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector = if (secInfo?.isSecure == true || isMtls) Icons.Rounded.Shield else Icons.Rounded.Warning,
                contentDescription = null,
                tint = bannerTextColor,
                modifier = Modifier.size(16.dp)
            )

            Spacer(modifier = Modifier.width(8.dp))

            Text(
                text = bannerText,
                fontSize = 11.sp,
                fontWeight = FontWeight.SemiBold,
                color = bannerTextColor,
                modifier = Modifier.weight(1f)
            )

            AssistChip(
                onClick = onBannerClick,
                label = { Text(if (isPendingPin && isMtls) "Enter PIN" else "Details", fontSize = 10.sp) },
                leadingIcon = {
                    Icon(
                        imageVector = Icons.Rounded.Lock,
                        contentDescription = null,
                        modifier = Modifier.size(12.dp)
                    )
                },
                colors = AssistChipDefaults.assistChipColors(
                    containerColor = bannerTextColor.copy(alpha = 0.15f),
                    labelColor = bannerTextColor
                ),
                modifier = Modifier.height(24.dp)
            )
        }
    }
}
