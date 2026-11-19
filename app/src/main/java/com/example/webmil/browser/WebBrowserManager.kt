package com.example.webmil.browser

import android.content.Context
import android.net.http.SslCertificate
import android.webkit.WebView
import com.example.webmil.browser.model.Bookmark
import com.example.webmil.browser.model.SslSecurityInfo
import com.example.webmil.browser.model.WebTab
import com.example.webmil.browser.storage.BookmarkStorage
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import java.util.UUID

/**
 * UI State for the Jetpack Compose Web Browser.
 */
data class WebBrowserUiState(
    val tabs: List<WebTab> = emptyList(),
    val activeTabId: String = "",
    val bookmarks: List<Bookmark> = BookmarkStorage.defaultMilitaryPortals,
    val isSecurityDialogVisible: Boolean = false,
    val isBookmarkSheetVisible: Boolean = false
) {
    val activeTab: WebTab?
        get() = tabs.find { it.id == activeTabId }
}

/**
 * Manages multi-tab navigation, URL loading, military portal bookmarks persistence,
 * and SSL security metadata.
 */
class WebBrowserManager(private val context: Context? = null) {

    private val bookmarkStorage = BookmarkStorage(context)
    private val _uiState = MutableStateFlow(WebBrowserUiState(bookmarks = bookmarkStorage.loadBookmarks()))
    val uiState: StateFlow<WebBrowserUiState> = _uiState.asStateFlow()

    init {
        // Create initial tab
        addTab("https://webmail.apps.mil", title = "DoD O365 Webmail")
    }

    fun addTab(initialUrl: String = "https://webmail.apps.mil", title: String = "New Tab"): String {
        val formattedUrl = formatUrl(initialUrl)
        val newTab = WebTab(
            id = UUID.randomUUID().toString(),
            url = formattedUrl,
            title = title,
            isBookmarked = isUrlBookmarked(formattedUrl)
        )
        _uiState.update { state ->
            state.copy(
                tabs = state.tabs + newTab,
                activeTabId = newTab.id
            )
        }
        return newTab.id
    }

    fun closeTab(tabId: String) {
        _uiState.update { state ->
            val updatedTabs = state.tabs.filterNot { it.id == tabId }
            if (updatedTabs.isEmpty()) {
                val fallbackTab = WebTab(
                    id = UUID.randomUUID().toString(),
                    url = "https://webmail.apps.mil",
                    title = "New Tab",
                    isBookmarked = isUrlBookmarked("https://webmail.apps.mil")
                )
                state.copy(tabs = listOf(fallbackTab), activeTabId = fallbackTab.id)
            } else {
                val newActiveId = if (state.activeTabId == tabId) {
                    updatedTabs.last().id
                } else {
                    state.activeTabId
                }
                state.copy(tabs = updatedTabs, activeTabId = newActiveId)
            }
        }
    }

    fun selectTab(tabId: String) {
        _uiState.update { state ->
            if (state.tabs.any { it.id == tabId }) {
                state.copy(activeTabId = tabId)
            } else {
                state
            }
        }
    }

    fun updateTabUrl(tabId: String, newUrl: String) {
        val formattedUrl = formatUrl(newUrl)
        val host = parseHost(formattedUrl)
        _uiState.update { state ->
            val updatedTabs = state.tabs.map { tab ->
                if (tab.id == tabId) {
                    val currentSec = tab.securityInfo
                    val isHttps = formattedUrl.startsWith("https://", ignoreCase = true)
                    tab.copy(
                        url = formattedUrl,
                        isBookmarked = isUrlBookmarked(formattedUrl),
                        securityInfo = currentSec.copy(
                            isSecure = isHttps && currentSec.sslError == null,
                            host = host
                        )
                    )
                } else tab
            }
            state.copy(tabs = updatedTabs)
        }
    }

    fun updateTabTitle(tabId: String, title: String) {
        if (title.isBlank()) return
        _uiState.update { state ->
            val updatedTabs = state.tabs.map { tab ->
                if (tab.id == tabId) tab.copy(title = title) else tab
            }
            state.copy(tabs = updatedTabs)
        }
    }

    fun updateTabLoading(tabId: String, isLoading: Boolean) {
        _uiState.update { state ->
            val updatedTabs = state.tabs.map { tab ->
                if (tab.id == tabId) tab.copy(isLoading = isLoading) else tab
            }
            state.copy(tabs = updatedTabs)
        }
    }

    fun updateTabNavigationState(tabId: String, canGoBack: Boolean, canGoForward: Boolean) {
        _uiState.update { state ->
            val updatedTabs = state.tabs.map { tab ->
                if (tab.id == tabId) tab.copy(canGoBack = canGoBack, canGoForward = canGoForward) else tab
            }
            state.copy(tabs = updatedTabs)
        }
    }

    fun updateTabSslCertificate(
        tabId: String,
        certificate: SslCertificate?,
        sslError: String? = null,
        isMtls: Boolean = false
    ) {
        _uiState.update { state ->
            val updatedTabs = state.tabs.map { tab ->
                if (tab.id == tabId) {
                    val host = parseHost(tab.url)
                    val isHttps = tab.url.startsWith("https://", ignoreCase = true)
                    val secInfo = SslSecurityInfo(
                        isSecure = isHttps && sslError == null,
                        isMtlsAuthenticated = isMtls,
                        host = host,
                        subjectDN = certificate?.issuedTo?.dName ?: "CN=$host",
                        issuerDN = certificate?.issuedBy?.dName ?: "Unknown CA",
                        validFrom = certificate?.validNotBeforeDate?.toString(),
                        validTo = certificate?.validNotAfterDate?.toString(),
                        sslError = sslError,
                        rawCertificate = certificate
                    )
                    tab.copy(securityInfo = secInfo)
                } else tab
            }
            state.copy(tabs = updatedTabs)
        }
    }

    fun registerWebView(tabId: String, webView: WebView) {
        _uiState.update { state ->
            val updatedTabs = state.tabs.map { tab ->
                if (tab.id == tabId) tab.copy(webView = webView) else tab
            }
            state.copy(tabs = updatedTabs)
        }
    }

    // --- BOOKMARK MANAGEMENT & PERSISTENCE ---

    fun addBookmark(url: String, title: String, category: String = "Government") {
        val updatedBookmarks = bookmarkStorage.addBookmark(_uiState.value.bookmarks, title, url, category)
        val formatted = formatUrl(url)
        _uiState.update { state ->
            val updatedTabs = state.tabs.map { tab ->
                if (tab.url == formatted) tab.copy(isBookmarked = true) else tab
            }
            state.copy(bookmarks = updatedBookmarks, tabs = updatedTabs)
        }
    }

    fun deleteBookmark(url: String) {
        val updatedBookmarks = bookmarkStorage.deleteBookmark(_uiState.value.bookmarks, url)
        val formatted = formatUrl(url)
        _uiState.update { state ->
            val updatedTabs = state.tabs.map { tab ->
                if (tab.url == formatted || tab.url == url) tab.copy(isBookmarked = false) else tab
            }
            state.copy(bookmarks = updatedBookmarks, tabs = updatedTabs)
        }
    }

    fun toggleBookmark(url: String, title: String) {
        val updatedBookmarks = bookmarkStorage.toggleBookmark(_uiState.value.bookmarks, url, title)
        val isBookmarkedNow = updatedBookmarks.any { it.url.equals(url, ignoreCase = true) || it.url.equals(formatUrl(url), ignoreCase = true) }
        _uiState.update { state ->
            val updatedTabs = state.tabs.map { tab ->
                if (tab.url.equals(url, ignoreCase = true) || tab.url.equals(formatUrl(url), ignoreCase = true)) {
                    tab.copy(isBookmarked = isBookmarkedNow)
                } else tab
            }
            state.copy(bookmarks = updatedBookmarks, tabs = updatedTabs)
        }
    }

    fun listBookmarks(): List<Bookmark> {
        return _uiState.value.bookmarks
    }

    fun isUrlBookmarked(url: String): Boolean {
        val formatted = formatUrl(url)
        return _uiState.value.bookmarks.any {
            it.url.equals(url, ignoreCase = true) || it.url.equals(formatted, ignoreCase = true)
        }
    }

    fun showSecurityDialog(show: Boolean = true) {
        _uiState.update { it.copy(isSecurityDialogVisible = show) }
    }

    fun showBookmarkSheet(show: Boolean = true) {
        _uiState.update { it.copy(isBookmarkSheetVisible = show) }
    }

    companion object {
        fun formatUrl(input: String): String {
            val trimmed = input.trim()
            if (trimmed.isEmpty()) return "https://webmail.apps.mil"
            return if (trimmed.startsWith("http://", ignoreCase = true) ||
                trimmed.startsWith("https://", ignoreCase = true)
            ) {
                trimmed
            } else {
                "https://$trimmed"
            }
        }

        fun parseHost(url: String): String {
            return try {
                val clean = url.substringAfter("://").substringBefore("/")
                clean.ifEmpty { url }
            } catch (_: Exception) {
                url
            }
        }
    }
}
