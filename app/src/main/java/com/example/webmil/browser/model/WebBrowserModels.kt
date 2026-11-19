package com.example.webmil.browser.model

import android.net.http.SslCertificate
import android.webkit.WebView
import java.util.UUID

/**
 * Information regarding SSL/TLS security of the current web page.
 */
data class SslSecurityInfo(
    val isSecure: Boolean = false,
    val isMtlsAuthenticated: Boolean = false,
    val host: String = "",
    val subjectDN: String? = null,
    val issuerDN: String? = null,
    val validFrom: String? = null,
    val validTo: String? = null,
    val sslError: String? = null,
    val rawCertificate: SslCertificate? = null
)

/**
 * Represents a single web browser tab.
 */
data class WebTab(
    val id: String,
    val url: String,
    val title: String = "New Tab",
    val isLoading: Boolean = false,
    val canGoBack: Boolean = false,
    val canGoForward: Boolean = false,
    val isBookmarked: Boolean = false,
    val securityInfo: SslSecurityInfo = SslSecurityInfo(),
    val webView: WebView? = null
)

/**
 * Web bookmark entry for DoD / Military / Government portals.
 */
data class Bookmark(
    val id: String = UUID.randomUUID().toString(),
    val title: String,
    val url: String,
    val category: String = "Government",
    val isDefault: Boolean = false
)
