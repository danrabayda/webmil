package com.example.webmil.smartcard.tls

import android.graphics.Bitmap
import android.net.http.SslError
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.webkit.ClientCertRequest
import android.webkit.SslErrorHandler
import android.webkit.WebView
import android.webkit.WebViewClient
import com.example.webmil.smartcard.SmartCardManager

/**
 * Custom WebViewClient that intercepts TLS ClientCertRequest and services Mutual TLS (mTLS)
 * using the authenticated Smart Card (PIV / CAC) certificate and private key.
 * Also provides callbacks for page loading state, navigation status, and SSL security details.
 */
class SmartCardWebViewClient(
    private val smartCardManager: SmartCardManager,
    private val onPageStartedCallback: ((String?) -> Unit)? = null,
    private val onPageFinishedCallback: ((WebView?, String?) -> Unit)? = null,
    private val onErrorCallback: ((String) -> Unit)? = null,
    private val onSslErrorCallback: ((SslError?) -> Unit)? = null,
    private val onMtlsRequestedCallback: ((String) -> Unit)? = null,
    private val onMtlsAuthenticatedCallback: ((String) -> Unit)? = null
) : WebViewClient() {

    private var pendingClientCertRequest: ClientCertRequest? = null
    private var attachedWebView: WebView? = null

    override fun onReceivedClientCertRequest(view: WebView?, request: ClientCertRequest?) {
        if (request == null) return

        attachedWebView = view
        val host = request.host
        val port = request.port
        val keyTypesStr = request.keyTypes?.joinToString(", ") ?: "none"
        val principalsStr = request.principals?.joinToString("; ") { it.name } ?: "none"

        logI(TAG, "Mutual TLS ClientCertRequest received from $host:$port | keyTypes: [$keyTypesStr] | principals size: ${request.principals?.size ?: 0} [$principalsStr]")
        smartCardManager.logSystemEvent("WebView requested Mutual TLS Client Certificate for $host:$port (keyTypes: [$keyTypesStr], principals: [$principalsStr])")
        onMtlsRequestedCallback?.invoke(host)

        val certChain = smartCardManager.getActiveCertChain(request.principals, host)
        val privateKey = smartCardManager.getSmartCardPrivateKey()
        val isAuthorized = smartCardManager.isSessionAuthorized()

        if (isAuthorized && privateKey != null && !certChain.isNullOrEmpty()) {
            val certSubject = certChain.firstOrNull()?.subjectX500Principal?.name ?: "unknown"
            val certIssuer = certChain.firstOrNull()?.issuerX500Principal?.name ?: "unknown"

            logI(TAG, "Auto-proceeding mTLS for host=$host using card cert Subject: $certSubject, Issuer: $certIssuer (chain size: ${certChain.size})")
            smartCardManager.logSystemEvent("Auto-proceeding mTLS request for $host with Smart Card certificate (Subject: $certSubject, Issuer: $certIssuer)")

            smartCardManager.setMtlsAuthenticated(true)
            smartCardManager.clearPendingTlsHost()
            onMtlsAuthenticatedCallback?.invoke(host)
            pendingClientCertRequest = null

            postToMain {
                try {
                    request.proceed(privateKey, certChain)
                    logI(TAG, "Successfully invoked request.proceed for host=$host")
                } catch (e: Exception) {
                    logE(TAG, "Error executing request.proceed on Main thread for host=$host", e)
                }
            }
        } else {
            logW(TAG, "Smart Card session not authorized or credentials incomplete for host=$host. Storing pending request and prompting for PIN.")
            pendingClientCertRequest = request
            smartCardManager.handlePendingTlsRequest(host, request)
        }
    }

    /**
     * Resumes and fulfills any pending ClientCertRequest immediately on the Main UI thread
     * once PIN verification succeeds.
     */
    fun resumePendingClientCertRequest() {
        val request = pendingClientCertRequest
        val principals = request?.principals
        val certChain = smartCardManager.getActiveCertChain(principals, request?.host)
        val privateKey = smartCardManager.getSmartCardPrivateKey()
        val isAuthorized = smartCardManager.isSessionAuthorized()

        logI(TAG, "resumePendingClientCertRequest invoked (hasPending=${request != null}, isAuthorized=$isAuthorized)")

        if (request != null && isAuthorized && !certChain.isNullOrEmpty() && privateKey != null) {
            val host = request.host
            val keyTypesStr = request.keyTypes?.joinToString(", ") ?: "none"
            val principalsStr = principals?.joinToString("; ") { it.name } ?: "none"
            val certSubject = certChain.firstOrNull()?.subjectX500Principal?.name ?: "unknown"
            val certIssuer = certChain.firstOrNull()?.issuerX500Principal?.name ?: "unknown"

            logI(TAG, "Fulfilling pending ClientCertRequest for host=$host | keyTypes: [$keyTypesStr] | principals: [$principalsStr] | cert Subject: $certSubject, Issuer: $certIssuer (chain size: ${certChain.size})")
            smartCardManager.logSystemEvent("Fulfilling pending ClientCertRequest on Main UI thread for $host with card certificate (Subject: $certSubject, Issuer: $certIssuer)")

            smartCardManager.setMtlsAuthenticated(true)
            smartCardManager.clearPendingTlsHost()
            onMtlsAuthenticatedCallback?.invoke(host)

            postToMain {
                try {
                    request.proceed(privateKey, certChain)
                    logI(TAG, "Successfully executed request.proceed on Main thread for host=$host")
                } catch (e: Exception) {
                    logE(TAG, "Error executing request.proceed on Main thread for host=$host", e)
                    try { request.cancel() } catch (_: Exception) {}
                }
            }
            pendingClientCertRequest = null
        } else if (request != null) {
            logW(TAG, "Session not authorized or credentials incomplete. Canceling pending ClientCertRequest.")
            smartCardManager.clearPendingTlsHost()
            postToMain {
                try {
                    request.cancel()
                } catch (e: Exception) {
                    logE(TAG, "Error executing request.cancel on Main thread", e)
                }
            }
            pendingClientCertRequest = null
        }

        // Also resume any pending TLS request held in SmartCardManager
        smartCardManager.resumePendingTlsRequest()
    }

    override fun onReceivedSslError(view: WebView?, handler: SslErrorHandler?, error: SslError?) {
        val errorMsg = error?.toString() ?: "Unknown SSL Error"
        logE(TAG, "WebView SSL Error: $errorMsg")
        smartCardManager.logSystemEvent("WebView SSL Error: $errorMsg")
        onSslErrorCallback?.invoke(error)
        onErrorCallback?.invoke("SSL Error: ${error?.primaryError}")
        // Allow user / testing to proceed if self-signed server cert is used during testing
        handler?.proceed()
    }

    override fun onPageStarted(view: WebView?, url: String?, favicon: Bitmap?) {
        super.onPageStarted(view, url, favicon)
        onPageStartedCallback?.invoke(url)
    }

    override fun onPageFinished(view: WebView?, url: String?) {
        super.onPageFinished(view, url)
        onPageFinishedCallback?.invoke(view, url)
    }

    private fun postToMain(block: () -> Unit) {
        try {
            Handler(Looper.getMainLooper()).post { block() }
        } catch (_: Throwable) {
            try { block() } catch (_: Throwable) {}
        }
    }

    private fun logI(tag: String, msg: String) {
        try { Log.i(tag, msg) } catch (_: Throwable) {}
    }

    private fun logW(tag: String, msg: String) {
        try { Log.w(tag, msg) } catch (_: Throwable) {}
    }

    private fun logE(tag: String, msg: String, t: Throwable? = null) {
        try {
            if (t != null) Log.e(tag, msg, t) else Log.e(tag, msg)
        } catch (_: Throwable) {}
    }

    companion object {
        private const val TAG = "SmartCardWebViewClient"
    }
}
