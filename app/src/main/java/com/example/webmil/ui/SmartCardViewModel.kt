package com.example.webmil.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.webmil.browser.WebBrowserManager
import com.example.webmil.browser.WebBrowserUiState
import com.example.webmil.smartcard.SmartCardManager
import com.example.webmil.smartcard.model.PinVerificationState
import com.example.webmil.smartcard.model.SmartCardUiState
import com.example.webmil.smartcard.tls.SmartCardWebViewClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class SmartCardViewModel(application: Application) : AndroidViewModel(application) {

    val smartCardManager: SmartCardManager = SmartCardManager(application.applicationContext)
    val uiState: StateFlow<SmartCardUiState> = smartCardManager.uiState

    val browserManager: WebBrowserManager = WebBrowserManager(application.applicationContext)
    val browserUiState: StateFlow<WebBrowserUiState> = browserManager.uiState

    private val registeredWebViewClients = mutableSetOf<SmartCardWebViewClient>()
    var smartCardWebViewClient: SmartCardWebViewClient? = null
        private set

    init {
        // Wire smart card removal events to rapid security session revocation
        smartCardManager.onCardRemovedListener = { _ ->
            smartCardManager.clearWebViewSslSessionCache()
        }
    }

    fun registerWebViewClient(client: SmartCardWebViewClient) {
        smartCardWebViewClient = client
        registeredWebViewClients.add(client)
    }

    fun unregisterWebViewClient(client: SmartCardWebViewClient) {
        registeredWebViewClients.remove(client)
        if (smartCardWebViewClient == client) {
            smartCardWebViewClient = registeredWebViewClients.firstOrNull()
        }
    }

    fun verifyPin(pin: String, onResult: ((Boolean) -> Unit)? = null) {
        viewModelScope.launch(Dispatchers.IO) {
            smartCardManager.setVerifyingPinState(true, PinVerificationState.VERIFYING)

            val success = smartCardManager.verifyPin(pin)

            withContext(Dispatchers.Main) {
                if (success) {
                    smartCardManager.setVerifyingPinState(false, PinVerificationState.SUCCESS)
                    // Auto-close security status / PIN dialog
                    browserManager.showSecurityDialog(false)
                    // Fulfill pending ClientCertRequest immediately
                    smartCardWebViewClient?.resumePendingClientCertRequest()
                    registeredWebViewClients.forEach { it.resumePendingClientCertRequest() }
                    smartCardManager.resumePendingTlsRequest()
                } else {
                    smartCardManager.setVerifyingPinState(false, PinVerificationState.FAILED)
                }
                onResult?.invoke(success)
            }
        }
    }

    fun scanUsbDevices() {
        smartCardManager.scanUsbDevices()
    }

    fun powerOnCard() {
        viewModelScope.launch(Dispatchers.IO) {
            smartCardManager.powerOnPhysicalCard()
        }
    }

    fun enableSimulationMode() {
        smartCardManager.enableSimulationMode()
    }

    fun selectCertificate(certificate: com.example.webmil.smartcard.model.SmartCardCertificate) {
        viewModelScope.launch(Dispatchers.IO) {
            smartCardManager.selectCertificate(certificate)
        }
    }

    fun ejectCard() {
        smartCardManager.ejectCard()
    }

    fun logoutSession() {
        smartCardManager.logoutSession()
    }

    fun dismissCardRemovalWarning() {
        smartCardManager.dismissCardRemovalWarning()
    }

    fun resetSession() {
        smartCardManager.resetSession()
    }

    fun disconnectReader() {
        smartCardManager.disconnectUsbReader()
    }

    fun addBookmark(url: String, title: String, category: String = "Government") {
        browserManager.addBookmark(url, title, category)
    }

    fun deleteBookmark(url: String) {
        browserManager.deleteBookmark(url)
    }

    fun toggleBookmark(url: String, title: String) {
        browserManager.toggleBookmark(url, title)
    }

    override fun onCleared() {
        super.onCleared()
        registeredWebViewClients.clear()
        smartCardWebViewClient = null
        smartCardManager.unregister()
    }
}
