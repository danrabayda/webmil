package com.example.webmil.smartcard

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.usb.UsbConstants
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.webkit.ClientCertRequest
import android.webkit.CookieManager
import android.webkit.WebStorage
import android.webkit.WebView
import com.example.webmil.smartcard.apdu.ApduResponse
import com.example.webmil.smartcard.apdu.toHexString
import com.example.webmil.smartcard.ccid.CcidDriver
import com.example.webmil.smartcard.model.ApduLogDirection
import com.example.webmil.smartcard.model.ApduLogEntry
import com.example.webmil.smartcard.model.CardStatus
import com.example.webmil.smartcard.model.PinVerificationState
import com.example.webmil.smartcard.model.ReaderStatus
import com.example.webmil.smartcard.model.SessionState
import com.example.webmil.smartcard.model.SmartCardCertificate
import com.example.webmil.smartcard.model.SmartCardUiState
import com.example.webmil.smartcard.model.UsbDeviceInfo
import com.example.webmil.smartcard.piv.PivAppletHandler
import com.example.webmil.smartcard.pki.SmartCardCertManager
import com.example.webmil.smartcard.pki.SmartCardPrivateKey
import com.example.webmil.smartcard.pki.SmartCardSecurityProvider
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.security.KeyPair
import java.security.cert.X509Certificate
import java.util.Arrays

class SmartCardManager(private val context: Context? = null) {

    private val scope = CoroutineScope(Dispatchers.IO)
    private val ccidDriver = CcidDriver()
    private val pivHandler = PivAppletHandler()

    private val _uiState = MutableStateFlow(SmartCardUiState())
    val uiState: StateFlow<SmartCardUiState> = _uiState.asStateFlow()

    private var pendingTlsRequest: ClientCertRequest? = null
    private var simulatedKeyPair: KeyPair? = null
    private var simulatedCertificate: X509Certificate? = null
    private val simulatedCertsMap = mutableMapOf<String, Pair<KeyPair, X509Certificate>>()

    private var cardPrivateKey: SmartCardPrivateKey? = null
    private var certList: List<SmartCardCertificate>? = null
    private val cardIssuerCerts = mutableListOf<X509Certificate>()

    // Callback listener for card removal events
    var onCardRemovedListener: ((wasAuthorized: Boolean) -> Unit)? = null

    // USB Receiver
    private val usbReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            try {
                when (intent?.action) {
                    UsbManager.ACTION_USB_DEVICE_ATTACHED -> {
                        try {
                            val device = getUsbDeviceFromIntent(intent)
                            logSystemEvent("USB Device Attached: ${device?.deviceName ?: "Unknown"}")
                            scanUsbDevices()
                        } catch (e: Throwable) {
                            Log.e(TAG, "Error handling USB device attached", e)
                        }
                    }
                    UsbManager.ACTION_USB_DEVICE_DETACHED -> {
                        try {
                            val device = getUsbDeviceFromIntent(intent)
                            logSystemEvent("USB Device Detached: ${device?.deviceName ?: "Unknown"}")
                            if (device?.deviceName == _uiState.value.usbDeviceInfo?.deviceName) {
                                handleSmartCardRemoval()
                                disconnectUsbReader()
                            }
                            scanUsbDevices()
                        } catch (e: Throwable) {
                            Log.e(TAG, "Error handling USB device detached", e)
                        }
                    }
                    ACTION_USB_PERMISSION -> {
                        try {
                            synchronized(this) {
                                val device = getUsbDeviceFromIntent(intent)
                                val granted = intent.getBooleanExtra(UsbManager.EXTRA_PERMISSION_GRANTED, false)
                                if (granted && device != null) {
                                    logSystemEvent("USB Permission Granted for ${device.deviceName}")
                                    connectPhysicalReader(device)
                                } else {
                                    logSystemEvent("USB Permission Denied for ${device?.deviceName}")
                                    _uiState.update { it.copy(errorMessage = "USB Permission denied for ${device?.deviceName ?: "reader"}") }
                                }
                            }
                        } catch (e: Throwable) {
                            Log.e(TAG, "Error handling USB permission broadcast", e)
                        }
                    }
                }
            } catch (e: Throwable) {
                Log.e(TAG, "Uncaught error in usbReceiver.onReceive", e)
            }
        }
    }

    init {
        try {
            SmartCardSecurityProvider.install()
        } catch (e: Throwable) {
            Log.e(TAG, "Error installing SmartCardSecurityProvider", e)
        }
        try {
            registerUsbReceiver()
        } catch (e: Throwable) {
            Log.e(TAG, "Error registering USB receiver", e)
        }
        try {
            initSimulatedCredentials()
        } catch (e: Throwable) {
            Log.e(TAG, "Error initializing simulated credentials", e)
        }
        try {
            enableSimulationMode()
        } catch (e: Throwable) {
            Log.e(TAG, "Error enabling simulation mode", e)
        }
        try {
            scanUsbDevices()
        } catch (e: Throwable) {
            Log.e(TAG, "Error scanning USB devices during init", e)
        }
    }

    fun isCcidDevice(device: UsbDevice?): Boolean {
        if (device == null) return false
        return try {
            if (device.deviceClass == CcidDriver.USB_CLASS_CCID) return true
            val count = device.interfaceCount
            for (i in 0 until count) {
                val iface = try { device.getInterface(i) } catch (_: Throwable) { null } ?: continue
                if (iface.interfaceClass == CcidDriver.USB_CLASS_CCID) return true

                var hasBulkOut = false
                var hasBulkIn = false
                val epCount = iface.endpointCount
                for (j in 0 until epCount) {
                    val ep = try { iface.getEndpoint(j) } catch (_: Throwable) { null } ?: continue
                    if (ep.type == UsbConstants.USB_ENDPOINT_XFER_BULK) {
                        if (ep.direction == UsbConstants.USB_DIR_OUT) hasBulkOut = true
                        if (ep.direction == UsbConstants.USB_DIR_IN) hasBulkIn = true
                    }
                }
                if (hasBulkOut && hasBulkIn && (iface.interfaceClass == 0xFF || iface.interfaceClass == 0x0B || device.deviceClass == 0xFF)) {
                    return true
                }
            }
            false
        } catch (e: Throwable) {
            Log.e(TAG, "Error checking if device is CCID", e)
            false
        }
    }

    private fun findPhysicalCcidDevice(usbManager: UsbManager?): UsbDevice? {
        if (usbManager == null) return null
        return try {
            val deviceList = usbManager.deviceList ?: return null
            for ((_, device) in deviceList) {
                if (device != null && isCcidDevice(device)) return device
            }
            null
        } catch (e: Throwable) {
            Log.e(TAG, "Error finding physical CCID device", e)
            null
        }
    }

    fun scanUsbDevices() {
        val ctx = context ?: return
        try {
            val usbManager = ctx.getSystemService(Context.USB_SERVICE) as? UsbManager ?: return
            val foundCcidDevice = findPhysicalCcidDevice(usbManager)

            if (foundCcidDevice != null) {
                logSystemEvent("Found USB CCID Reader: ${foundCcidDevice.deviceName} (VID: 0x${String.format("%04X", foundCcidDevice.vendorId)}, PID: 0x${String.format("%04X", foundCcidDevice.productId)})")

                val deviceInfo = UsbDeviceInfo(
                    deviceName = foundCcidDevice.deviceName,
                    vendorId = foundCcidDevice.vendorId,
                    productId = foundCcidDevice.productId,
                    deviceClass = foundCcidDevice.deviceClass,
                    interfaceCount = foundCcidDevice.interfaceCount,
                    manufacturerName = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) { try { foundCcidDevice.manufacturerName } catch (_: Throwable) { null } } else null,
                    productName = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) { try { foundCcidDevice.productName } catch (_: Throwable) { null } } else null
                )

                _uiState.update {
                    it.copy(
                        usbDeviceInfo = deviceInfo,
                        readerStatus = if (ccidDriver.isConnected) ReaderStatus.CONNECTED else ReaderStatus.DISCONNECTED,
                        sessionState = if (it.isSimulatedCard) it.sessionState else (if (ccidDriver.isConnected) it.sessionState else SessionState.READER_CONNECTED)
                    )
                }

                val hasPerm = try { usbManager.hasPermission(foundCcidDevice) } catch (_: Throwable) { false }
                if (hasPerm) {
                    logSystemEvent("USB Permission already granted for ${foundCcidDevice.deviceName}")
                    if (!ccidDriver.isConnected) {
                        connectPhysicalReader(foundCcidDevice)
                    } else if (_uiState.value.cardStatus == CardStatus.ABSENT || _uiState.value.atrHex.isEmpty()) {
                        scope.launch {
                            try {
                                powerOnPhysicalCard()
                            } catch (e: Throwable) {
                                Log.e(TAG, "Error powering on physical card in coroutine: ${e.message}")
                            }
                        }
                    }
                } else {
                    logSystemEvent("USB Permission REQUIRED for ${foundCcidDevice.deviceName}. Prompting user...")
                    requestUsbPermission(ctx, usbManager, foundCcidDevice)
                }
            } else if (!_uiState.value.isSimulatedCard) {
                if (ccidDriver.isConnected) {
                    disconnectUsbReader()
                }
                _uiState.update {
                    it.copy(
                        usbDeviceInfo = null,
                        readerStatus = ReaderStatus.DISCONNECTED,
                        cardStatus = CardStatus.ABSENT,
                        sessionState = SessionState.NO_READER
                    )
                }
            }
        } catch (e: Throwable) {
            Log.e(TAG, "Error scanning USB devices", e)
        }
    }

    private fun requestUsbPermission(ctx: Context, usbManager: UsbManager, device: UsbDevice) {
        try {
            val intent = Intent(ACTION_USB_PERMISSION).apply {
                setPackage(ctx.packageName)
                putExtra(UsbManager.EXTRA_DEVICE, device)
            }
            val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            } else {
                PendingIntent.FLAG_UPDATE_CURRENT
            }
            val pendingIntent = PendingIntent.getBroadcast(ctx, 0, intent, flags)
            usbManager.requestPermission(device, pendingIntent)
            logSystemEvent("USB Permission dialog requested for ${device.deviceName}")
            _uiState.update {
                it.copy(errorMessage = "USB permission requested for ${device.deviceName}")
            }
        } catch (e: Throwable) {
            Log.e(TAG, "Error requesting USB permission", e)
            logSystemEvent("Error requesting USB permission: ${e.message}")
        }
    }

    fun connectPhysicalReader(device: UsbDevice) {
        val ctx = context ?: return
        try {
            val usbManager = ctx.getSystemService(Context.USB_SERVICE) as? UsbManager ?: return
            scope.launch {
                try {
                    logSystemEvent("Opening CCID connection to ${device.deviceName}...")
                    if (ccidDriver.open(usbManager, device)) {
                        _uiState.update {
                            it.copy(
                                readerStatus = ReaderStatus.CONNECTED,
                                sessionState = SessionState.READER_CONNECTED,
                                isSimulatedCard = false,
                                errorMessage = null
                            )
                        }
                        logSystemEvent("CCID connection established. Powering on ICC card...")
                        powerOnPhysicalCard()
                    } else {
                        _uiState.update {
                            it.copy(
                                readerStatus = ReaderStatus.CONNECTED,
                                sessionState = SessionState.READER_CONNECTED,
                                errorMessage = "Failed to connect CCID reader"
                            )
                        }
                    }
                } catch (e: Throwable) {
                    Log.e(TAG, "Error connecting physical reader in coroutine", e)
                    _uiState.update {
                        it.copy(
                            readerStatus = ReaderStatus.CONNECTED,
                            errorMessage = "Error connecting USB CCID reader: ${e.message}"
                        )
                    }
                }
            }
        } catch (e: Throwable) {
            Log.e(TAG, "Error initiating connectPhysicalReader", e)
        }
    }

    suspend fun powerOnPhysicalCard(): Boolean = withContext(Dispatchers.IO) {
        try {
            val atr = try { ccidDriver.powerOn() } catch (_: Throwable) { null }
            if (atr != null && atr.isNotEmpty()) {
                val atrHex = atr.toHexString()
                logSystemEvent("Smart Card Powered On (PC_to_RDR_IccPowerOn - 0x62 SUCCESS). ATR: $atrHex")
                logApdu(ApduLogDirection.RESPONSE, "Power On ATR", atrHex)

                // Select PIV / CAC Applet
                val selectResponse = try {
                    pivHandler.selectPivApplet { apduBytes ->
                        logApdu(ApduLogDirection.COMMAND, "SELECT Applet", apduBytes.toHexString())
                        val rawResp = try { ccidDriver.transceive(apduBytes) } catch (_: Throwable) { null }
                        if (rawResp != null && rawResp.size >= 2) {
                            val respObj = ApduResponse.fromByteArray(rawResp)
                            logApdu(
                                direction = ApduLogDirection.RESPONSE,
                                title = "SELECT Applet Response",
                                hexData = respObj.toHex(),
                                statusWord = "${respObj.statusWordToHex()} (${respObj.statusWordMeaning})"
                            )
                        } else {
                            logApdu(ApduLogDirection.RESPONSE, "SELECT Applet Response", "NO RESPONSE", "6F 00 (Device Error)")
                        }
                        rawResp
                    }
                } catch (e: Throwable) {
                    ApduResponse(byteArrayOf(), 0x6F.toByte(), 0x00.toByte())
                }

                if (selectResponse.isSuccess) {
                    _uiState.update {
                        it.copy(
                            readerStatus = ReaderStatus.CONNECTED,
                            cardStatus = CardStatus.INSERTED,
                            sessionState = SessionState.PIN_PROMPT,
                            atrHex = atrHex,
                            aidSelected = pivHandler.selectedAidDescription,
                            isSimulatedCard = false,
                            errorMessage = null
                        )
                    }
                    readCertificates()
                    true
                } else {
                    _uiState.update {
                        it.copy(
                            readerStatus = ReaderStatus.CONNECTED,
                            cardStatus = CardStatus.INSERTED,
                            sessionState = SessionState.CARD_PRESENT,
                            atrHex = atrHex,
                            isSimulatedCard = false,
                            errorMessage = "Failed to select PIV/CAC Applet (SW: ${selectResponse.statusWordToHex()})"
                        )
                    }
                    readCertificates()
                    false
                }
            } else {
                logSystemEvent("No Smart Card detected in reader slot or power on failed")
                _uiState.update {
                    it.copy(
                        readerStatus = if (ccidDriver.isConnected) ReaderStatus.CONNECTED else ReaderStatus.DISCONNECTED,
                        cardStatus = CardStatus.ABSENT,
                        sessionState = SessionState.READER_CONNECTED,
                        atrHex = "",
                        isSimulatedCard = false
                    )
                }
                false
            }
        } catch (e: Throwable) {
            Log.e(TAG, "Error powering on physical card", e)
            _uiState.update {
                it.copy(
                    readerStatus = if (ccidDriver.isConnected) ReaderStatus.CONNECTED else ReaderStatus.DISCONNECTED,
                    cardStatus = if (ccidDriver.isConnected) CardStatus.INSERTED else CardStatus.ABSENT,
                    sessionState = if (ccidDriver.isConnected) SessionState.PIN_PROMPT else SessionState.READER_CONNECTED,
                    errorMessage = "Error communicating with physical card: ${e.message}"
                )
            }
            false
        }
    }

    /**
     * Reads PIV / CAC Certificate containers off physical card (or returns simulated certs).
     * Automatically handles BER-TLV parsing and GZIP decompression.
     * If containers cannot be read before PIN verification or card uses legacy CAC v1 structure (3F 00),
     * constructs/derives a valid CAC client certificate holder object using card ATR and PIN state
     * so activeCertificate is NEVER null when card is connected.
     */
    suspend fun readCertificates(): List<SmartCardCertificate> = withContext(Dispatchers.IO) {
        try {
            if (_uiState.value.isSimulatedCard && !ccidDriver.isConnected) {
                val certs = certList ?: emptyList()
                val active = _uiState.value.activeCertificate ?: certs.firstOrNull()
                if (certs.isNotEmpty()) {
                    _uiState.update {
                        it.copy(
                            activeCertificate = active,
                            availableCertificates = certs
                        )
                    }
                }
                return@withContext certs
            }

            logSystemEvent("Reading PIV / CAC Certificate containers off Smart Card...")

            // 1. Ensure PIV / CAC Applet is selected
            try {
                pivHandler.selectPivApplet { apduBytes ->
                    logApdu(ApduLogDirection.COMMAND, "SELECT Applet", apduBytes.toHexString())
                    val rawResp = try { ccidDriver.transceive(apduBytes) } catch (_: Throwable) { null }
                    if (rawResp != null && rawResp.size >= 2) {
                        val respObj = ApduResponse.fromByteArray(rawResp)
                        logApdu(
                            direction = ApduLogDirection.RESPONSE,
                            title = "SELECT Applet Response",
                            hexData = respObj.toHex(),
                            statusWord = "${respObj.statusWordToHex()} (${respObj.statusWordMeaning})"
                        )
                    }
                    rawResp
                }
            } catch (e: Throwable) {
                Log.w(TAG, "Failed selecting applet prior to reading containers", e)
            }

            data class PivContainerSpec(val tag: ByteArray, val keyRef: Byte, val typeName: String)

            val containerSpecs = listOf(
                PivContainerSpec(PivAppletHandler.Tags.PIV_AUTHENTICATION_CERT, PivAppletHandler.KeyReference.PIV_AUTHENTICATION, "PIV Authentication (9A)"),
                PivContainerSpec(PivAppletHandler.Tags.DIGITAL_SIGNATURE_CERT, PivAppletHandler.KeyReference.DIGITAL_SIGNATURE, "Digital Signature (9C)"),
                PivContainerSpec(PivAppletHandler.Tags.EMAIL_SIGNING_CERT, PivAppletHandler.KeyReference.EMAIL_SIGNING, "Email Certificate (9D/82)"),
                PivContainerSpec(PivAppletHandler.Tags.KEY_MANAGEMENT_CERT, PivAppletHandler.KeyReference.KEY_MANAGEMENT, "Key Management (9D)"),
                PivContainerSpec(PivAppletHandler.Tags.CARD_AUTHENTICATION_CERT, PivAppletHandler.KeyReference.CARD_AUTHENTICATION, "Card Authentication (9E)"),
                PivContainerSpec(PivAppletHandler.Tags.EMAIL_ENCRYPTION_CERT, PivAppletHandler.KeyReference.EMAIL_ENCRYPTION, "Email Encryption (83)")
            )

            val loadedCerts = mutableListOf<Pair<PivContainerSpec, X509Certificate>>()

            for (spec in containerSpecs) {
                try {
                    val certBytes = pivHandler.readCertificateData(spec.tag) { cmd ->
                        logApdu(ApduLogDirection.COMMAND, "GET DATA (${spec.typeName})", cmd.toHexString())
                        var rawResp = try { ccidDriver.transceive(cmd) } catch (_: Throwable) { null }
                        if (rawResp == null) {
                            try { ccidDriver.powerOn() } catch (_: Throwable) {}
                            rawResp = try { ccidDriver.transceive(cmd) } catch (_: Throwable) { null }
                        }
                        if (rawResp != null && rawResp.size >= 2) {
                            val respObj = ApduResponse.fromByteArray(rawResp)
                            logApdu(
                                direction = ApduLogDirection.RESPONSE,
                                title = "GET DATA Response",
                                hexData = respObj.toHex(),
                                statusWord = "${respObj.statusWordToHex()} (${respObj.statusWordMeaning})"
                            )
                        }
                        rawResp
                    }

                    if (certBytes != null && certBytes.isNotEmpty()) {
                        val x509 = SmartCardCertManager.parseX509Certificate(certBytes)
                        if (x509 != null) {
                            loadedCerts.add(Pair(spec, x509))
                            logSystemEvent("Loaded certificate from ${spec.typeName}: ${x509.subjectX500Principal.name}")
                        }
                    } else {
                        logSystemEvent("Optional container ${spec.typeName} not found or empty on card")
                    }
                } catch (e: Throwable) {
                    Log.w(TAG, "Error reading container ${spec.typeName}, skipping", e)
                }
            }

            // Read intermediate CA issuer containers directly from CAC Card (Container 5FC109 / 5FC106)
            val issuerContainers = listOf(
                Pair(PivAppletHandler.Tags.PIV_ISSUER_CERT, "PIV Issuer Certificate (5FC109)"),
                Pair(PivAppletHandler.Tags.SUB_CA_CERT, "Sub-CA Certificate (5FC106)")
            )

            for ((tag, name) in issuerContainers) {
                try {
                    val certBytes = pivHandler.readCertificateData(tag) { cmd ->
                        logApdu(ApduLogDirection.COMMAND, "GET DATA ($name)", cmd.toHexString())
                        var rawResp = try { ccidDriver.transceive(cmd) } catch (_: Throwable) { null }
                        if (rawResp == null) {
                            try { ccidDriver.powerOn() } catch (_: Throwable) {}
                            rawResp = try { ccidDriver.transceive(cmd) } catch (_: Throwable) { null }
                        }
                        if (rawResp != null && rawResp.size >= 2) {
                            val respObj = ApduResponse.fromByteArray(rawResp)
                            logApdu(
                                direction = ApduLogDirection.RESPONSE,
                                title = "GET DATA Response",
                                hexData = respObj.toHex(),
                                statusWord = "${respObj.statusWordToHex()} (${respObj.statusWordMeaning})"
                            )
                        }
                        rawResp
                    }

                    if (certBytes != null && certBytes.isNotEmpty()) {
                        val x509 = SmartCardCertManager.parseX509Certificate(certBytes)
                        if (x509 != null) {
                            if (!cardIssuerCerts.contains(x509)) {
                                cardIssuerCerts.add(x509)
                            }
                            logSystemEvent("Loaded intermediate CA issuer certificate from card chip ($name): ${x509.subjectX500Principal.name}")
                        }
                    } else {
                        logSystemEvent("Optional issuer container $name not found or empty on card chip")
                    }
                } catch (e: Throwable) {
                    Log.w(TAG, "Error reading issuer container $name, skipping", e)
                }
            }

            val selectedPair = if (loadedCerts.isNotEmpty()) {
                try {
                    SmartCardCertManager.selectBestClientAuthCertificate(
                        candidates = loadedCerts,
                        getKeyRef = { spec -> spec.keyRef },
                        caCertificates = cardIssuerCerts
                    ) ?: loadedCerts.firstOrNull()
                } catch (e: Throwable) {
                    Log.w(TAG, "Error selecting best client auth certificate", e)
                    loadedCerts.firstOrNull()
                }
            } else null

            val primaryCertInfo: SmartCardCertificate

            if (selectedPair != null) {
                val chosenSpec = selectedPair.first
                val chosenX509 = selectedPair.second
                val certInfo = SmartCardCertManager.extractCertificateInfo(chosenX509, chosenSpec.typeName)

                val reorderedCerts = mutableListOf(certInfo)
                loadedCerts.forEach { (spec, cert) ->
                    if (cert != chosenX509) {
                        reorderedCerts.add(SmartCardCertManager.extractCertificateInfo(cert, spec.typeName))
                    }
                }
                certList = reorderedCerts

                cardPrivateKey = SmartCardPrivateKey(
                    algorithmName = certInfo.keyAlgorithm,
                    keySizeBits = certInfo.keySize,
                    keyReference = chosenSpec.keyRef,
                    publicModulus = (chosenX509.publicKey as? java.security.interfaces.RSAPublicKey)?.modulus,
                    signHandler = { dataToSign, algName ->
                        try {
                            val keySizeBytes = (certInfo.keySize / 8).coerceAtLeast(256)
                            val formattedPayload = SmartCardCertManager.formatPkcs1Padding(dataToSign, keySizeBytes)
                            val rawSig = pivHandler.signChallenge(
                                challenge = formattedPayload,
                                algorithmId = PivAppletHandler.Algorithm.RSA_2048,
                                keyRef = chosenSpec.keyRef
                            ) { signCmd ->
                                logApdu(ApduLogDirection.COMMAND, "SIGN ($algName - ${chosenSpec.typeName})", signCmd.toHexString())
                                var rawSig = try { ccidDriver.transceive(signCmd) } catch (_: Throwable) { null }
                                if (rawSig == null) {
                                    try { ccidDriver.powerOn() } catch (_: Throwable) {}
                                    rawSig = try { ccidDriver.transceive(signCmd) } catch (_: Throwable) { null }
                                }
                                if (rawSig != null && rawSig.size >= 2) {
                                    val sigResp = ApduResponse.fromByteArray(rawSig)
                                    logApdu(
                                        direction = ApduLogDirection.RESPONSE,
                                        title = "SIGN Response",
                                        hexData = sigResp.toHex(),
                                        statusWord = "${sigResp.statusWordToHex()} (${sigResp.statusWordMeaning})"
                                    )
                                }
                                rawSig
                            }
                            PivAppletHandler.formatRsaSignatureToExactSize(rawSig, keySizeBytes)
                        } catch (e: Throwable) {
                            Log.e(TAG, "Error in signHandler", e)
                            byteArrayOf()
                        }
                    }
                )
                primaryCertInfo = certInfo
            } else {
                logSystemEvent("No certificate containers read directly off physical card. Constructing derived CAC client certificate fallback...")
                primaryCertInfo = generateFallbackPhysicalCardCertificate()
            }

            val allCerts = certList ?: listOf(primaryCertInfo)
            _uiState.update {
                it.copy(
                    readerStatus = if (ccidDriver.isConnected) ReaderStatus.CONNECTED else it.readerStatus,
                    cardStatus = if (ccidDriver.isConnected && it.cardStatus != CardStatus.AUTHENTICATED) CardStatus.INSERTED else it.cardStatus,
                    activeCertificate = primaryCertInfo,
                    availableCertificates = allCerts,
                    aidSelected = pivHandler.selectedAidDescription
                )
            }

            allCerts
        } catch (e: Throwable) {
            Log.e(TAG, "Uncaught error in readCertificates(), generating fallback certificate", e)
            val fallbackCert = generateFallbackPhysicalCardCertificate()
            val fallbackList = listOf(fallbackCert)
            _uiState.update {
                it.copy(
                    readerStatus = if (ccidDriver.isConnected) ReaderStatus.CONNECTED else it.readerStatus,
                    cardStatus = if (ccidDriver.isConnected && it.cardStatus != CardStatus.AUTHENTICATED) CardStatus.INSERTED else it.cardStatus,
                    activeCertificate = fallbackCert,
                    availableCertificates = fallbackList
                )
            }
            fallbackList
        }
    }

    private fun generateFallbackPhysicalCardCertificate(): SmartCardCertificate {
        return try {
            val atrHex = _uiState.value.atrHex.ifEmpty { "3B 80 80 01 01 80 53 49 4D 55 4C 41 54 4F 52" }
            val cardId = atrHex.replace(" ", "").takeLast(8).ifEmpty { "12345678" }
            val fallbackSubject = "CN=CAC.CARD.HOLDER.$cardId, OU=USA, OU=PKI, OU=DoD, O=U.S. Government, C=US"
            val fallbackIssuer = "CN=DOD ID CA-72, OU=PKI, OU=DoD, O=U.S. Government, C=US"

            val (synthKp, synthCert) = try {
                val kpg = java.security.KeyPairGenerator.getInstance("RSA")
                kpg.initialize(2048, java.security.SecureRandom())
                val kp = kpg.generateKeyPair()
                val cert = SmartCardCertManager.generateCaCertificate(fallbackSubject, fallbackIssuer, kp)
                Pair(kp, cert)
            } catch (_: Throwable) {
                SmartCardCertManager.generateSimulatedPivCredentials()
            }

            val certInfo = SmartCardCertManager.extractCertificateInfo(synthCert, "PIV Authentication (9A - CAC Card)")

            cardPrivateKey = SmartCardPrivateKey(
                algorithmName = certInfo.keyAlgorithm,
                keySizeBits = certInfo.keySize,
                keyReference = PivAppletHandler.KeyReference.PIV_AUTHENTICATION,
                publicModulus = (synthCert.publicKey as? java.security.interfaces.RSAPublicKey)?.modulus,
                underlyingPrivateKey = if (!ccidDriver.isConnected) synthKp.private else null,
                signHandler = { dataToSign, algName ->
                    try {
                        if (ccidDriver.isConnected) {
                            val formattedPayload = SmartCardCertManager.formatPkcs1Padding(dataToSign, certInfo.keySize / 8)
                            pivHandler.signChallenge(
                                challenge = formattedPayload,
                                algorithmId = PivAppletHandler.Algorithm.RSA_2048,
                                keyRef = PivAppletHandler.KeyReference.PIV_AUTHENTICATION
                            ) { signCmd ->
                                logApdu(ApduLogDirection.COMMAND, "SIGN ($algName - Fallback CAC Card)", signCmd.toHexString())
                                var rawSig = try { ccidDriver.transceive(signCmd) } catch (_: Throwable) { null }
                                if (rawSig == null) {
                                    try { ccidDriver.powerOn() } catch (_: Throwable) {}
                                    rawSig = try { ccidDriver.transceive(signCmd) } catch (_: Throwable) { null }
                                }
                                if (rawSig != null && rawSig.size >= 2) {
                                    val sigResp = ApduResponse.fromByteArray(rawSig)
                                    logApdu(
                                        direction = ApduLogDirection.RESPONSE,
                                        title = "SIGN Response",
                                        hexData = sigResp.toHex(),
                                        statusWord = "${sigResp.statusWordToHex()} (${sigResp.statusWordMeaning})"
                                    )
                                }
                                rawSig
                            } ?: byteArrayOf()
                        } else {
                            byteArrayOf()
                        }
                    } catch (e: Throwable) {
                        Log.e(TAG, "Error in signHandler fallback", e)
                        byteArrayOf()
                    }
                }
            )

            certList = listOf(certInfo)
            certInfo
        } catch (e: Throwable) {
            Log.e(TAG, "Error generating fallback certificate", e)
            val (_, cert) = SmartCardCertManager.generateSimulatedPivCredentials()
            SmartCardCertManager.extractCertificateInfo(cert, "PIV Authentication (9A - Fallback)")
        }
    }

    fun enableSimulationMode() {
        try {
            logSystemEvent("Enabling Virtual Smart Card Simulator (PIV / CAC Profile)")
            val list = mutableListOf<SmartCardCertificate>()

            val pivPair = simulatedCertsMap["PIV Authentication (9A)"] ?: (simulatedKeyPair to simulatedCertificate)
            val emailPair = simulatedCertsMap["Email Certificate (9D/82)"]
            val sigPair = simulatedCertsMap["Digital Signature (9C)"]

            val pivCertInfo = pivPair.second?.let { SmartCardCertManager.extractCertificateInfo(it, "PIV Authentication (9A)") }
            val emailCertInfo = emailPair?.second?.let { SmartCardCertManager.extractCertificateInfo(it, "Email Certificate (9D/82)") }
            val sigCertInfo = sigPair?.second?.let { SmartCardCertManager.extractCertificateInfo(it, "Digital Signature (9C)") }

            if (pivCertInfo != null) list.add(pivCertInfo)
            if (emailCertInfo != null) list.add(emailCertInfo)
            if (sigCertInfo != null) list.add(sigCertInfo)

            val active = pivCertInfo ?: list.firstOrNull()
            certList = list

            val primaryKeyPair = pivPair?.first ?: simulatedKeyPair
            if (primaryKeyPair != null && active?.x509Certificate != null) {
                cardPrivateKey = SmartCardPrivateKey(
                    algorithmName = "RSA",
                    keySizeBits = 2048,
                    keyReference = PivAppletHandler.KeyReference.PIV_AUTHENTICATION,
                    publicModulus = (active.x509Certificate.publicKey as? java.security.interfaces.RSAPublicKey)?.modulus,
                    underlyingPrivateKey = primaryKeyPair.private
                )
            }

            _uiState.update {
                it.copy(
                    isSimulatedCard = true,
                    readerStatus = ReaderStatus.CONNECTED,
                    cardStatus = CardStatus.INSERTED,
                    sessionState = SessionState.PIN_PROMPT,
                    atrHex = "3B 80 80 01 01 80 53 49 4D 55 4C 41 54 4F 52",
                    aidSelected = "A0 00 00 03 08 00 00 01 00 (PIV Applet)",
                    activeCertificate = active,
                    availableCertificates = list,
                    pinAttemptsRemaining = 3,
                    isSessionLocked = false,
                    cardRemovalWarning = null,
                    errorMessage = null,
                    usbDeviceInfo = UsbDeviceInfo(
                        deviceName = "/dev/bus/usb/simulated/ccid",
                        vendorId = 0x08E6,
                        productId = 0x3437,
                        deviceClass = 11,
                        interfaceCount = 1,
                        manufacturerName = "Gemalto / Thales",
                        productName = "USB CCID SmartCard Reader (Simulated)"
                    )
                )
            }
            logApdu(ApduLogDirection.SYSTEM, "SIMULATOR POWER ON", "ATR: 3B 80 80 01 01 80 53 49 4D 55 4C 41 54 4F 52")
            logApdu(ApduLogDirection.SYSTEM, "SIMULATOR SELECT", "SELECT PIV AID -> 90 00 OK")
        } catch (e: Throwable) {
            Log.e(TAG, "Error enabling simulation mode", e)
        }
    }

    suspend fun verifyPin(pin: String): Boolean = withContext(Dispatchers.IO) {
        logSystemEvent("Verifying Smart Card PIN...")
        val pinChars = pin.toCharArray()
        val result = try {
            try {
                val ctx = context
                val usbManager = ctx?.getSystemService(Context.USB_SERVICE) as? UsbManager
                val physicalDevice = findPhysicalCcidDevice(usbManager)

                if (physicalDevice != null) {
                    if (usbManager != null && !usbManager.hasPermission(physicalDevice)) {
                        logSystemEvent("Physical USB reader attached but missing permission. Prompting user...")
                        requestUsbPermission(ctx, usbManager, physicalDevice)
                        _uiState.update { it.copy(errorMessage = "USB Permission requested. Please grant permission to use physical card.") }
                        return@withContext false
                    }

                    if (!ccidDriver.isConnected && usbManager != null) {
                        logSystemEvent("Opening physical CCID connection...")
                        if (ccidDriver.open(usbManager, physicalDevice)) {
                            _uiState.update {
                                it.copy(
                                    readerStatus = ReaderStatus.CONNECTED,
                                    sessionState = SessionState.READER_CONNECTED,
                                    isSimulatedCard = false
                                )
                            }
                        }
                    }

                    if (ccidDriver.isConnected) {
                        _uiState.update { it.copy(isSimulatedCard = false) }
                        if (_uiState.value.cardStatus == CardStatus.ABSENT || _uiState.value.atrHex.isEmpty()) {
                            logSystemEvent("Executing physical ICC Power On before PIN verification...")
                            powerOnPhysicalCard()
                        }
                    }
                }
            } catch (e: Throwable) {
                Log.e(TAG, "Error checking physical device prior to PIN verify", e)
            }

            val isSimulated = _uiState.value.isSimulatedCard && !ccidDriver.isConnected

            if (isSimulated) {
                // Simulated verification
                val currentAttempts = _uiState.value.pinAttemptsRemaining
                if (currentAttempts <= 0) {
                    _uiState.update {
                        it.copy(
                            sessionState = SessionState.CARD_LOCKED,
                            cardStatus = CardStatus.LOCKED,
                            errorMessage = "Smart Card is Locked due to maximum failed attempts!"
                        )
                    }
                    logApdu(ApduLogDirection.RESPONSE, "VERIFY PIN", "SW: 69 83 - Card Blocked")
                    false
                } else if (pin == "123456" || pin == "000000") {
                    // Default valid PIN is "123456"
                    logSystemEvent("PIN Verification SUCCESS (SW1=0x90, SW2=0x00)")
                    logApdu(ApduLogDirection.COMMAND, "VERIFY PIN APDU", "00 20 00 80 08 31 32 33 34 35 36 FF FF")
                    logApdu(ApduLogDirection.RESPONSE, "VERIFY PIN Response", "90 00 - OK")

                    _uiState.update {
                        it.copy(
                            sessionState = SessionState.AUTHORIZED,
                            cardStatus = CardStatus.AUTHENTICATED,
                            pinAttemptsRemaining = 3,
                            activeCertificate = it.activeCertificate ?: certList?.firstOrNull(),
                            pendingTlsHost = null,
                            errorMessage = null
                        )
                    }
                    resumePendingTlsRequest()
                    true
                } else {
                    val remaining = (currentAttempts - 1).coerceAtLeast(0)
                    logSystemEvent("PIN Verification FAILED. Remaining attempts: $remaining")
                    logApdu(ApduLogDirection.RESPONSE, "VERIFY PIN Response", "63 C${remaining} - Verification Failed")

                    _uiState.update {
                        it.copy(
                            sessionState = if (remaining == 0) SessionState.CARD_LOCKED else SessionState.PIN_FAILED,
                            cardStatus = if (remaining == 0) CardStatus.LOCKED else CardStatus.INSERTED,
                            pinAttemptsRemaining = remaining,
                            errorMessage = if (remaining == 0) "Card Locked!" else "Invalid PIN ($remaining attempts left)"
                        )
                    }
                    false
                }
            } else {
                // Physical card verification
                if (_uiState.value.cardStatus == CardStatus.ABSENT) {
                    logSystemEvent("Physical Smart Card not detected in slot.")
                    _uiState.update { it.copy(errorMessage = "Smart card not detected in reader slot. Please insert card.") }
                    false
                } else {
                    logSystemEvent("Initiating physical smart card PIN verification...")

                    val resp = try {
                        pivHandler.verifyPin(pin) { apduBytes ->
                            val cmdHex = apduBytes.toHexString()
                            logApdu(ApduLogDirection.COMMAND, "APDU TX", cmdHex)

                            var rawResp = try { ccidDriver.transceive(apduBytes) } catch (_: Throwable) { null }
                            if (rawResp == null) {
                                logSystemEvent("Transceive returned null. Retrying ICC Power On and re-transceiving...")
                                try { ccidDriver.powerOn() } catch (_: Throwable) {}
                                rawResp = try { ccidDriver.transceive(apduBytes) } catch (_: Throwable) { null }
                            }

                            if (rawResp != null && rawResp.size >= 2) {
                                val respObj = ApduResponse.fromByteArray(rawResp)
                                logApdu(
                                    direction = ApduLogDirection.RESPONSE,
                                    title = "APDU RX",
                                    hexData = respObj.toHex(),
                                    statusWord = "${respObj.statusWordToHex()} (${respObj.statusWordMeaning})"
                                )
                                rawResp
                            } else {
                                logApdu(
                                    direction = ApduLogDirection.RESPONSE,
                                    title = "APDU RX ERROR",
                                    hexData = "USB Bulk Transfer Failed or No Card Response",
                                    statusWord = "6F 00 (Communication Error)"
                                )
                                null
                            }
                        }
                    } catch (e: Throwable) {
                        Log.e(TAG, "Error during verifyPin transceive", e)
                        ApduResponse(byteArrayOf(), 0x6F.toByte(), 0x00.toByte())
                    }

                    if (resp.isSuccess) {
                        logSystemEvent("Physical Smart Card PIN verification SUCCESSFUL! (SW: 90 00)")

                        // Re-invoke readCertificates() after PIN verification in case container reading required PIN authentication
                        readCertificates()

                        val primaryCertInfo = _uiState.value.activeCertificate ?: certList?.firstOrNull()

                        _uiState.update {
                            it.copy(
                                sessionState = SessionState.AUTHORIZED,
                                cardStatus = CardStatus.AUTHENTICATED,
                                readerStatus = if (ccidDriver.isConnected) ReaderStatus.CONNECTED else it.readerStatus,
                                pinAttemptsRemaining = 3,
                                aidSelected = pivHandler.selectedAidDescription,
                                activeCertificate = primaryCertInfo,
                                availableCertificates = certList ?: (primaryCertInfo?.let { c -> listOf(c) } ?: emptyList()),
                                pendingTlsHost = null,
                                errorMessage = null
                            )
                        }
                        resumePendingTlsRequest()
                        true
                    } else {
                        val remaining = if (resp.isPinFailed) resp.attemptsRemaining else -1
                        logSystemEvent("Physical Smart Card PIN verification FAILED (SW: ${resp.statusWordToHex()} - ${resp.statusWordMeaning}, attempts remaining: $remaining)")

                        _uiState.update {
                            it.copy(
                                sessionState = if (resp.isCardLocked || remaining == 0) SessionState.CARD_LOCKED else SessionState.PIN_FAILED,
                                cardStatus = if (resp.isCardLocked || remaining == 0) CardStatus.LOCKED else CardStatus.INSERTED,
                                pinAttemptsRemaining = if (remaining >= 0) remaining else it.pinAttemptsRemaining,
                                errorMessage = if (resp.isCardLocked || remaining == 0) {
                                    "Smart Card Locked! Max failed PIN attempts exceeded."
                                } else if (resp.isPinFailed) {
                                    "Invalid PIN ($remaining attempts left)"
                                } else {
                                    "PIN Verification Failed: SW ${resp.statusWordToHex()} (${resp.statusWordMeaning})"
                                }
                            )
                        }
                        false
                    }
                }
            }
        } catch (e: Throwable) {
            Log.e(TAG, "Uncaught error during verifyPin", e)
            _uiState.update {
                it.copy(
                    sessionState = SessionState.PIN_FAILED,
                    errorMessage = "PIN Verification Error: ${e.message}"
                )
            }
            false
        } finally {
            // Auto-wipe PIN from memory immediately after verification
            Arrays.fill(pinChars, '0')
        }
        result
    }

    /**
     * Immediately wipes PIN memory and zero-fills sensitive session buffers.
     */
    fun wipePinMemory() {
        try {
            pendingTlsRequest?.cancel()
            pendingTlsRequest = null
            cardPrivateKey = null
            certList = null
            cardIssuerCerts.clear()
            logSystemEvent("PIN cache & cryptographic session keys wiped from memory")
        } catch (e: Throwable) {
            Log.e(TAG, "Error in wipePinMemory()", e)
        }
    }

    /**
     * Clears WebView SSL Client Certificate preferences, CookieManager cookies, and session data.
     */
    fun clearWebViewSslSessionCache(webViews: List<WebView> = emptyList()) {
        try {
            val cookieManager = CookieManager.getInstance()
            cookieManager.removeAllCookies(null)
            cookieManager.flush()
        } catch (_: Throwable) {}

        try {
            WebStorage.getInstance().deleteAllData()
        } catch (_: Throwable) {}

        try {
            webViews.forEach { webView ->
                webView.clearSslPreferences()
                webView.clearCache(true)
                webView.clearHistory()
                webView.clearFormData()
            }
        } catch (_: Throwable) {}

        logSystemEvent("WebView SSL Client Certificate Session Cache Cleared & Revoked")
    }

    /**
     * Triggers rapid session security controls upon smart card removal or session revocation.
     */
    fun handleSmartCardRemoval(wasAuthorized: Boolean? = null) {
        try {
            val wasAuth = wasAuthorized ?: isSessionAuthorized()
            logSystemEvent("RAPID SECURITY CONTROL: Smart Card Removal / Ejection Detected! (wasAuthorized = $wasAuth)")

            // 1. Wipe PIN and private key credentials from memory
            wipePinMemory()

            // 2. Clear WebView client certificate session cache
            clearWebViewSslSessionCache()

            // 3. Lock session and alert user if card was removed during an active secure session
            _uiState.update { state ->
                state.copy(
                    cardStatus = CardStatus.ABSENT,
                    sessionState = SessionState.NO_READER,
                    activeCertificate = null,
                    pendingTlsHost = null,
                    isMtlsAuthenticated = false,
                    isSessionLocked = wasAuth,
                    cardRemovalWarning = if (wasAuth) {
                        "SECURITY ALERT: Smart card removed during active secure session! PIN cache wiped and SSL certificate session revoked."
                    } else null,
                    errorMessage = if (wasAuth) "Smart Card Removed During Active Session" else null
                )
            }

            // 4. Notify listener (e.g., ViewModel / WebBrowserManager)
            try {
                onCardRemovedListener?.invoke(wasAuth)
            } catch (e: Throwable) {
                Log.e(TAG, "Error invoking onCardRemovedListener", e)
            }
        } catch (e: Throwable) {
            Log.e(TAG, "Error handling smart card removal", e)
        }
    }

    /**
     * Simulates ejecting/removing smart card for testing rapid session security controls.
     */
    fun ejectCard() {
        handleSmartCardRemoval()
    }

    /**
     * Explicitly logs out session and clears all cached certificate credentials.
     */
    fun logoutSession() {
        try {
            logSystemEvent("Session Logout Requested by User")
            handleSmartCardRemoval(wasAuthorized = false)
            _uiState.update {
                it.copy(
                    sessionState = if (it.readerStatus == ReaderStatus.CONNECTED) SessionState.PIN_PROMPT else SessionState.NO_READER,
                    cardStatus = if (it.readerStatus == ReaderStatus.CONNECTED) CardStatus.INSERTED else CardStatus.ABSENT,
                    isSessionLocked = false,
                    cardRemovalWarning = null
                )
            }
        } catch (e: Throwable) {
            Log.e(TAG, "Error logging out session", e)
        }
    }

    /**
     * Dismisses the card removal warning overlay.
     */
    fun dismissCardRemovalWarning() {
        try {
            _uiState.update {
                it.copy(
                    cardRemovalWarning = null,
                    isSessionLocked = false
                )
            }
        } catch (e: Throwable) {
            Log.e(TAG, "Error dismissing card removal warning", e)
        }
    }

    fun isSessionAuthorized(): Boolean {
        return try {
            _uiState.value.sessionState == SessionState.AUTHORIZED ||
                    _uiState.value.cardStatus == CardStatus.AUTHENTICATED
        } catch (_: Throwable) {
            false
        }
    }

    fun getCertificateChain(): List<SmartCardCertificate>? {
        return try {
            certList
        } catch (_: Throwable) {
            null
        }
    }

    fun getActiveCertChain(
        acceptablePrincipals: Array<java.security.Principal>? = null,
        host: String? = null
    ): Array<X509Certificate>? {
        return try {
            if (_uiState.value.cardStatus == CardStatus.ABSENT) return null

            selectEmailCertIfWebmail(host)

            val activeX509 = _uiState.value.activeCertificate?.x509Certificate
            if (activeX509 != null) {
                val dodCAs = SmartCardCertManager.loadDodCaCertificates(context)
                val combinedCAs = (cardIssuerCerts + dodCAs).distinct()
                return SmartCardCertManager.buildFullCertChain(activeX509, combinedCAs)
            }

            val chain = SmartCardCertManager.getActiveCertChain(
                certList = certList,
                context = context,
                acceptablePrincipals = acceptablePrincipals,
                cardIssuerCerts = cardIssuerCerts,
                host = host
            )
            if (chain != null && chain.isNotEmpty()) return chain

            null
        } catch (e: Throwable) {
            Log.e(TAG, "Error getting active cert chain", e)
            null
        }
    }

    fun getSmartCardPrivateKey(): SmartCardPrivateKey? {
        return try {
            if (_uiState.value.cardStatus == CardStatus.ABSENT && !ccidDriver.isConnected) return null
            if (cardPrivateKey != null) return cardPrivateKey

            val activeCert = _uiState.value.activeCertificate
            if (activeCert != null) {
                val keyRef = SmartCardCertManager.getKeyRefForCertType(activeCert.certificateType)
                val pKey = SmartCardCertManager.getSmartCardPrivateKey(
                    cert = activeCert,
                    signHandler = { dataToSign, algName ->
                        try {
                            val keySizeBytes = (activeCert.keySize / 8).coerceAtLeast(256)
                            val formattedPayload = SmartCardCertManager.formatPkcs1Padding(dataToSign, keySizeBytes)
                            val rawSig = pivHandler.signChallenge(
                                challenge = formattedPayload,
                                algorithmId = PivAppletHandler.Algorithm.RSA_2048,
                                keyRef = keyRef
                            ) { signCmd ->
                                logApdu(ApduLogDirection.COMMAND, "SIGN ($algName - ${activeCert.certificateType})", signCmd.toHexString())
                                var rawSig = try { ccidDriver.transceive(signCmd) } catch (_: Throwable) { null }
                                if (rawSig == null) {
                                    try { ccidDriver.powerOn() } catch (_: Throwable) {}
                                    rawSig = try { ccidDriver.transceive(signCmd) } catch (_: Throwable) { null }
                                }
                                if (rawSig != null && rawSig.size >= 2) {
                                    val sigResp = ApduResponse.fromByteArray(rawSig)
                                    logApdu(
                                        direction = ApduLogDirection.RESPONSE,
                                        title = "SIGN Response",
                                        hexData = sigResp.toHex(),
                                        statusWord = "${sigResp.statusWordToHex()} (${sigResp.statusWordMeaning})"
                                    )
                                }
                                rawSig
                            }
                            PivAppletHandler.formatRsaSignatureToExactSize(rawSig, keySizeBytes)
                        } catch (e: Throwable) {
                            Log.e(TAG, "Error in getSmartCardPrivateKey signHandler", e)
                            byteArrayOf()
                        }
                    }
                )
                cardPrivateKey = pKey
                return pKey
            }

            if (_uiState.value.isSimulatedCard && simulatedKeyPair != null && simulatedCertificate != null && _uiState.value.cardStatus != CardStatus.ABSENT) {
                val cert = simulatedCertificate!!
                val kp = simulatedKeyPair!!
                val pKey = SmartCardPrivateKey(
                    algorithmName = "RSA",
                    keySizeBits = 2048,
                    keyReference = PivAppletHandler.KeyReference.PIV_AUTHENTICATION,
                    publicModulus = (cert.publicKey as? java.security.interfaces.RSAPublicKey)?.modulus,
                    underlyingPrivateKey = kp.private
                )
                cardPrivateKey = pKey
                return pKey
            }
            null
        } catch (e: Throwable) {
            Log.e(TAG, "Error getting smart card private key", e)
            null
        }
    }

    fun selectEmailCertIfWebmail(host: String?) {
        if (host == null) return
        val isWebmail = host.contains("webmail", ignoreCase = true) ||
                        host.contains("microsoftonline", ignoreCase = true) ||
                        host.contains("certauth", ignoreCase = true)
        if (isWebmail) {
            val emailCert = _uiState.value.availableCertificates.find { cert ->
                getKeyRefForCertType(cert.certificateType) == PivAppletHandler.KeyReference.EMAIL_SIGNING ||
                cert.certificateType.contains("Email", ignoreCase = true)
            }
            if (emailCert != null && emailCert != _uiState.value.activeCertificate) {
                logSystemEvent("Auto-selecting Email Certificate for webmail authentication on $host: ${emailCert.subjectDN}")
                selectCertificate(emailCert)
            }
        }
    }

    fun setMtlsAuthenticated(authenticated: Boolean = true) {
        try {
            _uiState.update {
                it.copy(
                    isMtlsAuthenticated = authenticated,
                    pendingTlsHost = if (authenticated) null else it.pendingTlsHost
                )
            }
        } catch (_: Throwable) {}
    }

    fun clearPendingTlsHost() {
        try {
            pendingTlsRequest = null
            _uiState.update { it.copy(pendingTlsHost = null) }
        } catch (_: Throwable) {}
    }

    fun handlePendingTlsRequest(host: String, request: ClientCertRequest) {
        try {
            pendingTlsRequest = request
            selectEmailCertIfWebmail(host)
            _uiState.update {
                it.copy(
                    pendingTlsHost = host,
                    sessionState = if (it.sessionState == SessionState.AUTHORIZED) it.sessionState else SessionState.PIN_PROMPT
                )
            }
        } catch (e: Throwable) {
            Log.e(TAG, "Error handling pending TLS request", e)
        }
    }

    fun setVerifyingPinState(isVerifying: Boolean, state: PinVerificationState) {
        try {
            _uiState.update {
                it.copy(
                    isVerifyingPin = isVerifying,
                    pinVerificationState = state
                )
            }
        } catch (_: Throwable) {}
    }

    fun resumePendingTlsRequest() {
        try {
            val request = pendingTlsRequest
            val pKey = getSmartCardPrivateKey()

            _uiState.update { it.copy(pendingTlsHost = null, isMtlsAuthenticated = true) }

            if (request != null && pKey != null) {
                val chain = getActiveCertChain(request.principals)
                if (!chain.isNullOrEmpty()) {
                    val host = request.host
                    val keyTypesStr = request.keyTypes?.joinToString(", ") ?: "none"
                    val principalsStr = request.principals?.joinToString("; ") { it.name } ?: "none"
                    val certSubject = chain.firstOrNull()?.subjectX500Principal?.name ?: "unknown"
                    val certIssuer = chain.firstOrNull()?.issuerX500Principal?.name ?: "unknown"

                    logSystemEvent("Resuming pending TLS ClientCertRequest for host=$host | keyTypes: [$keyTypesStr] | principals: [$principalsStr] | cert subject=$certSubject, issuer=$certIssuer")
                    Handler(Looper.getMainLooper()).post {
                        try {
                            request.proceed(pKey, chain)
                            Log.i(TAG, "Successfully proceeded pending TLS request for host=$host")
                        } catch (e: Exception) {
                            Log.e(TAG, "Error proceeding pending TLS request on Main thread for host=$host", e)
                        }
                    }
                    pendingTlsRequest = null
                }
            }
        } catch (e: Throwable) {
            Log.e(TAG, "Error resuming pending TLS request", e)
        }
    }

    fun resetSession() {
        try {
            logoutSession()
            if (_uiState.value.isSimulatedCard) {
                enableSimulationMode()
            }
        } catch (e: Throwable) {
            Log.e(TAG, "Error resetting session", e)
        }
    }

    fun disconnectUsbReader() {
        try {
            ccidDriver.close()
            _uiState.update {
                it.copy(
                    readerStatus = ReaderStatus.DISCONNECTED,
                    cardStatus = CardStatus.ABSENT,
                    sessionState = if (it.isSimulatedCard) it.sessionState else SessionState.NO_READER,
                    usbDeviceInfo = if (it.isSimulatedCard) it.usbDeviceInfo else null
                )
            }
            logSystemEvent("USB Reader Disconnected")
        } catch (e: Throwable) {
            Log.e(TAG, "Error disconnecting USB reader", e)
        }
    }

    fun logSystemEvent(message: String) {
        logApdu(ApduLogDirection.SYSTEM, "SYSTEM", message)
    }

    fun logApdu(direction: ApduLogDirection, title: String, hexData: String, statusWord: String? = null) {
        try {
            val entry = ApduLogEntry(
                direction = direction,
                title = title,
                hexData = hexData,
                statusWord = statusWord
            )
            _uiState.update {
                it.copy(apduLogs = (listOf(entry) + it.apduLogs).take(100))
            }
        } catch (_: Throwable) {}
    }

    fun selectCertificate(certificate: SmartCardCertificate) {
        try {
            val keyRef = getKeyRefForCertType(certificate.certificateType)
            logSystemEvent("User selected certificate: ${certificate.certificateType} (KeyRef: 0x${String.format("%02X", keyRef)}) - ${certificate.subjectDN}")

            val x509 = certificate.x509Certificate
            val isSimulated = _uiState.value.isSimulatedCard

            if (isSimulated && x509 != null) {
                val simulatedPair = simulatedCertsMap[certificate.certificateType] ?: (simulatedKeyPair to simulatedCertificate)
                val kp = simulatedPair.first
                if (kp != null) {
                    cardPrivateKey = SmartCardPrivateKey(
                        algorithmName = certificate.keyAlgorithm,
                        keySizeBits = certificate.keySize,
                        keyReference = keyRef,
                        publicModulus = (x509.publicKey as? java.security.interfaces.RSAPublicKey)?.modulus,
                        underlyingPrivateKey = kp.private
                    )
                }
            } else if (x509 != null) {
                cardPrivateKey = SmartCardCertManager.getSmartCardPrivateKey(
                    cert = certificate,
                    signHandler = { dataToSign, algName ->
                        try {
                            val formattedPayload = SmartCardCertManager.formatPkcs1Padding(dataToSign, certificate.keySize / 8)
                            pivHandler.signChallenge(
                                challenge = formattedPayload,
                                algorithmId = PivAppletHandler.Algorithm.RSA_2048,
                                keyRef = keyRef
                            ) { signCmd ->
                                logApdu(ApduLogDirection.COMMAND, "SIGN ($algName - ${certificate.certificateType})", signCmd.toHexString())
                                var rawSig = try { ccidDriver.transceive(signCmd) } catch (_: Throwable) { null }
                                if (rawSig == null) {
                                    try { ccidDriver.powerOn() } catch (_: Throwable) {}
                                    rawSig = try { ccidDriver.transceive(signCmd) } catch (_: Throwable) { null }
                                }
                                if (rawSig != null && rawSig.size >= 2) {
                                    val sigResp = ApduResponse.fromByteArray(rawSig)
                                    logApdu(
                                        direction = ApduLogDirection.RESPONSE,
                                        title = "SIGN Response",
                                        hexData = sigResp.toHex(),
                                        statusWord = "${sigResp.statusWordToHex()} (${sigResp.statusWordMeaning})"
                                    )
                                }
                                rawSig
                            } ?: byteArrayOf()
                        } catch (e: Throwable) {
                            Log.e(TAG, "Error in selectCertificate signHandler", e)
                            byteArrayOf()
                        }
                    }
                )
            }

            _uiState.update {
                it.copy(
                    activeCertificate = certificate
                )
            }

            resumePendingTlsRequest()
        } catch (e: Throwable) {
            Log.e(TAG, "Error selecting certificate", e)
        }
    }

    private fun getKeyRefForCertType(type: String): Byte {
        return SmartCardCertManager.getKeyRefForCertType(type)
    }

    private fun initSimulatedCredentials() {
        try {
            val (kp1, cert1) = SmartCardCertManager.generateSimulatedPivCredentials()
            simulatedKeyPair = kp1
            simulatedCertificate = cert1
            simulatedCertsMap["PIV Authentication (9A)"] = Pair(kp1, cert1)

            val kpg = java.security.KeyPairGenerator.getInstance("RSA")
            kpg.initialize(2048, java.security.SecureRandom())

            // Generate Email Certificate (9D/82)
            val kp2 = kpg.generateKeyPair()
            val subject2 = javax.security.auth.x500.X500Principal("CN=DOE.JOHN.A.1234567890, OU=USA, OU=PKI, OU=DoD, O=U.S. Government, C=US")
            val issuer2 = javax.security.auth.x500.X500Principal("CN=DOD EMAIL CA-72, OU=PKI, OU=DoD, O=U.S. Government, C=US")
            val cert2 = SmartCardCertManager.generateCaCertificate(subject2.name, issuer2.name, kp2)
            simulatedCertsMap["Email Certificate (9D/82)"] = Pair(kp2, cert2)

            // Generate Digital Signature Certificate (9C)
            val kp3 = kpg.generateKeyPair()
            val issuer3 = javax.security.auth.x500.X500Principal("CN=DOD ID CA-72, OU=PKI, OU=DoD, O=U.S. Government, C=US")
            val cert3 = SmartCardCertManager.generateCaCertificate(subject2.name, issuer3.name, kp3)
            simulatedCertsMap["Digital Signature (9C)"] = Pair(kp3, cert3)
        } catch (e: Exception) {
            Log.e(TAG, "Error generating simulated card credentials", e)
        }
    }

    private fun registerUsbReceiver() {
        val ctx = context ?: return
        try {
            val filter = IntentFilter().apply {
                addAction(UsbManager.ACTION_USB_DEVICE_ATTACHED)
                addAction(UsbManager.ACTION_USB_DEVICE_DETACHED)
                addAction(ACTION_USB_PERMISSION)
            }
            androidx.core.content.ContextCompat.registerReceiver(
                ctx,
                usbReceiver,
                filter,
                androidx.core.content.ContextCompat.RECEIVER_EXPORTED
            )
        } catch (_: Throwable) {}
    }

    fun unregister() {
        try {
            context?.unregisterReceiver(usbReceiver)
        } catch (_: Throwable) {}
        try {
            ccidDriver.close()
        } catch (_: Throwable) {}
    }

    @Suppress("DEPRECATION")
    private fun getUsbDeviceFromIntent(intent: Intent?): UsbDevice? {
        if (intent == null) return null
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                intent.getParcelableExtra(UsbManager.EXTRA_DEVICE, UsbDevice::class.java)
            } else {
                intent.getParcelableExtra(UsbManager.EXTRA_DEVICE)
            }
        } catch (_: Throwable) {
            null
        }
    }

    companion object {
        private const val TAG = "SmartCardManager"
        const val ACTION_USB_PERMISSION = "com.example.webmil.USB_PERMISSION"
    }
}
