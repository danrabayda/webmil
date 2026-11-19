package com.example.webmil.smartcard.model

import java.security.cert.X509Certificate

enum class ReaderStatus {
    DISCONNECTED,
    CONNECTED,
    ERROR
}

enum class CardStatus {
    ABSENT,
    INSERTED,
    AUTHENTICATED,
    LOCKED
}

enum class SessionState {
    NO_READER,
    READER_CONNECTED,
    CARD_PRESENT,
    PIN_PROMPT,
    AUTHORIZED,
    PIN_FAILED,
    CARD_LOCKED
}

data class UsbDeviceInfo(
    val deviceName: String,
    val vendorId: Int,
    val productId: Int,
    val deviceClass: Int,
    val interfaceCount: Int,
    val manufacturerName: String? = null,
    val productName: String? = null
) {
    fun toFormattedVendorId(): String = String.format("0x%04X", vendorId)
    fun toFormattedProductId(): String = String.format("0x%04X", productId)
}

data class SmartCardCertificate(
    val subjectDN: String,
    val issuerDN: String,
    val serialNumber: String,
    val validFrom: String,
    val validTo: String,
    val keyAlgorithm: String,
    val keySize: Int,
    val certificateType: String,
    val x509Certificate: X509Certificate? = null
)

enum class ApduLogDirection {
    COMMAND,
    RESPONSE,
    SYSTEM
}

data class ApduLogEntry(
    val id: Long = System.currentTimeMillis() + (0..999).random(),
    val timestamp: Long = System.currentTimeMillis(),
    val direction: ApduLogDirection,
    val title: String,
    val hexData: String,
    val statusWord: String? = null
)

enum class PinVerificationState {
    IDLE,
    VERIFYING,
    SUCCESS,
    FAILED
}

data class SmartCardUiState(
    val sessionState: SessionState = SessionState.NO_READER,
    val readerStatus: ReaderStatus = ReaderStatus.DISCONNECTED,
    val cardStatus: CardStatus = CardStatus.ABSENT,
    val usbDeviceInfo: UsbDeviceInfo? = null,
    val atrHex: String = "",
    val aidSelected: String = "",
    val pinAttemptsRemaining: Int = 3,
    val errorMessage: String? = null,
    val activeCertificate: SmartCardCertificate? = null,
    val availableCertificates: List<SmartCardCertificate> = emptyList(),
    val apduLogs: List<ApduLogEntry> = emptyList(),
    val isSimulatedCard: Boolean = true,
    val pendingTlsHost: String? = null,
    val isMtlsAuthenticated: Boolean = false,
    val isSessionLocked: Boolean = false,
    val cardRemovalWarning: String? = null,
    val isVerifyingPin: Boolean = false,
    val pinVerificationState: PinVerificationState = PinVerificationState.IDLE
)
