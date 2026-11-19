package com.example.webmil.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Badge
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.Key
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.LockOpen
import androidx.compose.material.icons.rounded.Security
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material.icons.rounded.SimCard
import androidx.compose.material.icons.rounded.Usb
import androidx.compose.material.icons.rounded.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Badge
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import com.example.webmil.browser.model.SslSecurityInfo
import com.example.webmil.smartcard.model.CardStatus
import com.example.webmil.smartcard.model.ReaderStatus
import com.example.webmil.smartcard.model.SessionState
import com.example.webmil.smartcard.model.SmartCardCertificate
import com.example.webmil.smartcard.model.SmartCardUiState

/**
 * Real-time Security Status Dialog showing:
 * 1. SSL/TLS security lock indicator & Certificate details
 * 2. CAC/PIV Reader state (Connected / Disconnected / Card Inserted / PIN Authenticated)
 * 3. Active client certificate subject identity (e.g. DoD CAC Common Name / EDIPI)
 * 4. Certificate Selector Dropdown / Picker for selecting CAC containers (9A, 9C, 9D/82)
 * 5. Quick PIN verification if authentication is pending.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SecurityStatusDialog(
    securityInfo: SslSecurityInfo,
    smartCardUiState: SmartCardUiState,
    onVerifyPin: (String) -> Unit,
    onSelectCertificate: ((SmartCardCertificate) -> Unit)? = null,
    onDismiss: () -> Unit
) {
    var pinInput by remember { mutableStateOf("") }
    var pinError by remember { mutableStateOf<String?>(null) }

    val (cn, edipi) = extractEdipiAndCn(
        smartCardUiState.activeCertificate?.subjectDN ?: ""
    )

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(
                    imageVector = Icons.Rounded.Shield,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(24.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = "Security & Hardware Status",
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold
                )
            }
        },
        text = {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(14.dp)
            ) {
                // SECTION 1: SSL/TLS Connection Security
                SslConnectionStatusCard(securityInfo = securityInfo)

                // SECTION 2: CAC/PIV Reader & Card Hardware State
                SmartCardHardwareStateCard(uiState = smartCardUiState)

                // SECTION 3: Active Client Certificate Subject Identity (DoD CAC)
                ClientCertIdentityCard(
                    uiState = smartCardUiState,
                    commonName = cn,
                    edipi = edipi
                )

                // SECTION 3.5: Certificate Selector Dropdown / Picker
                if (smartCardUiState.availableCertificates.isNotEmpty()) {
                    CertificateSelectorPicker(
                        activeCertificate = smartCardUiState.activeCertificate,
                        availableCertificates = smartCardUiState.availableCertificates,
                        onSelectCertificate = { cert ->
                            onSelectCertificate?.invoke(cert)
                        }
                    )
                }

                // SECTION 4: PIN Authentication Prompt (if pending or needed)
                val needsPinPrompt = smartCardUiState.pendingTlsHost != null ||
                        smartCardUiState.sessionState != SessionState.AUTHORIZED ||
                        smartCardUiState.activeCertificate == null

                if (needsPinPrompt &&
                    smartCardUiState.sessionState != SessionState.CARD_LOCKED &&
                    smartCardUiState.cardStatus != CardStatus.ABSENT
                ) {
                    PinPromptInlineSection(
                        pinInput = pinInput,
                        pinError = pinError ?: smartCardUiState.errorMessage,
                        pendingHost = smartCardUiState.pendingTlsHost,
                        attemptsRemaining = smartCardUiState.pinAttemptsRemaining,
                        isVerifying = smartCardUiState.isVerifyingPin,
                        onPinChange = {
                            pinInput = it
                            pinError = null
                        },
                        onVerifyClick = {
                            if (!smartCardUiState.isVerifyingPin && pinInput.isNotEmpty()) {
                                onVerifyPin(pinInput)
                            }
                        }
                    )
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) {
                Text("Close")
            }
        }
    )
}

@Composable
fun SslConnectionStatusCard(securityInfo: SslSecurityInfo) {
    val isSecure = securityInfo.isSecure
    val isMtls = securityInfo.isMtlsAuthenticated

    val statusTitle = when {
        isMtls -> "Mutual TLS (mTLS) Protected"
        isSecure -> "HTTPS Encrypted (TLS)"
        else -> "Unencrypted / Security Warning"
    }

    val statusColor = when {
        isMtls -> Color(0xFF2E7D32)
        isSecure -> Color(0xFF1565C0)
        else -> Color(0xFFE65100)
    }

    val icon = when {
        isMtls -> Icons.Rounded.Key
        isSecure -> Icons.Rounded.Lock
        else -> Icons.Rounded.Warning
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = statusColor.copy(alpha = 0.1f))
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = statusColor,
                    modifier = Modifier.size(20.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = statusTitle,
                    fontWeight = FontWeight.Bold,
                    fontSize = 14.sp,
                    color = statusColor
                )
            }

            Spacer(modifier = Modifier.height(8.dp))

            SecurityDetailLine("Host Name", securityInfo.host.ifEmpty { "webmail.apps.mil" })
            if (securityInfo.subjectDN != null) {
                SecurityDetailLine("Server Cert Subject", securityInfo.subjectDN)
            }
            if (securityInfo.issuerDN != null) {
                SecurityDetailLine("Issuer CA", securityInfo.issuerDN)
            }
            if (securityInfo.validTo != null) {
                SecurityDetailLine("Valid Until", securityInfo.validTo)
            }
            if (securityInfo.sslError != null) {
                SecurityDetailLine("SSL Error", securityInfo.sslError, isError = true)
            }
        }
    }
}

@Composable
fun SmartCardHardwareStateCard(uiState: SmartCardUiState) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp)
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
                modifier = Modifier.fillMaxWidth()
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = if (uiState.isSimulatedCard) Icons.Rounded.SimCard else Icons.Rounded.Usb,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(20.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "CAC / PIV Reader State",
                        fontWeight = FontWeight.Bold,
                        fontSize = 14.sp
                    )
                }

                StatusBadge(
                    text = if (uiState.isSimulatedCard) "SIMULATOR" else uiState.readerStatus.name,
                    color = if (uiState.readerStatus == ReaderStatus.CONNECTED) Color(0xFF2E7D32) else Color.Red
                )
            }

            Spacer(modifier = Modifier.height(8.dp))

            SecurityDetailLine("Reader Hardware", uiState.usbDeviceInfo?.productName ?: "Virtual CCID Reader")
            SecurityDetailLine("Card Slot State", uiState.cardStatus.name)
            SecurityDetailLine(
                "Session State",
                when (uiState.sessionState) {
                    SessionState.AUTHORIZED -> "AUTHENTICATED & AUTHORIZED"
                    SessionState.PIN_PROMPT -> "PIN REQUIRED"
                    SessionState.CARD_LOCKED -> "BLOCKED / LOCKED"
                    else -> uiState.sessionState.name
                }
            )
            if (uiState.atrHex.isNotEmpty()) {
                SecurityDetailLine("Card ATR", uiState.atrHex.take(28) + "...")
            }
        }
    }
}

@Composable
fun ClientCertIdentityCard(
    uiState: SmartCardUiState,
    commonName: String,
    edipi: String?
) {
    val cert = uiState.activeCertificate

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (uiState.sessionState == SessionState.AUTHORIZED)
                MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.25f)
            else
                MaterialTheme.colorScheme.surfaceVariant
        )
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = Icons.Rounded.Badge,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(20.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = "Active Client Certificate Identity",
                    fontWeight = FontWeight.Bold,
                    fontSize = 14.sp
                )
            }

            Spacer(modifier = Modifier.height(8.dp))

            if (cert != null) {
                SecurityDetailLine("Cardholder Common Name", commonName)
                if (edipi != null) {
                    SecurityDetailLine("DoD EDIPI / ID", edipi, isHighlight = true)
                }
                SecurityDetailLine("Certificate Type", cert.certificateType)
                SecurityDetailLine("Issuer DN", cert.issuerDN)
                SecurityDetailLine("Key Algo & Size", "${cert.keyAlgorithm} ${cert.keySize} bits")
                SecurityDetailLine("Serial Number", cert.serialNumber)
                SecurityDetailLine("Validity", "${cert.validFrom} to ${cert.validTo}")
            } else {
                Text(
                    text = "No active client certificate loaded. Insert card & verify PIN.",
                    fontSize = 12.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@Composable
fun PinPromptInlineSection(
    pinInput: String,
    pinError: String?,
    pendingHost: String?,
    attemptsRemaining: Int,
    isVerifying: Boolean = false,
    onPinChange: (String) -> Unit,
    onVerifyClick: () -> Unit
) {
    Surface(
        color = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.3f),
        shape = RoundedCornerShape(12.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Text(
                text = if (pendingHost != null)
                    "🔒 mTLS Authentication Requested for $pendingHost"
                else
                    "Enter Smart Card PIN to Authenticate mTLS",
                fontWeight = FontWeight.Bold,
                fontSize = 13.sp,
                color = MaterialTheme.colorScheme.onErrorContainer
            )

            Text(
                text = "Attempts remaining: $attemptsRemaining / 3",
                fontSize = 11.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 2.dp, bottom = 8.dp)
            )

            OutlinedTextField(
                value = pinInput,
                onValueChange = onPinChange,
                label = { Text("Smart Card PIN") },
                placeholder = { Text("Default simulated: 123456") },
                singleLine = true,
                enabled = !isVerifying,
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Number,
                    imeAction = ImeAction.Done
                ),
                keyboardActions = KeyboardActions(onDone = { if (!isVerifying && pinInput.isNotEmpty()) onVerifyClick() }),
                modifier = Modifier.fillMaxWidth()
            )

            if (pinError != null) {
                Text(
                    text = pinError,
                    fontSize = 11.sp,
                    color = MaterialTheme.colorScheme.error,
                    modifier = Modifier.padding(top = 4.dp)
                )
            }

            Spacer(modifier = Modifier.height(8.dp))

            Button(
                onClick = onVerifyClick,
                enabled = pinInput.isNotEmpty() && !isVerifying,
                modifier = Modifier.fillMaxWidth()
            ) {
                if (isVerifying) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(16.dp),
                        color = MaterialTheme.colorScheme.onPrimary,
                        strokeWidth = 2.dp
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Authenticating...")
                } else {
                    Icon(Icons.Rounded.CheckCircle, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Authenticate Card")
                }
            }
        }
    }
}

@Composable
fun SecurityDetailLine(
    label: String,
    value: String,
    isError: Boolean = false,
    isHighlight: Boolean = false
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 2.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(
            text = label,
            fontSize = 11.sp,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Text(
            text = value,
            fontSize = 11.sp,
            fontWeight = if (isHighlight) FontWeight.Bold else FontWeight.SemiBold,
            fontFamily = FontFamily.Monospace,
            color = when {
                isError -> MaterialTheme.colorScheme.error
                isHighlight -> MaterialTheme.colorScheme.primary
                else -> MaterialTheme.colorScheme.onSurface
            },
            modifier = Modifier.padding(start = 12.dp)
        )
    }
}

@Composable
fun StatusBadge(text: String, color: Color) {
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(6.dp))
            .background(color.copy(alpha = 0.15f))
            .border(1.dp, color.copy(alpha = 0.5f), RoundedCornerShape(6.dp))
            .padding(horizontal = 6.dp, vertical = 2.dp)
    ) {
        Text(
            text = text,
            fontSize = 10.sp,
            fontWeight = FontWeight.Bold,
            color = color
        )
    }
}

fun extractEdipiAndCn(subjectDN: String): Pair<String, String?> {
    if (subjectDN.isBlank()) return "Unknown Subject" to null
    val cnPart = subjectDN.split(",")
        .firstOrNull { it.trim().startsWith("CN=", ignoreCase = true) }
        ?.substringAfter("=")?.trim() ?: subjectDN

    val edipiRegex = Regex("\\b\\d{10}\\b")
    val match = edipiRegex.find(cnPart)
    val edipi = match?.value
    return cnPart to edipi
}

fun extractCnFromDn(dn: String): String {
    if (dn.isBlank()) return "Unknown Issuer"
    return dn.split(",")
        .firstOrNull { it.trim().startsWith("CN=", ignoreCase = true) }
        ?.substringAfter("=")?.trim() ?: dn
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CertificateSelectorPicker(
    activeCertificate: SmartCardCertificate?,
    availableCertificates: List<SmartCardCertificate>,
    onSelectCertificate: (SmartCardCertificate) -> Unit,
    modifier: Modifier = Modifier
) {
    if (availableCertificates.isEmpty()) return

    var expanded by remember { mutableStateOf(false) }

    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant
        )
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
                modifier = Modifier.fillMaxWidth()
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Rounded.Badge,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(20.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "CAC Certificate Selector",
                        fontWeight = FontWeight.Bold,
                        fontSize = 14.sp
                    )
                }

                StatusBadge(
                    text = "${availableCertificates.size} CERTS",
                    color = MaterialTheme.colorScheme.primary
                )
            }

            Spacer(modifier = Modifier.height(8.dp))

            ExposedDropdownMenuBox(
                expanded = expanded,
                onExpandedChange = { expanded = !expanded },
                modifier = Modifier.fillMaxWidth()
            ) {
                val currentCert = activeCertificate ?: availableCertificates.firstOrNull()
                val (cn, _) = extractEdipiAndCn(currentCert?.subjectDN ?: "")

                OutlinedTextField(
                    value = "${currentCert?.certificateType ?: "Select Cert"} - $cn",
                    onValueChange = {},
                    readOnly = true,
                    label = { Text("Active Certificate for mTLS Session") },
                    trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
                    colors = ExposedDropdownMenuDefaults.outlinedTextFieldColors(),
                    modifier = Modifier
                        .menuAnchor(androidx.compose.material3.ExposedDropdownMenuAnchorType.PrimaryNotEditable)
                        .fillMaxWidth()
                )

                ExposedDropdownMenu(
                    expanded = expanded,
                    onDismissRequest = { expanded = false },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    availableCertificates.forEach { cert ->
                        val isSelected = cert == activeCertificate
                        val (certCn, certEdipi) = extractEdipiAndCn(cert.subjectDN)
                        val issuerCn = extractCnFromDn(cert.issuerDN)

                        DropdownMenuItem(
                            text = {
                                Column(modifier = Modifier.padding(vertical = 4.dp)) {
                                    Row(
                                        verticalAlignment = Alignment.CenterVertically,
                                        horizontalArrangement = Arrangement.SpaceBetween,
                                        modifier = Modifier.fillMaxWidth()
                                    ) {
                                        Text(
                                            text = cert.certificateType,
                                            fontWeight = FontWeight.Bold,
                                            fontSize = 13.sp,
                                            color = if (isSelected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface
                                        )
                                        if (isSelected) {
                                            Icon(
                                                imageVector = Icons.Rounded.CheckCircle,
                                                contentDescription = "Selected",
                                                tint = MaterialTheme.colorScheme.primary,
                                                modifier = Modifier.size(16.dp)
                                            )
                                        }
                                    }

                                    Spacer(modifier = Modifier.height(2.dp))

                                    Text(
                                        text = "Subject: $certCn${if (certEdipi != null) " ($certEdipi)" else ""}",
                                        fontSize = 11.sp,
                                        fontFamily = FontFamily.Monospace,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )

                                    Text(
                                        text = "Issuer: $issuerCn",
                                        fontSize = 11.sp,
                                        fontFamily = FontFamily.Monospace,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.8f)
                                    )
                                }
                            },
                            onClick = {
                                onSelectCertificate(cert)
                                expanded = false
                            },
                            contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp)
                        )
                        HorizontalDivider()
                    }
                }
            }
        }
    }
}
