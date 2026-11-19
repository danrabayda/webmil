package com.example.webmil.ui.screens

import android.annotation.SuppressLint
import android.webkit.WebView
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.BugReport
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.Code
import androidx.compose.material.icons.rounded.CreditCard
import androidx.compose.material.icons.rounded.Eject
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.LockOpen
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material.icons.rounded.Security
import androidx.compose.material.icons.rounded.SimCard
import androidx.compose.material.icons.rounded.Usb
import androidx.compose.material.icons.rounded.Web
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.PrimaryTabRow
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import com.example.webmil.smartcard.model.ApduLogDirection
import com.example.webmil.smartcard.model.ApduLogEntry
import com.example.webmil.smartcard.model.CardStatus
import com.example.webmil.smartcard.model.ReaderStatus
import com.example.webmil.smartcard.model.SessionState
import com.example.webmil.smartcard.model.SmartCardCertificate
import com.example.webmil.smartcard.model.SmartCardUiState
import com.example.webmil.smartcard.model.UsbDeviceInfo
import com.example.webmil.smartcard.tls.SmartCardWebViewClient
import com.example.webmil.ui.SmartCardViewModel
import com.example.webmil.ui.theme.WebmilTheme

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SmartCardHomeScreen(
    uiState: SmartCardUiState,
    viewModel: SmartCardViewModel
) {
    var selectedTab by remember { mutableIntStateOf(0) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Rounded.Security,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.padding(end = 8.dp)
                        )
                        Text(
                            text = "CAC / PIV Smart Card Engine",
                            fontWeight = FontWeight.Bold
                        )
                    }
                },
                actions = {
                    AssistChip(
                        onClick = { viewModel.enableSimulationMode() },
                        label = {
                            Text(if (uiState.isSimulatedCard) "Simulated Reader" else "Physical USB")
                        },
                        leadingIcon = {
                            Icon(
                                imageVector = if (uiState.isSimulatedCard) Icons.Rounded.SimCard else Icons.Rounded.Usb,
                                contentDescription = null,
                                modifier = Modifier.size(16.dp)
                            )
                        },
                        colors = AssistChipDefaults.assistChipColors(
                            containerColor = if (uiState.isSimulatedCard)
                                MaterialTheme.colorScheme.secondaryContainer
                            else
                                MaterialTheme.colorScheme.tertiaryContainer
                        ),
                        modifier = Modifier.padding(end = 8.dp)
                    )
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface
                )
            )
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
        ) {
            PrimaryTabRow(selectedTabIndex = selectedTab) {
                Tab(
                    selected = selectedTab == 0,
                    onClick = { selectedTab = 0 },
                    text = { Text("Dashboard") },
                    icon = { Icon(Icons.Rounded.CreditCard, contentDescription = null) }
                )
                Tab(
                    selected = selectedTab == 1,
                    onClick = { selectedTab = 1 },
                    text = { Text("Mutual TLS WebView") },
                    icon = { Icon(Icons.Rounded.Web, contentDescription = null) }
                )
                Tab(
                    selected = selectedTab == 2,
                    onClick = { selectedTab = 2 },
                    text = { Text("APDU Console") },
                    icon = { Icon(Icons.Rounded.Code, contentDescription = null) }
                )
            }

            when (selectedTab) {
                0 -> DashboardTab(uiState = uiState, viewModel = viewModel)
                1 -> WebBrowserScreen(viewModel = viewModel)
                2 -> ApduConsoleTab(logs = uiState.apduLogs)
            }
        }
    }
}

@Composable
fun DashboardTab(
    uiState: SmartCardUiState,
    viewModel: SmartCardViewModel
) {
    var pinInput by remember { mutableStateOf("") }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Status Banner Card
        item {
            StatusBannerCard(uiState = uiState)
        }

        // Reader & USB Details Card
        item {
            UsbReaderCard(
                deviceInfo = uiState.usbDeviceInfo,
                readerStatus = uiState.readerStatus,
                isSimulated = uiState.isSimulatedCard,
                onScanClicked = { viewModel.scanUsbDevices() },
                onPowerOnClicked = { viewModel.powerOnCard() },
                onSimulateClicked = { viewModel.enableSimulationMode() }
            )
        }

        // Smart Card PIN Verification & Rapid Security Controls Card
        item {
            PinVerificationCard(
                uiState = uiState,
                pinInput = pinInput,
                onPinChange = { pinInput = it },
                onVerifyClick = {
                    viewModel.verifyPin(pinInput) { success ->
                        if (success) pinInput = ""
                    }
                },
                onResetClick = { viewModel.resetSession() },
                onEjectClick = { viewModel.ejectCard() }
            )
        }

        // Certificate Details Card
        if (uiState.activeCertificate != null) {
            item {
                CertificateDetailsCard(certificate = uiState.activeCertificate)
            }
        }

        // CAC Container Certificate Selector Card
        if (uiState.availableCertificates.isNotEmpty()) {
            item {
                com.example.webmil.ui.components.CertificateSelectorPicker(
                    activeCertificate = uiState.activeCertificate,
                    availableCertificates = uiState.availableCertificates,
                    onSelectCertificate = { cert ->
                        viewModel.selectCertificate(cert)
                    }
                )
            }
        }
    }
}

@Composable
fun StatusBannerCard(uiState: SmartCardUiState) {
    val (statusColor, statusText, statusIcon) = when (uiState.sessionState) {
        SessionState.AUTHORIZED -> Triple(
            Color(0xFF2E7D32),
            "AUTHENTICATED & AUTHORIZED",
            Icons.Rounded.LockOpen
        )
        SessionState.PIN_PROMPT -> Triple(
            Color(0xFFE65100),
            "PIN REQUIRED FOR SMART CARD",
            Icons.Rounded.Lock
        )
        SessionState.PIN_FAILED -> Triple(
            Color(0xFFC62828),
            "PIN VERIFICATION FAILED",
            Icons.Rounded.BugReport
        )
        SessionState.CARD_LOCKED -> Triple(
            Color(0xFFB71C1C),
            "SMART CARD BLOCKED / LOCKED",
            Icons.Rounded.Lock
        )
        SessionState.CARD_PRESENT -> Triple(
            Color(0xFF1565C0),
            "CARD PRESENT & PIV AID SELECTED",
            Icons.Rounded.CreditCard
        )
        SessionState.READER_CONNECTED -> Triple(
            Color(0xFF0277BD),
            "READER CONNECTED (INSERT CARD)",
            Icons.Rounded.Usb
        )
        SessionState.NO_READER -> Triple(
            Color(0xFF424242),
            "NO CCID READER DETECTED",
            Icons.Rounded.Info
        )
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = statusColor.copy(alpha = 0.12f))
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(48.dp)
                    .clip(CircleShape)
                    .background(statusColor.copy(alpha = 0.2f)),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = statusIcon,
                    contentDescription = null,
                    tint = statusColor,
                    modifier = Modifier.size(28.dp)
                )
            }

            Spacer(modifier = Modifier.width(16.dp))

            Column {
                Text(
                    text = statusText,
                    fontWeight = FontWeight.Bold,
                    fontSize = 15.sp,
                    color = statusColor
                )
                if (uiState.atrHex.isNotEmpty()) {
                    Text(
                        text = "ATR: ${uiState.atrHex.take(30)}...",
                        fontSize = 12.sp,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                if (uiState.errorMessage != null) {
                    Text(
                        text = uiState.errorMessage,
                        fontSize = 12.sp,
                        color = MaterialTheme.colorScheme.error
                    )
                }
            }
        }
    }
}

@Composable
fun UsbReaderCard(
    deviceInfo: UsbDeviceInfo?,
    readerStatus: ReaderStatus,
    isSimulated: Boolean,
    onScanClicked: () -> Unit,
    onPowerOnClicked: () -> Unit,
    onSimulateClicked: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "USB CCID Reader Hardware",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )

                Row {
                    IconButton(onClick = onScanClicked) {
                        Icon(Icons.Rounded.Refresh, contentDescription = "Scan USB")
                    }
                }
            }

            Spacer(modifier = Modifier.height(8.dp))

            if (deviceInfo != null) {
                DetailRow(label = "Device Name", value = deviceInfo.deviceName)
                DetailRow(label = "Vendor ID", value = deviceInfo.toFormattedVendorId())
                DetailRow(label = "Product ID", value = deviceInfo.toFormattedProductId())
                DetailRow(label = "USB Class", value = "0x0B (Smart Card / CCID)")
                if (deviceInfo.manufacturerName != null) {
                    DetailRow(label = "Manufacturer", value = deviceInfo.manufacturerName)
                }
            } else {
                Text(
                    text = "No physical USB reader attached. Connect a CCID reader via OTG or switch to Virtual Reader mode.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            Spacer(modifier = Modifier.height(12.dp))

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(
                    onClick = onScanClicked,
                    modifier = Modifier.weight(1f)
                ) {
                    Icon(Icons.Rounded.Usb, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(modifier = Modifier.width(4.dp))
                    Text("Scan USB")
                }

                if (readerStatus == ReaderStatus.CONNECTED && !isSimulated) {
                    OutlinedButton(
                        onClick = onPowerOnClicked,
                        modifier = Modifier.weight(1f)
                    ) {
                        Icon(Icons.Rounded.CreditCard, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("Power On")
                    }
                }

                Button(
                    onClick = onSimulateClicked,
                    modifier = Modifier.weight(1f)
                ) {
                    Icon(Icons.Rounded.SimCard, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(modifier = Modifier.width(4.dp))
                    Text("Simulated")
                }
            }
        }
    }
}

@Composable
fun PinVerificationCard(
    uiState: SmartCardUiState,
    pinInput: String,
    onPinChange: (String) -> Unit,
    onVerifyClick: () -> Unit,
    onResetClick: () -> Unit,
    onEjectClick: () -> Unit
) {
    val isAuthorized = uiState.sessionState == SessionState.AUTHORIZED

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (isAuthorized)
                MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.4f)
            else
                MaterialTheme.colorScheme.surfaceVariant
        )
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = "Smart Card PIN Management",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )

            Spacer(modifier = Modifier.height(8.dp))

            if (uiState.pendingTlsHost != null) {
                Surface(
                    color = MaterialTheme.colorScheme.errorContainer,
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(bottom = 12.dp)
                ) {
                    Text(
                        text = "🔒 WebView Mutual TLS Authentication requested for: ${uiState.pendingTlsHost}. Enter PIN to authorize.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onErrorContainer,
                        modifier = Modifier.padding(8.dp)
                    )
                }
            }

            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = "PIN Attempts Remaining: ",
                    style = MaterialTheme.typography.bodyMedium
                )
                Text(
                    text = "${uiState.pinAttemptsRemaining} / 3",
                    fontWeight = FontWeight.Bold,
                    color = if (uiState.pinAttemptsRemaining <= 1) Color.Red else MaterialTheme.colorScheme.primary
                )
            }

            Spacer(modifier = Modifier.height(12.dp))

            OutlinedTextField(
                value = pinInput,
                onValueChange = onPinChange,
                label = { Text("Smart Card PIN (e.g. 123456)") },
                placeholder = { Text("Default simulated PIN: 123456") },
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Number,
                    imeAction = ImeAction.Done
                ),
                keyboardActions = KeyboardActions(onDone = {
                    if (!uiState.isVerifyingPin && pinInput.isNotEmpty() && !isAuthorized && uiState.sessionState != SessionState.CARD_LOCKED) {
                        onVerifyClick()
                    }
                }),
                enabled = !isAuthorized && !uiState.isVerifyingPin && uiState.sessionState != SessionState.CARD_LOCKED,
                modifier = Modifier.fillMaxWidth()
            )

            Spacer(modifier = Modifier.height(12.dp))

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(
                    onClick = onVerifyClick,
                    enabled = pinInput.isNotEmpty() && !isAuthorized && !uiState.isVerifyingPin && uiState.sessionState != SessionState.CARD_LOCKED,
                    modifier = Modifier.weight(1f)
                ) {
                    if (uiState.isVerifyingPin) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(18.dp),
                            color = MaterialTheme.colorScheme.onPrimary,
                            strokeWidth = 2.dp
                        )
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("Verifying...")
                    } else {
                        Icon(Icons.Rounded.CheckCircle, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("Verify PIN")
                    }
                }

                if (isAuthorized) {
                    OutlinedButton(
                        onClick = onResetClick,
                        modifier = Modifier.weight(1f)
                    ) {
                        Text("Reset Session")
                    }
                }

                OutlinedButton(
                    onClick = onEjectClick,
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error),
                    modifier = Modifier.weight(1f)
                ) {
                    Icon(Icons.Rounded.Eject, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(modifier = Modifier.width(4.dp))
                    Text("Eject Card")
                }
            }
        }
    }
}

@Composable
fun CertificateDetailsCard(certificate: SmartCardCertificate) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    Icons.Rounded.Security,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = "Smart Card X.509 Certificate (PKI)",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
            }

            Spacer(modifier = Modifier.height(12.dp))

            DetailRow(label = "Type", value = certificate.certificateType)
            DetailRow(label = "Subject", value = certificate.subjectDN)
            DetailRow(label = "Issuer", value = certificate.issuerDN)
            DetailRow(label = "Serial No.", value = certificate.serialNumber)
            DetailRow(label = "Algorithm", value = "${certificate.keyAlgorithm} ${certificate.keySize} bits")
            DetailRow(label = "Valid From", value = certificate.validFrom)
            DetailRow(label = "Valid To", value = certificate.validTo)
        }
    }
}

@Composable
fun DetailRow(label: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(
            text = label,
            fontSize = 12.sp,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Text(
            text = value,
            fontSize = 12.sp,
            fontWeight = FontWeight.SemiBold,
            fontFamily = FontFamily.Monospace,
            modifier = Modifier.padding(start = 16.dp)
        )
    }
}

@SuppressLint("SetJavaScriptEnabled")
@Composable
fun WebViewMtlsTab(
    uiState: SmartCardUiState,
    viewModel: SmartCardViewModel
) {
    var urlInput by remember { mutableStateOf("https://webmail.apps.mil") }
    var currentLoadedUrl by remember { mutableStateOf(urlInput) }
    var webViewRef by remember { mutableStateOf<WebView?>(null) }

    Column(modifier = Modifier.fillMaxSize()) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            OutlinedTextField(
                value = urlInput,
                onValueChange = { urlInput = it },
                label = { Text("Mutual TLS Test URL") },
                singleLine = true,
                modifier = Modifier.weight(1f)
            )

            Spacer(modifier = Modifier.width(8.dp))

            Button(onClick = {
                currentLoadedUrl = urlInput
                webViewRef?.loadUrl(urlInput)
            }) {
                Text("Go")
            }
        }

        Box(
            modifier = Modifier
                .fillMaxWidth()
                .background(MaterialTheme.colorScheme.surfaceVariant)
                .padding(8.dp)
        ) {
            Text(
                text = if (uiState.sessionState == SessionState.AUTHORIZED)
                    "✅ Smart Card Authorized - ClientCertRequest will succeed"
                else
                    "⚠️ Smart Card Not Authorized - Enter PIN to proceed with mTLS",
                fontSize = 12.sp,
                fontWeight = FontWeight.Bold,
                color = if (uiState.sessionState == SessionState.AUTHORIZED) Color(0xFF2E7D32) else Color(0xFFE65100)
            )
        }

        val client = remember {
            SmartCardWebViewClient(viewModel.smartCardManager)
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
                    webViewClient = client
                    loadUrl(currentLoadedUrl)
                    webViewRef = this
                }
            },
            update = { webView ->
                webViewRef = webView
                webView.requestLayout()
                webView.invalidate()
            },
            modifier = Modifier.fillMaxSize()
        )
    }
}

@Composable
fun ApduConsoleTab(logs: List<ApduLogEntry>) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .background(Color(0xFF121212))
            .padding(8.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp)
    ) {
        items(logs, key = { it.id }) { log ->
            ApduLogItem(log = log)
        }
    }
}

@Composable
fun ApduLogItem(log: ApduLogEntry) {
    val (dirColor, dirTag) = when (log.direction) {
        ApduLogDirection.COMMAND -> Color(0xFF64B5F6) to "CMD >>"
        ApduLogDirection.RESPONSE -> Color(0xFF81C784) to "<< RESP"
        ApduLogDirection.SYSTEM -> Color(0xFFFFB74D) to "SYS"
    }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(6.dp))
            .background(Color(0xFF1E1E1E))
            .border(1.dp, Color(0xFF333333), RoundedCornerShape(6.dp))
            .padding(8.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Text(
                text = "$dirTag ${log.title}",
                fontWeight = FontWeight.Bold,
                fontSize = 12.sp,
                color = dirColor
            )
            if (log.statusWord != null) {
                Text(
                    text = log.statusWord,
                    fontWeight = FontWeight.Bold,
                    fontSize = 12.sp,
                    fontFamily = FontFamily.Monospace,
                    color = if (log.statusWord.startsWith("90 00")) Color(0xFF81C784) else Color(0xFFE57373)
                )
            }
        }

        Spacer(modifier = Modifier.height(4.dp))

        Text(
            text = log.hexData,
            fontSize = 11.sp,
            fontFamily = FontFamily.Monospace,
            color = Color(0xFFE0E0E0)
        )
    }
}

@Preview(showBackground = true)
@Composable
fun SmartCardHomeScreenPreview() {
    WebmilTheme {
        StatusBannerCard(
            uiState = SmartCardUiState(
                sessionState = SessionState.PIN_PROMPT,
                readerStatus = ReaderStatus.CONNECTED,
                cardStatus = CardStatus.INSERTED,
                atrHex = "3B 80 80 01 01 80 53 49 4D 55 4C 41 54 4F 52"
            )
        )
    }
}
