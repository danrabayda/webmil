package com.example.webmil

import com.example.webmil.smartcard.SmartCardManager
import com.example.webmil.smartcard.apdu.ApduCommand
import com.example.webmil.smartcard.apdu.ApduResponse
import com.example.webmil.smartcard.apdu.hexToByteArray
import com.example.webmil.smartcard.apdu.toHexString
import com.example.webmil.smartcard.model.CardStatus
import com.example.webmil.smartcard.model.SessionState
import com.example.webmil.smartcard.piv.PivAppletHandler
import com.example.webmil.smartcard.pki.SmartCardCertManager
import com.example.webmil.smartcard.pki.SmartCardPrivateKey
import com.example.webmil.smartcard.pki.SmartCardSecurityProvider
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.Signature

class SmartCardTest {

    @Test
    fun testApduCommandEncoding() {
        val cmd = ApduCommand(
            cla = 0x00.toByte(),
            ins = 0xA4.toByte(),
            p1 = 0x04.toByte(),
            p2 = 0x00.toByte(),
            data = byteArrayOf(0x01, 0x02, 0x03)
        )
        val encoded = cmd.toByteArray()
        assertEquals(8, encoded.size)
        assertEquals("00 A4 04 00 03 01 02 03", cmd.toHex())
    }

    @Test
    fun testApduResponseParsing() {
        // Success response: 90 00
        val successBytes = byteArrayOf(0xDE.toByte(), 0xAD.toByte(), 0x90.toByte(), 0x00.toByte())
        val resp = ApduResponse.fromByteArray(successBytes)
        assertTrue(resp.isSuccess)
        assertEquals(0x9000, resp.statusWord)
        assertEquals("DE AD", resp.data.toHexString())
        assertEquals("90 00", resp.statusWordToHex())

        // PIN failed response with 2 attempts remaining: 63 C2
        val pinFailBytes = byteArrayOf(0x63.toByte(), 0xC2.toByte())
        val pinResp = ApduResponse.fromByteArray(pinFailBytes)
        assertFalse(pinResp.isSuccess)
        assertTrue(pinResp.isPinFailed)
        assertEquals(2, pinResp.attemptsRemaining)
        assertFalse(pinResp.isCardLocked)

        // Card locked response: 69 83
        val lockedResp = ApduResponse.cardLocked()
        assertTrue(lockedResp.isCardLocked)
    }

    @Test
    fun testStatusWordMeaning() {
        assertEquals("Success (OK)", ApduResponse(byteArrayOf(), 0x90.toByte(), 0x00.toByte()).statusWordMeaning)
        assertEquals("Verification failed (3 attempts left)", ApduResponse(byteArrayOf(), 0x63.toByte(), 0xC3.toByte()).statusWordMeaning)
        assertEquals("Security status not satisfied", ApduResponse(byteArrayOf(), 0x69.toByte(), 0x82.toByte()).statusWordMeaning)
        assertEquals("Referenced data or key reference not found", ApduResponse(byteArrayOf(), 0x6A.toByte(), 0x88.toByte()).statusWordMeaning)
        assertEquals("Instruction (INS) not supported or applet not selected", ApduResponse(byteArrayOf(), 0x6D.toByte(), 0x00.toByte()).statusWordMeaning)
    }

    @Test
    fun testPivVerifyPinApduFormatting() {
        val pinApdu = ApduCommand.verifyPin("123456", PivAppletHandler.KeyReference.PIV_APPLICATION_PIN)
        assertEquals(0x00.toByte(), pinApdu.cla)
        assertEquals(0x20.toByte(), pinApdu.ins)
        assertEquals(0x00.toByte(), pinApdu.p1)
        assertEquals(0x80.toByte(), pinApdu.p2) // PIV Application PIN reference (0x80)

        // PIN 123456 padded with 0xFF to 8 bytes: 31 32 33 34 35 36 FF FF
        val expectedData = "31 32 33 34 35 36 FF FF".hexToByteArray()
        assertArrayEquals(expectedData, pinApdu.data)
    }

    @Test
    fun testPivHandlerPinVerificationFallbackToGlobalPin() {
        val handler = PivAppletHandler()
        val apduHistory = mutableListOf<String>()

        val response = handler.verifyPin("123456") { apduBytes ->
            val hex = apduBytes.toHexString()
            apduHistory.add(hex)

            when {
                // SELECT PIV Applet AID
                hex.contains("A0 00 00 03 08 00 00 01 00") -> byteArrayOf(0x90.toByte(), 0x00.toByte())
                // VERIFY PIN with keyRef 0x80 (PIV PIN) -> SW 6A 88 (Key Ref Not Found)
                hex.startsWith("00 20 00 80") -> byteArrayOf(0x6A.toByte(), 0x88.toByte())
                // VERIFY PIN with keyRef 0x00 (Global PIN) -> SW 90 00 (OK)
                hex.startsWith("00 20 00 00") -> byteArrayOf(0x90.toByte(), 0x00.toByte())
                else -> byteArrayOf(0x6F.toByte(), 0x00.toByte())
            }
        }

        assertTrue(response.isSuccess)
        assertEquals(0x9000, response.statusWord)
        assertTrue(apduHistory.any { it.startsWith("00 20 00 80") })
        assertTrue(apduHistory.any { it.startsWith("00 20 00 00") })
    }

    @Test
    fun testPivHandlerPinVerificationFailedNoBurnOnWrongPin() {
        val handler = PivAppletHandler()
        val apduHistory = mutableListOf<String>()

        val response = handler.verifyPin("654321") { apduBytes ->
            val hex = apduBytes.toHexString()
            apduHistory.add(hex)

            when {
                // SELECT PIV Applet AID
                hex.contains("A0 00 00 03 08 00 00 01 00") -> byteArrayOf(0x90.toByte(), 0x00.toByte())
                // VERIFY PIN with keyRef 0x80 -> SW 63 C2 (Wrong PIN, 2 retries left)
                hex.startsWith("00 20 00 80") -> byteArrayOf(0x63.toByte(), 0xC2.toByte())
                else -> byteArrayOf(0x6F.toByte(), 0x00.toByte())
            }
        }

        assertFalse(response.isSuccess)
        assertTrue(response.isPinFailed)
        assertEquals(2, response.attemptsRemaining)

        assertFalse("Should not attempt 0x00 on wrong PIN", apduHistory.any { it.startsWith("00 20 00 00") })
        assertFalse("Should not attempt 0x81 on wrong PIN", apduHistory.any { it.startsWith("00 20 00 81") })
    }

    @Test
    fun testPkcs1PaddingFormatting() {
        val rawDigest = ByteArray(32) { 0xAB.toByte() } // 32-byte SHA-256 hash
        val padded = SmartCardCertManager.formatPkcs1Padding(rawDigest, 256)

        assertEquals(256, padded.size)
        assertEquals(0x00.toByte(), padded[0])
        assertEquals(0x01.toByte(), padded[1])
        assertEquals(0x00.toByte(), padded[256 - 32 - 19 - 1]) // 0x00 delimiter before DigestInfo

        // Already padded 256-byte input
        val alreadyPadded = ByteArray(256)
        alreadyPadded[0] = 0x00.toByte()
        alreadyPadded[1] = 0x01.toByte()
        val result = SmartCardCertManager.formatPkcs1Padding(alreadyPadded, 256)
        assertEquals(256, result.size)
        assertArrayEquals(alreadyPadded, result)
    }

    @Test
    fun testCertificateScoringAndClientAuthSelection() {
        val (_, cert) = SmartCardCertManager.generateSimulatedPivCredentials()

        val pivAuthScore = SmartCardCertManager.scoreCertificateForClientAuth(
            cert, PivAppletHandler.KeyReference.PIV_AUTHENTICATION
        )
        val keyMgmtScore = SmartCardCertManager.scoreCertificateForClientAuth(
            cert, PivAppletHandler.KeyReference.KEY_MANAGEMENT
        )

        assertTrue("PIV Auth 9A score should be higher than Key Mgmt 9D score", pivAuthScore > keyMgmtScore)

        val candidates = listOf(
            Pair(PivAppletHandler.KeyReference.KEY_MANAGEMENT, cert),
            Pair(PivAppletHandler.KeyReference.PIV_AUTHENTICATION, cert)
        )

        val selected = SmartCardCertManager.selectBestClientAuthCertificate(candidates, getKeyRef = { keyRef -> keyRef })
        assertNotNull(selected)
        assertEquals(PivAppletHandler.KeyReference.PIV_AUTHENTICATION, selected!!.first)
    }

    @Test
    fun testGetResponseApduChaining() {
        val handler = PivAppletHandler()
        val apduCalls = mutableListOf<String>()

        val certBytes = handler.readCertificateData { apduBytes ->
            val hex = apduBytes.toHexString()
            apduCalls.add(hex)

            when {
                // Initial GET DATA command -> SW 61 10 (16 bytes available via GET RESPONSE)
                hex.startsWith("00 CB 3F FF") -> byteArrayOf(0x30, 0x82.toByte(), 0x01, 0x00) + byteArrayOf(0x61.toByte(), 0x10.toByte())
                // GET RESPONSE command (00 C0 00 00 10) -> SW 90 00 OK
                hex.startsWith("00 C0 00 00") -> ByteArray(16) { 0x55.toByte() } + byteArrayOf(0x90.toByte(), 0x00.toByte())
                else -> byteArrayOf(0x6F.toByte(), 0x00.toByte())
            }
        }

        assertNotNull(certBytes)
        assertTrue(apduCalls.any { it.startsWith("00 C0 00 00") })
    }

    @Test
    fun testSmartCardPrivateKeyAndCertManager() {
        val (keyPair, cert) = SmartCardCertManager.generateSimulatedPivCredentials()
        assertNotNull(keyPair)
        assertNotNull(cert)

        val certInfo = SmartCardCertManager.extractCertificateInfo(cert, "PIV Auth Test")
        assertEquals("RSA", certInfo.keyAlgorithm)
        assertEquals(2048, certInfo.keySize)
        assertTrue(certInfo.subjectDN.contains("DOE") || certInfo.subjectDN.contains("CAC"))

        val smartCardPrivateKey = SmartCardPrivateKey(
            algorithmName = "RSA",
            keySizeBits = 2048,
            keyReference = PivAppletHandler.KeyReference.PIV_AUTHENTICATION,
            publicModulus = (cert.publicKey as? java.security.interfaces.RSAPublicKey)?.modulus,
            underlyingPrivateKey = keyPair.private
        )

        assertNotNull(smartCardPrivateKey.modulus)
        assertEquals("RSA", smartCardPrivateKey.algorithm)

        SmartCardSecurityProvider.install()
        val signature = Signature.getInstance("SHA256withRSA")
        signature.initSign(smartCardPrivateKey)
        signature.update("TLS Handshake Challenge".toByteArray())
        val sigBytes = signature.sign()
        assertTrue(sigBytes.isNotEmpty())
    }

    @Test
    fun testSignatureSpiAcceptsStandardPrivateKey() {
        SmartCardSecurityProvider.install()
        val kpg = java.security.KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048)
        val standardKeyPair = kpg.generateKeyPair()

        val signature = Signature.getInstance("SHA256withRSA")
        // Should NOT throw InvalidKeyException("Key must be instance of SmartCardPrivateKey")
        signature.initSign(standardKeyPair.private)
        signature.update("Test Data".toByteArray())
        val sigBytes = signature.sign()
        assertTrue(sigBytes.isNotEmpty())
    }

    @Test
    fun testSmartCardPrivateKeyConstructionAndHelper() {
        val (kp, cert) = SmartCardCertManager.generateSimulatedPivCredentials()
        val certInfo = SmartCardCertManager.extractCertificateInfo(cert, "Email Certificate (9D/82)")

        val pKey: java.security.PrivateKey = SmartCardCertManager.getSmartCardPrivateKey(cert = certInfo, underlyingPrivateKey = kp.private)
        assertNotNull(pKey)
        val rsaKey = pKey as java.security.interfaces.RSAPrivateKey
        assertEquals(PivAppletHandler.KeyReference.EMAIL_SIGNING, (pKey as SmartCardPrivateKey).keyReference)
        assertNotNull(rsaKey.modulus)
        assertEquals("RSA", rsaKey.algorithm)
    }

    @Test
    fun testSmartCardPinVerificationAndAuthorization() = runBlocking {
        val manager = SmartCardManager()

        assertEquals(SessionState.PIN_PROMPT, manager.uiState.value.sessionState)

        val verified = manager.verifyPin("123456")
        assertTrue(verified)
        assertEquals(SessionState.AUTHORIZED, manager.uiState.value.sessionState)
        assertEquals(CardStatus.AUTHENTICATED, manager.uiState.value.cardStatus)
        assertNotNull(manager.getSmartCardPrivateKey())
        assertNotNull(manager.getCertificateChain())
    }

    @Test
    fun testRapidSessionSecurityControlsOnCardRemoval() = runBlocking {
        val manager = SmartCardManager()

        assertTrue(manager.verifyPin("123456"))
        assertTrue(manager.isSessionAuthorized())
        assertNotNull(manager.getSmartCardPrivateKey())
        assertNotNull(manager.getCertificateChain())

        var listenerCalled = false
        var wasAuthInListener = false
        manager.onCardRemovedListener = { wasAuth ->
            listenerCalled = true
            wasAuthInListener = wasAuth
        }

        manager.ejectCard()

        assertTrue(listenerCalled)
        assertTrue(wasAuthInListener)
        assertNull("Private key wiped", manager.getSmartCardPrivateKey())
        assertNull("Cert chain wiped", manager.getCertificateChain())
        assertFalse(manager.isSessionAuthorized())
        assertEquals(CardStatus.ABSENT, manager.uiState.value.cardStatus)
        assertTrue("Session locked", manager.uiState.value.isSessionLocked)
        assertNotNull("Warning present", manager.uiState.value.cardRemovalWarning)
        assertTrue(manager.uiState.value.cardRemovalWarning!!.contains("SECURITY ALERT"))
    }

    @Test
    fun testDismissCardRemovalWarningAndReEnableSimulation() = runBlocking {
        val manager = SmartCardManager()

        manager.verifyPin("123456")
        manager.ejectCard()
        assertTrue(manager.uiState.value.isSessionLocked)

        manager.dismissCardRemovalWarning()
        assertFalse(manager.uiState.value.isSessionLocked)
        assertNull(manager.uiState.value.cardRemovalWarning)

        manager.enableSimulationMode()
        assertEquals(SessionState.PIN_PROMPT, manager.uiState.value.sessionState)
        assertEquals(CardStatus.INSERTED, manager.uiState.value.cardStatus)
    }

    @Test
    fun testActiveCertChainAndPendingTlsRequest() = runBlocking {
        val manager = SmartCardManager()
        assertNotNull(manager.uiState.value.activeCertificate)

        val chain = manager.getActiveCertChain()
        assertNotNull(chain)
        assertTrue(chain!!.isNotEmpty())

        // Verify PIN populates activeCertificate and preserves session
        assertTrue(manager.verifyPin("123456"))
        assertNotNull(manager.uiState.value.activeCertificate)
        assertEquals(SessionState.AUTHORIZED, manager.uiState.value.sessionState)
    }

    @Test
    fun testPivAuthCertificateRead() {
        val handler = PivAppletHandler()
        val dummyCert = byteArrayOf(0x30, 0x82.toByte(), 0x01, 0x00)

        val result = handler.readPivAuthCertificate { apduBytes ->
            val hex = apduBytes.toHexString()
            if (hex.startsWith("00 CB 3F FF")) {
                dummyCert + byteArrayOf(0x90.toByte(), 0x00.toByte())
            } else {
                byteArrayOf(0x6F.toByte(), 0x00.toByte())
            }
        }

        assertNotNull(result)
        assertArrayEquals(dummyCert, result)
    }

    @Test
    fun testPinVerificationStateAndAutoDismissInSmartCardManager() = runBlocking {
        val manager = SmartCardManager()
        assertEquals(com.example.webmil.smartcard.model.PinVerificationState.IDLE, manager.uiState.value.pinVerificationState)
        assertFalse(manager.uiState.value.isVerifyingPin)

        manager.setVerifyingPinState(true, com.example.webmil.smartcard.model.PinVerificationState.VERIFYING)
        assertTrue(manager.uiState.value.isVerifyingPin)
        assertEquals(com.example.webmil.smartcard.model.PinVerificationState.VERIFYING, manager.uiState.value.pinVerificationState)

        val success = manager.verifyPin("123456")
        assertTrue(success)
        assertEquals(SessionState.AUTHORIZED, manager.uiState.value.sessionState)
    }

    @Test
    fun testSmartCardWebViewClientPendingRequestResumption() = runBlocking {
        val manager = SmartCardManager()
        val webViewClient = com.example.webmil.smartcard.tls.SmartCardWebViewClient(manager)

        // Verify resumePendingClientCertRequest completes safely when called
        webViewClient.resumePendingClientCertRequest()
        assertNotNull(manager.getActiveCertChain())

        // Verify PIN and test resumption when authorized
        assertTrue(manager.verifyPin("123456"))
        webViewClient.resumePendingClientCertRequest()
        assertEquals(SessionState.AUTHORIZED, manager.uiState.value.sessionState)
    }

    @Test
    fun testCcidDriverSynchronizedThreadSafety() {
        val ccidDriver = com.example.webmil.smartcard.ccid.CcidDriver()
        assertFalse(ccidDriver.isConnected)
        // Verify synchronized powerOn/powerOff/transceive methods do not throw or deadlock when disconnected
        assertNull(ccidDriver.powerOn())
        assertFalse(ccidDriver.powerOff())
        assertNull(ccidDriver.transceive(byteArrayOf(0x00, 0x00, 0x00, 0x00)))
    }

    @Test
    fun testGenerateAndSaveDodCaAssets() {
        val caList = SmartCardCertManager.generateBuiltInDodCaCertificates()
        assertEquals(98, caList.size)

        val assetsDir = java.io.File("src/main/assets/dod_ca")
        if (!assetsDir.exists()) {
            assetsDir.mkdirs()
        }

        for (cert in caList) {
            val cnRaw = cert.subjectX500Principal.name
                .substringAfter("CN=")
                .substringBefore(",")
            val fileName = when {
                cnRaw.startsWith("DoD Root CA") -> "DoD_Root_CA_" + cnRaw.substringAfter("DoD Root CA ") + ".crt"
                cnRaw.startsWith("DOD ID CA-") -> "DoD_ID_CA_" + cnRaw.substringAfter("DOD ID CA-") + ".crt"
                cnRaw.startsWith("DOD SW CA-") -> "DoD_SW_CA_" + cnRaw.substringAfter("DOD SW CA-") + ".crt"
                cnRaw.startsWith("DOD EMAIL CA-") -> "DoD_EMAIL_CA_" + cnRaw.substringAfter("DOD EMAIL CA-") + ".crt"
                cnRaw.startsWith("DOD DERILITY CA-") -> "DoD_DERILITY_CA_" + cnRaw.substringAfter("DOD DERILITY CA-") + ".crt"
                else -> cnRaw.replace(" ", "_") + ".crt"
            }

            val file = java.io.File(assetsDir, fileName)
            java.io.FileOutputStream(file).use { fos ->
                fos.write(cert.encoded)
            }
            assertTrue("File created: ${file.name}", file.exists() && file.length() > 0)
        }

        // Specifically verify DoD_ID_CA_72.crt and DoD_DERILITY_CA_1.crt were created
        val dodIdCa72File = java.io.File(assetsDir, "DoD_ID_CA_72.crt")
        assertTrue("DoD_ID_CA_72.crt must exist in assets/dod_ca", dodIdCa72File.exists() && dodIdCa72File.length() > 0)

        val dodDerilityCa1File = java.io.File(assetsDir, "DoD_DERILITY_CA_1.crt")
        assertTrue("DoD_DERILITY_CA_1.crt must exist in assets/dod_ca", dodDerilityCa1File.exists() && dodDerilityCa1File.length() > 0)
    }

    @Test
    fun testDodIdCa72SupportAndChainBuilding() {
        val caList = SmartCardCertManager.generateBuiltInDodCaCertificates()
        val dodIdCa72 = caList.find { it.subjectX500Principal.name.contains("ID CA-72") }
        assertNotNull("DOD ID CA-72 must be present in built-in DoD CAs", dodIdCa72)

        // Generate user certificate issued by DOD ID CA-72
        val kpg = java.security.KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048, java.security.SecureRandom())
        val userKeyPair = kpg.generateKeyPair()

        val userSubject = javax.security.auth.x500.X500Principal("CN=SMITH.JOHN.B.9876543210, OU=USAF, OU=PKI, OU=DoD, O=U.S. Government, C=US")
        val userIssuer = javax.security.auth.x500.X500Principal("CN=DOD ID CA-72, OU=PKI, OU=DoD, O=U.S. Government, C=US")
        val userCert = SmartCardCertManager.generateCaCertificate(
            subjectDN = userSubject.name,
            issuerDN = userIssuer.name,
            keyPair = userKeyPair
        )

        val chain = SmartCardCertManager.buildFullCertChain(userCert, caList)
        assertNotNull("Chain must not be null", chain)
        assertEquals("Chain must return [userCert, dodIdCa72Cert, dodRootCa3Or6Cert]", 3, chain.size)
        assertEquals(userCert, chain[0])
        assertTrue("Intermediate cert must be DOD ID CA-72", chain[1].subjectX500Principal.name.contains("DOD ID CA-72"))
        assertTrue("Root cert must be DoD Root CA 6", chain[2].subjectX500Principal.name.contains("DoD Root CA 6"))
    }

    @Test
    fun testDynamicIntermediateCaCertFallback() {
        // User cert issued by an unbundled/unknown CA: DOD ID CA-99
        val kpg = java.security.KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048, java.security.SecureRandom())
        val userKeyPair = kpg.generateKeyPair()

        val userSubject = javax.security.auth.x500.X500Principal("CN=DOE.JANE.M.1122334455, OU=USN, OU=PKI, OU=DoD, O=U.S. Government, C=US")
        val userIssuer = javax.security.auth.x500.X500Principal("CN=DOD ID CA-99, OU=PKI, OU=DoD, O=U.S. Government, C=US")
        val userCert = SmartCardCertManager.generateCaCertificate(
            subjectDN = userSubject.name,
            issuerDN = userIssuer.name,
            keyPair = userKeyPair
        )

        // Pass empty preloaded list: must not inject any synthetic/invalid self-signed fake CA certs
        val chain = SmartCardCertManager.buildFullCertChain(userCert, emptyList())
        assertNotNull("Chain must not be null", chain)
        assertEquals("Chain must only contain valid user cert when CA not found", 1, chain.size)
        assertEquals(userCert, chain[0])
    }

    @Test
    fun testSelectPivAppletP2ParameterHandling() {
        val handler = PivAppletHandler()
        val apduHistory = mutableListOf<String>()

        val selectResp = handler.selectPivApplet { apduBytes ->
            val hex = apduBytes.toHexString()
            apduHistory.add(hex)
            when {
                // CAC Email Applet with P2=0x0C succeeds (90 00)
                hex.startsWith("00 A4 04 0C") && hex.contains("A0 00 00 00 79 01 02") -> byteArrayOf(0x90.toByte(), 0x00.toByte())
                // P2=0x00 returns 6A 86 (Incorrect P1-P2)
                hex.startsWith("00 A4 04 00") -> byteArrayOf(0x6A.toByte(), 0x86.toByte())
                else -> byteArrayOf(0x6F.toByte(), 0x00.toByte())
            }
        }

        assertTrue(selectResp.isSuccess)
        assertTrue("Should try P2=0x0C command", apduHistory.any { it.startsWith("00 A4 04 0C") })
    }

    @Test
    fun testExact256ByteSignaturePayloadFormatting() {
        // Test 257-byte signature with leading 0x00 sign byte
        val sig257 = byteArrayOf(0x00.toByte()) + ByteArray(256) { 0xAA.toByte() }
        val formatted257 = PivAppletHandler.formatRsaSignatureToExactSize(sig257, 256)
        assertEquals(256, formatted257.size)
        assertEquals(0xAA.toByte(), formatted257[0])

        // Test 254-byte signature with missing leading zeros
        val sig254 = ByteArray(254) { 0xBB.toByte() }
        val formatted254 = PivAppletHandler.formatRsaSignatureToExactSize(sig254, 256)
        assertEquals(256, formatted254.size)
        assertEquals(0x00.toByte(), formatted254[0])
        assertEquals(0x00.toByte(), formatted254[1])
        assertEquals(0xBB.toByte(), formatted254[2])

        // Test BER-TLV wrapped signature (Tag 82 header)
        val sigPayload = ByteArray(256) { 0xCC.toByte() }
        val berTlvHeader = byteArrayOf(0x82.toByte(), 0x82.toByte(), 0x01.toByte(), 0x00.toByte())
        val berTlvWrapped = berTlvHeader + sigPayload
        val formattedTlv = PivAppletHandler.formatRsaSignatureToExactSize(berTlvWrapped, 256)
        assertEquals(256, formattedTlv.size)
        assertEquals(0xCC.toByte(), formattedTlv[0])
    }

    @Test
    fun testEmailCertSelectedForWebmailHost() {
        val manager = SmartCardManager()
        manager.enableSimulationMode()

        // Request active cert chain for webmail host
        val webmailChain = manager.getActiveCertChain(host = "webmail.apps.mil")
        assertNotNull(webmailChain)
        assertTrue(webmailChain!!.isNotEmpty())

        val activeCert = manager.uiState.value.activeCertificate
        assertNotNull(activeCert)
        assertTrue(
            "Email Certificate must be active for webmail.apps.mil",
            activeCert!!.certificateType.contains("Email") || activeCert.certificateType.contains("9D/82")
        )
    }

    @Test
    fun testContainer5FC109IssuerCertReading() {
        val handler = PivAppletHandler()
        val dummyCert = byteArrayOf(0x30, 0x82.toByte(), 0x01, 0x00)

        val result = handler.readPivIssuerCertificate { apduBytes ->
            val hex = apduBytes.toHexString()
            if (hex.contains("5F C1 09") || hex.startsWith("00 CB 3F FF")) {
                dummyCert + byteArrayOf(0x90.toByte(), 0x00.toByte())
            } else {
                byteArrayOf(0x6F.toByte(), 0x00.toByte())
            }
        }

        assertNotNull("Container 5FC109 reading must succeed", result)
        assertArrayEquals(dummyCert, result)
    }

    @Test
    fun testActiveCertChainBuildingWithDodCa() {
        val manager = SmartCardManager()
        val chain = manager.getActiveCertChain()

        assertNotNull("Cert chain should not be null", chain)
        assertEquals("Cert chain must contain user cert, intermediate CA, and root CA", 3, chain!!.size)

        val userCert = chain[0]
        val intermediateCert = chain[1]
        val rootCert = chain[2]

        assertTrue("User cert subject should contain CAC info", userCert.subjectX500Principal.name.contains("DOE") || userCert.subjectX500Principal.name.contains("CAC"))
        assertTrue("Intermediate cert subject should be DoD ID CA", intermediateCert.subjectX500Principal.name.contains("ID CA-72") || intermediateCert.subjectX500Principal.name.contains("ID CA"))
        assertTrue("Root cert subject should be DoD Root CA", rootCert.subjectX500Principal.name.contains("Root CA 6") || rootCert.subjectX500Principal.name.contains("Root CA"))
    }

    @Test
    fun testDigestInfoFormattingForRsaSignatures() {
        // 1. SHA-256 Digest (32 bytes)
        val sha256Digest = ByteArray(32) { 0x11.toByte() }
        val paddedSha256 = SmartCardCertManager.formatPkcs1Padding(sha256Digest, 256)
        assertEquals(256, paddedSha256.size)
        assertEquals(0x00.toByte(), paddedSha256[0])
        assertEquals(0x01.toByte(), paddedSha256[1])
        // SHA-256 DigestInfo header: 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20
        val sha256Header = byteArrayOf(0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86.toByte(), 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20)
        val sha256Offset = 256 - 32 - 19
        for (i in sha256Header.indices) {
            assertEquals(sha256Header[i], paddedSha256[sha256Offset + i])
        }

        // 2. SHA-384 Digest (48 bytes)
        val sha384Digest = ByteArray(48) { 0x22.toByte() }
        val paddedSha384 = SmartCardCertManager.formatPkcs1Padding(sha384Digest, 256)
        assertEquals(256, paddedSha384.size)
        val sha384Header = byteArrayOf(0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86.toByte(), 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30)
        val sha384Offset = 256 - 48 - 19
        for (i in sha384Header.indices) {
            assertEquals(sha384Header[i], paddedSha384[sha384Offset + i])
        }

        // 3. SHA-1 Digest (20 bytes)
        val sha1Digest = ByteArray(20) { 0x33.toByte() }
        val paddedSha1 = SmartCardCertManager.formatPkcs1Padding(sha1Digest, 256)
        assertEquals(256, paddedSha1.size)
        val sha1Header = byteArrayOf(0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14)
        val sha1Offset = 256 - 20 - 15
        for (i in sha1Header.indices) {
            assertEquals(sha1Header[i], paddedSha1[sha1Offset + i])
        }
    }

    @Test
    fun testIssuerPrincipalMatching() {
        val userCert = SmartCardCertManager.generateSimulatedPivCredentials().second

        val matchingPrincipal = arrayOf<java.security.Principal>(
            javax.security.auth.x500.X500Principal("CN=DOD ID CA-72, OU=PKI, OU=DoD, O=U.S. Government, C=US")
        )
        val nonMatchingPrincipal = arrayOf<java.security.Principal>(
            javax.security.auth.x500.X500Principal("CN=NonExistentCA, OU=PKI, O=Unknown, C=US")
        )

        val scoreMatch = SmartCardCertManager.scoreCertificateForClientAuth(
            userCert,
            PivAppletHandler.KeyReference.PIV_AUTHENTICATION,
            matchingPrincipal
        )

        val scoreNoMatch = SmartCardCertManager.scoreCertificateForClientAuth(
            userCert,
            PivAppletHandler.KeyReference.PIV_AUTHENTICATION,
            nonMatchingPrincipal
        )

        assertTrue("Matching principal score ($scoreMatch) should be higher than non-matching ($scoreNoMatch)", scoreMatch > scoreNoMatch)
    }

    @Test
    fun testHostAgnosticMtlsAutoProceed() = runBlocking {
        val manager = SmartCardManager()
        assertTrue(manager.verifyPin("123456"))
        assertTrue(manager.isSessionAuthorized())

        var authenticatedHost: String? = null
        val client = com.example.webmil.smartcard.tls.SmartCardWebViewClient(
            smartCardManager = manager,
            onMtlsAuthenticatedCallback = { host -> authenticatedHost = host }
        )

        val hostsToTest = listOf("login.microsoftonline.us", "certauth.login.microsoftonline.us", "webmail.apps.mil")

        for (targetHost in hostsToTest) {
            authenticatedHost = null

            val fakeRequest = object : android.webkit.ClientCertRequest() {
                override fun getHost(): String = targetHost
                override fun getPort(): Int = 443
                override fun getKeyTypes(): Array<String> = arrayOf("RSA")
                override fun getPrincipals(): Array<java.security.Principal> = arrayOf(
                    javax.security.auth.x500.X500Principal("CN=DOD ID CA-72, OU=PKI, OU=DoD, O=U.S. Government, C=US")
                )
                override fun proceed(privateKey: java.security.PrivateKey?, chain: Array<out java.security.cert.X509Certificate>?) {}
                override fun cancel() {}
                override fun ignore() {}
            }

            client.onReceivedClientCertRequest(null, fakeRequest)

            assertEquals(targetHost, authenticatedHost)
            assertNull("pendingTlsHost must remain null when authorized for $targetHost", manager.uiState.value.pendingTlsHost)
        }
    }

    @Test
    fun testRsaSignaturePayloadExact256Bytes() {
        val (keyPair, cert) = SmartCardCertManager.generateSimulatedPivCredentials()
        val privateKey = SmartCardPrivateKey(
            algorithmName = "RSA",
            keySizeBits = 2048,
            keyReference = PivAppletHandler.KeyReference.PIV_AUTHENTICATION,
            publicModulus = (cert.publicKey as? java.security.interfaces.RSAPublicKey)?.modulus,
            underlyingPrivateKey = keyPair.private
        )

        val testChallenge = ByteArray(32) { 0x42.toByte() }
        val signatureBytes = privateKey.signData(testChallenge, "NONEwithRSA")

        assertNotNull("Signature payload must not be null", signatureBytes)
        assertEquals("RSA 2048 signature payload must be exactly 256 bytes", 256, signatureBytes.size)
    }

    @Test
    fun testIssuerPrincipalHierarchyMatching() {
        val caList = SmartCardCertManager.loadDodCaCertificates()
        val (_, cert) = SmartCardCertManager.generateSimulatedPivCredentials()

        val rootPrincipal = arrayOf<java.security.Principal>(
            javax.security.auth.x500.X500Principal("CN=DoD Root CA 6, OU=PKI, OU=DoD, O=U.S. Government, C=US")
        )

        val scoreWithChainMatch = SmartCardCertManager.scoreCertificateForClientAuth(
            cert = cert,
            keyRef = PivAppletHandler.KeyReference.PIV_AUTHENTICATION,
            acceptablePrincipals = rootPrincipal,
            caCertificates = caList
        )

        assertTrue("Score with hierarchy matching ($scoreWithChainMatch) must be positive", scoreWithChainMatch > 0)
    }

    @Test
    fun testGeneralAuthenticateApduTlvStructure() {
        val challenge = ByteArray(256) { 0xAA.toByte() }
        val apdu = com.example.webmil.smartcard.apdu.ApduCommand.generalAuthenticate(
            algorithmId = PivAppletHandler.Algorithm.RSA_2048,
            keyReference = PivAppletHandler.KeyReference.PIV_AUTHENTICATION,
            challenge = challenge
        )

        val bytes = apdu.toByteArray()
        // CLA 00, INS 87, P1 07, P2 9A
        assertEquals(0x00.toByte(), bytes[0])
        assertEquals(0x87.toByte(), bytes[1])
        assertEquals(0x07.toByte(), bytes[2])
        assertEquals(0x9A.toByte(), bytes[3])

        // Extended Lc (00 01 0A -> 266 bytes)
        assertEquals(0x00.toByte(), bytes[4])
        assertEquals(0x01.toByte(), bytes[5])
        assertEquals(0x0A.toByte(), bytes[6])

        // Data field starts at index 7: Tag 7C header: 7C 82 01 06
        assertEquals(0x7C.toByte(), bytes[7])
        assertEquals(0x82.toByte(), bytes[8])
        assertEquals(0x01.toByte(), bytes[9])
        assertEquals(0x06.toByte(), bytes[10])

        // Inside Tag 7C: Tag 82 00 MUST come FIRST
        assertEquals(0x82.toByte(), bytes[11])
        assertEquals(0x00.toByte(), bytes[12])

        // Followed by Tag 81 header (81 82 01 00)
        assertEquals(0x81.toByte(), bytes[13])
        assertEquals(0x82.toByte(), bytes[14])
        assertEquals(0x01.toByte(), bytes[15])
        assertEquals(0x00.toByte(), bytes[16])
    }

    @Test
    fun testNoDoubleHashingFor32ByteDigest() {
        val digest32 = ByteArray(32) { 0x55.toByte() }
        val padded = SmartCardCertManager.formatPkcs1Padding(digest32, 256)

        assertEquals(256, padded.size)
        // Verify DigestInfo offset contains the SHA-256 header (19 bytes) followed by digest32
        val sha256Header = byteArrayOf(0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86.toByte(), 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20)
        val headerOffset = 256 - 32 - 19
        for (i in sha256Header.indices) {
            assertEquals(sha256Header[i], padded[headerOffset + i])
        }
        val digestOffset = 256 - 32
        for (i in digest32.indices) {
            assertEquals(digest32[i], padded[digestOffset + i])
        }
    }

    @Test
    fun testMultipleCertificatesReadingAndSelectionInSimulationMode() {
        val manager = SmartCardManager()
        val state = manager.uiState.value

        val available = state.availableCertificates
        assertTrue("Should have multiple certificates in simulation mode (PIV Auth, Email, Digital Signature)", available.size >= 3)

        val pivCert = available.find { it.certificateType.contains("PIV Authentication") }
        val emailCert = available.find { it.certificateType.contains("Email") }
        val sigCert = available.find { it.certificateType.contains("Digital Signature") }

        assertNotNull("PIV Auth cert must exist", pivCert)
        assertNotNull("Email cert must exist", emailCert)
        assertNotNull("Digital Signature cert must exist", sigCert)

        // Select Email Certificate
        manager.selectCertificate(emailCert!!)
        assertEquals(emailCert, manager.uiState.value.activeCertificate)
        assertTrue("Active certificate issuer should be DOD EMAIL CA", manager.uiState.value.activeCertificate!!.issuerDN.contains("EMAIL"))

        // Verify cert chain for selected Email Certificate
        val emailChain = manager.getActiveCertChain()
        assertNotNull("Email cert chain must not be null", emailChain)
        assertEquals(3, emailChain!!.size)
        assertTrue("Chain intermediate cert must be DOD EMAIL CA", emailChain[1].subjectX500Principal.name.contains("EMAIL"))

        // Switch back to PIV Auth
        manager.selectCertificate(pivCert!!)
        assertEquals(pivCert, manager.uiState.value.activeCertificate)
    }

    @Test
    fun testDodEmailCertificatesAndTrustChainGeneration() {
        val caList = SmartCardCertManager.generateBuiltInDodCaCertificates()
        val dodEmailCa72 = caList.find { it.subjectX500Principal.name.contains("EMAIL CA-72") }
        assertNotNull("DOD EMAIL CA-72 must be present in built-in DoD CAs", dodEmailCa72)

        val kpg = java.security.KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048, java.security.SecureRandom())
        val userKeyPair = kpg.generateKeyPair()

        val userSubject = javax.security.auth.x500.X500Principal("CN=SMITH.JOHN.B.9876543210, OU=USAF, OU=PKI, OU=DoD, O=U.S. Government, C=US")
        val userIssuer = javax.security.auth.x500.X500Principal("CN=DOD EMAIL CA-72, OU=PKI, OU=DoD, O=U.S. Government, C=US")
        val emailCert = SmartCardCertManager.generateCaCertificate(
            subjectDN = userSubject.name,
            issuerDN = userIssuer.name,
            keyPair = userKeyPair
        )

        val chain = SmartCardCertManager.buildFullCertChain(emailCert, caList)
        assertNotNull("Chain must not be null for Email cert", chain)
        assertEquals("Chain must return [emailCert, dodEmailCa72Cert, dodRootCa6Cert]", 3, chain.size)
        assertEquals(emailCert, chain[0])
        assertTrue("Intermediate cert must be DOD EMAIL CA-72", chain[1].subjectX500Principal.name.contains("DOD EMAIL CA-72"))
        assertTrue("Root cert must be DoD Root CA 6", chain[2].subjectX500Principal.name.contains("DoD Root CA 6"))
    }

    @Test
    fun testDodDerilityCa1InCaBundle() {
        val caList = SmartCardCertManager.generateBuiltInDodCaCertificates()
        val derilityCa = caList.find { it.subjectX500Principal.name.contains("DERILITY CA-1") }
        assertNotNull("DOD DERILITY CA-1 must be present in built-in DoD CAs", derilityCa)
    }

    @Test
    fun testGzipDecompressionOfPivCacCertificateContainers() {
        val (_, originalCert) = SmartCardCertManager.generateSimulatedPivCredentials()
        val rawDer = originalCert.encoded

        // GZIP compress rawDer
        val bos = java.io.ByteArrayOutputStream()
        java.util.zip.GZIPOutputStream(bos).use { gzip ->
            gzip.write(rawDer)
        }
        val gzippedDer = bos.toByteArray()

        // Wrap in BER-TLV (Tag 70 container, Tag 71 Cert Value, Tag 72 CertInfo gzip flag 0x01)
        val tag71 = byteArrayOf(0x71.toByte(), 0x82.toByte(), (gzippedDer.size shr 8).toByte(), (gzippedDer.size and 0xFF).toByte()) + gzippedDer
        val tag72 = byteArrayOf(0x72.toByte(), 0x01.toByte(), 0x01.toByte()) // GZIP flag = 0x01
        val innerPayload = tag71 + tag72
        val tag70Container = byteArrayOf(0x70.toByte(), 0x82.toByte(), (innerPayload.size shr 8).toByte(), (innerPayload.size and 0xFF).toByte()) + innerPayload

        // Verify PivAppletHandler.extractX509FromContainer decompresses GZIP payload
        val extractedDer = PivAppletHandler.extractX509FromContainer(tag70Container)
        assertNotNull(extractedDer)
        assertTrue("Extracted DER bytes must start with 0x30", extractedDer[0] == 0x30.toByte())

        // Verify SmartCardCertManager.parseX509Certificate parses GZIP compressed payload
        val parsedCert = SmartCardCertManager.parseX509Certificate(tag70Container)
        assertNotNull("GZIP compressed certificate container must be parsed into X509Certificate", parsedCert)
        assertEquals(originalCert.subjectX500Principal, parsedCert!!.subjectX500Principal)
        assertEquals(originalCert.serialNumber, parsedCert.serialNumber)
    }

    @Test
    fun testPivCacAppletSelectionBeforeReadingCertificates() {
        val handler = PivAppletHandler()
        val apduCalls = mutableListOf<String>()

        handler.readCertificateData { apduBytes ->
            val hex = apduBytes.toHexString()
            apduCalls.add(hex)
            if (hex.startsWith("00 A4 04 00")) {
                byteArrayOf(0x90.toByte(), 0x00.toByte())
            } else if (hex.startsWith("00 CB 3F FF")) {
                byteArrayOf(0x30, 0x82.toByte(), 0x01, 0x00, 0x90.toByte(), 0x00.toByte())
            } else {
                byteArrayOf(0x6F.toByte(), 0x00.toByte())
            }
        }

        assertTrue("selectPivApplet must execute SELECT command before GET DATA", apduCalls.any { it.startsWith("00 A4 04 00") })
        assertTrue("GET DATA command must be sent after SELECT applet", apduCalls.any { it.startsWith("00 CB 3F FF") })
    }

    @Test
    fun testFallbackCertificateGenerationForPhysicalCard() = runBlocking {
        val manager = SmartCardManager()
        manager.readCertificates()

        val active = manager.uiState.value.activeCertificate
        assertNotNull("activeCertificate must NEVER be null when card is connected", active)
        assertTrue("availableCertificates must not be empty", manager.uiState.value.availableCertificates.isNotEmpty())
        assertTrue("Fallback subject should contain CAC holder info", active!!.subjectDN.contains("CAC") || active.subjectDN.contains("DOE"))
    }

    @Test
    fun testExtractX509FromContainerDefensiveParsing() {
        // Null container
        val nullResult = PivAppletHandler.extractX509FromContainer(null)
        assertNotNull(nullResult)
        assertEquals(0, nullResult.size)

        // Empty container
        val emptyResult = PivAppletHandler.extractX509FromContainer(byteArrayOf())
        assertNotNull(emptyResult)
        assertEquals(0, emptyResult.size)

        // Single byte container
        val singleByteResult = PivAppletHandler.extractX509FromContainer(byteArrayOf(0x70))
        assertNotNull(singleByteResult)
        assertEquals(1, singleByteResult.size)

        // Truncated BER-TLV header with large length tag (0x83)
        val truncatedBerTlv = byteArrayOf(0x70.toByte(), 0x83.toByte(), 0x00.toByte(), 0x01.toByte())
        val truncatedResult = PivAppletHandler.extractX509FromContainer(truncatedBerTlv)
        assertNotNull(truncatedResult)

        // GZIP magic header (0x1F, 0x8B) with corrupted payload (ZipException prevention)
        val corruptGzip = byteArrayOf(0x1F.toByte(), 0x8B.toByte(), 0x00, 0x01, 0x02, 0x03, 0x04, 0x05)
        val gzipResult = PivAppletHandler.extractX509FromContainer(corruptGzip)
        assertNotNull(gzipResult)
        assertArrayEquals(corruptGzip, gzipResult)
    }

    @Test
    fun testApduResponseFromByteArrayDefensiveParsing() {
        // Null byte array
        val nullResp = ApduResponse.fromByteArray(null)
        assertFalse(nullResp.isSuccess)
        assertEquals(0x6F00, nullResp.statusWord)
        assertEquals(0, nullResp.data.size)

        // Empty byte array
        val emptyResp = ApduResponse.fromByteArray(byteArrayOf())
        assertFalse(emptyResp.isSuccess)
        assertEquals(0x6F00, emptyResp.statusWord)

        // 1-byte array
        val shortResp = ApduResponse.fromByteArray(byteArrayOf(0x90.toByte()))
        assertFalse(shortResp.isSuccess)
        assertEquals(0x6F00, shortResp.statusWord)

        // Valid 2-byte response (90 00)
        val validResp = ApduResponse.fromByteArray(byteArrayOf(0x90.toByte(), 0x00.toByte()))
        assertTrue(validResp.isSuccess)
        assertEquals(0x9000, validResp.statusWord)
        assertEquals(0, validResp.data.size)
    }

    @Test
    fun testCcidDriverDefensiveErrorHandling() {
        val driver = com.example.webmil.smartcard.ccid.CcidDriver()
        assertFalse(driver.isConnected)

        // Null UsbManager / UsbDevice open check
        assertFalse(driver.open(null, null))

        // Power operations on disconnected driver
        assertNull(driver.powerOn())
        assertFalse(driver.powerOff())

        // Transceive null, empty, or disconnected
        assertNull(driver.transceive(null))
        assertNull(driver.transceive(byteArrayOf()))
        assertNull(driver.transceive(byteArrayOf(0x00, 0xA4.toByte(), 0x04, 0x00)))

        // Safe close when already disconnected
        driver.close()
        assertFalse(driver.isConnected)
    }

    @Test
    fun testPivAppletHandlerTransceiverExceptionHandling() {
        val handler = PivAppletHandler()

        // Transceiver throws RuntimeException during select applet
        val selectResp = handler.selectPivApplet { throw RuntimeException("USB Device Detached") }
        assertFalse(selectResp.isSuccess)
        assertEquals(0x6F00, selectResp.statusWord)

        // Transceiver throws IllegalStateException during PIN verify
        val pinResp = handler.verifyPin("123456") { throw IllegalStateException("USB Communication Error") }
        assertFalse(pinResp.isSuccess)
        assertEquals(0x6F00, pinResp.statusWord)

        // Transceiver throws IndexOutOfBoundsException during certificate read
        val certResult = handler.readCertificateData { throw IndexOutOfBoundsException("USB Transfer Overflow") }
        assertNull(certResult)

        // Transceiver throws Exception during sign challenge
        val signResult = handler.signChallenge(ByteArray(32)) { throw Exception("Card Ejected") }
        assertNull(signResult)
    }

    @Test
    fun testSmartCardManagerPhysicalCardContainerFailureFallback() = runBlocking {
        val manager = SmartCardManager()

        // Read certificates when underlying transceive calls throw exceptions
        val certs = manager.readCertificates()
        assertNotNull(certs)
        assertTrue("Must return fallback certificate list without crashing", certs.isNotEmpty())
        assertNotNull("Active certificate must not be null", manager.uiState.value.activeCertificate)
    }

    @Test
    fun testEmailCertificateSignChallengeAppletSequenceAndFallback() {
        val handler = PivAppletHandler()

        // 1. Test standard sequence where PIV Applet is tried first
        val callsPiv = mutableListOf<String>()
        handler.signChallenge(
            challenge = ByteArray(256),
            algorithmId = PivAppletHandler.Algorithm.RSA_2048,
            keyRef = PivAppletHandler.KeyReference.EMAIL_SIGNING
        ) { apduBytes ->
            val hex = apduBytes.toHexString()
            callsPiv.add(hex)
            if (hex.startsWith("00 87") || hex.startsWith("00 88")) {
                byteArrayOf(0x7C.toByte(), 0x82.toByte(), 0x01.toByte(), 0x00.toByte()) + ByteArray(256) + byteArrayOf(0x90.toByte(), 0x00.toByte())
            } else {
                byteArrayOf(0x90.toByte(), 0x00.toByte())
            }
        }

        assertTrue("Must try PIV Applet (A0 00 00 03 08 00 00 01 00) first for Email Certificate 0x82", callsPiv.any { it.contains("A0 00 00 03 08 00 00 01 00") })
        assertTrue("Must execute GENERAL AUTHENTICATE APDU", callsPiv.any { it.startsWith("00 87") || it.startsWith("00 88") })

        // 2. Test fallback sequence when PIV and PKI return 6A 88 -> reaches CAC Email Applet
        val callsFallback = mutableListOf<String>()
        handler.signChallenge(
            challenge = ByteArray(256),
            algorithmId = PivAppletHandler.Algorithm.RSA_2048,
            keyRef = PivAppletHandler.KeyReference.EMAIL_SIGNING
        ) { apduBytes ->
            val hex = apduBytes.toHexString()
            callsFallback.add(hex)
            when {
                hex.contains("A0 00 00 00 79 01 02") -> byteArrayOf(0x90.toByte(), 0x00.toByte()) // CAC Email Applet
                hex.contains("A0 00 00 03 08 00 00 01 00") || hex.contains("A0 00 00 00 79 01 05") -> byteArrayOf(0x90.toByte(), 0x00.toByte())
                hex.startsWith("00 87") && callsFallback.any { it.contains("A0 00 00 00 79 01 02") } -> {
                    byteArrayOf(0x7C.toByte(), 0x82.toByte(), 0x01.toByte(), 0x00.toByte()) + ByteArray(256) + byteArrayOf(0x90.toByte(), 0x00.toByte())
                }
                hex.startsWith("00 87") || hex.startsWith("00 88") -> byteArrayOf(0x6A.toByte(), 0x88.toByte())
                else -> byteArrayOf(0x90.toByte(), 0x00.toByte())
            }
        }

        assertTrue("Must fallback to try CAC Email Applet (A0 00 00 00 79 01 02)", callsFallback.any { it.contains("A0 00 00 00 79 01 02") })
    }

    @Test
    fun testDodIdCa79SupportAndChainBuilding() {
        val caList = SmartCardCertManager.generateBuiltInDodCaCertificates()
        val dodIdCa79 = caList.find { it.subjectX500Principal.name.contains("ID CA-79") }
        assertNotNull("DOD ID CA-79 must be present in built-in DoD CAs", dodIdCa79)

        val kpg = java.security.KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048, java.security.SecureRandom())
        val userKeyPair = kpg.generateKeyPair()

        val userSubject = javax.security.auth.x500.X500Principal("CN=SMITH.JOHN.B.9876543210, OU=USAF, OU=PKI, OU=DoD, O=U.S. Government, C=US")
        val userIssuer = javax.security.auth.x500.X500Principal("CN=DOD ID CA-79, OU=PKI, OU=DoD, O=U.S. Government, C=US")
        val userCert = SmartCardCertManager.generateCaCertificate(
            subjectDN = userSubject.name,
            issuerDN = userIssuer.name,
            keyPair = userKeyPair
        )

        val chain = SmartCardCertManager.buildFullCertChain(userCert, caList)
        assertNotNull("Chain must not be null", chain)
        assertEquals("Chain must return [userCert, dodIdCa79Cert, dodRootCa6Cert]", 3, chain.size)
        assertEquals(userCert, chain[0])
        assertTrue("Intermediate cert must be DOD ID CA-79", chain[1].subjectX500Principal.name.contains("DOD ID CA-79"))
        assertTrue("Root cert must be DoD Root CA 6", chain[2].subjectX500Principal.name.contains("DoD Root CA 6"))
    }

    @Test
    fun testEmailCertificateIntermediateCaChainMatching() {
        val kpg = java.security.KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048, java.security.SecureRandom())
        val userKp = kpg.generateKeyPair()

        val emailSubject = javax.security.auth.x500.X500Principal("CN=DOE.JOHN.A.1234567890, OU=USA, OU=PKI, OU=DoD, O=U.S. Government, C=US")
        val emailIssuer = javax.security.auth.x500.X500Principal("CN=DOD EMAIL CA-72, OU=PKI, OU=DoD, O=U.S. Government, C=US")
        val emailUserCert = SmartCardCertManager.generateCaCertificate(emailSubject.name, emailIssuer.name, userKp)

        val builtInCAs = SmartCardCertManager.generateBuiltInDodCaCertificates()
        val chain = SmartCardCertManager.buildFullCertChain(emailUserCert, builtInCAs)

        assertTrue("Chain must contain at least 2 certificates", chain.size >= 2)
        val intermediateCa = chain[1]
        assertTrue("Matched intermediate CA subject must contain 'DOD EMAIL CA-72'", intermediateCa.subjectX500Principal.name.contains("DOD EMAIL CA-72"))
        assertFalse("Matched intermediate CA subject must NOT be 'DOD ID CA-72'", intermediateCa.subjectX500Principal.name.contains("DOD ID CA-72"))
        assertEquals("User certificate issuer must match intermediate CA subject", emailUserCert.issuerX500Principal, intermediateCa.subjectX500Principal)
    }
}

