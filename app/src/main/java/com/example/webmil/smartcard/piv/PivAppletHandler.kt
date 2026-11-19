package com.example.webmil.smartcard.piv

import com.example.webmil.smartcard.apdu.ApduCommand
import com.example.webmil.smartcard.apdu.ApduResponse
import com.example.webmil.smartcard.apdu.toHexString

/**
 * Handles NIST SP 800-73 PIV (Personal Identity Verification) and CAC Smart Card operations.
 */
class PivAppletHandler {

    /**
     * PIV Container Data Tags (NIST SP 800-73-4 & CAC Containers)
     */
    object Tags {
        val PIV_AUTHENTICATION_CERT = byteArrayOf(0x5F.toByte(), 0xC1.toByte(), 0x05.toByte())
        val CARD_AUTHENTICATION_CERT = byteArrayOf(0x5F.toByte(), 0xC1.toByte(), 0x01.toByte())
        val DIGITAL_SIGNATURE_CERT = byteArrayOf(0x5F.toByte(), 0xC1.toByte(), 0x0A.toByte())
        val KEY_MANAGEMENT_CERT = byteArrayOf(0x5F.toByte(), 0xC1.toByte(), 0x0B.toByte())
        val EMAIL_SIGNING_CERT = byteArrayOf(0x5F.toByte(), 0xC1.toByte(), 0x02.toByte())     // Container 5FC102 (Container 82 - Email Certificate / Dual Persona)
        val EMAIL_ENCRYPTION_CERT = byteArrayOf(0x5F.toByte(), 0xC1.toByte(), 0x03.toByte())  // Container 5FC103 (Container 83 - Email Encryption)
        val PIV_ISSUER_CERT = byteArrayOf(0x5F.toByte(), 0xC1.toByte(), 0x09.toByte()) // Container 5FC109 (PIV Issuer Certificate / Intermediate CA)
        val SUB_CA_CERT = byteArrayOf(0x5F.toByte(), 0xC1.toByte(), 0x06.toByte())     // Container 5FC106 (Sub-CA Certificate)
    }

    /**
     * Key References
     */
    object KeyReference {
        const val PIV_AUTHENTICATION: Byte = 0x9A.toByte()
        const val CARD_AUTHENTICATION: Byte = 0x9E.toByte()
        const val DIGITAL_SIGNATURE: Byte = 0x9C.toByte()
        const val KEY_MANAGEMENT: Byte = 0x9D.toByte()
        const val EMAIL_SIGNING: Byte = 0x82.toByte()
        const val EMAIL_ENCRYPTION: Byte = 0x83.toByte()
        const val PIV_APPLICATION_PIN: Byte = 0x80.toByte()
        const val GLOBAL_PIN: Byte = 0x00.toByte()
        const val LOCAL_PIN: Byte = 0x81.toByte()
    }

    /**
     * Algorithms
     */
    object Algorithm {
        const val RSA_2048: Byte = 0x07.toByte()
        const val ECC_P256: Byte = 0x11.toByte()
        const val ECC_P384: Byte = 0x14.toByte()
    }

    var selectedAidDescription: String = "A0 00 00 03 08 00 00 01 00 (PIV Applet)"
        private set
    var selectedAidHex: String = "A0 00 00 03 08 00 00 01 00"
        private set

    fun selectPivApplet(
        transceiver: (ByteArray) -> ByteArray?
    ): ApduResponse = selectPivApplet(null, transceiver)

    fun selectPivApplet(
        targetAid: ByteArray? = null,
        transceiver: (ByteArray) -> ByteArray?
    ): ApduResponse {
        return try {
            val aids = if (targetAid != null) {
                listOf(Pair(targetAid, getAidDescription(targetAid)))
            } else {
                listOf(
                    Pair(ApduCommand.PIV_AID, "A0 00 00 03 08 00 00 01 00 (PIV Applet)"),
                    Pair(ApduCommand.CAC_PKI_AID, "A0 00 00 00 79 01 05 (CAC Applet)"),
                    Pair(ApduCommand.CAC_EMAIL_AID, "A0 00 00 00 79 01 02 (CAC Email Applet)"),
                    Pair(ApduCommand.CAC_IDENTITY_AID, "A0 00 00 00 79 01 01 (CAC Identity Applet)"),
                    Pair(ApduCommand.CAC_KEY_MGMT_AID, "A0 00 00 00 79 01 03 (CAC Key Management Applet)"),
                    Pair(ApduCommand.NIST_PIV_UNIVERSAL_AID, "A0 00 00 03 08 00 00 10 00 (NIST PIV Universal AID)"),
                    Pair(ApduCommand.CAC_AID_2, "A0 00 00 00 79 01 (CAC Container)"),
                    Pair(ApduCommand.CAC_AID_3, "A0 00 00 00 79 02 (CAC Identity)")
                )
            }

            val p2Options = listOf(0x0C.toByte(), 0x00.toByte())
            var lastResponse = ApduResponse(byteArrayOf(), 0x6F.toByte(), 0x00.toByte())

            for ((aid, desc) in aids) {
                for (p2 in p2Options) {
                    val command = ApduCommand.selectApplet(aid, p2)
                    val rawResponse = try {
                        transceiver(command.toByteArray())
                    } catch (_: Throwable) {
                        null
                    } ?: continue

                    val response = ApduResponse.fromByteArray(rawResponse)
                    if (response.isSuccess || response.sw1 == 0x61.toByte()) {
                        selectedAidHex = aid.toHexString()
                        selectedAidDescription = desc
                        return response
                    }
                    lastResponse = response
                }
            }
            lastResponse
        } catch (_: Throwable) {
            ApduResponse(byteArrayOf(), 0x6F.toByte(), 0x00.toByte())
        }
    }

    private fun getAidDescription(aid: ByteArray): String {
        val hex = aid.toHexString()
        return when {
            aid.contentEquals(ApduCommand.PIV_AID) -> "A0 00 00 03 08 00 00 01 00 (PIV Applet)"
            aid.contentEquals(ApduCommand.CAC_PKI_AID) -> "A0 00 00 00 79 01 05 (CAC Applet)"
            aid.contentEquals(ApduCommand.CAC_EMAIL_AID) -> "A0 00 00 00 79 01 02 (CAC Email Applet)"
            aid.contentEquals(ApduCommand.CAC_IDENTITY_AID) -> "A0 00 00 00 79 01 01 (CAC Identity Applet)"
            aid.contentEquals(ApduCommand.CAC_KEY_MGMT_AID) -> "A0 00 00 00 79 01 03 (CAC Key Management Applet)"
            aid.contentEquals(ApduCommand.NIST_PIV_UNIVERSAL_AID) -> "A0 00 00 03 08 00 00 10 00 (NIST PIV Universal AID)"
            aid.contentEquals(ApduCommand.CAC_AID_2) -> "A0 00 00 00 79 01 (CAC Container)"
            aid.contentEquals(ApduCommand.CAC_AID_3) -> "A0 00 00 00 79 02 (CAC Identity)"
            else -> "$hex (SmartCard Applet)"
        }
    }

    /**
     * Verifies PIN with automatic key reference fallback (0x80 -> 0x00 -> 0x81) and applet selection retry.
     */
    fun verifyPin(
        pin: String,
        transceiver: (ByteArray) -> ByteArray?
    ): ApduResponse {
        return try {
            // 1. Ensure PIV / CAC applet is selected
            val selectResp = selectPivApplet(transceiver)
            if (!selectResp.isSuccess) {
                // Retry applet selection once
                selectPivApplet(transceiver)
            }

            // Key references to try: 0x80 (PIV Card Application PIN), 0x00 (Global PIN), 0x81 (Local PIN)
            val keyRefs = listOf(
                KeyReference.PIV_APPLICATION_PIN, // 0x80
                KeyReference.GLOBAL_PIN,          // 0x00
                KeyReference.LOCAL_PIN            // 0x81
            )

            var lastResponse = ApduResponse(byteArrayOf(), 0x6F.toByte(), 0x00.toByte())

            for (keyRef in keyRefs) {
                val command = ApduCommand.verifyPin(pin, keyRef)
                val rawResponse = try {
                    transceiver(command.toByteArray())
                } catch (_: Throwable) {
                    null
                } ?: return ApduResponse(byteArrayOf(), 0x6F.toByte(), 0x00.toByte())

                val response = ApduResponse.fromByteArray(rawResponse)

                if (response.isSuccess) {
                    return response
                }

                // CRITICAL SAFETY CHECK:
                // If response is SW 63 Cx (incorrect PIN digits) or 69 83 (card locked),
                // return immediately so we DO NOT burn remaining PIN attempts on fallback key references!
                if (response.isPinFailed || response.isCardLocked) {
                    return response
                }

                lastResponse = response

                // If SW indicates applet deselected or file not found (6D 00 / 6A 82 / 69 82), re-select applet
                if (response.statusWord == 0x6D00 || response.statusWord == 0x6A82 || response.statusWord == 0x6982) {
                    selectPivApplet(transceiver)
                }
            }

            lastResponse
        } catch (_: Throwable) {
            ApduResponse(byteArrayOf(), 0x6F.toByte(), 0x00.toByte())
        }
    }

    /**
     * Overloaded verifyPin for specifying a single Key Reference directly.
     */
    fun verifyPin(
        pin: String,
        keyRef: Byte,
        transceiver: (ByteArray) -> ByteArray?
    ): ApduResponse {
        return try {
            val command = ApduCommand.verifyPin(pin, keyRef)
            val rawResponse = try {
                transceiver(command.toByteArray())
            } catch (_: Throwable) {
                null
            } ?: return ApduResponse(byteArrayOf(), 0x6F.toByte(), 0x00.toByte())

            ApduResponse.fromByteArray(rawResponse)
        } catch (_: Throwable) {
            ApduResponse(byteArrayOf(), 0x6F.toByte(), 0x00.toByte())
        }
    }

    /**
     * Reads PIV Authentication Certificate (Container 9A - Tag 5F C1 05)
     */
    fun readPivAuthCertificate(transceiver: (ByteArray) -> ByteArray?): ByteArray? {
        return readCertificateData(Tags.PIV_AUTHENTICATION_CERT, transceiver)
    }

    /**
     * Reads PIV Issuer Certificate / Intermediate CA (Container 5FC109 - Tag 5F C1 09)
     */
    fun readPivIssuerCertificate(transceiver: (ByteArray) -> ByteArray?): ByteArray? {
        return readCertificateData(Tags.PIV_ISSUER_CERT, transceiver)
    }

    /**
     * Reads Sub-CA Certificate (Container 5FC106 - Tag 5F C1 06)
     */
    fun readSubCaCertificate(transceiver: (ByteArray) -> ByteArray?): ByteArray? {
        return readCertificateData(Tags.SUB_CA_CERT, transceiver)
    }

    fun readCertificateData(
        tag: ByteArray = Tags.PIV_AUTHENTICATION_CERT,
        transceiver: (ByteArray) -> ByteArray?
    ): ByteArray? {
        return try {
            selectPivApplet(transceiver)

            var certData = tryReadContainerData(tag, transceiver)
            if (certData != null && certData.isNotEmpty()) {
                return certData
            }

            val candidateAids = listOf(
                ApduCommand.PIV_AID,
                ApduCommand.CAC_PKI_AID,
                ApduCommand.CAC_EMAIL_AID,
                ApduCommand.CAC_IDENTITY_AID,
                ApduCommand.CAC_KEY_MGMT_AID,
                ApduCommand.NIST_PIV_UNIVERSAL_AID,
                ApduCommand.CAC_AID_2,
                ApduCommand.CAC_AID_3
            )

            for (aid in candidateAids) {
                val selectResp = selectPivApplet(targetAid = aid, transceiver = transceiver)
                if (selectResp.isSuccess || selectResp.sw1 == 0x61.toByte()) {
                    certData = tryReadContainerData(tag, transceiver)
                    if (certData != null && certData.isNotEmpty()) {
                        return certData
                    }
                }
            }
            null
        } catch (_: Throwable) {
            null
        }
    }

    private fun tryReadContainerData(
        tag: ByteArray,
        transceiver: (ByteArray) -> ByteArray?
    ): ByteArray? {
        val command = ApduCommand.getData(tag)
        val rawResponse = try {
            transceiver(command.toByteArray())
        } catch (_: Throwable) {
            null
        } ?: return null

        var response = ApduResponse.fromByteArray(rawResponse)
        val accumulatedData = java.io.ByteArrayOutputStream()
        accumulatedData.write(response.data)

        var maxGetRespRetries = 20
        while (response.sw1 == 0x61.toByte() && maxGetRespRetries-- > 0) {
            val le = response.sw2.toInt() and 0xFF
            val getRespCmd = ApduCommand(
                cla = 0x00.toByte(),
                ins = 0xC0.toByte(),
                p1 = 0x00.toByte(),
                p2 = 0x00.toByte(),
                le = if (le == 0) 256 else le
            )
            val nextRaw = try {
                transceiver(getRespCmd.toByteArray())
            } catch (_: Throwable) {
                null
            } ?: break

            response = ApduResponse.fromByteArray(nextRaw)
            accumulatedData.write(response.data)
        }

        val fullData = accumulatedData.toByteArray()
        if (fullData.isEmpty()) return null

        return extractCertificateFromTlv(fullData)
    }

    fun signChallenge(
        challenge: ByteArray,
        algorithmId: Byte = Algorithm.RSA_2048,
        keyRef: Byte = KeyReference.PIV_AUTHENTICATION,
        transceiver: (ByteArray) -> ByteArray?
    ): ByteArray? {
        return try {
            val isEmailCertKey = keyRef == KeyReference.EMAIL_SIGNING ||
                    keyRef == KeyReference.KEY_MANAGEMENT ||
                    keyRef == 0x82.toByte() ||
                    keyRef == 0x9D.toByte()

            data class AppletTrySpec(val aid: ByteArray, val keyRefs: List<Byte>)

            val appletSequence = if (isEmailCertKey) {
                listOf(
                    AppletTrySpec(
                        ApduCommand.PIV_AID,
                        listOf(KeyReference.EMAIL_SIGNING, KeyReference.PIV_AUTHENTICATION, KeyReference.DIGITAL_SIGNATURE, KeyReference.PIV_APPLICATION_PIN)
                    ),
                    AppletTrySpec(
                        ApduCommand.CAC_PKI_AID,
                        listOf(KeyReference.EMAIL_SIGNING, KeyReference.PIV_APPLICATION_PIN)
                    ),
                    AppletTrySpec(
                        ApduCommand.CAC_EMAIL_AID,
                        listOf(KeyReference.EMAIL_SIGNING, KeyReference.PIV_APPLICATION_PIN)
                    )
                )
            } else {
                val keyRefSeq = listOf(
                    keyRef,
                    KeyReference.EMAIL_SIGNING,        // 0x82
                    KeyReference.PIV_AUTHENTICATION,   // 0x9A
                    KeyReference.DIGITAL_SIGNATURE,    // 0x9C
                    KeyReference.PIV_APPLICATION_PIN, // 0x80
                    KeyReference.LOCAL_PIN,             // 0x81
                    KeyReference.GLOBAL_PIN             // 0x00
                ).distinct()
                listOf(
                    AppletTrySpec(ApduCommand.PIV_AID, keyRefSeq),
                    AppletTrySpec(ApduCommand.CAC_PKI_AID, listOf(keyRef, KeyReference.PIV_APPLICATION_PIN).distinct()),
                    AppletTrySpec(ApduCommand.CAC_EMAIL_AID, listOf(keyRef, KeyReference.PIV_APPLICATION_PIN).distinct())
                )
            }

            fun transceiveWithGetResponse(cmd: ApduCommand): ApduResponse? {
                val cmdBytes = cmd.toByteArray()
                android.util.Log.i("PivAppletHandler", "APDU TX: ${cmdBytes.toHexString()}")
                val raw = try {
                    transceiver(cmdBytes)
                } catch (e: Throwable) {
                    android.util.Log.e("PivAppletHandler", "APDU TX Error: ${e.message}")
                    null
                } ?: return null

                var response = ApduResponse.fromByteArray(raw)
                android.util.Log.i("PivAppletHandler", "APDU RX SW: ${response.statusWordToHex()} (${response.statusWordMeaning})")

                val accumulatedData = java.io.ByteArrayOutputStream()
                accumulatedData.write(response.data)

                var maxGetRespRetries = 20
                while (response.sw1 == 0x61.toByte() && maxGetRespRetries-- > 0) {
                    val le = response.sw2.toInt() and 0xFF
                    val getRespCmd = ApduCommand(
                        cla = 0x00.toByte(),
                        ins = 0xC0.toByte(),
                        p1 = 0x00.toByte(),
                        p2 = 0x00.toByte(),
                        le = if (le == 0) 256 else le
                    )
                    val getRespBytes = getRespCmd.toByteArray()
                    android.util.Log.i("PivAppletHandler", "APDU TX (GET RESPONSE): ${getRespBytes.toHexString()}")
                    val nextRaw = try {
                        transceiver(getRespBytes)
                    } catch (_: Throwable) {
                        null
                    } ?: break

                    response = ApduResponse.fromByteArray(nextRaw)
                    android.util.Log.i("PivAppletHandler", "APDU RX (GET RESPONSE) SW: ${response.statusWordToHex()}")
                    accumulatedData.write(response.data)
                }

                return ApduResponse(accumulatedData.toByteArray(), response.sw1, response.sw2)
            }

            val algSequence = listOf(algorithmId, 0x00.toByte()).distinct()

            for (spec in appletSequence) {
                val selectResp = selectPivApplet(targetAid = spec.aid, transceiver = transceiver)
                if (!selectResp.isSuccess && selectResp.sw1 != 0x61.toByte()) {
                    continue
                }

                for (kr in spec.keyRefs) {
                    for (alg in algSequence) {
                        val genAuthCmd = ApduCommand.generalAuthenticate(alg, kr, challenge)
                        android.util.Log.i("PivAppletHandler", "Sending GENERAL AUTHENTICATE: AID=${spec.aid.toHexString()} CLA=00 INS=87 P1=${String.format("%02X", alg)} P2=${String.format("%02X", kr)}")
                        val response = transceiveWithGetResponse(genAuthCmd)
                        if (response != null && response.isSuccess) {
                            android.util.Log.i("PivAppletHandler", "GENERAL AUTHENTICATE SUCCESS for AID=${spec.aid.toHexString()} KeyRef=0x${String.format("%02X", kr)} Alg=0x${String.format("%02X", alg)}")
                            val sig = extractSignatureFromTlv(response.data)
                            val raw = if (sig.isNotEmpty()) sig else response.data
                            val formatted = formatRsaSignatureToExactSize(raw, 256)
                            if (formatted.isNotEmpty()) return formatted
                        }
                    }
                }

                for (kr in spec.keyRefs) {
                    val intAuthCmd = ApduCommand.internalAuthenticate(kr, challenge)
                    android.util.Log.i("PivAppletHandler", "Sending INTERNAL AUTHENTICATE fallback: AID=${spec.aid.toHexString()} CLA=00 INS=88 P1=00 P2=${String.format("%02X", kr)}")
                    val response = transceiveWithGetResponse(intAuthCmd)
                    if (response != null && response.isSuccess) {
                        android.util.Log.i("PivAppletHandler", "INTERNAL AUTHENTICATE SUCCESS for AID=${spec.aid.toHexString()} KeyRef=0x${String.format("%02X", kr)}")
                        val sig = extractSignatureFromTlv(response.data)
                        val raw = if (sig.isNotEmpty()) sig else response.data
                        val formatted = formatRsaSignatureToExactSize(raw, 256)
                        if (formatted.isNotEmpty()) return formatted
                    }
                }
            }

            null
        } catch (e: Throwable) {
            android.util.Log.e("PivAppletHandler", "Error in signChallenge", e)
            null
        }
    }

    /**
     * Helper to extract DER X.509 Certificate bytes from PIV BER-TLV payload.
     */
    private fun extractCertificateFromTlv(tlvData: ByteArray?): ByteArray {
        return extractX509FromContainer(tlvData)
    }

    /**
     * Helper to extract signature bytes from GENERAL AUTHENTICATE response TLV (Tag 7C -> Tag 82).
     */
    private fun extractSignatureFromTlv(tlvData: ByteArray?): ByteArray {
        if (tlvData == null || tlvData.isEmpty()) return byteArrayOf()
        return try {
            var index = 0
            if (tlvData[0] == 0x7C.toByte()) {
                index = 1
                if (index < tlvData.size) {
                    val lenByte = tlvData[index].toInt() and 0xFF
                    index++
                    if (lenByte == 0x81 && index < tlvData.size) {
                        index++
                    } else if (lenByte == 0x82 && index + 1 < tlvData.size) {
                        index += 2
                    } else if (lenByte == 0x83 && index + 2 < tlvData.size) {
                        index += 3
                    }
                }
            }

            while (index < tlvData.size - 1) {
                if (tlvData[index] == 0x82.toByte()) {
                    val lenByte = tlvData[index + 1].toInt() and 0xFF
                    var dataOffset = index + 2
                    var sigLength = lenByte
                    if (lenByte == 0x81 && index + 2 < tlvData.size) {
                        sigLength = tlvData[index + 2].toInt() and 0xFF
                        dataOffset = index + 3
                    } else if (lenByte == 0x82 && index + 3 < tlvData.size) {
                        sigLength = ((tlvData[index + 2].toInt() and 0xFF) shl 8) or (tlvData[index + 3].toInt() and 0xFF)
                        dataOffset = index + 4
                    }
                    if (dataOffset >= 0 && sigLength > 0 && dataOffset + sigLength <= tlvData.size) {
                        return tlvData.copyOfRange(dataOffset, dataOffset + sigLength)
                    }
                }
                index++
            }
            if (tlvData.size == 256 || tlvData.size == 128 || tlvData.size == 384 || tlvData.size == 512) {
                tlvData
            } else {
                tlvData
            }
        } catch (_: Throwable) {
            tlvData
        }
    }

    companion object {
        fun formatRsaSignatureToExactSize(rawSignature: ByteArray?, keySizeBytes: Int = 256): ByteArray {
            if (rawSignature == null || rawSignature.isEmpty()) return byteArrayOf()

            var bytes = extractSignatureFromTlv(rawSignature)
            if (bytes.isEmpty()) bytes = rawSignature

            if (bytes.size > 2 && bytes[0] == 0x82.toByte()) {
                val lenByte = bytes[1].toInt() and 0xFF
                var offset = 2
                var len = lenByte
                if (lenByte == 0x81 && bytes.size > 2) {
                    len = bytes[2].toInt() and 0xFF
                    offset = 3
                } else if (lenByte == 0x82 && bytes.size > 3) {
                    len = ((bytes[2].toInt() and 0xFF) shl 8) or (bytes[3].toInt() and 0xFF)
                    offset = 4
                }
                if (len > 0 && offset + len <= bytes.size) {
                    bytes = bytes.copyOfRange(offset, offset + len)
                }
            }

            if (bytes.size == keySizeBytes) {
                return bytes
            }

            if (bytes.size > keySizeBytes) {
                var offset = 0
                while (offset < bytes.size - keySizeBytes && bytes[offset] == 0x00.toByte()) {
                    offset++
                }
                if (bytes.size - offset == keySizeBytes) {
                    return bytes.copyOfRange(offset, offset + keySizeBytes)
                }
                return bytes.copyOfRange(bytes.size - keySizeBytes, bytes.size)
            }

            val padded = ByteArray(keySizeBytes)
            System.arraycopy(bytes, 0, padded, keySizeBytes - bytes.size, bytes.size)
            return padded
        }

        private fun extractSignatureFromTlv(tlvData: ByteArray?): ByteArray {
            if (tlvData == null || tlvData.isEmpty()) return byteArrayOf()
            return try {
                var index = 0
                if (tlvData[0] == 0x7C.toByte()) {
                    index = 1
                    if (index < tlvData.size) {
                        val lenByte = tlvData[index].toInt() and 0xFF
                        index++
                        if (lenByte == 0x81 && index < tlvData.size) {
                            index++
                        } else if (lenByte == 0x82 && index + 1 < tlvData.size) {
                            index += 2
                        } else if (lenByte == 0x83 && index + 2 < tlvData.size) {
                            index += 3
                        }
                    }
                }

                while (index < tlvData.size - 1) {
                    if (tlvData[index] == 0x82.toByte()) {
                        val lenByte = tlvData[index + 1].toInt() and 0xFF
                        var dataOffset = index + 2
                        var sigLength = lenByte
                        if (lenByte == 0x81 && index + 2 < tlvData.size) {
                            sigLength = tlvData[index + 2].toInt() and 0xFF
                            dataOffset = index + 3
                        } else if (lenByte == 0x82 && index + 3 < tlvData.size) {
                            sigLength = ((tlvData[index + 2].toInt() and 0xFF) shl 8) or (tlvData[index + 3].toInt() and 0xFF)
                            dataOffset = index + 4
                        }
                        if (dataOffset >= 0 && sigLength > 0 && dataOffset + sigLength <= tlvData.size) {
                            return tlvData.copyOfRange(dataOffset, dataOffset + sigLength)
                        }
                    }
                    index++
                }
                tlvData
            } catch (_: Throwable) {
                tlvData
            }
        }
        /**
         * Extracts and decompresses DER X.509 Certificate bytes from NIST SP 800-73-4 / CAC BER-TLV container payload.
         * Handles:
         * - Tag 70 / 53 container structure
         * - Tag 71 Certificate Value extraction
         * - Tag 72 CertInfo compression flag (0x00 = uncompressed, 0x01 = GZIP compressed)
         * - GZIP magic header 0x1F, 0x8B decompression
         * - Finding raw DER X.509 sequence start (Tag 0x30)
         */
        fun extractX509FromContainer(containerData: ByteArray?): ByteArray {
            if (containerData == null || containerData.isEmpty()) return byteArrayOf()

            var certBytes = containerData
            var isGzipCompressed = false
            var tag71Value: ByteArray? = null

            try {
                var index = 0
                while (index < containerData.size) {
                    val tag = containerData[index].toInt() and 0xFF
                    index++
                    if (index >= containerData.size) break

                    // Read BER-TLV length
                    var len = containerData[index].toInt() and 0xFF
                    index++
                    if (len == 0x81) {
                        if (index >= containerData.size) break
                        len = containerData[index].toInt() and 0xFF
                        index++
                    } else if (len == 0x82) {
                        if (index + 1 >= containerData.size) break
                        len = ((containerData[index].toInt() and 0xFF) shl 8) or (containerData[index + 1].toInt() and 0xFF)
                        index += 2
                    } else if (len == 0x83) {
                        if (index + 2 >= containerData.size) break
                        len = ((containerData[index].toInt() and 0xFF) shl 16) or
                                ((containerData[index + 1].toInt() and 0xFF) shl 8) or
                                (containerData[index + 2].toInt() and 0xFF)
                        index += 3
                    }

                    if (tag == 0x70 || tag == 0x53) {
                        // Container wrapper tag 70 or 53 - continue parsing inner TLVs inside tag 70
                        continue
                    } else if (tag == 0x71) {
                        // Tag 71: Certificate Value
                        if (index >= 0 && len > 0 && index + len <= containerData.size) {
                            tag71Value = containerData.copyOfRange(index, index + len)
                        }
                        index += len
                    } else if (tag == 0x72) {
                        // Tag 72: CertInfo (00 = uncompressed, 01 = gzip compressed)
                        if (index < containerData.size && containerData[index] == 0x01.toByte()) {
                            isGzipCompressed = true
                        }
                        index += len
                    } else {
                        index += len
                    }
                }
            } catch (_: Throwable) {
                // Ignore TLV parse errors and fall back to scanning containerData directly
            }

            if (tag71Value != null) {
                certBytes = tag71Value
            }

            // Check for GZIP magic header (0x1F, 0x8B) safely with array bounds check (certBytes.size >= 2)
            if (certBytes.size >= 2 && certBytes[0] == 0x1F.toByte() && (certBytes[1].toInt() and 0xFF) == 0x8B) {
                isGzipCompressed = true
            }

            if (isGzipCompressed && certBytes.isNotEmpty()) {
                try {
                    java.util.zip.GZIPInputStream(java.io.ByteArrayInputStream(certBytes)).use { gzip ->
                        val bos = java.io.ByteArrayOutputStream()
                        val buffer = ByteArray(1024)
                        var bytesRead: Int
                        while (gzip.read(buffer).also { bytesRead = it } != -1) {
                            bos.write(buffer, 0, bytesRead)
                        }
                        val decompressed = bos.toByteArray()
                        if (decompressed.isNotEmpty()) {
                            certBytes = decompressed
                        }
                    }
                } catch (_: Throwable) {
                    // Ignore GZIP decompression errors and use certBytes as-is
                }
            }

            // Locate DER X.509 sequence start (0x30 tag) with bounds checks
            try {
                if (certBytes.size >= 3) {
                    var derIndex = 0
                    while (derIndex <= certBytes.size - 2) {
                        if (certBytes[derIndex] == 0x30.toByte() &&
                            (certBytes[derIndex + 1] == 0x82.toByte() || certBytes[derIndex + 1] == 0x81.toByte())
                        ) {
                            return certBytes.copyOfRange(derIndex, certBytes.size)
                        }
                        derIndex++
                    }
                }
            } catch (_: Throwable) {
                // Ignore DER scan error
            }

            return certBytes
        }
    }
}
