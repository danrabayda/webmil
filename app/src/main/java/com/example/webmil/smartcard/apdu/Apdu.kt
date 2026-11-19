package com.example.webmil.smartcard.apdu

/**
 * ISO 7816-4 Command APDU representation.
 */
data class ApduCommand(
    val cla: Byte,
    val ins: Byte,
    val p1: Byte,
    val p2: Byte,
    val data: ByteArray = byteArrayOf(),
    val le: Int? = null
) {
    fun toByteArray(): ByteArray {
        val hasData = data.isNotEmpty()
        val hasLe = le != null

        val lc = data.size
        return when {
            !hasData && !hasLe -> byteArrayOf(cla, ins, p1, p2)
            !hasData && hasLe -> byteArrayOf(cla, ins, p1, p2, (le!! and 0xFF).toByte())
            hasData && !hasLe -> {
                if (lc > 255) {
                    byteArrayOf(cla, ins, p1, p2, 0x00.toByte(), (lc shr 8).toByte(), (lc and 0xFF).toByte()) + data
                } else {
                    byteArrayOf(cla, ins, p1, p2, (lc and 0xFF).toByte()) + data
                }
            }
            else -> {
                if (lc > 255) {
                    byteArrayOf(cla, ins, p1, p2, 0x00.toByte(), (lc shr 8).toByte(), (lc and 0xFF).toByte()) + data + byteArrayOf(0x00.toByte(), 0x00.toByte())
                } else {
                    byteArrayOf(cla, ins, p1, p2, (lc and 0xFF).toByte()) + data + byteArrayOf((le!! and 0xFF).toByte())
                }
            }
        }
    }

    fun toHex(): String = toByteArray().toHexString()

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as ApduCommand
        if (cla != other.cla) return false
        if (ins != other.ins) return false
        if (p1 != other.p1) return false
        if (p2 != other.p2) return false
        if (!data.contentEquals(other.data)) return false
        if (le != other.le) return false
        return true
    }

    override fun hashCode(): Int {
        var result = cla.toInt()
        result = 31 * result + ins.toInt()
        result = 31 * result + p1.toInt()
        result = 31 * result + p2.toInt()
        result = 31 * result + data.contentHashCode()
        result = 31 * result + (le ?: 0)
        return result
    }

    companion object {
        val PIV_AID = byteArrayOf(
            0xA0.toByte(), 0x00.toByte(), 0x00.toByte(), 0x03.toByte(),
            0x08.toByte(), 0x00.toByte(), 0x00.toByte(), 0x01.toByte(), 0x00.toByte()
        )

        val CAC_PKI_AID = byteArrayOf(
            0xA0.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(),
            0x79.toByte(), 0x01.toByte(), 0x05.toByte()
        )

        val CAC_EMAIL_AID = byteArrayOf(
            0xA0.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(),
            0x79.toByte(), 0x01.toByte(), 0x02.toByte()
        )

        val CAC_IDENTITY_AID = byteArrayOf(
            0xA0.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(),
            0x79.toByte(), 0x01.toByte(), 0x01.toByte()
        )

        val CAC_KEY_MGMT_AID = byteArrayOf(
            0xA0.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(),
            0x79.toByte(), 0x01.toByte(), 0x03.toByte()
        )

        val NIST_PIV_UNIVERSAL_AID = byteArrayOf(
            0xA0.toByte(), 0x00.toByte(), 0x00.toByte(), 0x03.toByte(),
            0x08.toByte(), 0x00.toByte(), 0x00.toByte(), 0x10.toByte(), 0x00.toByte()
        )

        val CAC_AID_1 = CAC_PKI_AID

        val CAC_AID_2 = byteArrayOf(
            0xA0.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(),
            0x79.toByte(), 0x01.toByte()
        )

        val CAC_AID_3 = byteArrayOf(
            0xA0.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(),
            0x79.toByte(), 0x02.toByte()
        )

        fun selectApplet(aid: ByteArray, p2: Byte = 0x00.toByte()): ApduCommand {
            return ApduCommand(
                cla = 0x00.toByte(),
                ins = 0xA4.toByte(),
                p1 = 0x04.toByte(),
                p2 = p2,
                data = aid
            )
        }

        fun verifyPin(pin: String, keyReference: Byte = 0x80.toByte()): ApduCommand {
            val pinBytes = pin.toByteArray(Charsets.US_ASCII)
            val paddedPin = ByteArray(8) { 0xFF.toByte() }
            val len = pinBytes.size.coerceAtMost(8)
            System.arraycopy(pinBytes, 0, paddedPin, 0, len)

            return ApduCommand(
                cla = 0x00.toByte(),
                ins = 0x20.toByte(),
                p1 = 0x00.toByte(),
                p2 = keyReference,
                data = paddedPin
            )
        }

        fun getData(containerTag: ByteArray): ApduCommand {
            val tlvData = byteArrayOf(0x5C.toByte(), containerTag.size.toByte()) + containerTag
            return ApduCommand(
                cla = 0x00.toByte(),
                ins = 0xCB.toByte(),
                p1 = 0x3F.toByte(),
                p2 = 0xFF.toByte(),
                data = tlvData
            )
        }

        fun generalAuthenticate(
            algorithmId: Byte = 0x07.toByte(),
            keyReference: Byte = 0x9A.toByte(),
            challenge: ByteArray
        ): ApduCommand {
            // Dynamic Authentication Template Tag 7C with BER-TLV length encoding:
            // Tag 82 00: Response challenge request (must come FIRST)
            // Tag 81: Challenge payload (256 bytes for RSA 2048)
            val responsePlaceholder = byteArrayOf(0x82.toByte(), 0x00.toByte())
            val challengeTlv = byteArrayOf(0x81.toByte()) + encodeBerTlvLength(challenge.size) + challenge
            val templatePayload = responsePlaceholder + challengeTlv
            val templateTlv = byteArrayOf(0x7C.toByte()) + encodeBerTlvLength(templatePayload.size) + templatePayload

            return ApduCommand(
                cla = 0x00.toByte(),
                ins = 0x87.toByte(),
                p1 = algorithmId,
                p2 = keyReference,
                data = templateTlv,
                le = 0
            )
        }

        private fun encodeBerTlvLength(length: Int): ByteArray {
            return if (length < 128) {
                byteArrayOf(length.toByte())
            } else if (length <= 255) {
                byteArrayOf(0x81.toByte(), length.toByte())
            } else {
                byteArrayOf(0x82.toByte(), (length shr 8).toByte(), (length and 0xFF).toByte())
            }
        }

        fun internalAuthenticate(
            keyReference: Byte = 0x9A.toByte(),
            challenge: ByteArray
        ): ApduCommand {
            return ApduCommand(
                cla = 0x00.toByte(),
                ins = 0x88.toByte(),
                p1 = 0x00.toByte(),
                p2 = keyReference,
                data = challenge
            )
        }
    }
}

/**
 * ISO 7816-4 Response APDU representation.
 */
data class ApduResponse(
    val data: ByteArray,
    val sw1: Byte,
    val sw2: Byte
) {
    val statusWord: Int get() = ((sw1.toInt() and 0xFF) shl 8) or (sw2.toInt() and 0xFF)

    val isSuccess: Boolean get() = statusWord == 0x9000 || sw1 == 0x61.toByte()

    val isPinFailed: Boolean get() = sw1 == 0x63.toByte() && (sw2.toInt() and 0xF0) == 0xC0

    val attemptsRemaining: Int get() = if (isPinFailed) (sw2.toInt() and 0x0F) else -1

    val isCardLocked: Boolean get() = statusWord == 0x6983 || (isPinFailed && attemptsRemaining == 0)

    val statusWordMeaning: String
        get() {
            val sw = statusWord
            if (sw == 0x9000) return "Success (OK)"
            if (isPinFailed) return "Verification failed ($attemptsRemaining attempts left)"
            return when (sw) {
                0x6300, 0x63C0 -> "Verification failed (0 attempts remaining - Card Locked)"
                0x6700 -> "Wrong length / Lc incorrect"
                0x6881 -> "Logical channel not supported"
                0x6882 -> "Secure messaging not supported"
                0x6982 -> "Security status not satisfied"
                0x6983 -> "Authentication method blocked / Card locked"
                0x6985 -> "Conditions of use not satisfied"
                0x6986 -> "Command not allowed"
                0x6A80 -> "Incorrect parameters in command data field"
                0x6A81 -> "Function not supported"
                0x6A82 -> "File or application not found"
                0x6A86 -> "Incorrect parameters P1-P2"
                0x6A88 -> "Referenced data or key reference not found"
                0x6D00 -> "Instruction (INS) not supported or applet not selected"
                0x6E00 -> "Class (CLA) not supported"
                0x6F00 -> "Technical error / Unknown diagnosis"
                else -> if ((sw and 0xFF00) == 0x6100) "Bytes available (${sw and 0xFF})" else "SW 0x${String.format("%04X", sw)}"
            }
        }

    fun statusWordToHex(): String = String.format("%02X %02X", sw1, sw2)

    fun toHex(): String {
        val dataHex = if (data.isNotEmpty()) data.toHexString() + " " else ""
        return dataHex + statusWordToHex()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as ApduResponse
        if (!data.contentEquals(other.data)) return false
        if (sw1 != other.sw1) return false
        if (sw2 != other.sw2) return false
        return true
    }

    override fun hashCode(): Int {
        var result = data.contentHashCode()
        result = 31 * result + sw1.toInt()
        result = 31 * result + sw2.toInt()
        return result
    }

    companion object {
        val SUCCESS = ApduResponse(byteArrayOf(), 0x90.toByte(), 0x00.toByte())

        fun fromByteArray(bytes: ByteArray?): ApduResponse {
            if (bytes == null || bytes.size < 2) {
                return ApduResponse(byteArrayOf(), 0x6F.toByte(), 0x00.toByte())
            }
            return try {
                val data = bytes.copyOfRange(0, bytes.size - 2)
                val sw1 = bytes[bytes.size - 2]
                val sw2 = bytes[bytes.size - 1]
                ApduResponse(data, sw1, sw2)
            } catch (_: Throwable) {
                ApduResponse(byteArrayOf(), 0x6F.toByte(), 0x00.toByte())
            }
        }

        fun pinFailed(attemptsLeft: Int): ApduResponse {
            val sw2 = (0xC0 or (attemptsLeft and 0x0F)).toByte()
            return ApduResponse(byteArrayOf(), 0x63.toByte(), sw2)
        }

        fun cardLocked(): ApduResponse {
            return ApduResponse(byteArrayOf(), 0x69.toByte(), 0x83.toByte())
        }
    }
}

fun ByteArray.toHexString(): String {
    return joinToString(" ") { String.format("%02X", it) }
}

fun String.hexToByteArray(): ByteArray {
    val clean = this.replace(" ", "").replace("\n", "").replace("\r", "")
    if (clean.isEmpty()) return byteArrayOf()
    val result = ByteArray(clean.length / 2)
    for (i in result.indices) {
        val index = i * 2
        result[i] = clean.substring(index, index + 2).toInt(16).toByte()
    }
    return result
}
