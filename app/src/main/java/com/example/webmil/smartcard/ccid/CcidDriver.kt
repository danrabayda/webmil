package com.example.webmil.smartcard.ccid

import android.hardware.usb.UsbConstants
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbDeviceConnection
import android.hardware.usb.UsbEndpoint
import android.hardware.usb.UsbInterface
import android.hardware.usb.UsbManager
import android.util.Log
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Driver for USB CCID (Chip Card Interface Device) Smart Card Readers using Android USB Host API.
 */
class CcidDriver {

    private var connection: UsbDeviceConnection? = null
    private var ccidInterface: UsbInterface? = null
    private var bulkOutEndpoint: UsbEndpoint? = null
    private var bulkInEndpoint: UsbEndpoint? = null
    private var sequenceNumber: Byte = 0

    var isConnected: Boolean = false
        private set

    fun open(usbManager: UsbManager?, device: UsbDevice?): Boolean {
        return try {
            close()

            if (usbManager == null || device == null) {
                safeLogE(TAG, "Cannot open CCID connection: UsbManager or UsbDevice is null")
                return false
            }

            var targetInterface: UsbInterface? = null
            var outEp: UsbEndpoint? = null
            var inEp: UsbEndpoint? = null

            // Search device interfaces for a valid CCID or bulk-endpoint interface
            val ifaceCount = device.interfaceCount
            for (i in 0 until ifaceCount) {
                val iface = try { device.getInterface(i) } catch (_: Throwable) { null } ?: continue
                var tempOut: UsbEndpoint? = null
                var tempIn: UsbEndpoint? = null

                val epCount = iface.endpointCount
                for (j in 0 until epCount) {
                    val ep = try { iface.getEndpoint(j) } catch (_: Throwable) { null } ?: continue
                    if (ep.type == UsbConstants.USB_ENDPOINT_XFER_BULK) {
                        if (ep.direction == UsbConstants.USB_DIR_OUT) {
                            tempOut = ep
                        } else if (ep.direction == UsbConstants.USB_DIR_IN) {
                            tempIn = ep
                        }
                    }
                }

                if (tempOut != null && tempIn != null) {
                    if (iface.interfaceClass == USB_CLASS_CCID || device.deviceClass == USB_CLASS_CCID || targetInterface == null) {
                        targetInterface = iface
                        outEp = tempOut
                        inEp = tempIn
                        if (iface.interfaceClass == USB_CLASS_CCID) break // Prefer standard CCID class match
                    }
                }
            }

            if (targetInterface == null || outEp == null || inEp == null) {
                safeLogE(TAG, "Could not find suitable CCID USB interface or Bulk endpoints on device ${device.deviceName}")
                return false
            }

            val conn = try { usbManager.openDevice(device) } catch (e: Throwable) {
                safeLogE(TAG, "Exception opening UsbDeviceConnection", e)
                null
            }
            if (conn == null) {
                safeLogE(TAG, "Failed to open UsbDeviceConnection")
                return false
            }

            val claimed = try { conn.claimInterface(targetInterface, true) } catch (e: Throwable) {
                safeLogE(TAG, "Exception claiming UsbInterface", e)
                false
            }

            if (!claimed) {
                safeLogE(TAG, "Failed to claim UsbInterface")
                try { conn.close() } catch (_: Throwable) {}
                return false
            }

            this.connection = conn
            this.ccidInterface = targetInterface
            this.bulkOutEndpoint = outEp
            this.bulkInEndpoint = inEp
            this.sequenceNumber = 0
            this.isConnected = true

            safeLogI(TAG, "CCID Reader successfully connected: ${device.deviceName}")
            true
        } catch (e: Throwable) {
            safeLogE(TAG, "Error opening CCID driver connection", e)
            close()
            false
        }
    }

    fun close() {
        try {
            connection?.let { conn ->
                ccidInterface?.let { iface ->
                    try { conn.releaseInterface(iface) } catch (_: Throwable) {}
                }
                try { conn.close() } catch (_: Throwable) {}
            }
        } catch (e: Throwable) {
            safeLogW(TAG, "Error closing connection", e)
        } finally {
            connection = null
            ccidInterface = null
            bulkOutEndpoint = null
            bulkInEndpoint = null
            isConnected = false
        }
    }

    /**
     * Sends PC_to_RDR_IccPowerOn (0x62) to power up smart card and retrieve ATR.
     */
    @Synchronized
    fun powerOn(): ByteArray? {
        return try {
            if (!isConnected || connection == null) return null
            val seq = getNextSequence()
            val header = buildCcidHeader(
                messageType = PC_TO_RDR_ICC_POWER_ON,
                paramLength = 0,
                slot = 0,
                seq = seq,
                bBWI = 0x00, // Auto power selection 5V/3V
                wLevelParameter = 0
            )

            val response = sendAndReceive(header, expectedSeq = seq) ?: return null
            extractPayload(response, RDR_TO_PC_DATA_BLOCK)
        } catch (e: Throwable) {
            safeLogE(TAG, "Error in powerOn()", e)
            null
        }
    }

    /**
     * Sends PC_to_RDR_IccPowerOff (0x63).
     */
    @Synchronized
    fun powerOff(): Boolean {
        return try {
            if (!isConnected || connection == null) return false
            val seq = getNextSequence()
            val header = buildCcidHeader(
                messageType = PC_TO_RDR_ICC_POWER_OFF,
                paramLength = 0,
                slot = 0,
                seq = seq,
                bBWI = 0x00,
                wLevelParameter = 0
            )

            val response = sendAndReceive(header, expectedSeq = seq)
            response != null
        } catch (e: Throwable) {
            safeLogE(TAG, "Error in powerOff()", e)
            false
        }
    }

    /**
     * Transceives an APDU command block via PC_to_RDR_XfrBlock (0x6F).
     */
    @Synchronized
    fun transceive(apdu: ByteArray?): ByteArray? {
        return try {
            if (apdu == null || apdu.isEmpty() || !isConnected || connection == null) return null
            val seq = getNextSequence()
            val header = buildCcidHeader(
                messageType = PC_TO_RDR_XFR_BLOCK,
                paramLength = apdu.size,
                slot = 0,
                seq = seq,
                bBWI = 0x00,
                wLevelParameter = 0
            )

            val requestPayload = header + apdu
            val response = sendAndReceive(requestPayload, expectedSeq = seq) ?: return null
            extractPayload(response, RDR_TO_PC_DATA_BLOCK)
        } catch (e: Throwable) {
            safeLogE(TAG, "Error in transceive()", e)
            null
        }
    }

    private fun sendAndReceive(request: ByteArray?, expectedSeq: Byte): ByteArray? {
        return try {
            if (request == null || request.isEmpty()) return null
            val conn = connection ?: return null
            val outEp = bulkOutEndpoint ?: return null
            val inEp = bulkInEndpoint ?: return null

            val sent = try {
                conn.bulkTransfer(outEp, request, request.size, TIMEOUT_MS)
            } catch (e: Throwable) {
                safeLogE(TAG, "Exception during USB bulkTransfer OUT", e)
                -1
            }

            if (sent < request.size) {
                safeLogE(TAG, "Bulk transfer OUT failed ($sent / ${request.size} bytes sent)")
                return null
            }

            val maxRetries = 3
            var retryCount = 0

            while (retryCount < maxRetries) {
                val responseBuffer = ByteArray(4096)
                var totalRead = try {
                    conn.bulkTransfer(inEp, responseBuffer, responseBuffer.size, TIMEOUT_MS)
                } catch (e: Throwable) {
                    safeLogE(TAG, "Exception during USB bulkTransfer IN", e)
                    -1
                }

                if (totalRead < 10) {
                    safeLogE(TAG, "Bulk transfer IN failed (read $totalRead bytes, expected >= 10 header bytes)")
                    return null
                }

                val respSeq = responseBuffer[6]
                if (respSeq != expectedSeq) {
                    safeLogW(TAG, "CCID Sequence mismatch: received $respSeq, expected $expectedSeq. Retrying read...")
                    retryCount++
                    continue
                }

                val dwLength = ((responseBuffer[1].toInt() and 0xFF)) or
                        ((responseBuffer[2].toInt() and 0xFF) shl 8) or
                        ((responseBuffer[3].toInt() and 0xFF) shl 16) or
                        ((responseBuffer[4].toInt() and 0xFF) shl 24)

                if (dwLength < 0 || dwLength > 65536) {
                    safeLogE(TAG, "Invalid CCID dwLength: $dwLength")
                    return null
                }

                val totalExpected = 10 + dwLength

                val startTime = System.currentTimeMillis()
                while (totalRead < totalExpected && totalRead < responseBuffer.size && (System.currentTimeMillis() - startTime) < TIMEOUT_MS) {
                    val chunkSize = minOf(responseBuffer.size - totalRead, 512)
                    if (chunkSize <= 0) break
                    val tempBuf = ByteArray(chunkSize)
                    val read = try {
                        conn.bulkTransfer(inEp, tempBuf, tempBuf.size, 1000)
                    } catch (_: Throwable) {
                        -1
                    }
                    if (read > 0 && totalRead + read <= responseBuffer.size) {
                        System.arraycopy(tempBuf, 0, responseBuffer, totalRead, read)
                        totalRead += read
                    } else {
                        break
                    }
                }

                val status = responseBuffer[7].toInt() and 0xFF
                val cmdStatus = status and 0x03

                // CCID Time Extension Request (bmCommandStatus = 2)
                if (cmdStatus == 0x02) {
                    val bBWT = responseBuffer[8].toInt() and 0xFF
                    safeLogD(TAG, "CCID Time Extension requested (bBWT multiplier: $bBWT). Reading follow-up response...")
                    retryCount++
                    continue
                }

                return if (totalRead >= 10 && totalRead <= responseBuffer.size) {
                    responseBuffer.copyOfRange(0, totalRead)
                } else null
            }

            safeLogE(TAG, "CCID sendAndReceive failed after $maxRetries retries")
            null
        } catch (e: Throwable) {
            safeLogE(TAG, "Error in sendAndReceive()", e)
            null
        }
    }

    private fun buildCcidHeader(
        messageType: Byte,
        paramLength: Int,
        slot: Byte,
        seq: Byte,
        bBWI: Byte,
        wLevelParameter: Short
    ): ByteArray {
        val buffer = ByteBuffer.allocate(10).order(ByteOrder.LITTLE_ENDIAN)
        buffer.put(messageType)
        buffer.putInt(paramLength)
        buffer.put(slot)
        buffer.put(seq)
        buffer.put(bBWI)
        buffer.putShort(wLevelParameter)
        return buffer.array()
    }

    private fun extractPayload(response: ByteArray?, expectedMessageType: Byte): ByteArray? {
        if (response == null || response.size < 10) return null
        return try {
            val buffer = ByteBuffer.wrap(response).order(ByteOrder.LITTLE_ENDIAN)
            val msgType = buffer.get()
            val dwLength = buffer.int
            val slot = buffer.get()
            val seq = buffer.get()
            val status = buffer.get().toInt() and 0xFF
            val error = buffer.get().toInt() and 0xFF
            val chain = buffer.get()

            if (msgType != expectedMessageType) {
                safeLogW(TAG, "Unexpected CCID response msgType: 0x${String.format("%02X", msgType)}")
            }

            val cmdStatus = status and 0x03
            val iccStatus = (status and 0xC0) ushr 6

            if (iccStatus == 2) {
                safeLogW(TAG, "CCID: No smart card present in reader slot (bmICCStatus = 2)")
                return null
            }

            if (cmdStatus == 1) {
                safeLogE(TAG, "CCID Command Error: bStatus=0x${String.format("%02X", status)}, bError=0x${String.format("%02X", error)}")
                if (dwLength == 0) return null
            }

            val payloadSize = dwLength.coerceAtMost(response.size - 10)
            if (payloadSize <= 0) return null

            if (10 + payloadSize <= response.size) {
                val payload = ByteArray(payloadSize)
                buffer.position(10)
                buffer.get(payload, 0, payloadSize)
                payload
            } else {
                null
            }
        } catch (e: Throwable) {
            safeLogE(TAG, "Error in extractPayload()", e)
            null
        }
    }

    @Synchronized
    private fun getNextSequence(): Byte {
        val current = sequenceNumber
        sequenceNumber = ((sequenceNumber + 1) and 0xFF).toByte()
        return current
    }

    private fun safeLogE(tag: String, msg: String, tr: Throwable? = null) {
        try {
            if (tr != null) Log.e(tag, msg, tr) else Log.e(tag, msg)
        } catch (_: Throwable) {}
    }

    private fun safeLogI(tag: String, msg: String) {
        try { Log.i(tag, msg) } catch (_: Throwable) {}
    }

    private fun safeLogW(tag: String, msg: String, tr: Throwable? = null) {
        try {
            if (tr != null) Log.w(tag, msg, tr) else Log.w(tag, msg)
        } catch (_: Throwable) {}
    }

    private fun safeLogD(tag: String, msg: String) {
        try { Log.d(tag, msg) } catch (_: Throwable) {}
    }

    companion object {
        private const val TAG = "CcidDriver"
        const val USB_CLASS_CCID = 11 // 0x0B
        private const val TIMEOUT_MS = 5000

        const val PC_TO_RDR_ICC_POWER_ON: Byte = 0x62
        const val PC_TO_RDR_ICC_POWER_OFF: Byte = 0x63
        const val PC_TO_RDR_GET_SLOT_STATUS: Byte = 0x65
        const val PC_TO_RDR_XFR_BLOCK: Byte = 0x6F
        val RDR_TO_PC_DATA_BLOCK: Byte = 0x80.toByte()
        val RDR_TO_PC_SLOT_STATUS: Byte = 0x81.toByte()
    }
}
