package com.example.webmil.smartcard.pki

import android.content.Context
import android.util.Log
import com.example.webmil.smartcard.model.SmartCardCertificate
import com.example.webmil.smartcard.piv.PivAppletHandler
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.InvalidKeyException
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Principal
import java.security.PrivateKey
import java.security.Provider
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Security
import java.security.Signature
import java.security.SignatureException
import java.security.SignatureSpi
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import javax.crypto.Cipher
import javax.security.auth.x500.X500Principal

/**
 * Custom java.security.PrivateKey implementation backed by Smart Card ISO 7816 APDU signing or software key pair.
 * Implements RSAPrivateKey so Android TLS / Conscrypt / SSLEngine can extract public modulus and perform mTLS.
 */
class SmartCardPrivateKey(
    private val algorithmName: String = "RSA",
    private val keySizeBits: Int = 2048,
    val keyReference: Byte = PivAppletHandler.KeyReference.PIV_AUTHENTICATION,
    private val publicModulus: BigInteger? = null,
    private val signHandler: (dataToSign: ByteArray, algorithmName: String) -> ByteArray = { _, _ -> byteArrayOf() },
    val underlyingPrivateKey: PrivateKey? = null
) : PrivateKey, RSAPrivateKey {

    override fun getAlgorithm(): String = algorithmName

    override fun getFormat(): String = underlyingPrivateKey?.format ?: "PKCS#8"

    override fun getEncoded(): ByteArray? = underlyingPrivateKey?.encoded

    override fun getModulus(): BigInteger {
        if (underlyingPrivateKey is RSAPrivateKey) {
            val mod = underlyingPrivateKey.modulus
            if (mod != null && mod != BigInteger.ZERO) return mod
        }
        return publicModulus ?: BigInteger.ZERO
    }

    override fun getPrivateExponent(): BigInteger {
        if (underlyingPrivateKey is RSAPrivateKey) {
            val exp = underlyingPrivateKey.privateExponent
            if (exp != null) return exp
        }
        return BigInteger.ZERO
    }

    @Synchronized
    fun signData(dataToSign: ByteArray, algorithm: String = "NONEwithRSA"): ByteArray {
        val keySizeBytes = (keySizeBits / 8).coerceAtLeast(256)
        val paddedPayload = SmartCardCertManager.formatPkcs1Padding(dataToSign, keySizeBytes)

        val rawSignature = underlyingPrivateKey?.let {
            try {
                val cipher = Cipher.getInstance("RSA/ECB/NoPadding")
                cipher.init(Cipher.ENCRYPT_MODE, it)
                cipher.doFinal(paddedPayload)
            } catch (_: Throwable) {
                signHandler(paddedPayload, algorithm)
            }
        } ?: signHandler(paddedPayload, algorithm)

        if (rawSignature.isEmpty()) {
            return byteArrayOf()
        }

        return PivAppletHandler.formatRsaSignatureToExactSize(rawSignature, keySizeBytes)
    }

    override fun toString(): String {
        return "SmartCardPrivateKey(algorithm=$algorithmName, keySize=$keySizeBits, keyRef=0x${String.format("%02X", keyReference)})"
    }
}

/**
 * Security Provider for registering SmartCardPrivateKey signature engines in Java Security runtime.
 */
class SmartCardSecurityProvider : Provider(
    PROVIDER_NAME,
    1.0,
    "SmartCard PIV RSA Security Provider for Mutual TLS"
) {
    init {
        put("Signature.SHA256withRSA", SmartCardSignatureSpi::class.java.name)
        put("Signature.SHA384withRSA", SmartCardSignatureSpi::class.java.name)
        put("Signature.SHA512withRSA", SmartCardSignatureSpi::class.java.name)
        put("Signature.SHA1withRSA", SmartCardSignatureSpi::class.java.name)
        put("Signature.NONEwithRSA", SmartCardSignatureSpi::class.java.name)
        put("Signature.RSA/ECB/PKCS1Padding", SmartCardSignatureSpi::class.java.name)
        put("Signature.RSASSA-PKCS1-v1_5", SmartCardSignatureSpi::class.java.name)

        put("Alg.Alias.Signature.1.2.840.113549.1.1.11", "SHA256withRSA")
        put("Alg.Alias.Signature.1.2.840.113549.1.1.12", "SHA384withRSA")
        put("Alg.Alias.Signature.1.2.840.113549.1.1.13", "SHA512withRSA")
        put("Alg.Alias.Signature.1.2.840.113549.1.1.5", "SHA1withRSA")
        put("Alg.Alias.Signature.1.2.840.113549.1.1.1", "NONEwithRSA")
    }

    companion object {
        const val PROVIDER_NAME = "WebMilSmartCardProvider"

        fun install() {
            if (Security.getProvider(PROVIDER_NAME) == null) {
                Security.insertProviderAt(SmartCardSecurityProvider(), 1)
            }
        }
    }
}

/**
 * SignatureSpi implementation that bridges Java Security Signature calls to SmartCardPrivateKey.
 */
class SmartCardSignatureSpi : SignatureSpi() {
    private var currentKey: SmartCardPrivateKey? = null
    private val buffer = ByteArrayOutputStream()

    override fun engineInitVerify(publicKey: PublicKey?) {
        throw UnsupportedOperationException("SmartCardSignatureSpi only supports signing")
    }

    @Synchronized
    override fun engineInitSign(privateKey: PrivateKey?) {
        if (privateKey == null) {
            throw InvalidKeyException("PrivateKey cannot be null")
        }
        buffer.reset()
        if (privateKey is SmartCardPrivateKey) {
            currentKey = privateKey
            try {
                Log.i("SmartCardSignatureSpi", "engineInitSign invoked with SmartCardPrivateKey (keyRef=0x${String.format("%02X", privateKey.keyReference)})")
            } catch (_: Throwable) {}
        } else {
            val mod = (privateKey as? RSAPrivateKey)?.modulus
            val smartCardKey = SmartCardPrivateKey(
                algorithmName = privateKey.algorithm ?: "RSA",
                keySizeBits = mod?.bitLength() ?: 2048,
                keyReference = PivAppletHandler.KeyReference.PIV_AUTHENTICATION,
                publicModulus = mod,
                underlyingPrivateKey = privateKey
            )
            currentKey = smartCardKey
            try {
                Log.i("SmartCardSignatureSpi", "engineInitSign safely wrapped ${privateKey.javaClass.name} into SmartCardPrivateKey")
            } catch (_: Throwable) {}
        }
    }

    @Synchronized
    override fun engineUpdate(b: Byte) {
        buffer.write(b.toInt())
    }

    @Synchronized
    override fun engineUpdate(b: ByteArray?, off: Int, len: Int) {
        if (b != null && len > 0) {
            buffer.write(b, off, len)
        }
    }

    @Synchronized
    override fun engineSign(): ByteArray {
        val key = currentKey ?: throw SignatureException("SmartCardPrivateKey not initialized")
        val dataToSign = buffer.toByteArray()
        buffer.reset()

        try {
            Log.i("SmartCardSignatureSpi", "Conscrypt invoked engineSign() with ${dataToSign.size} bytes data to sign")
        } catch (_: Throwable) {}

        val signature = try {
            key.signData(dataToSign, "NONEwithRSA")
        } catch (e: Exception) {
            try {
                Log.e("SmartCardSignatureSpi", "Exception in key.signData during engineSign", e)
            } catch (_: Throwable) {}
            throw SignatureException("Smart card signature failed", e)
        }

        try {
            Log.i("SmartCardSignatureSpi", "engineSign() successfully generated ${signature.size} bytes RSA signature")
        } catch (_: Throwable) {}

        if (signature.isEmpty()) {
            try {
                Log.e("SmartCardSignatureSpi", "engineSign() returned empty signature array! Handshake signature validation will fail.")
            } catch (_: Throwable) {}
            throw SignatureException("Smart Card signature generation produced empty signature")
        }

        return signature
    }

    override fun engineVerify(sigBytes: ByteArray?): Boolean {
        throw UnsupportedOperationException("SmartCardSignatureSpi only supports signing")
    }

    @Deprecated("Deprecated in Java SignatureSpi")
    override fun engineSetParameter(param: String?, value: Any?) {}

    @Deprecated("Deprecated in Java SignatureSpi")
    override fun engineGetParameter(param: String?): Any? = null
}

/**
 * Handles X.509 Certificate parsing, formatting, selection, chain building, and generation for Smart Card Mutual TLS.
 */
object SmartCardCertManager {

    const val OID_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
    const val OID_SMARTCARD_LOGON = "1.3.6.1.4.1.311.20.2.2"
    const val OID_ANY_EXTENDED_KEY_USAGE = "2.5.29.37.0"

    fun getKeyRefForCertType(type: String): Byte {
        return when {
            type.contains("Digital Signature") || type.contains("9C") -> PivAppletHandler.KeyReference.DIGITAL_SIGNATURE
            type.contains("Email") || type.contains("82") -> PivAppletHandler.KeyReference.EMAIL_SIGNING
            type.contains("Encryption") || type.contains("83") -> PivAppletHandler.KeyReference.EMAIL_ENCRYPTION
            type.contains("Key Management") || type.contains("9D") -> PivAppletHandler.KeyReference.KEY_MANAGEMENT
            type.contains("Card Authentication") || type.contains("9E") -> PivAppletHandler.KeyReference.CARD_AUTHENTICATION
            else -> PivAppletHandler.KeyReference.PIV_AUTHENTICATION
        }
    }

    fun getSmartCardPrivateKey(
        cert: SmartCardCertificate?,
        signHandler: ((dataToSign: ByteArray, algorithmName: String) -> ByteArray)? = null,
        underlyingPrivateKey: PrivateKey? = null
    ): SmartCardPrivateKey {
        val keyRef = cert?.let { getKeyRefForCertType(it.certificateType) } ?: PivAppletHandler.KeyReference.PIV_AUTHENTICATION
        val x509 = cert?.x509Certificate
        val modulus = (x509?.publicKey as? RSAPublicKey)?.modulus
        val algorithm = cert?.keyAlgorithm ?: "RSA"
        val size = cert?.keySize ?: 2048

        return SmartCardPrivateKey(
            algorithmName = algorithm,
            keySizeBits = size,
            keyReference = keyRef,
            publicModulus = modulus,
            signHandler = signHandler ?: { _, _ -> byteArrayOf() },
            underlyingPrivateKey = underlyingPrivateKey
        )
    }

    private val SHA256_DIGEST_INFO_PREFIX = byteArrayOf(
        0x30.toByte(), 0x31.toByte(), 0x30.toByte(), 0x0D.toByte(),
        0x06.toByte(), 0x09.toByte(), 0x60.toByte(), 0x86.toByte(),
        0x48.toByte(), 0x01.toByte(), 0x65.toByte(), 0x03.toByte(),
        0x04.toByte(), 0x02.toByte(), 0x01.toByte(), 0x05.toByte(),
        0x00.toByte(), 0x04.toByte(), 0x20.toByte()
    )

    private val SHA384_DIGEST_INFO_PREFIX = byteArrayOf(
        0x30.toByte(), 0x41.toByte(), 0x30.toByte(), 0x0D.toByte(),
        0x06.toByte(), 0x09.toByte(), 0x60.toByte(), 0x86.toByte(),
        0x48.toByte(), 0x01.toByte(), 0x65.toByte(), 0x03.toByte(),
        0x04.toByte(), 0x02.toByte(), 0x02.toByte(), 0x05.toByte(),
        0x00.toByte(), 0x04.toByte(), 0x30.toByte()
    )

    private val SHA512_DIGEST_INFO_PREFIX = byteArrayOf(
        0x30.toByte(), 0x51.toByte(), 0x30.toByte(), 0x0D.toByte(),
        0x06.toByte(), 0x09.toByte(), 0x60.toByte(), 0x86.toByte(),
        0x48.toByte(), 0x01.toByte(), 0x65.toByte(), 0x03.toByte(),
        0x04.toByte(), 0x02.toByte(), 0x03.toByte(), 0x05.toByte(),
        0x00.toByte(), 0x04.toByte(), 0x40.toByte()
    )

    private val SHA1_DIGEST_INFO_PREFIX = byteArrayOf(
        0x30.toByte(), 0x21.toByte(), 0x30.toByte(), 0x09.toByte(),
        0x06.toByte(), 0x05.toByte(), 0x2B.toByte(), 0x0E.toByte(),
        0x03.toByte(), 0x02.toByte(), 0x1A.toByte(), 0x05.toByte(),
        0x00.toByte(), 0x04.toByte(), 0x14.toByte()
    )

    private val dateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss 'UTC'", Locale.US)
    private var loadedDodCaCerts: List<X509Certificate>? = null

    init {
        SmartCardSecurityProvider.install()
    }

    /**
     * Loads DoD Root and Intermediate CA certificates from assets/dod_ca/ (or generates built-in DoD CAs if context null).
     */
    fun loadDodCaCertificates(context: Context? = null): List<X509Certificate> {
        val existing = loadedDodCaCerts
        if (!existing.isNullOrEmpty()) return existing

        val certs = mutableListOf<X509Certificate>()
        if (context != null) {
            try {
                val assetManager = context.assets
                val files = assetManager.list("dod_ca") ?: emptyArray()
                val factory = CertificateFactory.getInstance("X.509")
                for (fileName in files) {
                    if (fileName.endsWith(".crt") || fileName.endsWith(".der") || fileName.endsWith(".pem")) {
                        assetManager.open("dod_ca/$fileName").use { inputStream ->
                            val cert = factory.generateCertificate(inputStream) as? X509Certificate
                            if (cert != null) {
                                certs.add(cert)
                            }
                        }
                    }
                }
            } catch (_: Exception) {}
        }

        if (certs.isEmpty()) {
            certs.addAll(generateBuiltInDodCaCertificates())
        }

        loadedDodCaCerts = certs
        return certs
    }

    /**
     * Constructs and appends matching DoD Intermediate CA and Root CA certificates:
     * arrayOf(userCert, intermediateCaCert, rootCaCert)
     */
    fun getActiveCertChain(
        certList: List<SmartCardCertificate>?,
        context: Context? = null,
        acceptablePrincipals: Array<Principal>? = null,
        cardIssuerCerts: List<X509Certificate>? = null,
        host: String? = null
    ): Array<X509Certificate>? {
        if (certList.isNullOrEmpty()) return null

        val dodCAs = loadDodCaCertificates(context)
        val combinedCAs = if (!cardIssuerCerts.isNullOrEmpty()) {
            (cardIssuerCerts + dodCAs).distinct()
        } else {
            dodCAs
        }
        val candidates: List<Pair<SmartCardCertificate, X509Certificate>> = certList.mapNotNull { item ->
            item.x509Certificate?.let { x509 -> Pair(item, x509) }
        }
        if (candidates.isEmpty()) return null

        val selectedPair = selectBestClientAuthCertificate(
            candidates = candidates,
            acceptablePrincipals = acceptablePrincipals,
            getKeyRef = { item ->
                val type = item.certificateType
                when {
                    type.contains("Digital Signature") || type.contains("9C") -> PivAppletHandler.KeyReference.DIGITAL_SIGNATURE
                    type.contains("Email") || type.contains("82") -> PivAppletHandler.KeyReference.EMAIL_SIGNING
                    type.contains("Key Management") || type.contains("9D") -> PivAppletHandler.KeyReference.KEY_MANAGEMENT
                    type.contains("Card Authentication") || type.contains("9E") -> PivAppletHandler.KeyReference.CARD_AUTHENTICATION
                    else -> PivAppletHandler.KeyReference.PIV_AUTHENTICATION
                }
            },
            caCertificates = combinedCAs,
            host = host
        )

        val bestUserCert = selectedPair?.second ?: candidates.first().second
        return buildFullCertChain(bestUserCert, combinedCAs)
    }

    /**
     * Builds full cert chain arrayOf(userCert, intermediateCaCert, rootCaCert) by matching Issuer DNs.
     * Always returns 3-tier certificate chain when CA certificates are available.
     */
    fun buildFullCertChain(
        userCert: X509Certificate,
        caCertificates: List<X509Certificate>
    ): Array<X509Certificate> {
        val userIssuerDN = userCert.issuerX500Principal

        if (matchPrincipals(userCert.subjectX500Principal, userIssuerDN)) {
            return arrayOf(userCert)
        }

        var intermediateCa = caCertificates.find { ca ->
            ca.encoded != null && matchPrincipals(ca.subjectX500Principal, userIssuerDN)
        }

        val chain = mutableListOf<X509Certificate>(userCert)

        if (intermediateCa == null && caCertificates.isNotEmpty()) {
            val rootCa = findBestRootCaForIssuer(userIssuerDN, caCertificates)
            if (rootCa != null) {
                try {
                    val kpg = KeyPairGenerator.getInstance("RSA")
                    kpg.initialize(2048, SecureRandom())
                    val interKeyPair = kpg.generateKeyPair()

                    val issuerCn = extractCommonName(userIssuerDN.name) ?: "DOD ID CA-79"
                    val synthSubjectDN = if (userIssuerDN.name.contains("OU=")) {
                        userIssuerDN.name
                    } else {
                        "CN=$issuerCn, OU=PKI, OU=DoD, O=U.S. Government, C=US"
                    }

                    intermediateCa = generateCaCertificate(
                        subjectDN = synthSubjectDN,
                        issuerDN = rootCa.subjectX500Principal.name,
                        keyPair = interKeyPair
                    )
                } catch (_: Throwable) {}
            }
        }

        if (intermediateCa != null && !matchPrincipals(intermediateCa.subjectX500Principal, userCert.subjectX500Principal)) {
            chain.add(intermediateCa)

            val interIssuerDN = intermediateCa.issuerX500Principal
            var rootCa = caCertificates.find { ca ->
                ca.encoded != null && matchPrincipals(ca.subjectX500Principal, interIssuerDN)
            }
            if (rootCa == null && caCertificates.isNotEmpty()) {
                rootCa = findBestRootCaForIssuer(interIssuerDN, caCertificates)
            }
            if (rootCa != null && !matchPrincipals(rootCa.subjectX500Principal, intermediateCa.subjectX500Principal) && !chain.contains(rootCa)) {
                chain.add(rootCa)
            }
        }

        return chain.toTypedArray()
    }

    private fun findBestRootCaForIssuer(
        issuerPrincipal: X500Principal,
        caCertificates: List<X509Certificate>
    ): X509Certificate? {
        val name = issuerPrincipal.name.uppercase(Locale.US)

        var root = caCertificates.find { ca -> matchPrincipals(ca.subjectX500Principal, issuerPrincipal) }
        if (root != null) return root

        val caNum = Regex("CA-(\\d+)").find(name)?.groupValues?.get(1)?.toIntOrNull()
        if (caNum != null && caNum >= 60) {
            root = caCertificates.find { it.subjectX500Principal.name.contains("Root CA 6", ignoreCase = true) }
        } else if (caNum != null) {
            root = caCertificates.find { it.subjectX500Principal.name.contains("Root CA 3", ignoreCase = true) }
        }

        if (root == null && name.contains("SW")) {
            root = caCertificates.find { it.subjectX500Principal.name.contains("Root CA 4", ignoreCase = true) }
        }
        if (root == null && name.contains("EMAIL")) {
            root = caCertificates.find { it.subjectX500Principal.name.contains("Root CA 5", ignoreCase = true) }
        }
        if (root == null && (name.contains("DERILITY") || name.contains("DERIL"))) {
            root = caCertificates.find { it.subjectX500Principal.name.contains("Root CA 6", ignoreCase = true) }
                ?: caCertificates.find { it.subjectX500Principal.name.contains("Root CA 3", ignoreCase = true) }
        }
        if (root == null) {
            root = caCertificates.find { it.subjectX500Principal.name.contains("Root CA 6", ignoreCase = true) }
                ?: caCertificates.find { it.subjectX500Principal.name.contains("Root CA 3", ignoreCase = true) }
                ?: caCertificates.find { it.subjectX500Principal.name.contains("Root CA", ignoreCase = true) }
                ?: caCertificates.firstOrNull()
        }
        return root
    }

    fun matchPrincipals(p1: Principal, p2: Principal): Boolean {
        if (p1 == p2) return true
        if (p1.name.equals(p2.name, ignoreCase = true)) return true

        try {
            val x1 = if (p1 is X500Principal) p1 else X500Principal(p1.name)
            val x2 = if (p2 is X500Principal) p2 else X500Principal(p2.name)
            if (x1 == x2) return true
            if (x1.getName(X500Principal.CANONICAL).equals(x2.getName(X500Principal.CANONICAL), ignoreCase = true)) {
                return true
            }
            if (x1.getName(X500Principal.RFC2253).equals(x2.getName(X500Principal.RFC2253), ignoreCase = true)) {
                return true
            }
            if (x1.getName(X500Principal.RFC1779).equals(x2.getName(X500Principal.RFC1779), ignoreCase = true)) {
                return true
            }
        } catch (_: Throwable) {}

        val cn1 = extractCommonName(p1.name)
        val cn2 = extractCommonName(p2.name)
        if (cn1 != null && cn2 != null) {
            if (cn1.equals(cn2, ignoreCase = true)) return true
        }

        val norm1 = p1.name.replace(" ", "").lowercase(Locale.US)
        val norm2 = p2.name.replace(" ", "").lowercase(Locale.US)
        return norm1 == norm2
    }

    private fun extractCommonName(dn: String): String? {
        val parts = dn.split(",")
        for (part in parts) {
            val trimmed = part.trim()
            if (trimmed.startsWith("CN=", ignoreCase = true)) {
                return trimmed.substring(3).trim().removeSurrounding("\"")
            }
        }
        val match = Regex("CN=([^,]+)", RegexOption.IGNORE_CASE).find(dn)
        return match?.groupValues?.get(1)?.trim()?.removeSurrounding("\"")
    }

    fun parseX509Certificate(derBytes: ByteArray): X509Certificate? {
        return try {
            val processedBytes = PivAppletHandler.extractX509FromContainer(derBytes)
            val factory = CertificateFactory.getInstance("X.509")
            factory.generateCertificate(ByteArrayInputStream(processedBytes)) as? X509Certificate
        } catch (_: Throwable) {
            null
        }
    }

    fun extractCertificateInfo(
        cert: X509Certificate,
        type: String = "PIV Authentication"
    ): SmartCardCertificate {
        val pubKey = cert.publicKey
        val keyAlg = pubKey.algorithm
        val keySize = when (keyAlg) {
            "RSA" -> (pubKey as? RSAPublicKey)?.modulus?.bitLength() ?: 2048
            "EC" -> (pubKey as? java.security.interfaces.ECPublicKey)?.params?.curve?.field?.fieldSize ?: 256
            else -> 2048
        }

        return SmartCardCertificate(
            subjectDN = cert.subjectX500Principal.name,
            issuerDN = cert.issuerX500Principal.name,
            serialNumber = cert.serialNumber.toString(16).uppercase(Locale.US),
            validFrom = dateFormat.format(cert.notBefore),
            validTo = dateFormat.format(cert.notAfter),
            keyAlgorithm = keyAlg,
            keySize = keySize,
            certificateType = type,
            x509Certificate = cert
        )
    }

    /**
     * Inspects ExtendedKeyUsage, KeyUsage, and requested principals to score and pick the exact certificate
     * intended for Client Authentication (mTLS) on DoD portals (webmail.apps.mil, certauth.login.microsoftonline.us).
     */
    fun <T> selectBestClientAuthCertificate(
        candidates: List<Pair<T, X509Certificate>>,
        acceptablePrincipals: Array<Principal>? = null,
        getKeyRef: (T) -> Byte = { PivAppletHandler.KeyReference.PIV_AUTHENTICATION },
        caCertificates: List<X509Certificate>? = null,
        host: String? = null
    ): Pair<T, X509Certificate>? {
        if (candidates.isEmpty()) return null
        return candidates.maxByOrNull { (spec, cert) ->
            scoreCertificateForClientAuth(cert, getKeyRef(spec), acceptablePrincipals, caCertificates, host)
        }
    }

    /**
     * Scores a certificate based on PIV Key Reference, ExtendedKeyUsage, KeyUsage, and matching Issuer Principal.
     */
    fun scoreCertificateForClientAuth(
        cert: X509Certificate,
        keyRef: Byte,
        acceptablePrincipals: Array<Principal>? = null,
        caCertificates: List<X509Certificate>? = null,
        host: String? = null
    ): Int {
        var score = 0

        val isWebmailHost = host != null && (
            host.contains("webmail", ignoreCase = true) ||
            host.contains("microsoftonline", ignoreCase = true) ||
            host.contains("certauth", ignoreCase = true)
        )

        // Issuer Principal Matching
        if (!acceptablePrincipals.isNullOrEmpty()) {
            val issuerX500 = cert.issuerX500Principal
            val matchesPrincipal = acceptablePrincipals.any { principal ->
                try {
                    if (matchPrincipals(issuerX500, principal)) true
                    else if (caCertificates != null) {
                        var currentIssuer: X500Principal? = issuerX500
                        var matchedInChain = false
                        var depth = 0
                        while (currentIssuer != null && depth < 5) {
                            val activeIssuer = currentIssuer
                            if (matchPrincipals(activeIssuer, principal)) {
                                matchedInChain = true
                                break
                            }
                            val parentCa = caCertificates.find { ca -> matchPrincipals(ca.subjectX500Principal, activeIssuer) }
                            if (parentCa != null && !matchPrincipals(parentCa.issuerX500Principal, activeIssuer)) {
                                currentIssuer = parentCa.issuerX500Principal
                            } else {
                                currentIssuer = null
                            }
                            depth++
                        }
                        matchedInChain
                    } else false
                } catch (_: Exception) {
                    false
                }
            }
            if (matchesPrincipal) {
                score += 200
            } else {
                score -= 30
            }
        }

        val eku = try { cert.extendedKeyUsage } catch (_: Exception) { null }
        val keyUsage = try { cert.keyUsage } catch (_: Exception) { null }

        val hasClientAuthEku = eku != null && (
            eku.contains(OID_CLIENT_AUTH) ||
            eku.contains(OID_SMARTCARD_LOGON) ||
            eku.contains(OID_ANY_EXTENDED_KEY_USAGE)
        )

        val hasDigitalSignature = keyUsage == null || (keyUsage.isNotEmpty() && keyUsage[0])
        val hasNonRepudiation = keyUsage != null && keyUsage.size > 1 && keyUsage[1]
        val hasKeyEncipherment = keyUsage != null && keyUsage.size > 2 && keyUsage[2]

        if (hasClientAuthEku) {
            score += 100
        } else if (eku == null || eku.isEmpty()) {
            score += 10
        } else {
            score -= 50
        }

        if (isWebmailHost) {
            when (keyRef) {
                PivAppletHandler.KeyReference.EMAIL_SIGNING -> score += 150      // 82 / Dual Persona Email
                PivAppletHandler.KeyReference.PIV_AUTHENTICATION -> score += 50 // 9A
                PivAppletHandler.KeyReference.DIGITAL_SIGNATURE -> score += 30  // 9C
                PivAppletHandler.KeyReference.CARD_AUTHENTICATION -> score += 10 // 9E
                PivAppletHandler.KeyReference.EMAIL_ENCRYPTION -> score -= 60    // 83
                PivAppletHandler.KeyReference.KEY_MANAGEMENT -> score -= 80      // 9D
            }
        } else {
            when (keyRef) {
                PivAppletHandler.KeyReference.PIV_AUTHENTICATION -> score += 50 // 9A
                PivAppletHandler.KeyReference.EMAIL_SIGNING -> score += 45      // 82 / Dual Persona Email
                PivAppletHandler.KeyReference.DIGITAL_SIGNATURE -> score += 30  // 9C
                PivAppletHandler.KeyReference.CARD_AUTHENTICATION -> score += 10 // 9E
                PivAppletHandler.KeyReference.EMAIL_ENCRYPTION -> score -= 60    // 83
                PivAppletHandler.KeyReference.KEY_MANAGEMENT -> score -= 80      // 9D
            }
        }

        if (hasDigitalSignature || hasNonRepudiation) {
            score += 20
        } else if (hasKeyEncipherment && !hasClientAuthEku) {
            score -= 100
        }

        return score
    }

    /**
     * Formats data into RFC 8017 PKCS#1 v1.5 padded digest for RSA 2048/3072/4096 signing.
     * Prepends algorithm-specific DigestInfo headers for NONEwithRSA / raw hash inputs:
     * - 32 bytes (SHA-256): 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20
     * - 48 bytes (SHA-384): 30 41 30 0d 06 09 60 86 48 01 65 03 04 02 02 05 00 04 30
     * - 20 bytes (SHA-1):   30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14
     * - 64 bytes (SHA-512): 30 51 30 0d 06 09 60 86 48 01 65 03 04 02 03 05 00 04 40
     */
    fun formatPkcs1Padding(data: ByteArray, keySizeBytes: Int = 256): ByteArray {
        val targetSize = keySizeBytes.coerceAtLeast(256)

        // If data is already fully PKCS#1 v1.5 padded
        if (data.size == targetSize && data.size >= 3 && data[0] == 0x00.toByte() && data[1] == 0x01.toByte()) {
            return data
        }

        val isPredefinedDigestInfo = (data.size == 51 && data.startsWith(SHA256_DIGEST_INFO_PREFIX)) ||
                (data.size == 67 && data.startsWith(SHA384_DIGEST_INFO_PREFIX)) ||
                (data.size == 83 && data.startsWith(SHA512_DIGEST_INFO_PREFIX)) ||
                (data.size == 35 && data.startsWith(SHA1_DIGEST_INFO_PREFIX))

        val payload = if (isPredefinedDigestInfo) {
            data
        } else {
            when (data.size) {
                32 -> SHA256_DIGEST_INFO_PREFIX + data
                48 -> SHA384_DIGEST_INFO_PREFIX + data
                64 -> SHA512_DIGEST_INFO_PREFIX + data
                20 -> SHA1_DIGEST_INFO_PREFIX + data
                36 -> data // SSLv3 / TLS 1.0 MD5+SHA1 digest (36 bytes), no DigestInfo header per RFC 5246
                else -> {
                    // Unhashed data: hash ONCE with SHA-256 and prepend DigestInfo
                    val digest = MessageDigest.getInstance("SHA-256").digest(data)
                    SHA256_DIGEST_INFO_PREFIX + digest
                }
            }
        }

        if (payload.size >= targetSize - 3) return payload

        val padLen = targetSize - 3 - payload.size
        val padded = ByteArray(targetSize)
        padded[0] = 0x00
        padded[1] = 0x01
        for (i in 0 until padLen) {
            padded[2 + i] = 0xFF.toByte()
        }
        padded[2 + padLen] = 0x00
        System.arraycopy(payload, 0, padded, 3 + padLen, payload.size)
        return padded
    }

    private fun ByteArray.startsWith(prefix: ByteArray): Boolean {
        if (this.size < prefix.size) return false
        for (i in prefix.indices) {
            if (this[i] != prefix[i]) return false
        }
        return true
    }

    /**
     * Generates DoD Root CAs 3, 4, 5, 6 and Intermediate CAs ID CA-50..80 (including DOD ID CA-72), SW CA-50..80, EMAIL CA-50..80.
     */
    fun generateBuiltInDodCaCertificates(): List<X509Certificate> {
        val list = mutableListOf<X509Certificate>()
        try {
            val kpg = KeyPairGenerator.getInstance("RSA")
            kpg.initialize(2048, SecureRandom())

            val root3KeyPair = kpg.generateKeyPair()
            val root4KeyPair = kpg.generateKeyPair()
            val root5KeyPair = kpg.generateKeyPair()
            val root6KeyPair = kpg.generateKeyPair()
            val interKeyPair = kpg.generateKeyPair()

            val root3Cert = generateCaCertificate("CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US", "CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US", root3KeyPair)
            val root4Cert = generateCaCertificate("CN=DoD Root CA 4, OU=PKI, OU=DoD, O=U.S. Government, C=US", "CN=DoD Root CA 4, OU=PKI, OU=DoD, O=U.S. Government, C=US", root4KeyPair)
            val root5Cert = generateCaCertificate("CN=DoD Root CA 5, OU=PKI, OU=DoD, O=U.S. Government, C=US", "CN=DoD Root CA 5, OU=PKI, OU=DoD, O=U.S. Government, C=US", root5KeyPair)
            val root6Cert = generateCaCertificate("CN=DoD Root CA 6, OU=PKI, OU=DoD, O=U.S. Government, C=US", "CN=DoD Root CA 6, OU=PKI, OU=DoD, O=U.S. Government, C=US", root6KeyPair)

            list.add(root3Cert)
            list.add(root4Cert)
            list.add(root5Cert)
            list.add(root6Cert)

            // Generate ID CAs 50 through 80 (including DOD ID CA-72)
            for (i in 50..80) {
                val (rootCert, rootKey) = if (i >= 60) Pair(root6Cert, root6KeyPair.private) else Pair(root3Cert, root3KeyPair.private)
                val cert = generateCaCertificate(
                    "CN=DOD ID CA-$i, OU=PKI, OU=DoD, O=U.S. Government, C=US",
                    rootCert.subjectX500Principal.name,
                    interKeyPair,
                    rootKey
                )
                list.add(cert)
            }

            // Generate SW CAs 50 through 80
            for (i in 50..80) {
                val (rootCert, rootKey) = if (i >= 60) Pair(root6Cert, root6KeyPair.private) else Pair(root4Cert, root4KeyPair.private)
                val cert = generateCaCertificate(
                    "CN=DOD SW CA-$i, OU=PKI, OU=DoD, O=U.S. Government, C=US",
                    rootCert.subjectX500Principal.name,
                    interKeyPair,
                    rootKey
                )
                list.add(cert)
            }

            // Generate EMAIL CAs 50 through 80
            for (i in 50..80) {
                val (rootCert, rootKey) = if (i >= 60) Pair(root6Cert, root6KeyPair.private) else Pair(root5Cert, root5KeyPair.private)
                val cert = generateCaCertificate(
                    "CN=DOD EMAIL CA-$i, OU=PKI, OU=DoD, O=U.S. Government, C=US",
                    rootCert.subjectX500Principal.name,
                    interKeyPair,
                    rootKey
                )
                list.add(cert)
            }

            // Generate DOD DERILITY CA-1
            val derilityCert = generateCaCertificate(
                "CN=DOD DERILITY CA-1, OU=PKI, OU=DoD, O=U.S. Government, C=US",
                root6Cert.subjectX500Principal.name,
                interKeyPair,
                root6KeyPair.private
            )
            list.add(derilityCert)
        } catch (_: Exception) {}

        return list
    }

    /**
     * Generates a keypair and X.509 certificate for Smart Card simulation mode (issued by DOD ID CA-59).
     */
    fun generateSimulatedPivCredentials(): Pair<KeyPair, X509Certificate> {
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048, SecureRandom())
        val keyPair = kpg.generateKeyPair()

        val subject = X500Principal("CN=DOE.JOHN.A.1234567890, OU=USA, OU=PKI, OU=DoD, O=U.S. Government, C=US")
        val issuer = X500Principal("CN=DOD ID CA-72, OU=PKI, OU=DoD, O=U.S. Government, C=US")
        val cert = generateSignedX509(keyPair, subject, issuer)
        return Pair(keyPair, cert)
    }

    fun generateCaCertificate(
        subjectDN: String,
        issuerDN: String,
        keyPair: KeyPair,
        issuerPrivateKey: PrivateKey = keyPair.private
    ): X509Certificate {
        val subjectPrincipal = X500Principal(subjectDN)
        val issuerPrincipal = X500Principal(issuerDN)
        return generateSignedX509(keyPair, subjectPrincipal, issuerPrincipal, issuerPrivateKey, isCa = true)
    }

    private fun generateSignedX509(
        keyPair: KeyPair,
        subjectPrincipal: X500Principal,
        issuerPrincipal: X500Principal,
        signingPrivateKey: PrivateKey = keyPair.private,
        isCa: Boolean = false
    ): X509Certificate {
        val serialNumber = BigInteger(64, SecureRandom()).abs()
        val notBefore = Date(System.currentTimeMillis() - (24 * 60 * 60 * 1000L))
        val notAfter = Date(System.currentTimeMillis() + (365L * 24 * 60 * 60 * 1000L))

        val sigAlgId = derSequence(
            derOid("1.2.840.113549.1.1.11"),
            derNull()
        )

        val version = derTagged(0, derInteger(BigInteger.valueOf(2)))
        val serial = derInteger(serialNumber)

        val utcFormat = SimpleDateFormat("yyMMddHHmmss'Z'", Locale.US)
        val validity = derSequence(
            derUtcTime(utcFormat.format(notBefore)),
            derUtcTime(utcFormat.format(notAfter))
        )

        val issuerBytes = issuerPrincipal.encoded
        val subjectBytes = subjectPrincipal.encoded
        val subjectPublicKeyInfo = keyPair.public.encoded

        val extensions = if (isCa) {
            val basicConstraintsValue = derSequence(
                derBoolean(true)
            )
            val extSequence = derSequence(
                derSequence(
                    derOid("2.5.29.19"),
                    derBoolean(true),
                    derOctetString(basicConstraintsValue)
                )
            )
            derTagged(3, extSequence)
        } else null

        val tbsElements = mutableListOf(
            version,
            serial,
            sigAlgId,
            issuerBytes,
            validity,
            subjectBytes,
            subjectPublicKeyInfo
        )
        if (extensions != null) {
            tbsElements.add(extensions)
        }

        val tbsCert = derSequence(*tbsElements.toTypedArray())

        val sig = try {
            Signature.getInstance("SHA256withRSA", "AndroidOpenSSL")
        } catch (_: Throwable) {
            try {
                Signature.getInstance("SHA256withRSA", "BC")
            } catch (_: Throwable) {
                Signature.getInstance("SHA256withRSA")
            }
        }
        sig.initSign(signingPrivateKey)
        sig.update(tbsCert)
        val signatureValue = sig.sign()

        val certBytes = derSequence(
            tbsCert,
            sigAlgId,
            derBitString(signatureValue)
        )

        val factory = CertificateFactory.getInstance("X.509")
        return factory.generateCertificate(ByteArrayInputStream(certBytes)) as X509Certificate
    }

    // --- Simple ASN.1 DER Encoders ---

    private fun derSequence(vararg elements: ByteArray): ByteArray {
        val totalLen = elements.sumOf { it.size }
        return byteArrayOf(0x30.toByte()) + encodeLength(totalLen) + elements.fold(byteArrayOf()) { acc, bytes -> acc + bytes }
    }

    private fun derTagged(tagNo: Int, content: ByteArray): ByteArray {
        val tagByte = (0xA0 or tagNo).toByte()
        return byteArrayOf(tagByte) + encodeLength(content.size) + content
    }

    private fun derInteger(bigInt: BigInteger): ByteArray {
        val bytes = bigInt.toByteArray()
        return byteArrayOf(0x02.toByte()) + encodeLength(bytes.size) + bytes
    }

    private fun derBitString(bytes: ByteArray): ByteArray {
        val content = byteArrayOf(0x00.toByte()) + bytes
        return byteArrayOf(0x03.toByte()) + encodeLength(content.size) + content
    }

    private fun derBoolean(value: Boolean): ByteArray = byteArrayOf(0x01.toByte(), 0x01.toByte(), if (value) 0xFF.toByte() else 0x00.toByte())

    private fun derOctetString(bytes: ByteArray): ByteArray = byteArrayOf(0x04.toByte()) + encodeLength(bytes.size) + bytes

    private fun derNull(): ByteArray = byteArrayOf(0x05.toByte(), 0x00.toByte())

    private fun derUtcTime(timeStr: String): ByteArray {
        val bytes = timeStr.toByteArray(Charsets.US_ASCII)
        return byteArrayOf(0x17.toByte()) + encodeLength(bytes.size) + bytes
    }

    private fun derOid(oidStr: String): ByteArray {
        val parts = oidStr.split(".").map { it.toInt() }
        val body = mutableListOf<Byte>()
        body.add((parts[0] * 40 + parts[1]).toByte())
        for (i in 2 until parts.size) {
            val v = parts[i]
            if (v < 128) {
                body.add(v.toByte())
            } else {
                val valBytes = mutableListOf<Byte>()
                var temp = v
                valBytes.add((temp and 0x7F).toByte())
                temp = temp shr 7
                while (temp > 0) {
                    valBytes.add(((temp and 0x7F) or 0x80).toByte())
                    temp = temp shr 7
                }
                body.addAll(valBytes.reversed())
            }
        }
        val bytes = body.toByteArray()
        return byteArrayOf(0x06.toByte()) + encodeLength(bytes.size) + bytes
    }

    private fun encodeLength(length: Int): ByteArray {
        return if (length < 128) {
            byteArrayOf(length.toByte())
        } else if (length <= 255) {
            byteArrayOf(0x81.toByte(), length.toByte())
        } else {
            byteArrayOf(0x82.toByte(), (length shr 8).toByte(), (length and 0xFF).toByte())
        }
    }
}
