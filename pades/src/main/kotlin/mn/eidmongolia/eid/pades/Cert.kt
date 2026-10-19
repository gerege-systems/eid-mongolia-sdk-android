package mn.eidmongolia.eid.pades

import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.PublicKey
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey

/**
 * X.509 certificate with the raw DER fields the Go reference compares byte-wise (RawIssuer, RawSubject, serial,
 * SPKI) — parsed here, never re-encoded by the platform. Crypto goes through `java.security`.
 */
internal class Cert private constructor(val raw: ByteArray, val x509: X509Certificate) {
    val rawIssuer: ByteArray
    val rawSubject: ByteArray
    val serial: BigInteger
    /** SubjectPublicKeyInfo.subjectPublicKey BIT STRING contents without the unused-bits byte (OCSP issuerKeyHash). */
    val publicKeyBits: ByteArray
    private val extensions: List<Triple<String, Boolean, ByteArray>>
    private val subjectAttrs: List<Pair<String, String>>
    private val issuerAttrs: List<Pair<String, String>>

    init {
        val tbs = Der.parse(raw).child(0)
        val f = tbs.children()
        var i = if (f[0].tag == Der.ctx(0)) 1 else 0 // [0] version
        serial = f[i++].bigInt()
        i++ // signature AlgorithmIdentifier
        rawIssuer = f[i++].encoded()
        i++ // validity
        val subject = f[i++]
        rawSubject = subject.encoded()
        val spki = f[i++]
        val bits = spki.child(1)
        publicKeyBits = bits.buf.copyOfRange(bits.valueStart + 1, bits.end)
        val exts = ArrayList<Triple<String, Boolean, ByteArray>>()
        f.drop(i).firstOrNull { it.tag == Der.ctx(3) }?.child(0)?.children()?.forEach { e ->
            val c = e.children()
            val critical = c.size == 3 && c[1].tag == Der.BOOLEAN && c[1].value()[0] != 0.toByte()
            exts += Triple(c[0].oid(), critical, c.last().value())
        }
        extensions = exts
        subjectAttrs = nameAttrs(subject)
        issuerAttrs = nameAttrs(Der.parse(rawIssuer))
    }

    val publicKey: PublicKey get() = x509.publicKey
    val isRsa get() = publicKey is RSAPublicKey
    val isEc get() = publicKey is ECPublicKey

    override fun equals(other: Any?) = other is Cert && raw.contentEquals(other.raw)
    override fun hashCode() = raw.contentHashCode()

    /** The signature verifies with [issuer]'s key (Go `issuer.CheckSignature` — no CA checks; see [issuedBy]). */
    fun signedBy(issuer: Cert): Boolean = try {
        x509.verify(issuer.publicKey)
        true
    } catch (_: Exception) {
        false
    }

    /**
     * Go `bytes.Equal(c.RawIssuer, issuer.RawSubject) && c.CheckSignatureFrom(issuer) == nil`: the issuer must be a CA
     * allowed to sign certificates (basicConstraints cA, keyUsage keyCertSign when present).
     */
    fun issuedBy(issuer: Cert) = rawIssuer.contentEquals(issuer.rawSubject) && issuer.mayIssue(KU_CERT_SIGN) && signedBy(issuer)

    /** basicConstraints extension present (Go `BasicConstraintsValid`). */
    val basicConstraintsValid: Boolean get() = extension(OID_BASIC_CONSTRAINTS) != null
    /** basicConstraints cA = true. */
    val isCa: Boolean get() = basicConstraintsValid && x509.basicConstraints >= 0
    /** pathLenConstraint; null = no limit (Go `MaxPathLen` -1). */
    val maxPathLen: Int? get() = x509.basicConstraints.takeIf { isCa && it != Int.MAX_VALUE }

    /**
     * Go `CheckSignatureFrom` / `RevocationList.CheckSignatureFrom` parent checks: a v3 certificate needs basicConstraints
     * with cA = true (v1/v2 without the extension are accepted, like Go); a non-empty keyUsage must include [usageBit]
     * ([KU_CERT_SIGN] for certificates, [KU_CRL_SIGN] for CRLs).
     */
    fun mayIssue(usageBit: Int): Boolean {
        if (x509.version == 3 && !basicConstraintsValid || basicConstraintsValid && !isCa) return false
        val ku = x509.keyUsage ?: return true
        return ku.none { it } || (usageBit < ku.size && ku[usageBit])
    }

    /** Go `Verify` path-length rule: [intermediates] CA certificates below this one in the chain. */
    fun allowsPath(intermediates: Int): Boolean = maxPathLen?.let { intermediates <= it } ?: true

    fun validAt(at: java.util.Date) = !at.before(x509.notBefore) && !at.after(x509.notAfter)

    /** SubjectKeyIdentifier (empty if absent). */
    val subjectKeyId: ByteArray
        get() = extension(OID_SKI)?.second?.let { Der.parse(it).value() } ?: ByteArray(0)

    /** Errors name certificates by serial (Go `SerialNumber.Text(16)`), never by CN — the citizen's name is PII. */
    val serialRef: String get() = "serial " + serial.toString(16)

    fun extension(oid: String): Pair<Boolean, ByteArray>? =
        extensions.firstOrNull { it.first == oid }?.let { it.second to it.third }

    fun extensionCount(oid: String) = extensions.count { it.first == oid }

    /** AIA id-ad-ocsp URIs, in order (Go `OCSPServer`). */
    val ocspServers: List<String>
        get() = extension(OID_AIA)?.second?.let { v ->
            Der.parse(v).children().filter { it.child(0).oid() == OID_AD_OCSP && it.child(1).tag == 0x86 }
                .map { String(it.child(1).value(), Charsets.ISO_8859_1) }
        } ?: emptyList()

    /** CRL distribution point fullName URIs, in order (Go `CRLDistributionPoints`). */
    val crlDistributionPoints: List<String>
        get() = extension(OID_CRL_DP)?.second?.let { v ->
            val out = ArrayList<String>()
            for (dp in Der.parse(v).children()) {
                val name = dp.children().firstOrNull { it.tag == Der.ctx(0) } ?: continue // distributionPoint
                val full = name.children().firstOrNull { it.tag == Der.ctx(0) } ?: continue // fullName
                for (gn in full.children()) if (gn.tag == 0x86) out += String(gn.value(), Charsets.ISO_8859_1)
            }
            out
        } ?: emptyList()

    /** ExtendedKeyUsage OIDs (empty if absent). */
    val extKeyUsage: List<String>
        get() = extension(OID_EKU)?.second?.let { v -> Der.parse(v).children().map { it.oid() } } ?: emptyList()

    /** Go eidcrypto.IsTSASigningCert: exactly one EKU extension, critical, = {timeStamping}. */
    val isTsaSigningCert: Boolean
        get() {
            if (extensionCount(OID_EKU) != 1) return false
            val (critical, v) = extension(OID_EKU)!!
            val oids = try { Der.parse(v).children().map { it.oid() } } catch (_: Exception) { return false }
            return critical && oids == listOf(OID_KP_TIMESTAMPING)
        }

    /** Go core.SignerDisplayName: GIVENNAME SURNAME (last of each wins), else CN. */
    val displayName: String
        get() {
            val given = subjectAttrs.lastOrNull { it.first == "2.5.4.42" }?.second ?: ""
            val sur = subjectAttrs.lastOrNull { it.first == "2.5.4.4" }?.second ?: ""
            val n = GoText.trimSpace("$given $sur")
            return n.ifEmpty { commonName }
        }

    val commonName: String get() = subjectAttrs.lastOrNull { it.first == "2.5.4.3" }?.second ?: ""

    /** Subject attribute (last occurrence wins, like Go pkix.Name). */
    fun subjectAttr(oid: String): String? = subjectAttrs.lastOrNull { it.first == oid }?.second

    /** Go `cert.Issuer.CommonName`. */
    val issuerCommonName: String get() = issuerAttrs.lastOrNull { it.first == "2.5.4.3" }?.second ?: ""

    private fun nameAttrs(name: Der.Tlv): List<Pair<String, String>> {
        val attrs = ArrayList<Pair<String, String>>()
        for (rdn in name.children()) for (atv in rdn.children()) {
            val a = atv.children()
            attrs += a[0].oid() to Asn1Text.decode(a[1])
        }
        return attrs
    }

    companion object {
        const val OID_AIA = "1.3.6.1.5.5.7.1.1"
        const val OID_AD_OCSP = "1.3.6.1.5.5.7.48.1"
        const val OID_CRL_DP = "2.5.29.31"
        const val OID_EKU = "2.5.29.37"
        const val OID_ANY_EKU = "2.5.29.37.0"
        const val OID_SERIAL_NUMBER = "2.5.4.5"
        const val OID_BASIC_CONSTRAINTS = "2.5.29.19"
        const val OID_SKI = "2.5.29.14"
        const val OID_AKI = "2.5.29.35"
        /** java.security.cert.X509Certificate.getKeyUsage() indices. */
        const val KU_CERT_SIGN = 5
        const val KU_CRL_SIGN = 6
        const val OID_KP_TIMESTAMPING = "1.3.6.1.5.5.7.3.8"
        const val OID_KP_OCSP_SIGNING = "1.3.6.1.5.5.7.3.9"

        fun parse(der: ByteArray): Cert {
            val x = CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(der)) as X509Certificate
            // The DER we keep is the input element itself (no trailing bytes, no re-encoding).
            val t = Der.parse(der)
            require(t.end == der.size) { "trailing data after certificate" }
            return Cert(der.copyOf(), x)
        }

        /** PEM CERTIFICATE blocks → DER (resources / test fixtures). */
        fun pemBlocks(pem: String): List<ByteArray> =
            Regex("-----BEGIN CERTIFICATE-----([^-]+)-----END CERTIFICATE-----").findAll(pem)
                .map { Base64Std.decode(it.groupValues[1]) }.toList()
    }
}

/** Signature verification by algorithm OID (CMS / OCSP / CRL / TSA tokens). */
internal object Sig {
    private val names = mapOf(
        "1.2.840.113549.1.1.5" to "SHA1withRSA",
        "1.2.840.113549.1.1.11" to "SHA256withRSA",
        "1.2.840.113549.1.1.12" to "SHA384withRSA",
        "1.2.840.113549.1.1.13" to "SHA512withRSA",
        "1.2.840.10045.4.1" to "SHA1withECDSA",
        "1.2.840.10045.4.3.2" to "SHA256withECDSA",
        "1.2.840.10045.4.3.3" to "SHA384withECDSA",
        "1.2.840.10045.4.3.4" to "SHA512withECDSA",
    )
    private val digestNames = mapOf(
        "1.3.14.3.2.26" to "SHA-1",
        "2.16.840.1.101.3.4.2.1" to "SHA-256",
        "2.16.840.1.101.3.4.2.2" to "SHA-384",
        "2.16.840.1.101.3.4.2.3" to "SHA-512",
    )

    fun digestName(oid: String): String? = digestNames[oid]

    /** CMS SignerInfo: digestAlgorithm + signatureAlgorithm (rsaEncryption / ecPublicKey or a combined OID). */
    fun cmsAlgorithm(digestOid: String, sigOid: String): String? {
        names[sigOid]?.let { return it }
        val d = digestNames[digestOid]?.replace("-", "") ?: return null
        return when (sigOid) {
            "1.2.840.113549.1.1.1" -> "${d}withRSA"
            "1.2.840.10045.2.1" -> "${d}withECDSA"
            else -> null
        }
    }

    fun verify(alg: String?, key: PublicKey, data: ByteArray, sig: ByteArray): Boolean = try {
        alg != null && Signature.getInstance(alg).run {
            initVerify(key)
            update(data)
            verify(sig)
        }
    } catch (_: Exception) {
        false
    }

    fun verifyOid(sigOid: String, key: PublicKey, data: ByteArray, sig: ByteArray) = verify(names[sigOid], key, data, sig)
}

/** ASN.1 directory string → String (Go pkix value decoding for the string types X.509 names use). */
internal object Asn1Text {
    fun decode(t: Der.Tlv): String = when (t.tag) {
        Der.BMP_STRING -> String(t.value(), Charsets.UTF_16BE)
        Der.T61_STRING, Der.IA5_STRING, Der.PRINTABLE_STRING -> String(t.value(), Charsets.ISO_8859_1)
        else -> String(t.value(), Charsets.UTF_8)
    }
}

/** Go string helpers with Go semantics. */
internal object GoText {
    /** Go `unicode.IsSpace`. */
    fun isSpace(c: Int) = when (c) {
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0x85, 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000 -> true
        else -> c in 0x2000..0x200a
    }

    /** Go `strings.TrimSpace`. */
    fun trimSpace(s: String): String {
        var a = 0
        var b = s.length
        while (a < b && isSpace(s.codePointAt(a))) a += Character.charCount(s.codePointAt(a))
        while (b > a && isSpace(s.codePointBefore(b))) b -= Character.charCount(s.codePointBefore(b))
        return s.substring(a, b)
    }
}
