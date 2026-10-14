package mn.eidmongolia.eid.pades

import java.math.BigInteger
import java.security.MessageDigest
import java.security.interfaces.ECPublicKey

/** CMS SignedData (CAdES baseline, detached) — Go reference `pades/internal/core/cms.go`, byte for byte. */
internal object Cms {
    const val OID_DATA = "1.2.840.113549.1.7.1"
    const val OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
    const val OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
    const val OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
    const val OID_SIGNING_CERT_V2 = "1.2.840.113549.1.9.16.2.47"
    const val OID_TIMESTAMP_TOKEN = "1.2.840.113549.1.9.16.2.14"
    const val OID_SHA256 = "2.16.840.1.101.3.4.2.1"
    const val OID_SHA256_RSA = "1.2.840.113549.1.1.11"
    const val OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2"
    const val OID_SIGNER_ATTR_V2 = "0.4.0.19122.1.1"
    const val OID_ROLE = "2.5.4.72"
    const val CLAIMED_ROLE_MAX_RUNES = 900

    /**
     * DER SET OF Attribute: contentType = id-data, messageDigest, signingCertificateV2 (+ signer-attributes-v2 with
     * claimedRole). No signingTime. Sorted by encoded bytes (X.690 §11.6).
     */
    fun signedAttributes(messageDigest: ByteArray, signer: Cert, claimedRole: String?): ByteArray {
        require(messageDigest.size == 32) { "messageDigest is not SHA-256" }
        val role = claimedRole ?: ""
        if (role.isNotEmpty()) {
            require(validSurrogates(role) && role.codePointCount(0, role.length) <= CLAIMED_ROLE_MAX_RUNES) { "claimed role" }
        }
        val certHash = sha256(signer.raw)
        val attrs = ArrayList<ByteArray>()
        attrs += attr(OID_CONTENT_TYPE, Der.oid(OID_DATA))
        attrs += attr(OID_MESSAGE_DIGEST, Der.octets(messageDigest))
        attrs += attr(
            OID_SIGNING_CERT_V2,
            Der.seq( // SigningCertificateV2
                Der.seq( // certs
                    Der.seq( // ESSCertIDv2
                        Der.octets(certHash),
                        Der.seq( // IssuerSerial
                            Der.seq(Der.tlv(Der.ctx(4), signer.rawIssuer)), // GeneralNames { directoryName [4] }
                            Der.int(signer.serial),
                        ),
                    ),
                ),
            ),
        )
        if (role.isNotEmpty()) {
            attrs += attr(
                OID_SIGNER_ATTR_V2,
                Der.seq(
                    Der.tlv(
                        Der.ctx(0),
                        Der.seq(Der.seq(Der.oid(OID_ROLE), Der.set(Der.tlv(Der.UTF8_STRING, role.toByteArray(Charsets.UTF_8))))),
                    ),
                ),
            )
        }
        attrs.sortWith(Der.BYTES_ORDER)
        return Der.set(*attrs.toTypedArray())
    }

    private fun validSurrogates(s: String): Boolean {
        var i = 0
        while (i < s.length) {
            val c = s[i]
            if (Character.isHighSurrogate(c)) {
                if (i + 1 >= s.length || !Character.isLowSurrogate(s[i + 1])) return false
                i += 2
                continue
            }
            if (Character.isLowSurrogate(c)) return false
            i++
        }
        return true
    }

    private fun attr(oid: String, value: ByteArray) = Der.seq(Der.oid(oid), Der.set(value))

    fun dtbs(signedAttrs: ByteArray): ByteArray = sha256(signedAttrs)

    fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)

    private fun algId(oid: String, nullParams: Boolean) =
        if (nullParams) Der.seq(Der.oid(oid), Der.nullValue()) else Der.seq(Der.oid(oid))

    /** ContentInfo{SignedData}: certificates = signer + chain (sorted), one SignerInfo, unsigned [1] = timestamp token. */
    fun assemble(signedAttrs: ByteArray, signer: Cert, chain: List<Cert>, signature: ByteArray, tst: ByteArray?): ByteArray {
        require(signedAttrs.size >= 2 && signedAttrs[0] == 0x31.toByte()) { "signedAttrs is not a DER SET" }
        val sigAlg = when {
            signer.isRsa -> OID_SHA256_RSA
            signer.isEc -> OID_ECDSA_SHA256
            else -> throw IllegalArgumentException("unsupported signer key")
        }
        val implicitAttrs = signedAttrs.copyOf().also { it[0] = 0xA0.toByte() }
        val certs = ArrayList<ByteArray>()
        certs += signer.raw
        for (c in chain) if (c != signer) certs += c.raw
        certs.sortWith(Der.BYTES_ORDER)
        val signerInfo = Der.seq(
            Der.int(1),
            Der.seq(signer.rawIssuer, Der.int(signer.serial)),
            algId(OID_SHA256, false),
            implicitAttrs,
            algId(sigAlg, sigAlg == OID_SHA256_RSA),
            Der.octets(signature),
            if (tst != null && tst.isNotEmpty()) {
                Der.tlv(Der.ctx(1), Der.seq(Der.oid(OID_TIMESTAMP_TOKEN), Der.set(tst)))
            } else ByteArray(0),
        )
        val signedData = Der.seq(
            Der.int(1),
            Der.set(algId(OID_SHA256, false)),
            Der.seq(Der.oid(OID_DATA)),
            Der.tlv(Der.ctx(0), Der.concat(*certs.toTypedArray())),
            Der.set(signerInfo),
        )
        return Der.seq(Der.oid(OID_SIGNED_DATA), Der.tlv(Der.ctx(0), signedData))
    }

    /**
     * Go complete.go citizenSignature: verify over DTBS and return the CMS form — RSA PKCS#1 v1.5 as is; ECDSA r‖s
     * (2n bytes) → DER, or DER as is. Null when it does not verify.
     */
    fun citizenSignature(cert: Cert, dtbs: ByteArray, sig: ByteArray): ByteArray? {
        if (cert.isRsa) return if (Sig.verify("NONEwithRSA", cert.publicKey, digestInfoSha256(dtbs), sig)) sig else null
        if (cert.isEc) {
            val bits = (cert.publicKey as ECPublicKey).params.curve.field.fieldSize
            val n = (bits + 7) / 8
            if (sig.size == 2 * n) {
                val der = Der.seq(
                    Der.int(BigInteger(1, sig.copyOfRange(0, n))),
                    Der.int(BigInteger(1, sig.copyOfRange(n, 2 * n))),
                )
                if (Sig.verify("NONEwithECDSA", cert.publicKey, dtbs, der)) return der
            }
            return if (Sig.verify("NONEwithECDSA", cert.publicKey, dtbs, sig)) sig else null
        }
        return null
    }

    /** PKCS#1 v1.5 DigestInfo for SHA-256 (verify a pre-hashed DTBS with NONEwithRSA). */
    private fun digestInfoSha256(h: ByteArray) = Der.seq(algId(OID_SHA256, true), Der.octets(h))

    // ── parsing (prior signatures, TSA tokens) ──

    class Parsed(
        val certificates: List<Cert>,
        val signer: Cert?,
        val signerCount: Int,
        val digestOid: String,
        val sigOid: String,
        /** signedAttrs re-tagged as a DER SET (what the signature covers). */
        val signedAttrsSet: ByteArray?,
        val messageDigest: ByteArray?,
        val signature: ByteArray,
        /** eContent (TSTInfo for timestamp tokens), null when detached. */
        val eContent: ByteArray?,
        val unsignedAttrOids: List<String>,
    )

    /** ContentInfo{SignedData} → the parts verification needs. */
    fun parse(der: ByteArray): Parsed {
        val ci = Der.parse(der)
        require(ci.tag == Der.SEQUENCE && ci.child(0).oid() == OID_SIGNED_DATA) { "not CMS SignedData" }
        val sd = ci.child(1).child(0)
        val f = sd.children()
        var i = 2 // version, digestAlgorithms
        val encap = f[i++]
        val eContent = encap.children().getOrNull(1)?.child(0)?.value()
        val certs = ArrayList<Cert>()
        if (f[i].tag == Der.ctx(0)) {
            for (c in f[i].children()) if (c.tag == Der.SEQUENCE) certs += Cert.parse(c.encoded())
            i++
        }
        if (f[i].tag == Der.ctx(1)) i++ // crls
        val infos = f[i].children()
        val si = infos.first().children()
        var j = 1
        val sid = si[j++]
        val digestOid = si[j++].child(0).oid()
        var attrsSet: ByteArray? = null
        var md: ByteArray? = null
        if (si[j].tag == Der.ctx(0)) {
            val raw = si[j++].encoded()
            attrsSet = raw.copyOf().also { it[0] = 0x31 }
            for (a in Der.parse(attrsSet).children()) {
                if (a.child(0).oid() == OID_MESSAGE_DIGEST) md = a.child(1).child(0).value()
            }
        }
        val sigOid = si[j++].child(0).oid()
        val signature = si[j++].value()
        val unsigned = si.getOrNull(j)?.takeIf { it.tag == Der.ctx(1) }?.children()?.map { it.child(0).oid() } ?: emptyList()
        val signer = certs.firstOrNull { matchesSid(it, sid) }
        return Parsed(certs, signer, infos.size, digestOid, sigOid, attrsSet, md, signature, eContent, unsigned)
    }

    private fun matchesSid(c: Cert, sid: Der.Tlv): Boolean = when (sid.tag) {
        Der.SEQUENCE -> c.rawIssuer.contentEquals(sid.child(0).encoded()) && c.serial == sid.child(1).bigInt()
        else -> false // subjectKeyIdentifier [0] — not produced by eID / our TSA
    }

    /** digitorus pkcs7 Verify (no chain): messageDigest = H(content) and the signature over signedAttrs. */
    fun verify(p: Parsed, content: ByteArray): Boolean {
        val signer = p.signer ?: return false
        val attrs = p.signedAttrsSet
        val alg = Sig.cmsAlgorithm(p.digestOid, p.sigOid) ?: return false
        if (attrs == null) return Sig.verify(alg, signer.publicKey, content, p.signature)
        val dn = Sig.digestName(p.digestOid) ?: return false
        val h = MessageDigest.getInstance(dn).digest(content)
        if (p.messageDigest == null || !MessageDigest.isEqual(h, p.messageDigest)) return false
        return Sig.verify(alg, signer.publicKey, attrs, p.signature)
    }
}
