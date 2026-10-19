package mn.eidmongolia.eid.pades

import java.io.IOException
import java.math.BigInteger
import java.security.MessageDigest
import java.util.Date

/** DSS payload of one signature (Go core.DSS). */
internal class DssData(
    val certs: MutableList<ByteArray> = ArrayList(),
    val ocsps: MutableList<ByteArray> = ArrayList(),
    val crls: MutableList<ByteArray> = ArrayList(),
    var contents: ByteArray? = null,
)

/**
 * A chain certificate is revoked by its issuer-signed OCSP response or CRL (Go `pades.ErrCertificateRevoked`). Final —
 * `complete` stops at once (no other URL/CRL is tried for a "good" answer, no retry).
 */
internal class CertificateRevoked(val ref: String) : IOException("certificate revoked ($ref)")

/**
 * B-LT collection — Go reference `pades/ltv.go`: OCSP (SHA-1 CertID) and CRL (CDP) per chain certificate, checked for
 * signature/issuer, CertID, freshness ([Revocation.freshAt] at the current time); fail-closed; revoked → [CertificateRevoked].
 */
internal object Ltv {
    class NotFresh(msg: String) : IOException(msg)
    class Incomplete(msg: String) : IOException(msg)

    private const val AFTER_TS_MS = 2_000L
    private const val WAIT_MAX_MS = 5_000L
    private const val RETRY_MS = 1_000L

    /** Wait until 2 s after genTime (≤ 5 s), retry on a not-yet-fresh leaf OCSP every 1 s, total wait ≤ 5 s. */
    fun collectWithWait(
        f: Fetcher, now: () -> Date, sleep: (Long) -> Unit, genTime: Date, roots: List<Cert>, vararg chains: List<Cert>,
    ): DssData {
        var waited = 0L
        var d = minOf((genTime.time / 1000) * 1000 + AFTER_TS_MS - now().time, WAIT_MAX_MS)
        while (true) {
            if (d > 0) {
                sleep(d)
                waited += d
            }
            try {
                return collect(f, now(), genTime, roots, *chains)
            } catch (e: NotFresh) {
                if (waited + RETRY_MS > WAIT_MAX_MS) throw e
            }
            d = RETRY_MS
        }
    }

    fun collect(f: Fetcher, now: Date, after: Date?, roots: List<Cert>, vararg chains: List<Cert>): DssData {
        val d = DssData()
        fun add(list: MutableList<ByteArray>, der: ByteArray) {
            if (list.none { it.contentEquals(der) }) list += der
        }
        val pool = chains.flatMap { it }
        fun issuerOf(c: Cert) = (pool + roots).firstOrNull { c.issuedBy(it) }
        val seen = HashSet<Cert>()
        for (ch in chains) {
            for ((i, c) in ch.withIndex()) {
                if (c in seen || roots.contains(c)) continue
                seen += c
                add(d.certs, c.raw)
                val issuer = issuerOf(c) ?: throw Incomplete("issuer of ${c.serialRef} not found")
                var ok = false
                var freshErr: NotFresh? = null
                val fresh = if (i == 0) after else null
                for (u in c.ocspServers) {
                    try {
                        val (der, resp) = fetchOcsp(f, u, c, issuer, now, fresh)
                        add(d.ocsps, der)
                        resp.certificate?.let { if (it != issuer) add(d.certs, it.raw) } // delegated responder
                        ok = true
                        break
                    } catch (e: CertificateRevoked) {
                        throw e
                    } catch (e: NotFresh) {
                        freshErr = e
                    } catch (_: Exception) {
                    }
                }
                for (u in c.crlDistributionPoints) {
                    val der = try { f.get(u) } catch (_: Exception) { continue }
                    if (Crl.covers(der, c, issuer, now)) {
                        add(d.crls, der)
                        ok = true
                    }
                }
                if (!ok) {
                    freshErr?.let { throw NotFresh("${it.message}: ${c.serialRef}") }
                    throw Incomplete("no valid OCSP/CRL for ${c.serialRef}")
                }
                if (i == 0 && after != null && freshErr != null && c.ocspServers.isNotEmpty() && !hasFreshOcsp(d.ocsps, c, issuer, after)) {
                    throw NotFresh("${freshErr.message}: ${c.serialRef}")
                }
            }
        }
        return d
    }

    private fun hasFreshOcsp(list: List<ByteArray>, c: Cert, issuer: Cert, after: Date) = list.any {
        try { Ocsp.parseForCert(it, c, issuer).thisUpdate.after(after) && Ocsp.certIdMatches(it, c, issuer) } catch (_: Exception) { false }
    }

    /**
     * Go fetchOCSP: SHA-1 CertID request; signed by the issuer (or a delegated id-kp-OCSPSigning responder), CertID = this
     * certificate + issuer, revoked → [CertificateRevoked], good and fresh now, thisUpdate after [after] (when given).
     */
    fun fetchOcsp(f: Fetcher, url: String, c: Cert, issuer: Cert, now: Date, after: Date?): Pair<ByteArray, Ocsp.Response> {
        val der = f.post(url, "application/ocsp-request", Ocsp.request(c, issuer))
        val resp = Ocsp.parseForCert(der, c, issuer)
        if (!Ocsp.responderOk(resp, issuer)) throw IOException("OCSP responder EKU is not OCSPSigning")
        if (!Ocsp.certIdMatches(der, c, issuer)) throw IOException("OCSP CertID is not this certificate's")
        if (resp.status == Ocsp.REVOKED) throw CertificateRevoked(c.serialRef)
        if (resp.status != Ocsp.GOOD || !Revocation.freshAt(resp.thisUpdate, resp.nextUpdate, now, now)) {
            throw IOException("OCSP ${c.serialRef}: not good or not fresh")
        }
        if (after != null && !resp.thisUpdate.after(after)) throw NotFresh("OCSP thisUpdate is not after the timestamp")
        return der to resp
    }
}

/** Freshness of revocation evidence — Go `validate.FreshAt` (README §7.2, golden validate/v4). */
internal object Revocation {
    /** thisUpdate may be at most this long before the check time when nextUpdate does not cover it. */
    const val MAX_AGE_MS = 24 * 3600_000L
    /** Responder ↔ checker clock tolerance. */
    const val CLOCK_SKEW_MS = 5 * 60_000L

    /**
     * A response with thisUpdate/nextUpdate is "good" evidence at [at] (the check time — the timestamp time, else now):
     * thisUpdate not after now + skew; nextUpdate (when present) not before at − skew; thisUpdate ≥ at − 24 h, or
     * [thisUpdate, nextUpdate] covers [at]. Not applied to "revoked" (a revocation does not expire).
     */
    fun freshAt(thisUpdate: Date, nextUpdate: Date?, at: Date, now: Date): Boolean {
        if (thisUpdate.time > now.time + CLOCK_SKEW_MS) return false
        if (nextUpdate != null && nextUpdate.time < at.time - CLOCK_SKEW_MS) return false
        if (thisUpdate.time >= at.time - MAX_AGE_MS) return true
        return nextUpdate != null && thisUpdate.time <= at.time
    }
}

/** CRL (RFC 5280 §5.1) — Go `validate.CRLFor` / `CRLListed` / `crlCovers`. */
internal object Crl {
    class Parsed(
        val rawIssuer: ByteArray,
        val authorityKeyId: ByteArray,
        val thisUpdate: Date,
        val nextUpdate: Date?,
        val revoked: List<BigInteger>,
        val tbs: ByteArray,
        val sigOid: String,
        val signature: ByteArray,
    )

    fun parse(der: ByteArray): Parsed? = try {
        val top = Der.parse(der)
        require(top.tag == Der.SEQUENCE && top.end == der.size)
        val list = top.children()
        require(list.size == 3 && list[0].tag == Der.SEQUENCE && list[2].tag == Der.BIT_STRING)
        val bits = list[2]
        require(bits.length >= 1 && bits.buf[bits.valueStart].toInt() == 0)
        val t = list[0].children()
        var i = if (t[0].tag == Der.INTEGER) 1 else 0
        i++ // signature algorithm
        val issuer = t[i++]
        require(issuer.tag == Der.SEQUENCE)
        val thisUpdate = Asn1Time.parse(t[i++])
        var next: Date? = null
        if (i < t.size && (t[i].tag == Der.UTC_TIME || t[i].tag == Der.GENERALIZED_TIME)) next = Asn1Time.parse(t[i++])
        var revoked = emptyList<BigInteger>()
        if (i < t.size && t[i].tag == Der.SEQUENCE) revoked = t[i++].children().map { e -> e.child(0).also { require(it.tag == Der.INTEGER) }.bigInt() }
        var aki = ByteArray(0)
        if (i < t.size && t[i].tag == Der.ctx(0)) {
            for (ext in t[i].child(0).children()) {
                val p = ext.children()
                if (p[0].oid() != Cert.OID_AKI) continue
                Der.parse(p.last().value()).children().firstOrNull { it.tag == Der.ctx(0, constructed = false) }?.let { aki = it.value() }
            }
        }
        Parsed(issuer.encoded(), aki, thisUpdate, next, revoked, list[0].encoded(), list[1].child(0).oid(),
            bits.buf.copyOfRange(bits.valueStart + 1, bits.end))
    } catch (_: Exception) {
        null
    }

    /**
     * Go `validate.CRLFor`: the CRL of [cert]'s issuer — CRL issuer = cert issuer = issuer subject (raw bytes), AKI (when
     * both present) = the issuer's SKI, signed by the issuer (a CA allowed to sign CRLs).
     */
    fun isFor(crl: Parsed, cert: Cert, issuer: Cert): Boolean {
        if (!crl.rawIssuer.contentEquals(cert.rawIssuer) || !crl.rawIssuer.contentEquals(issuer.rawSubject)) return false
        val ski = issuer.subjectKeyId
        if (crl.authorityKeyId.isNotEmpty() && ski.isNotEmpty() && !crl.authorityKeyId.contentEquals(ski)) return false
        return issuer.mayIssue(Cert.KU_CRL_SIGN) && Sig.verifyOid(crl.sigOid, issuer.publicKey, crl.tbs, crl.signature)
    }

    /**
     * Go crlCovers: a CRL of [c]'s issuer with a nextUpdate, fresh now ([Revocation.freshAt]), [c] not listed.
     * @throws CertificateRevoked when [c] is listed in its issuer's CRL
     */
    fun covers(der: ByteArray, c: Cert, issuer: Cert, now: Date): Boolean {
        val crl = parse(der) ?: return false
        if (!isFor(crl, c, issuer)) return false
        if (crl.revoked.any { it == c.serial }) throw CertificateRevoked(c.serialRef)
        return crl.nextUpdate != null && Revocation.freshAt(crl.thisUpdate, crl.nextUpdate, now, now)
    }
}

/** OCSP (RFC 6960) request/response — x/crypto/ocsp semantics the Go reference uses. */
internal object Ocsp {
    const val GOOD = 0
    const val REVOKED = 1
    private const val OID_SHA1 = "1.3.14.3.2.26"
    private const val OID_BASIC = "1.3.6.1.5.5.7.48.1.1"

    class Response(val status: Int, val thisUpdate: Date, val nextUpdate: Date?, val certificate: Cert?)

    /** OCSPRequest { tbsRequest { requestList { Request { CertID(SHA-1 + NULL) } } } } (x/crypto CreateRequest). */
    fun request(c: Cert, issuer: Cert): ByteArray {
        val sha1 = MessageDigest.getInstance("SHA-1")
        val nameHash = sha1.digest(issuer.rawSubject)
        val keyHash = MessageDigest.getInstance("SHA-1").digest(issuer.publicKeyBits)
        val certId = Der.seq(Der.seq(Der.oid(OID_SHA1), Der.nullValue()), Der.octets(nameHash), Der.octets(keyHash), Der.int(c.serial))
        return Der.seq(Der.seq(Der.seq(Der.seq(certId))))
    }

    /** x/crypto ParseResponseForCert: signature by issuer or by an included cert the issuer signed; the cert's SingleResponse. */
    fun parseForCert(der: ByteArray, c: Cert, issuer: Cert): Response {
        val top = Der.parse(der).children()
        require(top[0].tag == Der.ENUMERATED && top[0].value().single() == 0.toByte()) { "OCSP response status" }
        val rb = top[1].child(0)
        require(rb.child(0).oid() == OID_BASIC) { "not a basic OCSP response" }
        val basic = Der.parse(rb.child(1).value()).children()
        val tbs = basic[0]
        val sigOid = basic[1].child(0).oid()
        val bits = basic[2]
        val sig = bits.buf.copyOfRange(bits.valueStart + 1, bits.end)
        val certs = basic.getOrNull(3)?.takeIf { it.tag == Der.ctx(0) }?.child(0)?.children()?.map { Cert.parse(it.encoded()) } ?: emptyList()
        val responder = certs.firstOrNull()
        if (responder != null) {
            require(responder == issuer || responder.signedBy(issuer)) { "OCSP responder not issued by the issuer" }
            require(Sig.verifyOid(sigOid, responder.publicKey, tbs.encoded(), sig)) { "OCSP signature" }
        } else {
            require(Sig.verifyOid(sigOid, issuer.publicKey, tbs.encoded(), sig)) { "OCSP signature" }
        }
        val rd = tbs.children()
        var i = if (rd[0].tag == Der.ctx(0)) 1 else 0
        i += 2 // responderID, producedAt
        val single = rd[i].children().firstOrNull { it.child(0).child(3).bigInt() == c.serial }
            ?: throw IllegalArgumentException("no OCSP response for the certificate")
        val s = single.children()
        val status = when (s[1].tag and 0x1f) { 0 -> 0; 1 -> 1; else -> 2 }
        val thisUpdate = Asn1Time.parse(s[2])
        val next = s.drop(3).firstOrNull { it.tag == Der.ctx(0) }?.let { Asn1Time.parse(it.child(0)) }
        return Response(status, thisUpdate, next, responder)
    }

    private val HASHES = mapOf(
        "1.3.14.3.2.26" to "SHA-1",
        "2.16.840.1.101.3.4.2.1" to "SHA-256",
        "2.16.840.1.101.3.4.2.2" to "SHA-384",
        "2.16.840.1.101.3.4.2.3" to "SHA-512",
    )

    /**
     * Go `validate.OCSPCertIDMatches`: every SingleResponse for [c]'s serial carries [issuer]'s CertID (issuerNameHash =
     * H(issuer subject), issuerKeyHash = H(issuer subjectPublicKey); SHA-1/256/384/512) and there is at least one.
     * [parseForCert] selects by serial only, so a response for another issuer's certificate with the same serial (even
     * from the same responder) must not count for this certificate.
     */
    fun certIdMatches(der: ByteArray, c: Cert, issuer: Cert): Boolean {
        try {
            val top = Der.parse(der).children()
            require(top[0].tag == Der.ENUMERATED && top[0].value().single() == 0.toByte())
            val basic = Der.parse(top[1].child(0).child(1).value()).children()
            val rd = basic[0].children()
            var i = if (rd[0].tag == Der.ctx(0)) 1 else 0
            i += 2 // responderID, producedAt
            var found = false
            for (single in rd[i].children()) {
                val id = single.child(0).children()
                require(id.size == 4 && id[1].tag == Der.OCTET_STRING && id[2].tag == Der.OCTET_STRING && id[3].tag == Der.INTEGER)
                if (id[3].bigInt() != c.serial) continue
                val h = HASHES[id[0].child(0).oid()] ?: return false
                if (!id[1].value().contentEquals(MessageDigest.getInstance(h).digest(issuer.rawSubject)) ||
                    !id[2].value().contentEquals(MessageDigest.getInstance(h).digest(issuer.publicKeyBits))
                ) return false
                found = true
            }
            return found
        } catch (_: Exception) {
            return false
        }
    }

    /** Go responderOK: issuer itself, or a responder certificate with id-kp-OCSPSigning. */
    fun responderOk(r: Response, issuer: Cert): Boolean =
        r.certificate == null || r.certificate == issuer || Cert.OID_KP_OCSP_SIGNING in r.certificate.extKeyUsage
}
