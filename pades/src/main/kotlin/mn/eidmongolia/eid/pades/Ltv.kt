package mn.eidmongolia.eid.pades

import java.io.IOException
import java.security.MessageDigest
import java.util.Date

/** DSS payload of one signature (Go core.DSS). */
internal class DssData(
    val certs: MutableList<ByteArray> = ArrayList(),
    val ocsps: MutableList<ByteArray> = ArrayList(),
    val crls: MutableList<ByteArray> = ArrayList(),
    var contents: ByteArray? = null,
)

/** B-LT collection — Go reference `pades/ltv.go` (OCSP SHA-1 CertID, CRL by CDP, fail-closed). */
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
        fun issuerOf(c: Cert) = (pool + roots).firstOrNull { it.rawSubject.contentEquals(c.rawIssuer) && c.signedBy(it) }
        val seen = HashSet<Cert>()
        for (ch in chains) {
            for ((i, c) in ch.withIndex()) {
                if (c in seen || roots.contains(c)) continue
                seen += c
                add(d.certs, c.raw)
                val issuer = issuerOf(c) ?: throw Incomplete("issuer of ${c.commonName} not found")
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
                    } catch (e: NotFresh) {
                        freshErr = e
                    } catch (_: Exception) {
                    }
                }
                for (u in c.crlDistributionPoints) {
                    try {
                        val der = f.get(u)
                        if (crlCovers(der, c, issuer, now)) {
                            add(d.crls, der)
                            ok = true
                        }
                    } catch (_: Exception) {
                    }
                }
                if (!ok) {
                    freshErr?.let { throw NotFresh("${it.message}: ${c.commonName}") }
                    throw Incomplete("no valid OCSP/CRL for ${c.commonName}")
                }
                if (i == 0 && after != null && freshErr != null && c.ocspServers.isNotEmpty() && !hasFreshOcsp(d.ocsps, c, issuer, after)) {
                    throw NotFresh("${freshErr.message}: ${c.commonName}")
                }
            }
        }
        return d
    }

    private fun hasFreshOcsp(list: List<ByteArray>, c: Cert, issuer: Cert, after: Date) = list.any {
        try { Ocsp.parseForCert(it, c, issuer).thisUpdate.after(after) } catch (_: Exception) { false }
    }

    private fun fetchOcsp(f: Fetcher, url: String, c: Cert, issuer: Cert, now: Date, after: Date?): Pair<ByteArray, Ocsp.Response> {
        val der = f.post(url, "application/ocsp-request", Ocsp.request(c, issuer))
        val resp = Ocsp.parseForCert(der, c, issuer)
        if (!Ocsp.responderOk(resp, issuer)) throw IOException("OCSP responder EKU is not OCSPSigning")
        if (resp.status != Ocsp.GOOD || (resp.nextUpdate != null && resp.nextUpdate.before(now))) {
            throw IOException("OCSP ${c.commonName}: status ${resp.status}")
        }
        if (after != null && !resp.thisUpdate.after(after)) throw NotFresh("OCSP thisUpdate is not after the timestamp")
        return der to resp
    }

    /** Go crlCovers: CRL of c's issuer (signature checked), nextUpdate not passed, c not listed. */
    fun crlCovers(der: ByteArray, c: Cert, issuer: Cert, now: Date): Boolean = try {
        val list = Der.parse(der).children()
        val tbs = list[0]
        val f = tbs.children()
        var i = if (f[0].tag == Der.INTEGER) 1 else 0
        i++ // signature algorithm
        val crlIssuer = f[i++].encoded()
        i++ // thisUpdate
        val next = f.getOrNull(i)?.takeIf { it.tag == Der.UTC_TIME || it.tag == Der.GENERALIZED_TIME }?.let { i++; Asn1Time.parse(it) }
        val revoked = f.getOrNull(i)?.takeIf { it.tag == Der.SEQUENCE }?.children()?.map { it.child(0).bigInt() } ?: emptyList()
        val sigOid = list[1].child(0).oid()
        val bits = list[2]
        val sig = bits.buf.copyOfRange(bits.valueStart + 1, bits.end)
        crlIssuer.contentEquals(c.rawIssuer) &&
            Sig.verifyOid(sigOid, issuer.publicKey, tbs.encoded(), sig) &&
            next != null && !next.before(now) &&
            revoked.none { it == c.serial }
    } catch (_: Exception) {
        false
    }
}

/** OCSP (RFC 6960) request/response — x/crypto/ocsp semantics the Go reference uses. */
internal object Ocsp {
    const val GOOD = 0
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

    /** Go responderOK: issuer itself, or a responder certificate with id-kp-OCSPSigning. */
    fun responderOk(r: Response, issuer: Cert): Boolean =
        r.certificate == null || r.certificate == issuer || Cert.OID_KP_OCSP_SIGNING in r.certificate.extKeyUsage
}
