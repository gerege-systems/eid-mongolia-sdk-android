package mn.eidmongolia.eid.pades

import java.math.BigInteger
import java.util.Calendar
import java.util.Date
import java.util.TimeZone

/** ASN.1 time → Date (UTCTime / GeneralizedTime, `Z` or ±hhmm, optional fraction truncated to ms). */
internal object Asn1Time {
    fun parse(t: Der.Tlv): Date {
        val s = String(t.value(), Charsets.US_ASCII)
        // UTCTime YY, GeneralizedTime YYYY (a greedy \d{2,4} read UTCTime "261014…" as year 2610 — CRL thisUpdate).
        val yy = if (t.tag == Der.UTC_TIME) "\\d{2}" else "\\d{4}"
        val m = Regex("^($yy)(\\d{2})(\\d{2})(\\d{2})(\\d{2})(\\d{2})?(?:[.,](\\d+))?(Z|[+-]\\d{4})$").matchEntire(s)
            ?: throw IllegalArgumentException("ASN.1 time $s")
        val g = m.groupValues
        var year = g[1].toInt()
        if (t.tag == Der.UTC_TIME) year += if (year < 50) 2000 else 1900
        val c = Calendar.getInstance(TimeZone.getTimeZone("UTC"))
        c.clear()
        c.set(year, g[2].toInt() - 1, g[3].toInt(), g[4].toInt(), g[5].toInt(), g[6].ifEmpty { "0" }.toInt())
        c.set(Calendar.MILLISECOND, (g[7] + "000").take(3).toInt())
        var ms = c.timeInMillis
        if (g[8] != "Z") {
            val sign = if (g[8][0] == '-') -1 else 1
            ms -= sign * (g[8].substring(1, 3).toInt() * 3600_000L + g[8].substring(3, 5).toInt() * 60_000L)
        }
        return Date(ms)
    }
}

/** RFC 3161 client — Go reference `pades/tsa.go` (request bytes per `pades/WIRE.md`). */
internal object Tsa {
    private const val MAX_SKEW_MS = 10 * 60_000L

    class Token(val raw: ByteArray, val genTime: Date, val certificates: List<Cert>)

    /** TimeStampReq { v1, messageImprint {sha256 + NULL, hash}, nonce, certReq TRUE } (digitorus Request.Marshal). */
    fun request(hash: ByteArray, nonce: BigInteger): ByteArray = Der.seq(
        Der.int(1),
        Der.seq(Der.seq(Der.oid(Cms.OID_SHA256), Der.nullValue()), Der.octets(hash)),
        Der.int(nonce),
        Der.bool(true),
    )

    fun timestamp(f: Fetcher, url: String, signature: ByteArray, roots: List<Cert>, inter: List<Cert>, now: Date, nonceBytes: ByteArray): Token {
        val sum = Cms.sha256(signature)
        val nonce = BigInteger(1, nonceBytes)
        val body = f.post(url, "application/timestamp-query", request(sum, nonce))
        val resp = Der.parse(body)
        val parts = resp.children()
        val status = parts[0].child(0).bigInt().toInt()
        require(status == 0 || status == 1) { "TSA status $status" }
        require(parts.size >= 2) { "TSA response without token" }
        val tokenDer = parts[1].encoded()
        val p = Cms.parse(tokenDer)
        val tst = p.eContent ?: throw IllegalArgumentException("token without TSTInfo")
        require(p.signerCount == 1 && p.signer != null) { "token signer" }
        require(Cms.verify(p, tst)) { "token signature" }
        val info = Der.parse(tst).children()
        val imprint = info[2]
        require(imprint.child(0).child(0).oid() == Cms.OID_SHA256 && imprint.child(1).value().contentEquals(sum)) { "timestamp hash does not match" }
        val genTime = Asn1Time.parse(info[4])
        val tokenNonce = info.drop(5).firstOrNull { it.tag == Der.INTEGER }?.bigInt()
        require(tokenNonce == nonce) { "nonce mismatch" }
        val signer = p.signer!!
        require(signer.isTsaSigningCert) { "TSA signer EKU is not critical {timeStamping}" }
        require(Chain.verify(signer, roots, p.certificates + inter, genTime)) { "TSA certificate chain" }
        require(Math.abs(now.time - genTime.time) <= MAX_SKEW_MS) { "TSA genTime too far from local time" }
        require(p.certificates.isNotEmpty()) { "token without certificates" }
        return Token(tokenDer, genTime, p.certificates)
    }
}

/**
 * Minimal path validation — Go `x509.Verify` (verifyTSAChain, KeyUsages timeStamping): subject/issuer + signature, every
 * certificate valid at [at], each issuer a CA allowed to sign certificates (cA + keyCertSign; intermediates must carry
 * basicConstraints), pathLenConstraint and the EKU of every issuer (empty, anyExtendedKeyUsage or timeStamping).
 */
internal object Chain {
    fun verify(leaf: Cert, roots: List<Cert>, pool: List<Cert>, at: Date): Boolean {
        fun ekuOk(c: Cert) = c.extKeyUsage.let { it.isEmpty() || Cert.OID_ANY_EKU in it || Cert.OID_KP_TIMESTAMPING in it }
        var cur = leaf
        var below = 0 // CA certificates between the leaf and the next issuer (Go numIntermediates)
        val used = HashSet<Cert>()
        repeat(8) {
            if (!cur.validAt(at)) return false
            if (roots.any { it == cur }) return true
            if (roots.any { cur.issuedBy(it) && it.validAt(at) && it.allowsPath(below) && ekuOk(it) }) return true
            val next = pool.firstOrNull {
                it != cur && it !in used && cur.issuedBy(it) && it.isCa && it.allowsPath(below) && ekuOk(it)
            } ?: return false
            used += cur
            cur = next
            below++
        }
        return false
    }
}
