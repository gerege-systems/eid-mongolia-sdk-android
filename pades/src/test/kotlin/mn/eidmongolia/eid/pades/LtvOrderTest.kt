package mn.eidmongolia.eid.pades

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.IOException
import java.io.InterruptedIOException
import java.text.SimpleDateFormat
import java.util.Collections
import java.util.Date
import java.util.Locale
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread

/**
 * LTV revocation collection order by certificate role: the end entity (first certificate of a chain) asks its OCSP first
 * (full timeout) and then its CRL; a CA certificate fetches its CRL first and sends no OCSP request at all when the CRL
 * is valid (a dead CA responder — ocsp.esign.gov.mn accepts the connection and never answers — is never contacted),
 * falling back to OCSP only without a valid CRL. Fail-closed, revoked fatal, an interrupted caller ends the collection.
 * iOS `LTVOrderTests` 1:1. Golden PKI: citizen ← 04 ← 03 ← 02 ← root; OCSP only for citizen and 04.
 */
class LtvOrderTest {
    private val m = JSONObject(String(Golden.file("manifest.json"), Charsets.UTF_8))
    private fun cert(n: String) = Cert.parse(Golden.pem("pki/$n.pem"))
    private val citizen = cert("citizen")
    private val ca04 = cert("04")
    private val ca03 = cert("03")
    private val root = cert("root")
    private val chain = listOf(citizen, ca04, ca03, cert("02"))
    private val now: Date =
        SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX", Locale.US).parse(m.getString("now").replace(Regex("\\.\\d+"), ""))!!
    private val citizenOcsp = citizen.ocspServers[0]
    private val ca04Ocsp = ca04.ocspServers[0]
    private val citizenCrl = citizen.crlDistributionPoints[0]
    private val ca04Crl = ca04.crlDistributionPoints[0]

    private val replay = EidPadesTransport { method, url, _, body ->
        val key = "$method $url ${Hex.encode(Cms.sha256(body ?: ByteArray(0))).substring(0, 16)}"
        val f = m.getJSONObject("http").optString(key)
        if (f.isEmpty()) throw IOException("no golden HTTP fixture for $key")
        Golden.file(f)
    }

    private sealed interface Act
    private object Hang : Act
    private object Fail : Act
    private class Body(val b: ByteArray) : Act
    private class Delay(val ms: Long) : Act
    private class FailAfter(val ms: Long) : Act

    /** golden/http replay with per-request behaviour (key "METHOD url"); records requests; interrupt → InterruptedIOException. */
    private inner class Fake(private val acts: Map<String, Act> = emptyMap()) : EidPadesTransport {
        val inFlight = AtomicInteger()
        val requests: MutableList<String> = Collections.synchronizedList(ArrayList())

        override fun send(method: String, url: String, contentType: String?, body: ByteArray?): ByteArray {
            val key = "$method $url"
            requests += key
            inFlight.incrementAndGet()
            try {
                when (val a = acts[key]) {
                    is Hang -> {
                        sleep(120_000)
                        throw IOException("hang ended")
                    }
                    is Fail -> throw IOException("404")
                    is FailAfter -> {
                        sleep(a.ms)
                        throw IOException("timed out")
                    }
                    is Body -> return a.b
                    is Delay -> sleep(a.ms)
                    null -> Unit
                }
                return replay.send(method, url, contentType, body)
            } finally {
                inFlight.decrementAndGet()
            }
        }

        private fun sleep(ms: Long) = try {
            Thread.sleep(ms)
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            throw InterruptedIOException("interrupted")
        }
    }

    private fun collect(t: EidPadesTransport) = Ltv.collect(Fetcher(t), now, Date(0), listOf(root), chain)

    private fun post(c: Cert, issuer: Cert) = Fetcher(replay).post(c.ocspServers[0], "application/ocsp-request", Ocsp.request(c, issuer))

    private fun get(url: String) = Fetcher(replay).get(url)

    private fun hex(l: List<ByteArray>) = l.map(Hex::encode)

    /** golden/validate/<name>.pdf /DSS OCSPs and CRLs. */
    private fun dss(name: String): Pair<List<ByteArray>, List<ByteArray>> {
        val r = PdfReader.open(Golden.file("validate/$name.pdf"))
        val catalog = r.get(r.trailer, "Root").dict!!
        val d = r.get(catalog, "DSS").dict!!
        fun streams(k: String) = (r.get(d, k) as? PdfObj.Arr)?.items?.map { r.decodedStream(r.resolve(it)) } ?: emptyList()
        return streams("OCSPs") to streams("CRLs")
    }

    private fun ms(since: Long) = (System.nanoTime() - since) / 1_000_000

    /** Healthy chain: leaf OCSP + every CRL; the CA certificate 04 (valid CRL) never contacts its OCSP responder. */
    @Test
    fun caWithValidCrlSendsNoOcsp() {
        val t = Fake(mapOf("POST $ca04Ocsp" to Hang))
        val start = System.nanoTime()
        val got = collect(t)
        assertTrue("${ms(start)} ms", ms(start) < 5_000)
        assertFalse(t.requests.toString(), "POST $ca04Ocsp" in t.requests)
        assertEquals(listOf("POST $citizenOcsp"), t.requests.filter { it.startsWith("POST") })
        assertEquals(hex(listOf(post(citizen, ca04))), hex(got.ocsps))
        assertEquals(4, got.crls.size) // 04, 03, 02, root CRLs, chain order
        assertEquals(hex(listOf(get(citizenCrl), get(ca04Crl))), hex(got.crls.take(2)))
        assertEquals(hex(chain.map { it.raw }), hex(got.certs.take(4)))
        assertEquals(0, t.inFlight.get())
    }

    /** Leaf: OCSP is asked first, then its CRL. */
    @Test
    fun leafAsksOcspFirst() {
        val t = Fake()
        collect(t)
        assertEquals(listOf("POST $citizenOcsp", "GET $citizenCrl"), t.requests.take(2))
    }

    /** CA certificate without a valid CRL (missing, or not its issuer's) → OCSP fallback, embedded. */
    @Test
    fun caWithoutValidCrlFallsBackToOcsp() {
        // golden/http has no OCSP for 04 since v11 (its CRL is used); the validate DSS still carries one.
        val ocsp04 = dss("dss-crl-only").first.first {
            try { Ocsp.parseForCert(it, ca04, ca03); true } catch (_: Exception) { false }
        }
        val wrongIssuer = get(citizenCrl) // 04's CRL, not 03's
        for (act in listOf(Fail, Body(wrongIssuer))) {
            val t = Fake(mapOf("GET $ca04Crl" to act, "POST $ca04Ocsp" to Body(ocsp04)))
            val got = collect(t)
            assertTrue("POST $ca04Ocsp" in t.requests)
            assertTrue(got.ocsps.any { it.contentEquals(ocsp04) })
            assertEquals(3, got.crls.size)
        }
        // Neither CRL nor OCSP → fail-closed.
        try {
            collect(Fake(mapOf("GET $ca04Crl" to Fail, "POST $ca04Ocsp" to Fail)))
            fail("CA certificate without revocation data accepted")
        } catch (e: Exception) {
            assertTrue(e.message, e.message!!.contains("no valid OCSP/CRL for serial 3ec"))
        }
    }

    /** A slow leaf OCSP is awaited and embedded (full timeout), even though its CRL is valid. */
    @Test
    fun slowLeafOcspIsAwaited() {
        val t = Fake(mapOf("POST $citizenOcsp" to Delay(600)))
        val start = System.nanoTime()
        val got = collect(t)
        assertTrue("${ms(start)} ms", ms(start) >= 550)
        assertEquals(hex(listOf(post(citizen, ca04))), hex(got.ocsps))
    }

    /** A dead leaf OCSP (transport timeout) → its CRL after the timeout; without a CRL either → fail-closed. */
    @Test
    fun deadLeafOcspFallsBackToCrl() {
        val start = System.nanoTime()
        val got = collect(Fake(mapOf("POST $citizenOcsp" to FailAfter(400))))
        assertTrue("${ms(start)} ms", ms(start) >= 350)
        assertTrue(got.ocsps.isEmpty())
        assertEquals(Hex.encode(get(citizenCrl)), Hex.encode(got.crls.first()))
        try {
            collect(Fake(mapOf("POST $citizenOcsp" to Fail, "GET $citizenCrl" to Fail)))
            fail("leaf without revocation data accepted")
        } catch (e: CertificateRevoked) {
            fail("not revoked")
        } catch (e: Exception) {
            assertTrue(e.message, e.message!!.contains("no valid OCSP/CRL for serial 3ed"))
        }
    }

    /** Revoked is fatal from either source: the leaf's CRL lists it (even with a good OCSP), or its OCSP says revoked. */
    @Test
    fun revokedFromEitherSourceIsFatal() {
        val revokedCrl = dss("dss-crl-revoked").second.first { der ->
            val p = Crl.parse(der)
            p != null && Crl.isFor(p, citizen, ca04) && p.revoked.any { it == citizen.serial }
        }
        val revokedOcsp = dss("dss-ocsp-revoked").first.first {
            try { Ocsp.parseForCert(it, citizen, ca04).status == Ocsp.REVOKED } catch (_: Exception) { false }
        }
        for (acts in listOf(mapOf("GET $citizenCrl" to Body(revokedCrl)), mapOf("POST $citizenOcsp" to Body(revokedOcsp)))) {
            try {
                collect(Fake(acts))
                fail("revoked certificate collected (${acts.keys})")
            } catch (e: CertificateRevoked) {
                assertEquals("serial 3ed", e.ref)
            }
        }
    }

    @Test
    fun garbageLeafOcspFallsBackToCrl() {
        val got = collect(Fake(mapOf("POST $citizenOcsp" to Body(byteArrayOf(0x30, 0x03, 0x02, 0x01, 0x00)))))
        assertTrue(got.ocsps.isEmpty())
        assertEquals(4, got.crls.size)
    }

    @Test
    fun callerInterruptIsPropagated() {
        val t = Fake(mapOf("POST $citizenOcsp" to Hang))
        val err = AtomicReference<Throwable?>()
        val start = System.nanoTime()
        val worker = thread {
            try {
                collect(t)
            } catch (e: Throwable) {
                err.set(e)
            }
        }
        Thread.sleep(200)
        worker.interrupt()
        worker.join(5_000)
        assertFalse("interrupted collect still running", worker.isAlive)
        assertTrue("${ms(start)} ms", ms(start) < 5_000)
        val e = err.get()
        assertTrue("$e", e is InterruptedIOException)
        assertEquals(0, t.inFlight.get())
    }
}
