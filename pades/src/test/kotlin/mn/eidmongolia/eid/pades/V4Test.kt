package mn.eidmongolia.eid.pades

import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.zip.Deflater

/**
 * Golden v4 (Go reference v0.8.0): revocation-evidence matching/freshness and revoked = hard error in complete's OCSP/CRL
 * collection (golden/validate/dss-*.pdf — the citizen's OCSP/CRL replaced in the DSS), PRECHECKS #2a/#2b structure
 * checks (golden/validate/deep-nesting*.pdf, Go TestCheckStructureObjStmGraph inputs) and #4 direct /Encrypt. iOS
 * `V4Tests` 1:1.
 */
class V4Test {
    private val m = JSONObject(String(Golden.file("manifest.json"), Charsets.UTF_8))
    private val citizen = Golden.pem("pki/citizen.pem")
    private val chainDer = listOf("04", "03", "02").map { Golden.pem("pki/$it.pem") }
    private val root = Golden.pem("pki/root.pem")
    private fun time(s: String): Date =
        SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX", Locale.US).parse(s.replace(Regex("\\.\\d+"), ""))!!

    private fun code(f: () -> Unit): String = try {
        f()
        "OK"
    } catch (e: EidPadesException) {
        e.code
    }

    private fun failsStructure(doc: ByteArray) = try {
        Structure.check(doc)
        false
    } catch (_: Structure.Failure) {
        true
    }

    // PRECHECKS #2a / #2b / #4

    @Test
    fun deepNestingRejected() {
        val o = PrepareOptions(signerCert = citizen, chain = chainDer, verifyPage = true, fileName = "x.pdf")
        for (name in listOf("deep-nesting", "deep-nesting-objstm")) {
            val doc = Golden.file("validate/$name.pdf")
            assertTrue(name, failsStructure(doc))
            assertEquals(name, "PDF_INVALID", code { EidPades.prepare(doc, o) })
        }
        val cases = m.getJSONArray("cases")
        for (i in 0 until cases.length()) {
            val input = cases.getJSONObject(i).getString("input")
            if (!input.startsWith("case:")) assertFalse(input, failsStructure(Golden.file(input)))
        }
        fun nested(n: Int) = ("%PDF-1.4\n1 0 obj\n<< /X " + "[".repeat(n - 1) + "]".repeat(n - 1) + " >>\nendobj\n").toByteArray()
        assertFalse(failsStructure(nested(256)))
        assertTrue(failsStructure(nested(257)))
        // The same depth inside a FlateDecode object stream.
        val inner = ("1 0 " + "[".repeat(300) + "]".repeat(300)).toByteArray()
        val z = ByteArrayOutputStream().also { out ->
            val d = Deflater()
            d.setInput(inner)
            d.finish()
            val buf = ByteArray(4096)
            while (!d.finished()) out.write(buf, 0, d.deflate(buf))
            d.end()
        }.toByteArray()
        val doc = "%PDF-1.5\n2 0 obj\n<< /Type /ObjStm /N 1 /First 4 /Filter /FlateDecode /Length ${z.size} >>\nstream\n".toByteArray() +
            z + "\nendstream\nendobj\n".toByteArray()
        assertTrue(failsStructure(doc))
    }

    /** Go `xrefStreamPDF`: obj 1 Catalog (/X 3 0 R), obj 2 xref stream, obj 3 = object 0 of ObjStm 4, obj 4 ObjStm. */
    private fun xrefStreamPdf(size: String, length4: String, row3: ByteArray? = null, row4: ByteArray? = null): ByteArray {
        val b = ByteArrayOutputStream()
        b.write(("%PDF-1.5\n%" + "x".repeat(300) + "\n").toByteArray())
        val off1 = b.size()
        b.write("1 0 obj\n<< /Type /Catalog /X 3 0 R >>\nendobj\n".toByteArray())
        val off4 = b.size()
        b.write("4 0 obj\n<< /Type /ObjStm /N 1 /First 4 /Length $length4 >>\nstream\n3 0 << >>\nendstream\nendobj\n".toByteArray())
        val off2 = b.size()
        fun row(t: Int, f2: Int, f3: Int) = byteArrayOf(t.toByte(), (f2 shr 8).toByte(), f2.toByte(), f3.toByte())
        val rows = row(0, 0, 0xff) + row(1, off1, 0) + row(1, off2, 0) + (row3 ?: row(2, 4, 0)) + (row4 ?: row(1, off4, 0))
        b.write("2 0 obj\n<< /Type /XRef /Size $size /W [1 2 1] /Index [0 5] /Root 1 0 R /Length ${rows.size} >>\nstream\n".toByteArray())
        b.write(rows)
        b.write("\nendstream\nendobj\nstartxref\n$off2\n%%EOF\n".toByteArray())
        return b.toByteArray()
    }

    @Test
    fun objStmGraph() {
        fun inStm(container: Int) = byteArrayOf(2, 0, container.toByte(), 0)
        val cases = listOf(
            Triple("legitimate ObjStm", xrefStreamPdf("5", "9"), false),
            Triple("/Size = max", xrefStreamPdf(Structure.MAX_XREF_SIZE.toString(), "9"), false),
            Triple("obj 3 is its own container", xrefStreamPdf("5", "9", row3 = inStm(3)), true),
            Triple("ObjStm 4 inside ObjStm 3 (mutual)", xrefStreamPdf("5", "9", row4 = inStm(3)), true),
            Triple("ObjStm /Length inside its own ObjStm", xrefStreamPdf("5", "3 0 R"), true),
            Triple("/Size 10^10", xrefStreamPdf("10000000000", "9"), true),
        )
        for ((name, doc, bad) in cases) {
            assertEquals(name, bad, failsStructure(doc))
            if (!bad) assertNotNull(name, PdfReader.open(doc).obj(PdfRef(3, 0)).dict)
        }
    }

    @Test
    fun encryptScan() {
        for ((s, want) in listOf(
            "/Encrypt 5 0 R" to true, "/Encrypt<</V 5>>" to true, "/Encrypt\n<<" to true,
            "/EncryptMetadata false" to false, "/Encrypt 5 R" to false, "/Encrypt5 0 R" to false,
        )) assertEquals(s, want, Structure.hasEncryptRef(s.toByteArray()))
        // A document the reader cannot open but with a direct /Encrypt dictionary → PDF_ENCRYPTED (#4), not PDF_INVALID.
        val doc = "%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R /Encrypt << /Filter /Standard /V 5 >> >>\n".toByteArray()
        assertEquals("PDF_ENCRYPTED", code { EidPades.prepare(doc, PrepareOptions(signerCert = citizen, chain = chainDer)) })
    }

    // Revocation evidence (complete's OCSP/CRL collection)

    /** The final Catalog's /DSS OCSPs and CRLs. */
    private fun dss(name: String): Pair<List<ByteArray>, List<ByteArray>> {
        val r = PdfReader.open(Golden.file("validate/$name.pdf"))
        val root = r.get(r.trailer, "Root").dict!!
        val d = r.get(root, "DSS").dict!!
        fun streams(k: String) = (r.get(d, k) as? PdfObj.Arr)?.items?.map { r.decodedStream(r.resolve(it)) } ?: emptyList()
        return streams("OCSPs") to streams("CRLs")
    }

    private fun ocspSerials(der: ByteArray): List<java.math.BigInteger> = try {
        val basic = Der.parse(Der.parse(der).child(1).child(0).child(1).value()).children()
        val rd = basic[0].children()
        val i = (if (rd[0].tag == Der.ctx(0)) 1 else 0) + 2
        rd[i].children().map { it.child(0).child(3).bigInt() }
    } catch (_: Exception) {
        emptyList()
    }

    /**
     * Serves the DSS evidence as the responders would: OCSP by the requested serial, CRL by the CDP owner's issuer (else
     * a CRL of an issuer outside the chain — the "wrong issuer" case).
     */
    private fun dssTransport(ocsps: List<ByteArray>, crls: List<ByteArray>, chain: List<Cert>) = EidPadesTransport { method, url, _, body ->
        if (method == "POST") {
            val serial = Der.parse(body!!).child(0).child(0).child(0).child(0).child(3).bigInt()
            ocsps.firstOrNull { serial in ocspSerials(it) } ?: throw IOException("404")
        } else {
            val owner = chain.firstOrNull { url in it.crlDistributionPoints } ?: throw IOException("404")
            val parsed = crls.mapNotNull { der -> Crl.parse(der)?.let { der to it } }
            parsed.firstOrNull { it.second.rawIssuer.contentEquals(owner.rawIssuer) }?.first
                ?: parsed.firstOrNull { p -> chain.none { it.rawIssuer.contentEquals(p.second.rawIssuer) } }?.first
                ?: throw IOException("404")
        }
    }

    @Test
    fun revocationEvidenceV4() {
        val chain = (listOf(citizen) + chainDer).map(Cert::parse)
        val roots = listOf(Cert.parse(root))
        val now = time("2026-10-14T04:00:30Z") // validate manifest `time`
        val cases = listOf(
            "dss-ocsp-stale" to "unavailable", "dss-ocsp-expired" to "unavailable", "dss-ocsp-future" to "unavailable",
            "dss-ocsp-other-serial" to "unavailable", "dss-ocsp-other-issuer" to "unavailable",
            "dss-ocsp-revoked" to "revoked", "dss-ocsp-revoked-after-signing" to "revoked", "dss-crl-revoked" to "revoked",
            "dss-crl-wrong-issuer" to "unavailable", "dss-crl-only" to "ok", "dss-no-revocation" to "unavailable",
        )
        for ((name, want) in cases) {
            val (ocsps, crls) = dss(name)
            val f = Fetcher(dssTransport(ocsps, crls, chain))
            try {
                Ltv.collect(f, now, Date(0), roots, chain)
                assertEquals(name, want, "ok")
            } catch (e: CertificateRevoked) {
                assertEquals("$name: ${e.message}", want, "revoked")
                assertEquals(name, "serial 3ed", e.ref)
            } catch (e: Exception) {
                assertEquals("$name: ${e.message}", want, "unavailable")
                // The citizen is named by serial, never by CN (PII).
                assertTrue("$name: ${e.message}", e.message!!.contains("serial 3ed"))
                assertFalse("$name: ${e.message}", e.message!!.contains("TESTOV"))
            }
        }
    }

    private fun goldenCase(name: String): JSONObject {
        val cases = m.getJSONArray("cases")
        return (0 until cases.length()).map { cases.getJSONObject(it) }.single { it.getString("name") == name }
    }

    private val replay = EidPadesTransport { method, url, _, body ->
        val key = "$method $url ${Hex.encode(Cms.sha256(body ?: ByteArray(0))).substring(0, 16)}"
        val f = m.getJSONObject("http").optString(key)
        if (f.isEmpty()) throw IOException("no golden HTTP fixture for $key")
        Golden.file(f)
    }

    private fun options(c: JSONObject): PrepareOptions {
        val p = c.getJSONObject("prepare")
        return PrepareOptions(
            signerCert = citizen, chain = chainDer, signingTime = time(m.getString("signingTime")),
            reason = p.optString("reason").ifEmpty { null }, claimedRole = p.optString("claimedRole").ifEmpty { null },
            docId = p.optString("docId").ifEmpty { null }, verifyPage = p.optBoolean("verifyPage", false),
            fileName = p.optString("fileName").ifEmpty { null }, lang = p.optString("lang").ifEmpty { null },
        )
    }

    private fun complete(c: JSONObject, input: ByteArray, transport: EidPadesTransport = replay): Pair<Completed, PrepState> {
        val prep = Pades.prepare(input, options(c))
        val name = c.getString("name")
        val now = time(m.getString("now"))
        val nonce = Cms.sha256("golden-nonce:$name".toByteArray() + byteArrayOf(0)).copyOf(8)
        val res = Pades.complete(
            prep.state, Hex.decode(c.getJSONObject("expect").getString("signature")),
            CompleteOptions(tsaUrl = "http://tsa.pki.test/", roots = listOf(root), transport = transport),
            Pades.Env(now = { now }, sleep = {}, nonce = { nonce }),
        )
        return res to PrepState.decode(prep.state)
    }

    /**
     * complete with a revoked citizen OCSP: LTV_UNAVAILABLE, certificateRevoked, not retryable (Go ErrCertificateRevoked)
     * — before, a revoked OCSP was skipped and a clean CRL completed the DSS.
     */
    @Test
    fun completeRevokedIsFinal() {
        val c = goldenCase("quartz-pdf13")
        val cert = Cert.parse(citizen)
        val revoked = dss("dss-ocsp-revoked").first.first { cert.serial in ocspSerials(it) }
        val ocspUrl = cert.ocspServers.first()
        val t = EidPadesTransport { method, url, ct, body -> if (method == "POST" && url == ocspUrl) revoked else replay.send(method, url, ct, body) }
        try {
            complete(c, Golden.file(c.getString("input")), t)
            fail("revoked certificate completed")
        } catch (e: EidPadesException.LtvUnavailable) {
            assertTrue(e.message, e.certificateRevoked)
            assertFalse(e.retryable)
            assertFalse(e.message, e.message!!.contains("TESTOV"))
        }
    }

    /** The output self-check accepts the real output and rejects one whose new signature is not what was prepared. */
    @Test
    fun selfCheck() {
        val first = goldenCase("quartz-pdf13")
        val (d1, _) = complete(first, Golden.file(first.getString("input")))
        val (d2, st) = complete(goldenCase("quartz-pdf13-second"), d1.pdf)
        val prior = Precheck.selfCheck(d2.pdf, st.byteRange, d2.cms, st.revIndex)
        assertEquals(d2.priorCmsSha256, prior.map { it.first })
        assertEquals(d2.priorRevisionSha256, prior.map { it.second })
        fun rejects(f: () -> Unit) = try {
            f()
            false
        } catch (_: Exception) {
            true
        }
        assertTrue(rejects { Precheck.selfCheck(d2.pdf, st.byteRange, d1.cms, st.revIndex) })
        assertTrue(rejects { Precheck.selfCheck(d2.pdf, st.byteRange, d2.cms, 1) })
        val tampered = d2.pdf.copyOf()
        tampered[st.byteRange[1].toInt() - 10] = (tampered[st.byteRange[1].toInt() - 10].toInt() xor 1).toByte()
        assertTrue(rejects { Precheck.selfCheck(tampered, st.byteRange, d2.cms, st.revIndex) })
    }

    /** UTCTime is YYMMDD… (CRL thisUpdate/nextUpdate); GeneralizedTime YYYYMMDD… */
    @Test
    fun asn1Time() {
        fun t(tag: Int, s: String) = Asn1Time.parse(Der.parse(Der.tlv(tag, s.toByteArray())))
        assertEquals(time("2026-10-14T04:00:00Z"), t(Der.UTC_TIME, "261014040000Z"))
        assertEquals(time("1999-12-31T23:59:59Z"), t(Der.UTC_TIME, "991231235959Z"))
        assertEquals(time("2026-10-14T04:00:00Z"), t(Der.GENERALIZED_TIME, "20261014040000Z"))
    }

    // Chain building (Go CheckSignatureFrom / Verify)

    @Test
    fun issuerMustBeCa() {
        val c = Cert.parse(citizen)
        val ca04 = Cert.parse(chainDer[0])
        assertTrue(ca04.isCa && ca04.basicConstraintsValid)
        assertTrue(c.issuedBy(ca04))
        assertFalse("an end-entity certificate cannot issue", c.mayIssue(Cert.KU_CERT_SIGN))
        assertFalse(ca04.issuedBy(c))
        for (der in chainDer + root) {
            val x = Cert.parse(der)
            assertTrue(x.mayIssue(Cert.KU_CERT_SIGN))
            x.maxPathLen?.let {
                assertTrue(x.allowsPath(it))
                assertFalse(x.allowsPath(it + 1))
            }
        }
        assertArrayEquals(ca04.subjectKeyId, ca04.subjectKeyId) // parses
    }
}
