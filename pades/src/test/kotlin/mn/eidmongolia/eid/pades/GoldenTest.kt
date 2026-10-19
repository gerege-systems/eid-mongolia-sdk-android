package mn.eidmongolia.eid.pades

import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.IOException
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Conformance against the Go reference golden vectors (`golden/SOURCE` = eid-mongolia-sdk-go tag): every case must
 * reproduce prepare (docId, digest, DTBS, signedAttrs, prepared PDF, ByteRange) and complete (output PDF sha256 = byte
 * identity, CMS, revision hashes) with the manifest's citizen signature, replayed TSA/OCSP/CRL responses, fixed clock and nonce.
 */
class GoldenTest {
    private val m = JSONObject(String(Golden.file("manifest.json"), Charsets.UTF_8))

    private fun file(name: String) = Golden.file(name)
    private fun pem(name: String) = Golden.pem(name)
    private fun time(s: String): Date =
        SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX", Locale.US).parse(s.replace(Regex("\\.\\d+"), ""))!!

    private val citizen = pem("pki/citizen.pem")
    private val chain = listOf(pem("pki/04.pem"), pem("pki/03.pem"), pem("pki/02.pem"))
    private val root = pem("pki/root.pem")

    /** Replay transport: key = "METHOD URL hex(SHA-256(body))[0:16]" (WIRE.md). */
    private val transport = EidPadesTransport { method, url, _, body ->
        val key = "$method $url ${Hex.encode(Cms.sha256(body ?: ByteArray(0))).substring(0, 16)}"
        val f = m.getJSONObject("http").optString(key)
        if (f.isEmpty()) throw IOException("no golden HTTP fixture for $key")
        file(f)
    }

    /** WIRE.md §4: block k = SHA-256(prev ‖ byte(k)), prev starts as the seed; nonce = first 8 bytes. */
    private fun nonce(case: String): ByteArray = Cms.sha256("golden-nonce:$case".toByteArray() + byteArrayOf(0)).copyOf(8)

    @Test
    fun goldenCases() {
        val cases = m.getJSONArray("cases")
        val signingTime = time(m.getString("signingTime"))
        val now = time(m.getString("now"))
        var completed = 0
        val outputs = HashMap<String, ByteArray>() // case:<name> inputs = this run's own earlier outputs (Go golden_test)
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val name = c.getString("name")
            val input = c.getString("input").let {
                if (it.startsWith("case:")) outputs[it.removePrefix("case:")] ?: error("$name: no output of $it") else file(it)
            }
            val p = c.getJSONObject("prepare")
            val e = c.getJSONObject("expect")
            assertEquals("$name inputSha256", e.getString("inputSha256"), Hex.encode(Cms.sha256(input)))
            val opts = PrepareOptions(
                signerCert = citizen, chain = chain, signingTime = signingTime,
                signerName = p.optString("signerName").ifEmpty { null }, reason = p.optString("reason").ifEmpty { null },
                claimedRole = p.optString("claimedRole").ifEmpty { null }, docId = p.optString("docId").ifEmpty { null },
                verifyPage = p.optBoolean("verifyPage", false), fileName = p.optString("fileName").ifEmpty { null },
                lang = p.optString("lang").ifEmpty { null },
                appearance = p.optJSONObject("appearance")?.let {
                    SignatureAppearance(
                        page = it.optInt("page", 0), x = it.getDouble("x"), y = it.getDouble("y"),
                        width = it.getDouble("width"), height = it.getDouble("height"), lang = it.optString("lang").ifEmpty { null },
                    )
                },
            )
            val want = e.optString("error").ifEmpty { null }
            val prep = try {
                Pades.prepare(input, opts)
            } catch (x: EidPadesException) {
                assertEquals("$name error (${x.message})", want, x.code)
                continue
            }
            if (want != null) fail("$name: expected $want")
            assertEquals("$name docId", e.getString("docId"), prep.docId)
            assertEquals("$name digest", e.getString("digest"), Hex.encode(prep.digest))
            assertEquals("$name signedAttrs", e.getString("signedAttrs"), Hex.encode(PrepState.decode(prep.state).signedAttrs))
            assertEquals("$name dtbs", e.getString("dtbs"), Hex.encode(prep.dtbs))
            val st = PrepState.decode(prep.state)
            assertEquals("$name preparedSha256", e.getString("preparedSha256"), Hex.encode(Cms.sha256(st.pdf)))
            val br = e.getJSONArray("byteRange")
            assertArrayEquals("$name byteRange", LongArray(4) { br.getLong(it) }, st.byteRange)

            val res = Pades.complete(
                prep.state, Hex.decode(e.getString("signature")),
                CompleteOptions(tsaUrl = "http://tsa.pki.test/", roots = listOf(root), transport = transport),
                Pades.Env(now = { now }, sleep = {}, nonce = { nonce(name) }),
            )
            assertEquals("$name cmsSha256", e.getString("cmsSha256"), Hex.encode(Cms.sha256(res.cms)))
            assertEquals("$name sigRevSha256", e.getString("sigRevSha256"), res.sigRevSha256)
            assertEquals("$name revIndex", e.getInt("revIndex"), res.revIndex)
            assertEquals("$name hasPage", e.optBoolean("hasPage", false), res.hasPage)
            assertEquals("$name pageSha256", e.optString("pageSha256").ifEmpty { null }, res.pageSha256)
            val prior = e.optJSONArray("priorCmsSha256")
            assertEquals("$name priorCmsSha256", (0 until (prior?.length() ?: 0)).map { prior!!.getString(it) }, res.priorCmsSha256)
            // Each prior signature's revision hash = its own sigRevSha256 (inputs "case:<prev>" carry one prior signature).
            val prev = c.getString("input").takeIf { it.startsWith("case:") }?.removePrefix("case:")
            val wantPriorRev = prev?.let { pn ->
                listOf((0 until cases.length()).map { cases.getJSONObject(it) }.single { it.getString("name") == pn }.getJSONObject("expect").getString("sigRevSha256"))
            } ?: emptyList()
            assertEquals("$name priorRevisionSha256", wantPriorRev, res.priorRevisionSha256)
            assertEquals("$name outSha256", e.getString("outSha256"), res.outSha256)
            checkRegistration(name, res, p.optString("fileName").ifEmpty { null })
            outputs[name] = res.pdf
            completed++
        }
        val okCases = (0 until cases.length()).count { cases.getJSONObject(it).getJSONObject("expect").optString("error").isEmpty() }
        assertTrue("no complete case ran", okCases > 0)
        assertEquals("completed cases", okCases, completed)

        // Visible signature on a signed document without a verify page (no docId) → REQUEST_INVALID (verify URL needs it).
        val noPage = outputs["quartz-pdf13-nopage"] ?: error("quartz-pdf13-nopage output")
        val vis = SignatureAppearance(x = 36.0, y = 36.0, width = 220.0, height = 64.0)
        try {
            Pades.prepare(noPage, PrepareOptions(signerCert = citizen, chain = chain, signingTime = signingTime, appearance = vis))
            fail("visible without docId: expected REQUEST_INVALID")
        } catch (x: EidPadesException) {
            assertEquals("visible without docId", "REQUEST_INVALID", x.code)
        }
    }

    /**
     * [Completed.registration] = Go `pades.Registration`: fileName from prepare, pageSha256 only for revIndex 1, prior
     * signatures only as priorCmsSha256 (never also as priorRevisionSha256 — the CA answers 400), signerEtsi.
     */
    private fun checkRegistration(name: String, done: Completed, fileName: String?) {
        assertEquals("$name fileName", Pades.cleanFileName(fileName), done.fileName)
        if (done.fileName == null || done.revIndex == 1 && !done.hasPage) {
            try {
                done.registration(Medium.TOKEN)
                fail("$name: registration without fileName/page")
            } catch (_: EidPadesException.RequestInvalid) {
            }
            return
        }
        val r = done.registration(Medium.PHONE, sessionId = "00000000-0000-4000-8000-000000000001")
        assertEquals(name, done.docId, r.docID)
        assertEquals(name, done.revIndex, r.revIndex)
        assertEquals(name, done.fileName, r.fileName)
        assertEquals(name, Base64Std.encode(done.cms), r.cms)
        assertEquals(name, if (done.revIndex == 1) done.pageSha256 else null, r.pageSha256)
        assertEquals(name, done.priorCmsSha256.ifEmpty { null }, r.priorCmsSha256)
        assertEquals(name, null, r.priorRevisionSha256)
        assertEquals(name, done.priorRevisionSha256, r.priorSignatures.map { it.revisionSha256 })
        assertEquals(name, "PNOMN-00000000000", r.signerEtsi)
        val json = JSONObject(r.toJson())
        val want = mutableSetOf("docID", "revIndex", "medium", "sessionID", "cms", "fileName", "inSha256", "sigRevSha256", "outSha256", "signerEtsi")
        want += if (done.revIndex == 1) "pageSha256" else "priorCmsSha256"
        assertEquals(name, want, json.keySet())
        assertEquals(name, "phone", json.getString("medium"))
        assertEquals(name, done.fileName, json.getString("fileName"))
    }

    @Test
    fun wireExamples() {
        // WIRE.md §1 example request.
        val req = Tsa.request(Cms.sha256("example signature bytes".toByteArray()), java.math.BigInteger("9817c2613697bd4d", 16))
        assertEquals(
            "3044020101303130" + "0d060960864801650304020105000420" +
                "9a68ee19b28bcddef1da4964977ae0a070eafb5ccfcbb300b03d4fb9f1ebbfd6" + "0209009817c2613697bd4d0101ff",
            Hex.encode(req),
        )
        // WIRE.md §2 example (golden citizen, issuer 04).
        assertEquals(
            "30433041303f303d303b300906052b0e03021a0500" + "041466d7a67d8f5b73eb50670437691b40eaf94c3b86" +
                "04141722dd2dafa7e06b2a74a1c92a1d0ba6da740df9" + "020203ed",
            Hex.encode(Ocsp.request(Cert.parse(citizen), Cert.parse(chain[0]))),
        )
    }
}
