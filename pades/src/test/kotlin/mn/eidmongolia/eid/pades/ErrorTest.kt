package mn.eidmongolia.eid.pades

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

/** Stable error codes (Go `pades/errors.go`) for the light prechecks and complete's input checks. */
class ErrorTest {
    private val citizen = Golden.pem("pki/citizen.pem")
    private val chain = listOf("04", "03", "02").map { Golden.pem("pki/$it.pem") }
    private val pdf = Golden.file("input/quartz-pdf13.pdf")
    private val DOC = "0b2f8a1e-6c3d-4e5f-8a9b-1c2d3e4f5a6b"
    private val T = java.util.Date(1_791_950_400_000L)

    private fun code(f: () -> Unit): String = try {
        f()
        "OK"
    } catch (e: EidPadesException) {
        e.code
    }

    @Test
    fun prepareCodes() {
        val o = PrepareOptions(signerCert = citizen, chain = chain)
        assertEquals("PDF_TOO_LARGE", code { EidPades.prepare(ByteArray(Pades.MAX_INPUT_BYTES + 1), o) })
        assertEquals("PDF_INVALID", code { EidPades.prepare("hello".toByteArray(), o) })
        assertEquals("SIGNER_INVALID", code { EidPades.prepare(pdf, PrepareOptions(signerCert = byteArrayOf(1, 2, 3))) })
        assertEquals("SIGNER_INVALID", code { EidPades.prepare(pdf, PrepareOptions(signerCert = citizen)) }) // test issuer not embedded
        assertEquals("REQUEST_INVALID", code { EidPades.prepare(pdf, PrepareOptions(signerCert = citizen, chain = chain, docId = "NOT-A-UUID")) })
        assertEquals("REQUEST_INVALID", code { EidPades.prepare(pdf, PrepareOptions(signerCert = citizen, chain = chain, lang = "de")) })
        assertEquals("REQUEST_INVALID", code { EidPades.prepare(pdf, PrepareOptions(signerCert = citizen, chain = chain, verifyPage = true)) })
        assertEquals("PDF_INVALID", code { EidPades.prepare("%PDF-1.4\nbroken".toByteArray(), o) })
        assertEquals("OK", code { EidPades.prepare(pdf, o) })
    }

    /** Go TestAppearanceRejects — APPEARANCE_SPEC.md §1, §3: bad placement/size or text that does not fit → REQUEST_INVALID. */
    @Test
    fun appearanceRejects() {
        val ok = SignatureAppearance(x = 36.0, y = 36.0, width = 220.0, height = 64.0) // quartz-pdf13: 612 × 792, 1 page
        fun opts(a: SignatureAppearance, signerName: String? = null, claimedRole: String? = null) = PrepareOptions(
            signerCert = citizen, chain = chain, verifyPage = true, fileName = "test.pdf", signerName = signerName,
            claimedRole = claimedRole, appearance = a,
        )
        fun at(page: Int = 0, x: Double = 36.0, y: Double = 36.0, width: Double = 220.0, height: Double = 64.0, lang: String? = null) =
            SignatureAppearance(page, x, y, width, height, lang)
        val cases = mapOf(
            "page missing" to opts(at(page = 2)),
            "negative page" to opts(at(page = -1)),
            "off the page (x)" to opts(at(x = 500.0)),
            "off the page (y)" to opts(at(y = 760.0)),
            "too low (QR < 1 pt)" to opts(at(height = 44.0)),
            "too narrow (text)" to opts(at(width = 90.0)),
            "zero width" to opts(at(width = 0.0)),
            "NaN" to opts(at(x = Double.NaN)),
            "> 14400" to opts(at(height = 14401.0)),
            "lang" to opts(at(lang = "de")),
            "/Name not writable" to opts(ok, signerName = "a stream b"),
            "role control char" to opts(ok, claimedRole = "a\u200eb"),
        )
        for ((name, o) in cases) assertEquals(name, "REQUEST_INVALID", code { EidPades.prepare(pdf, o) })
        // Minimum (45 pt high) is accepted and differs from the invisible DTBS (same docId and signing time).
        fun fixed(a: SignatureAppearance?) = PrepareOptions(
            signerCert = citizen, chain = chain, verifyPage = true, fileName = "test.pdf", docId = DOC, signingTime = T, appearance = a,
        )
        val p45 = EidPades.prepare(pdf, fixed(at(height = 45.0)))
        val inv = EidPades.prepare(pdf, fixed(null))
        assertFalse(p45.dtbs.contentEquals(inv.dtbs))
    }

    @Test
    fun completeCodes() {
        val prep = EidPades.prepare(pdf, PrepareOptions(signerCert = citizen, chain = chain))
        val noNet = CompleteOptions(transport = { _, _, _, _ -> throw java.io.IOException("offline") })
        assertEquals("STATE_INVALID", code { Pades.complete(byteArrayOf(1, 2), ByteArray(256), noNet) })
        val tampered = prep.state.copyOf().also { it[it.size - 10] = (it[it.size - 10] + 1).toByte() }
        assertEquals("STATE_INVALID", code { Pades.complete(tampered, ByteArray(256), noNet) })
        assertEquals("SIGNATURE_INVALID", code { Pades.complete(prep.state, ByteArray(256), noNet) })
    }

    @Test
    fun textRules() {
        assertEquals("<4a6f686e20446f65>", SignatureRevision.sigText("  John Doe ", 120))
        assertEquals("<feff041104300442>", SignatureRevision.sigText("Бат", 120))
        assertEquals(null, SignatureRevision.sigText("a\u0007b", 120))
        assertEquals(null, SignatureRevision.sigText("x endobj", 120))
        assertEquals(null, SignatureRevision.sigText("x".repeat(128), 127))
        assertEquals("(D:20261014120000+08'00')", SignatureRevision.pdfDate(java.util.Date(1_791_950_400_000L)))
        assertEquals("14.1 KB", VerifyPage.humanSize(14452))
        assertEquals("ca.eidmongolia.mn/verify", VerifyPage.urlHost("https://ca.eidmongolia.mn/verify/abc"))
        assertEquals(null, Pades.cleanFileName("​ \u0007"))
        assertFalse(Pades.cleanFileName("a".repeat(121)) != null)
    }
}
