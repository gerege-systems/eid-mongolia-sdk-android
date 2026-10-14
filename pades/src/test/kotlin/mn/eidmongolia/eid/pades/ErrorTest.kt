package mn.eidmongolia.eid.pades

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

/** Stable error codes (Go `pades/errors.go`) for the light prechecks and complete's input checks. */
class ErrorTest {
    private val citizen = Golden.pem("pki/citizen.pem")
    private val chain = listOf("04", "03", "02").map { Golden.pem("pki/$it.pem") }
    private val pdf = Golden.file("input/quartz-pdf13.pdf")

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
