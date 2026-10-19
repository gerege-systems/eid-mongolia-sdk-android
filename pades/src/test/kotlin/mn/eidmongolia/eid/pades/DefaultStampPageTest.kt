package mn.eidmongolia.eid.pades

import org.junit.Assert.assertEquals
import org.junit.Test

/** PLACEMENT_SPEC.md §1a: appearance.page 0 = the last page that is not an eID verify page (Go TestDefaultStampPage, iOS DefaultStampPageTests). */
class DefaultStampPageTest {
    private val docA = "f5a6b7c8-d9e0-4f1a-8b2c-3d4e5f607182"

    private fun check(doc: ByteArray, docId: String, page: Int, n: Int, name: String) =
        assertEquals(name, page to n, Appearance.defaultStampPage(doc, Precheck.VERIFY_URL + docId))

    @Test
    fun defaultStampPage() {
        check(Golden.file("input/two-verify.pdf"), docA, 1, 3, "two verify pages")
        check(Golden.file("input/two-verify.pdf"), "a6b7c8d9-e0f1-4a2b-9c3d-4e5f60718293", 3, 3, "other docId")
        check(Golden.file("input/fake-verify.pdf"), docA, 2, 2, "fake verify")
        check(Golden.file("input/quartz-pdf13.pdf"), docA, 1, 1, "no verify page")
    }

    /** Hand-built pages: a direct /Link annotation, every page a verify page → the last page. */
    @Test
    fun allVerifyPages() {
        val uri = Precheck.VERIFY_URL + docA
        val objs = listOf(
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots [<< /Subtype /Link /A << /S /URI /URI ($uri) >> >>] >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots [5 0 R] >>",
            "<< /Type /Annot /Subtype /Link /Rect [0 0 1 1] /A << /S /URI /URI ($uri) >> >>",
        )
        val b = StringBuilder("%PDF-1.4\n")
        val offs = ArrayList<Int>()
        objs.forEachIndexed { i, o ->
            offs.add(b.length)
            b.append("${i + 1} 0 obj\n$o\nendobj\n")
        }
        val x = b.length
        b.append("xref\n0 ${objs.size + 1}\n0000000000 65535 f \n")
        offs.forEach { b.append(String.format(java.util.Locale.ROOT, "%010d 00000 n \n", it)) }
        b.append("trailer\n<< /Size ${objs.size + 1} /Root 1 0 R >>\nstartxref\n$x\n%%EOF\n")
        check(b.toString().toByteArray(Charsets.US_ASCII), docA, 2, 2, "all verify")
    }
}
