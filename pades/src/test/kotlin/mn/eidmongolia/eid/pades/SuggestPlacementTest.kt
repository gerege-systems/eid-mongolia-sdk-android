package mn.eidmongolia.eid.pades

import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test

/**
 * PLACEMENT_SPEC.md §6b: the checks suggestPlacement shares with prepare (Go TestSuggestPlacementErrors, iOS
 * SuggestPlacementTests). Field-for-field results are in [GoldenTest] (expect.suggestion).
 */
class SuggestPlacementTest {
    @Test
    fun errors() {
        val table = Golden.file("input/table-bottom.pdf")
        val enc = Golden.file("input/encrypted.pdf")
        val a = SignatureAppearance(x = 340.0, y = 36.0, width = 220.0, height = 64.0)
        val cases = listOf(
            Triple("not-pdf", "hello".toByteArray() to a, "PDF_INVALID"),
            Triple("encrypted", enc to a, "PDF_ENCRYPTED"),
            Triple("page-beyond", table to SignatureAppearance(page = 2, x = 340.0, y = 36.0, width = 220.0, height = 64.0), "REQUEST_INVALID"),
            Triple("outside", table to SignatureAppearance(x = 400.0, y = 36.0, width = 220.0, height = 64.0, exact = true), "REQUEST_INVALID"),
            Triple("outside-auto", table to SignatureAppearance(x = 400.0, y = 36.0, width = 220.0, height = 64.0), "REQUEST_INVALID"),
            Triple("negative", table to SignatureAppearance(x = -1.0, y = 36.0, width = 220.0, height = 64.0), "REQUEST_INVALID"),
            Triple("zero-size", table to SignatureAppearance(x = 1.0, y = 36.0, width = 0.0, height = 64.0), "REQUEST_INVALID"),
        )
        for ((name, input, code) in cases) {
            try {
                EidPades.suggestPlacement(input.first, input.second)
                fail("$name: expected $code")
            } catch (x: EidPadesException) {
                assertEquals(name, code, x.code)
            }
        }
        val s = EidPades.suggestPlacement(table, SignatureAppearance(x = 340.0, y = 36.0, width = 220.0, height = 64.0, exact = true))
        assertEquals(PlacementStatus.OVERLAP, s.status)
        assertEquals(listOf(340.0, 36.0), listOf(s.x, s.y))
        assertEquals(1, s.pageCount)
        assertEquals(1, s.pages.size)
        // Without exact the same request moves off the table (golden table-bottom-visible).
        assertEquals(PlacementStatus.MOVED, EidPades.suggestPlacement(table, a).status)
    }
}
