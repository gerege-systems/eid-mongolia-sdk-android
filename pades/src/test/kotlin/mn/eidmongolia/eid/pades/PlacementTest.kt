package mn.eidmongolia.eid.pades

import org.json.JSONArray
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayOutputStream

/**
 * PLACEMENT_SPEC.md conformance: the occupancy scanner and candidate search against the Go reference vectors
 * (golden/placement/vectors.json, box-for-box), plus robustness on malformed content / broken streams. iOS
 * `PlacementTests.swift` runs the same checks.
 */
class PlacementTest {
    private class Run(val box: LongArray, val rot: Int, val boxes: List<LongArray>?, val result: StampPlacement.Result)

    /** Scanner + choice exactly as SignatureRevision.prepare runs them. */
    private fun run(doc: ByteArray, page: Int, q: DoubleArray): Run {
        val inc = Incremental(doc)
        val rd = inc.reader
        val p = Appearance.nthPage(rd, inc.root["Pages"], inc.rootRef, page) ?: error("page $page")
        val g = Appearance.geometry(rd, p.first)
        val x = Appearance.round100(q[0])
        val y = Appearance.round100(q[1])
        val w = Appearance.round100(q[2])
        val h = Appearance.round100(q[3])
        val boxes = try { Occupancy.scan(rd, p.first, p.second.id, g.box) } catch (_: Exception) { null }
        return Run(g.box, g.rot, boxes, StampPlacement.choose(rd, p.first, p.second.id, g.box, g.rot, x, y, w, h))
    }

    private fun longs(a: JSONArray) = LongArray(a.length()) { a.getLong(it) }

    @Test
    fun vectors() {
        val vs = JSONArray(String(Golden.file("placement/vectors.json"), Charsets.UTF_8))
        assertEquals(29, vs.length())
        for (i in 0 until vs.length()) {
            val v = vs.getJSONObject(i)
            val name = v.getString("name")
            val e = v.getJSONObject("expect")
            val req = v.getJSONArray("request")
            val got = run(Golden.file(v.getString("input")), v.getInt("page"), DoubleArray(4) { req.getDouble(it) })
            assertEquals("$name box", longs(e.getJSONArray("box")).toList(), got.box.toList())
            assertEquals("$name rotate", e.getInt("rotate"), got.rot)
            val want = e.optJSONArray("boxes")?.let { b -> (0 until b.length()).map { longs(b.getJSONArray(it)).toList() } }
            assertEquals("$name boxes", want, got.boxes?.map { it.toList() })
            assertEquals("$name status", e.getString("status"), got.result.status.wire)
            assertEquals("$name position", listOf(e.getLong("x"), e.getLong("y")), listOf(got.result.x, got.result.y))
        }
    }

    /** Go TestPlacementCandidates: the trial order on A4 with the portal's default request. */
    @Test
    fun candidates() {
        val c = StampPlacement.candidates(59528, 84189, 34000, 3600, 22000, 6400)
        assertEquals(listOf(34000L to 3600L, 3528L to 3600L, 34000L to 4800L), c.take(3))
        val n = (84189 - 3600 - 3600 - 6400) / 1200
        assertEquals(2 + 2 * n, c.size)
        assertEquals(3528L to 4800L, c[2 + n])
        val centred = StampPlacement.candidates(1000, 3000, 400, 0, 200, 100)
        assertEquals(3, centred.size)
        assertEquals(400L to 1200L, centred[1])
    }

    // ── Robustness ──

    /** Go placement_test fxPDF: a minimal classic-xref PDF, objs[0] = object 1 (Catalog). */
    private fun pdf(objs: List<ByteArray>): ByteArray {
        val b = ByteArrayOutputStream()
        fun w(s: String) = b.write(s.toByteArray(Charsets.ISO_8859_1))
        w("%PDF-1.4\n%âãÏÓ\n")
        val offs = ArrayList<Int>()
        objs.forEachIndexed { i, o ->
            offs += b.size()
            w("${i + 1} 0 obj\n")
            b.write(o)
            w("\nendobj\n")
        }
        val x = b.size()
        w("xref\n0 ${objs.size + 1}\n0000000000 65535 f \n")
        for (o in offs) w(String.format("%010d 00000 n \n", o))
        w("trailer\n<< /Size ${objs.size + 1} /Root 1 0 R >>\nstartxref\n$x\n%%EOF\n")
        return b.toByteArray()
    }

    private fun stream(dict: String, data: ByteArray): ByteArray =
        "<< $dict/Length ${data.size} >>\nstream\n".toByteArray(Charsets.ISO_8859_1) + data + "\nendstream".toByteArray(Charsets.ISO_8859_1)

    private fun s(x: String) = x.toByteArray(Charsets.ISO_8859_1)

    /** One letter page whose content is [content] (+ a self-recursive form /X). */
    private fun page(content: ByteArray, filter: String = ""): ByteArray = pdf(
        listOf(
            s("<< /Type /Catalog /Pages 2 0 R >>"),
            s("<< /Type /Pages /Kids [3 0 R] /Count 1 >>"),
            s("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> /XObject << /X 6 0 R >> >> /Contents 4 0 R >>"),
            stream(filter, content),
            s("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /FirstChar 32 /Widths [250 300] >>"),
            stream("/Type /XObject /Subtype /Form /BBox [0 0 1 1] /Resources << /XObject << /X 6 0 R >> >> ", content),
        ),
    )

    private fun status(doc: ByteArray) = run(doc, 1, doubleArrayOf(340.0, 36.0, 220.0, 64.0)).result.status

    /** Go compress/zlib BestCompression of "0 g 340 36 220 64 re f" (fills the requested spot). */
    private val zlib = intArrayOf(
        0x78, 0xda, 0x32, 0x50, 0x48, 0x57, 0x30, 0x36, 0x31, 0x50, 0x30, 0x36, 0x53, 0x30, 0x32, 0x32,
        0x50, 0x30, 0x33, 0x51, 0x28, 0x4a, 0x55, 0x48, 0x03, 0x04, 0x00, 0x00, 0xff, 0xff, 0x31, 0xed, 0x04, 0xb3,
    ).map { it.toByte() }.toByteArray()

    /** zlib framing (RFC 1950): header, truncation and Adler-32 errors make the page unscannable, never a crash. */
    @Test
    fun brokenFlate() {
        assertEquals("0 g 340 36 220 64 re f", String(Occupancy.inflate(zlib, 1 shl 20), Charsets.ISO_8859_1))
        val flate = "/Filter /FlateDecode "
        assertEquals(StampPlacement.Status.MOVED, status(page(zlib, flate)))
        val badAdler = zlib.copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() }
        val badHeader = zlib.copyOf().also { it[1] = (it[1].toInt() xor 1).toByte() }
        // FDICT (0x78 0x20, FCHECK valid): Go accepts DICTID 1 (Adler-32 of no dictionary), rejects any other.
        val body = zlib.copyOfRange(2, zlib.size)
        val dict1 = byteArrayOf(0x78, 0x20, 0, 0, 0, 1) + body
        val dict2 = byteArrayOf(0x78, 0x20, 0, 0, 0, 2) + body
        val truncated = zlib.copyOf(zlib.size - 3) // Adler-32 cut
        val truncatedData = zlib.copyOf(zlib.size - 8) // deflate data cut
        val trailing = zlib + s(" AB") // bytes after the checksum are ignored
        for ((name, data, want) in listOf(
            Triple("adler", badAdler, StampPlacement.Status.UNSCANNED),
            Triple("header", badHeader, StampPlacement.Status.UNSCANNED),
            Triple("fdict-1", dict1, StampPlacement.Status.MOVED),
            Triple("fdict-2", dict2, StampPlacement.Status.UNSCANNED),
            Triple("truncated", truncated, StampPlacement.Status.UNSCANNED),
            Triple("truncated-data", truncatedData, StampPlacement.Status.UNSCANNED),
            Triple("empty", ByteArray(0), StampPlacement.Status.UNSCANNED),
            Triple("trailing", trailing, StampPlacement.Status.MOVED),
        )) {
            assertEquals(name, want, status(page(data, flate)))
        }
        assertEquals(StampPlacement.Status.UNSCANNED, status(page(zlib, "/Filter /FlateDecode /DecodeParms << /Predictor 12 >> ")))
        assertEquals(StampPlacement.Status.MOVED, status(page(zlib, "/Filter [/FlateDecode] /DecodeParms [null] ")))
        assertEquals(StampPlacement.Status.UNSCANNED, status(page(zlib, "/Filter [/FlateDecode /FlateDecode] ")))
        try {
            Occupancy.inflate(zlib, 10)
            fail("output over the limit")
        } catch (_: Occupancy.Unscannable) {
        }
    }

    /**
     * Arbitrary content bytes (Go FuzzOccupancy): the scanner never throws past its boundary, loops or escapes its
     * limits; it either returns boxes or reports unscannable. Deterministic PRNG (same xorshift as iOS).
     */
    @Test
    fun arbitraryContent() {
        var seed = -0x61c8864680b583ebL // 0x9E3779B97F4A7C15
        fun next(): Long {
            seed = seed xor (seed shl 13)
            seed = seed xor (seed ushr 7)
            seed = seed xor (seed shl 17)
            return seed
        }
        fun rnd(n: Int) = java.lang.Long.remainderUnsigned(next(), n.toLong()).toInt()
        val alphabet = s("0123456789.-+ \n\r\t()<>[]{}/%#\\qQcmwgGrRkKsSfFbBnWhlvyreTcTwTzTLTfTdTDTmTjTJ'\"*DoBIIDEIBTETshcsCS")
        val docs = mutableListOf(
            s("BT /F1 12 Tf (abc) Tj ET q 1 0 0 1 0 0 cm 0 0 10 10 re f Q BI /W 1 ID x EI"),
            s("q 1e308 0 0 1e308 0 0 cm 1 w 0 0 m 99999999999999999999999999999 1 l S Q"),
            s("BT /F1 99999999999999999999999999999 Tf 99999999999999999999999999999 Tz (aaaa) Tj ET"),
            s("/X Do"),
            s("[".repeat(40)),
            s("q ".repeat(70)),
            s("BI /W 1 ID"),
            s("(unterminated \\"),
            s("<abc"),
        )
        repeat(300) { docs += ByteArray(rnd(400)) { alphabet[rnd(alphabet.size)] } }
        repeat(100) { docs += ByteArray(rnd(300)) { next().toByte() } }
        for (content in docs) {
            val got = run(page(content), 1, doubleArrayOf(340.0, 36.0, 220.0, 64.0))
            if (got.result.status == StampPlacement.Status.UNSCANNED) assertNull(got.boxes) else assertNotNull(got.boxes)
        }
        // The self-recursive form hits the depth limit, never recursion without end.
        assertEquals(StampPlacement.Status.UNSCANNED, status(page(s("/X Do"))))
        assertTrue(docs.size > 400)
    }
}
