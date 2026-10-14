package mn.eidmongolia.eid.pades

/** Visible signature placement / size / page invalid or the text does not fit (→ REQUEST_INVALID). */
internal class AppearanceException(msg: String) : Exception(msg)

/**
 * Visible signature — APPEARANCE_SPEC.md (pades-client/1), 1:1 port of Go reference `pades/internal/core/appearance.go`.
 * The widget sits on the chosen page with a /Rect; /AP /N is an uncompressed form XObject (verify-page font assets, own
 * QR). Every length/coordinate is an integer in 1/100 pt (h100), written with [num100].
 */
internal object Appearance {
    /** prepareSignature's visible input: placement (displayed page space, h100) and texts. [page] is 1-based, resolved. */
    class Visible(
        val page: Int, val x: Long, val y: Long, val w: Long, val h: Long,
        val name: String, val role: String, val lang: String,
        /** «YYYY-MM-DD HH:MM (+08)» */
        val date: String,
        /** https://ca.eidmongolia.mn/verify/<docId>/<revIndex> */
        val url: String,
    )

    /** Form XObject input: displayed (post-rotation) width/height in h100, page /Rotate 0|90|180|270. */
    class Params(val w: Int, val h: Int, val rotate: Int, val name: String, val role: String, val lang: String, val date: String, val url: String)

    private const val PAD = 400
    private const val GAP = 400
    private const val MIN_MODULE = 100
    private const val MAX_SIZE = 11
    private const val MIN_SIZE = 7
    private const val BODY_DELTA = 2
    private const val LEADING = 125
    private const val DESCENT = 25
    private const val MAX_LINES = 2
    private const val MAX_DEPTH = 32

    /** Max width/height (14400 pt), h100. */
    const val MAX_SIDE = 1440000

    private val labels = mapOf("mn" to "eID Mongolia-аар зурсан", "en" to "Signed with eID Mongolia")

    /** pt → h100: floor(v × 100 + 0.5). */
    fun round100(v: Double): Long = Math.floor(v * 100 + 0.5).toLong()

    /** h100 → PDF number: «N», «N.d», «N.dd» (no trailing zero), «-» when negative. */
    fun num100(v0: Long): String {
        var v = v0
        val sb = StringBuilder()
        if (v < 0) { sb.append('-'); v = -v }
        sb.append(v / 100)
        val f = v % 100
        if (f != 0L) sb.append('.').append(if (f % 10 == 0L) (f / 10).toString() else f.toString().padStart(2, '0'))
        return sb.toString()
    }

    private fun num100(v: Int) = num100(v.toLong())

    private class Rotation(val cm: String, val bw: Int, val bh: Int)

    private fun rotation(rot: Int, w: Int, h: Int): Rotation = when (rot) {
        0 -> Rotation("", w, h)
        90 -> Rotation("0 1 -1 0 ${num100(h)} 0 cm", h, w)
        180 -> Rotation("-1 0 0 -1 ${num100(w)} ${num100(h)} cm", w, h)
        270 -> Rotation("0 -1 1 0 0 ${num100(w)} cm", h, w)
        else -> throw AppearanceException("/Rotate $rot")
    }

    private class Line(val font: Int, val size: Int, val color: String, val text: String)

    /** Form XObject content stream (APPEARANCE_SPEC.md §3). */
    fun content(p: Params): ByteArray {
        val label = labels[p.lang] ?: throw AppearanceException("language ${p.lang}")
        if (!VerifyPage.asciiUrl(p.url)) throw AppearanceException("URL is not ASCII")
        if (p.w <= 0 || p.h <= 0 || p.w > MAX_SIDE || p.h > MAX_SIDE) throw AppearanceException("size")
        val m = try {
            Qr.encode(p.url.toByteArray(Charsets.US_ASCII))
        } catch (e: Exception) {
            throw AppearanceException(e.message ?: "QR")
        }
        val n = m.size
        val mod = (p.h - 2 * PAD) / n
        if (mod < MIN_MODULE) throw AppearanceException("too small (height ≥ ${num100(2 * PAD + n * MIN_MODULE)} pt)")
        val tx = PAD + mod * n + GAP
        val tw = p.w - tx - PAD
        val w = VerifyPage.Writer(PageFont.regular, PageFont.bold)
        var lines: List<Line>? = null
        var f = MAX_SIZE
        while (f >= MIN_SIZE && lines == null && tw > 0) {
            lines = layout(w, p, label, f, tw)
            f--
        }
        if (lines == null) throw AppearanceException("too small (text does not fit)")
        val total = lines.sumOf { it.size * LEADING }
        val cm = rotation(p.rotate, p.w, p.h).cm
        w.op("/EIDVerify <</URL (${p.url})>> BDC")
        if (cm.isNotEmpty()) {
            w.op("q")
            w.op(cm)
        }
        w.op("${VerifyPage.OK} RG")
        w.op("1 w")
        w.op("0.5 0.5 ${num100(p.w - 100)} ${num100(p.h - 100)} re S")
        w.op("q ${num100(mod)} 0 0 ${num100(mod)} ${num100(PAD)} ${num100((p.h - mod * n) / 2)} cm")
        w.op("0 0 0 rg")
        for (r in 0 until n) {
            var c = 0
            while (c < n) {
                if (!m[r][c]) { c++; continue }
                val s = c
                while (c < n && m[r][c]) c++
                w.op("$s ${n - 1 - r} ${c - s} 1 re")
            }
        }
        w.op("f")
        w.op("Q")
        var cursor = p.h - PAD - (p.h - 2 * PAD - total) / 2
        for (l in lines) {
            cursor -= l.size * LEADING
            w.op("${l.color} rg")
            w.op("BT /F${l.font} ${l.size} Tf ${num100(tx)} ${num100(cursor + l.size * DESCENT)} Td ${w.glyphHex(l.font, l.text)} Tj ET")
        }
        if (cm.isNotEmpty()) w.op("Q")
        w.op("EMC")
        return w.ops.toString().toByteArray(Charsets.ISO_8859_1)
    }

    private fun layout(w: VerifyPage.Writer, p: Params, label: String, f: Int, tw: Int): List<Line>? {
        val b = f - BODY_DELTA
        val limit = tw * 10
        val lines = ArrayList<Line>()
        for (t in w.wrapLimit(2, f, p.name, limit, MAX_LINES)) lines += Line(2, f, VerifyPage.TEXT, t)
        if (p.role.isNotEmpty()) for (t in w.wrapLimit(1, b, p.role, limit, MAX_LINES)) lines += Line(1, b, VerifyPage.TEXT, t)
        lines += Line(1, b, VerifyPage.OK, label)
        lines += Line(1, b, VerifyPage.MUTED, p.date)
        var total = 0
        for (l in lines) {
            if (l.text.isEmpty() || w.width1000(l.font, l.size, l.text) > limit) return null
            total += l.size * LEADING
        }
        if (total > p.h - 2 * PAD) return null
        return lines
    }

    /** /AP /N form XObject and its 2 fonts (11 objects): ids = [form, F1 ×5, F2 ×5]; returns the bodies in that order. */
    fun objects(p: Params, ids: IntArray): List<ByteArray> {
        val rot = rotation(p.rotate, p.w, p.h)
        val content = content(p)
        val form = VerifyPage.streamObj(
            " /Type /XObject /Subtype /Form /BBox [0 0 ${num100(rot.bw)} ${num100(rot.bh)}] /Resources << /Font << /F1 ${ids[1]} 0 R /F2 ${ids[6]} 0 R >> >>",
            content,
        )
        return listOf(form) + VerifyPage.fontBodies(ids.copyOfRange(1, 6), PageFont.regular) +
            VerifyPage.fontBodies(ids.copyOfRange(6, 11), PageFont.bold)
    }

    /** Visible signature field/widget body (APPEARANCE_SPEC.md §2); [rect] in user space (h100). */
    fun widget(fieldName: String, rect: LongArray, page: PdfRef, sigId: Int, formId: Int): ByteArray =
        ("<<\n  /Type /Annot\n  /Subtype /Widget\n  /Rect [${rect.joinToString(" ") { num100(it) }}]\n  /P ${page.id} ${page.gen} R\n" +
            "  /F 4\n  /FT /Sig\n  /T ($fieldName)\n  /V $sigId 0 R\n  /AP << /N $formId 0 R >>\n>>").toByteArray(Charsets.ISO_8859_1)

    /** Displayed (x, y, w, h) → user-space /Rect (APPEARANCE_SPEC.md §1). */
    fun rect(box: LongArray, rot: Int, x: Long, y: Long, w: Long, h: Long): LongArray {
        val (b0, b1, b2, b3) = box
        val bw = b2 - b0
        val bh = b3 - b1
        val vw = if (rot == 90 || rot == 270) bh else bw
        val vh = if (rot == 90 || rot == 270) bw else bh
        if (x < 0 || y < 0 || w <= 0 || h <= 0 || x + w > vw || y + h > vh) throw AppearanceException("rectangle outside the page (CropBox)")
        fun pt(vx: Long, vy: Long): Pair<Long, Long> = when (rot) {
            90 -> (b2 - vy) to (b1 + vx)
            180 -> (b2 - vx) to (b3 - vy)
            270 -> (b0 + vy) to (b3 - vx)
            else -> (b0 + vx) to (b1 + vy)
        }
        val (x1, y1) = pt(x, y)
        val (x2, y2) = pt(x + w, y + h)
        return longArrayOf(minOf(x1, x2), minOf(y1, y2), maxOf(x1, x2), maxOf(y1, y2))
    }

    class Geometry(val box: LongArray, val rot: Int)

    /** Page's (inherited) CropBox, else MediaBox, normalised in h100, and /Rotate (0–270). */
    fun geometry(rd: PdfReader, page: PdfDict): Geometry {
        fun inh(key: String): PdfObj? {
            var v = page
            repeat(MAX_DEPTH) {
                val x = rd.get(v, key)
                if (!x.isNull) return x
                v = (rd.get(v, "Parent") as? PdfObj.Dict)?.d ?: return null
            }
            return null
        }
        val b = (inh("CropBox") ?: inh("MediaBox")) as? PdfObj.Arr
        if (b == null || b.items.size != 4) throw AppearanceException("page MediaBox missing")
        val f = LongArray(4) { i ->
            val v = when (val e = rd.resolve(b.items[i])) {
                is PdfObj.Int -> e.v.toDouble()
                is PdfObj.Real -> e.v
                else -> throw AppearanceException("page box invalid")
            }
            if (!v.isFinite() || Math.abs(v) > 1e7) throw AppearanceException("page box invalid")
            round100(v)
        }
        val box = longArrayOf(minOf(f[0], f[2]), minOf(f[1], f[3]), maxOf(f[0], f[2]), maxOf(f[1], f[3]))
        var rot = 0
        val r = inh("Rotate")
        if (r != null) {
            if (r !is PdfObj.Int || r.v % 90 != 0L) throw AppearanceException("page /Rotate is not a multiple of 90")
            rot = (((r.v % 360) + 360) % 360).toInt()
        }
        return Geometry(box, rot)
    }

    /** n-th (1-based) /Page of the /Pages tree in tree order (depth ≤ 32) + the reference it was reached by. */
    fun nthPage(rd: PdfReader, pages: PdfObj, owner: PdfRef?, n0: Int): Pair<PdfDict, PdfRef>? {
        if (n0 < 1) return null
        var n = n0
        fun walk(v: PdfObj, owner: PdfRef?, depth: Int): Pair<PdfDict, PdfRef>? {
            if (depth > MAX_DEPTH) return null
            val ref = v.ref ?: owner
            val d = rd.resolve(v).dict ?: return null
            when (rd.get(d, "Type").name) {
                "Page" -> {
                    n--
                    return if (n == 0 && ref != null) d to ref else null
                }
                "Pages" -> {
                    val kids = (rd.get(d, "Kids") as? PdfObj.Arr)?.items ?: return null
                    for (kid in kids) {
                        walk(kid, ref, depth + 1)?.let { return it }
                        if (n <= 0) break
                    }
                }
            }
            return null
        }
        return walk(pages, owner, 0)
    }

    /** Number of /Page objects in the document's /Pages tree (counts the tree, ignores /Count). */
    fun pageCount(doc: ByteArray): Int {
        val inc = Incremental(doc)
        val rd = inc.reader
        var n = 0
        fun walk(v: PdfObj, depth: Int) {
            if (depth > MAX_DEPTH || n > (1 shl 16)) return
            val d = rd.resolve(v).dict ?: return
            when (rd.get(d, "Type").name) {
                "Page" -> n++
                "Pages" -> (rd.get(d, "Kids") as? PdfObj.Arr)?.items?.forEach { walk(it, depth + 1) }
            }
        }
        walk(inc.root["Pages"], 0)
        return n
    }
}
