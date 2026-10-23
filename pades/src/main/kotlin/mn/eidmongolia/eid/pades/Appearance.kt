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
        /** PLACEMENT_SPEC §6a: never move the stamp; the scan only reports OVERLAP. */
        val exact: Boolean = false,
        /** APPEARANCE_SPEC §6: signature / organization-stamp images (null = none); [w], [h] then cover the stamp's overflow. */
        val sig: PdfImage? = null,
        val stamp: PdfImage? = null,
    )

    /** Form XObject input: displayed (post-rotation) width/height in h100, page /Rotate 0|90|180|270. */
    class Params(
        val w: Int, val h: Int, val rotate: Int, val name: String, val role: String, val lang: String, val date: String, val url: String,
        /** APPEARANCE_SPEC §6 (null = none; both null = the §3 layout, byte-identical to golden v9). */
        val sig: PdfImage? = null,
        val stamp: PdfImage? = null,
    )

    /** PDF image limits (APPEARANCE_SPEC §6.1). */
    const val MAX_IMAGE_SIDE = 1600
    const val MAX_IMAGE_ALPHA_BYTES = 300 shl 10

    /**
     * Go `core.CheckPDFImage` (APPEARANCE_SPEC §6.1): 1 ≤ w, h ≤ 1600; colour 0–255; 1 ≤ alpha ≤ 300 KiB; alpha is one zlib
     * stream (Adler-32 verified, nothing after it) inflating to exactly w·h bytes. No preset dictionary: the FDICT bit
     * is rejected even with DICTID 1 (which `java.util.zip.Inflater` and Go `compress/zlib` would accept).
     */
    fun checkImage(im: PdfImage) {
        fun bad(msg: String) = AppearanceException("image: $msg")
        if (im.width < 1 || im.height < 1 || im.width > MAX_IMAGE_SIDE || im.height > MAX_IMAGE_SIDE) throw bad("size 1…1600 px")
        if (im.color.size != 3 || im.color.any { it < 0 || it > 255 }) throw bad("colour 0…255")
        if (im.alpha.isEmpty() || im.alpha.size > MAX_IMAGE_ALPHA_BYTES) throw bad("alpha 1 B…300 KiB")
        if (im.alpha.size >= 2 && im.alpha[1].toInt() and 0x20 != 0) throw bad("alpha preset dictionary (FDICT)")
        val want = im.width.toLong() * im.height
        val inf = java.util.zip.Inflater()
        try {
            inf.setInput(im.alpha)
            val buf = ByteArray(64 shl 10)
            var n = 0L
            while (!inf.finished()) {
                val k = inf.inflate(buf)
                if (k == 0 && inf.needsInput()) throw bad("alpha is not exactly width×height bytes (or damaged)")
                n += k
                if (n > want) throw bad("alpha is not exactly width×height bytes (or damaged)")
            }
            if (n != want || inf.remaining != 0) throw bad("alpha is not exactly width×height bytes (or damaged)")
        } catch (e: java.util.zip.DataFormatException) {
            throw bad("alpha is not zlib")
        } finally {
            inf.end()
        }
    }

    /** §6.3 geometry (h100): border box height, QR/text row height, image placements [dx dy dw dh] (null = none). */
    private class ImageLayout(val boxH: Int, val rowH: Int, val sig: IntArray?, val stamp: IntArray?)

    /** Go apFit: fit-contain iw × ih px into bw × bh (h100), 64-bit products, the scaled side ≥ 1. */
    private fun fit(iw: Int, ih: Int, bw: Int, bh: Int): Pair<Int, Int> =
        if (iw.toLong() * bh >= ih.toLong() * bw) bw to maxOf(1L, bw.toLong() * ih / iw).toInt()
        else maxOf(1L, bh.toLong() * iw / ih).toInt() to bh

    private fun layoutImages(p: Params): ImageLayout {
        if (p.sig == null && p.stamp == null) return ImageLayout(p.h, p.h, null, null)
        val small = AppearanceException("too small (appearance with images)")
        val boxH = if (p.stamp != null) p.h * 4 / 5 else p.h
        val band = boxH * 9 / 22
        val rowH = boxH - band
        val sh = band * 14 / 15
        val sy = rowH - band * 2 / 15
        var sx = (p.w - p.w * 15 / 22) / 2
        var sw = p.w * 15 / 22
        var stamp: IntArray? = null
        if (p.stamp != null) {
            val d = boxH * 2 / 3
            val qx = minOf(p.w * 41 / 60 - d / 2, p.w - d)
            if (qx < 0 || d <= 0) throw small
            val (dw, dh) = fit(p.stamp.width, p.stamp.height, d, d)
            stamp = intArrayOf(qx + (d - dw) / 2, p.h - d + (d - dh) / 2, dw, dh)
            sx = p.w / 30
            sw = qx + d / 2 - sx
        }
        var sig: IntArray? = null
        if (p.sig != null) {
            if (sw <= 0 || sh <= 0) throw small
            val (dw, dh) = fit(p.sig.width, p.sig.height, sw, sh)
            val dx = if (p.stamp == null) sx + (sw - dw) / 2 else sx
            sig = intArrayOf(dx, sy + (sh - dh) / 2, dw, dh)
        }
        return ImageLayout(boxH, rowH, sig, stamp)
    }

    /** `q dw 0 0 dh dx dy cm /<name> Do Q` (APPEARANCE_SPEC §6.4). */
    private fun drawImage(w: VerifyPage.Writer, name: String, r: IntArray) =
        w.op("q ${num100(r[2])} 0 0 ${num100(r[3])} ${num100(r[0])} ${num100(r[1])} cm /$name Do Q")

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
        if (p.stamp != null && p.role.isEmpty()) throw AppearanceException("stamp image only on behalf of an organization (claimedRole)")
        p.sig?.let(::checkImage)
        p.stamp?.let(::checkImage)
        val il = layoutImages(p)
        val rowH = il.rowH
        val m = try {
            Qr.encode(p.url.toByteArray(Charsets.US_ASCII))
        } catch (e: Exception) {
            throw AppearanceException(e.message ?: "QR")
        }
        val n = m.size
        val mod = (rowH - 2 * PAD) / n
        if (mod < MIN_MODULE) throw AppearanceException("too small (height ≥ ${num100(2 * PAD + n * MIN_MODULE)} pt)")
        val tx = PAD + mod * n + GAP
        val tw = p.w - tx - PAD
        val w = VerifyPage.Writer(PageFont.regular, PageFont.bold)
        var lines: List<Line>? = null
        var f = MAX_SIZE
        while (f >= MIN_SIZE && lines == null && tw > 0) {
            lines = layout(w, p, label, f, tw, rowH)
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
        w.op("0.5 0.5 ${num100(p.w - 100)} ${num100(il.boxH - 100)} re S")
        if (p.sig != null || p.stamp != null) {
            w.op("0.5 w")
            w.op("0 ${num100(rowH)} m ${num100(p.w)} ${num100(rowH)} l S")
        }
        il.sig?.let { drawImage(w, "Sig", it) }
        w.op("q ${num100(mod)} 0 0 ${num100(mod)} ${num100(PAD)} ${num100((rowH - mod * n) / 2)} cm")
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
        var cursor = rowH - PAD - (rowH - 2 * PAD - total) / 2
        for (l in lines) {
            cursor -= l.size * LEADING
            w.op("${l.color} rg")
            w.op("BT /F${l.font} ${l.size} Tf ${num100(tx)} ${num100(cursor + l.size * DESCENT)} Td ${w.glyphHex(l.font, l.text)} Tj ET")
        }
        il.stamp?.let { drawImage(w, "Stamp", it) }
        if (cm.isNotEmpty()) w.op("Q")
        w.op("EMC")
        return w.ops.toString().toByteArray(Charsets.ISO_8859_1)
    }

    private fun layout(w: VerifyPage.Writer, p: Params, label: String, f: Int, tw: Int, rowH: Int): List<Line>? {
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
        if (total > rowH - 2 * PAD) return null
        return lines
    }

    /** Number of objects [objects] writes: 11 (form, F1 ×5, F2 ×5) + 2 per image (Go AppearanceObjectCount). */
    fun objectCount(sig: PdfImage?, stamp: PdfImage?): Int = 11 + (if (sig != null) 2 else 0) + (if (stamp != null) 2 else 0)

    /**
     * /AP /N form XObject, its 2 fonts and 2 objects per image (APPEARANCE_SPEC §6.2): ids = [form, F1 ×5, F2 ×5,
     * (Sig base, Sig mask), (Stamp base, Stamp mask)]; returns the bodies in that order. The alpha is written verbatim.
     */
    fun objects(p: Params, ids: IntArray): List<ByteArray> {
        if (ids.size != objectCount(p.sig, p.stamp)) throw AppearanceException("object count")
        val rot = rotation(p.rotate, p.w, p.h)
        val content = content(p)
        val res = StringBuilder("/Font << /F1 ${ids[1]} 0 R /F2 ${ids[6]} 0 R >>")
        val imgs = ArrayList<ByteArray>()
        if (p.sig != null || p.stamp != null) {
            res.append(" /XObject <<")
            var next = 11
            for ((name, im) in listOf("Sig" to p.sig, "Stamp" to p.stamp)) {
                if (im == null) continue
                val base = ids[next]
                val mask = ids[next + 1]
                next += 2
                res.append(" /$name $base 0 R")
                imgs += VerifyPage.streamObj(
                    " /Type /XObject /Subtype /Image /Width 1 /Height 1 /ColorSpace /DeviceRGB /BitsPerComponent 8 /SMask $mask 0 R",
                    byteArrayOf(im.color[0].toByte(), im.color[1].toByte(), im.color[2].toByte()),
                )
                imgs += VerifyPage.streamObj(
                    " /Type /XObject /Subtype /Image /Width ${im.width} /Height ${im.height} /ColorSpace /DeviceGray /BitsPerComponent 8 /Filter /FlateDecode",
                    im.alpha,
                )
            }
            res.append(" >>")
        }
        val form = VerifyPage.streamObj(
            " /Type /XObject /Subtype /Form /BBox [0 0 ${num100(rot.bw)} ${num100(rot.bh)}] /Resources << $res >>",
            content,
        )
        return listOf(form) + VerifyPage.fontBodies(ids.copyOfRange(1, 6), PageFont.regular) +
            VerifyPage.fontBodies(ids.copyOfRange(6, 11), PageFont.bold) + imgs
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

    /**
     * Go `core.DefaultStampPage` (PLACEMENT_SPEC §1a): the page for `appearance.page` 0 — the last page (tree order) that
     * is not an eID verify page — and the page count n. All pages verify pages → n.
     */
    fun defaultStampPage(doc: ByteArray, verifyUri: String): Pair<Int, Int> {
        val inc = Incremental(doc)
        val pages = pageList(inc.reader, inc.root["Pages"])
        return lastContentPage(inc.reader, pages, verifyUri) to pages.size
    }

    /** The last page (1-based) of [pages] that is not an eID verify page of [verifyUri] ("" = none skipped); all verify pages → the page count. */
    private fun lastContentPage(rd: PdfReader, pages: List<PdfDict>, verifyUri: String): Int {
        for (i in pages.size - 1 downTo 0) {
            if (verifyUri.isEmpty() || !isVerifyPage(rd, pages[i], verifyUri)) return i + 1
        }
        return pages.size
    }

    /** Go `pageList`: the /Page dictionaries in /Pages tree order (depth ≤ 32, at most 65 537). */
    private fun pageList(rd: PdfReader, root: PdfObj): List<PdfDict> {
        val pages = ArrayList<PdfDict>()
        fun walk(v: PdfObj, depth: Int) {
            if (depth > MAX_DEPTH || pages.size > (1 shl 16)) return
            val d = rd.resolve(v).dict ?: return
            when (rd.get(d, "Type").name) {
                "Page" -> pages.add(d)
                "Pages" -> (rd.get(d, "Kids") as? PdfObj.Arr)?.items?.forEach { walk(it, depth + 1) }
            }
        }
        walk(root, 0)
        return pages
    }

    /** [suggest]'s result: resolved page, the choice, and every page's visible (w, h) in h100 (null = geometry unreadable). */
    class Suggested(val page: Int, val result: StampPlacement.Result, val sizes: List<Pair<Long, Long>?>)

    /**
     * Go `core.SuggestVisible` (PLACEMENT_SPEC §6b): the placement [SignatureRevision.prepare] would choose, without
     * writing anything. [page] 0 → the last page that is not a verify page of [verifyUri] ("" = the last page); x, y,
     * w, h in h100. Request errors (page > count, geometry, rect outside the page) are [AppearanceException]; anything
     * else is a PDF error.
     */
    fun suggest(doc: ByteArray, verifyUri: String, page0: Int, x: Long, y: Long, w: Long, h: Long, exact: Boolean): Suggested {
        val inc = Incremental(doc)
        val rd = inc.reader
        val pages = pageList(rd, inc.root["Pages"])
        val n = pages.size
        val page = if (page0 == 0) lastContentPage(rd, pages, verifyUri) else page0
        if (page < 1 || page > n) throw AppearanceException("page $page > page count $n")
        val sizes = pages.map { d ->
            try {
                val g = geometry(rd, d)
                val bw = g.box[2] - g.box[0]
                val bh = g.box[3] - g.box[1]
                if (g.rot == 90 || g.rot == 270) bh to bw else bw to bh
            } catch (_: Exception) {
                null
            }
        }
        val loc = StampPlacement.locate(rd, inc.root["Pages"], rd.trailer["Root"].ref, page, x, y, w, h, exact)
        return Suggested(page, loc.result, sizes)
    }

    /** Go `isVerifyPage`: /Annots (first 10 000) holds a /Link whose /A is `/S /URI` with /URI byte-equal to verifyUri. Unreadable → false. */
    fun isVerifyPage(rd: PdfReader, page: PdfDict, verifyUri: String): Boolean {
        val want = verifyUri.toByteArray(Charsets.US_ASCII)
        val annots = try { rd.get(page, "Annots") as? PdfObj.Arr } catch (e: Exception) { null } ?: return false
        for (e in annots.items.take(10_000)) {
            val hit = try {
                val a = rd.resolve(e).dict
                val act = a?.takeIf { rd.get(it, "Subtype").name == "Link" }?.let { rd.get(it, "A").dict }
                val uri = act?.takeIf { rd.get(it, "S").name == "URI" }?.let { rd.get(it, "URI") } as? PdfObj.Str
                uri != null && uri.bytes.contentEquals(want)
            } catch (x: Exception) { false }
            if (hit) return true
        }
        return false
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
