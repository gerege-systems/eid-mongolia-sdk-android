package mn.eidmongolia.eid.pades

import org.json.JSONObject
import java.util.Locale

/** Fixed font asset (PAGE_SPEC §9): FontFile2 bytes as shipped (zlib, never re-compressed) + metrics. */
internal class PageFont(
    val psName: String,
    val stream: ByteArray,
    val length1: Int,
    val ascent: Int,
    val descent: Int,
    val capHeight: Int,
    val bbox: IntArray,
    val widths: IntArray,
    val gid: Map<Int, Int>,
) {
    fun width1000(g: Int) = widths[minOf(g, widths.size - 1)]

    companion object {
        private fun res(name: String): ByteArray =
            PageFont::class.java.getResourceAsStream("/mn/eidmongolia/eid/pades/fonts/$name")?.use { it.readBytes() }
                ?: throw IllegalStateException("font asset $name missing")

        private fun load(base: String): PageFont {
            val m = JSONObject(String(res("$base.metrics.json"), Charsets.UTF_8))
            val w = m.getJSONArray("widths")
            val bb = m.getJSONArray("bbox")
            val cm = m.getJSONArray("cmap")
            val gid = HashMap<Int, Int>(cm.length() * 2)
            for (i in 0 until cm.length()) cm.getJSONArray(i).let { gid[it.getInt(0)] = it.getInt(1) }
            return PageFont(
                m.getString("psName"), res("$base.ttf.zlib"), m.getInt("length1"), m.getInt("ascent"), m.getInt("descent"),
                m.getInt("capHeight"), IntArray(4) { bb.getInt(it) }, IntArray(w.length()) { w.getInt(it) }, gid,
            )
        }

        val regular by lazy { load("NotoSans-Regular") }
        val bold by lazy { load("NotoSans-Bold") }
    }
}

/** Verification page — PAGE_SPEC.md (Go reference `pades/internal/core/vpage.go`), byte for byte. */
internal object VerifyPage {
    class Data(
        val brand: String, val fileName: String, val documentHash: String, val fileSize: Long, val docId: String,
        val verifyUrl: String, val trustUrl: String, val caName: String, val tsaName: String, val provider: String,
        /** "mn" (default when null/empty) | "en" — PAGE_SPEC §3a. */
        val lang: String? = null,
    )

    /** PAGE_SPEC §3a page texts. */
    private class Texts(
        val title: String, val subtitle: String, val document: String, val fileName: String, val hashAlg: String,
        val size: String, val docHash: String, val docId: String, val verification: String, val scan: String,
        val scanHint: String, val trust: String, val provider: String,
    )

    private val texts = mapOf(
        "mn" to Texts(
            title = "-аар гарын үсэг зурсан баримт",
            subtitle = "Гарын үсгүүд энэ PDF-д шингэсэн. Доорх холбоосоор эсвэл Adobe Acrobat-ын Signatures самбараар шалгана уу.",
            document = "БАРИМТ", fileName = "БАРИМТЫН НЭР", hashAlg = "HASH АЛГОРИТМ", size = "ХЭМЖЭЭ",
            docHash = "БАРИМТЫН HASH", docId = "БАРИМТЫН ID", verification = "ШАЛГАХ", scan = "Гарын үсгийг шалгах",
            scanHint = "QR кодыг утасны камераар уншуулах эсвэл холбоосыг нээнэ үү.",
            trust = "Adobe Acrobat-д Монгол Улсын үндэсний Root CA-д итгэх заавар:", provider = "Үйлчилгээ",
        ),
        "en" to Texts(
            title = " — Electronically signed document",
            subtitle = "Signatures are embedded in this PDF. Verify them with the link below or in Adobe Acrobat's Signatures panel.",
            document = "DOCUMENT", fileName = "FILE NAME", hashAlg = "HASH ALGORITHM", size = "SIZE",
            docHash = "DOCUMENT HASH", docId = "DOCUMENT ID", verification = "VERIFICATION", scan = "Scan to verify",
            scanHint = "Scan this QR code with your phone camera to verify.",
            trust = "Adobe Acrobat: trust the Mongolian National Root CA", provider = "Provider",
        ),
    )

    private const val MEDIA_BOX = "[0 0 595.28 841.89]"
    private const val LEFT = 42
    private const val WIDTH = 510
    private const val COL2 = 297
    private const val QR_MODULE = 2
    private const val QR_TEXT_X = 136
    private const val FILE_NAME_MAX = 3
    const val TEXT = "0.118 0.118 0.118"
    const val MUTED = "0.431 0.431 0.431"
    const val OK = "0.086 0.541 0.31"
    private const val BANNER = "0.863 0.961 0.902"
    private const val LINE = "0.863 0.863 0.863"
    private const val LINK = "0.118 0.431 0.863"
    private const val BANNER_PATH = "48 800 m\n546 800 l\n549.31 800 552 797.31 552 794 c\n552 754 l\n552 750.69 549.31 748 546 748 c\n" +
        "48 748 l\n44.69 748 42 750.69 42 754 c\n42 794 l\n42 797.31 44.69 800 48 800 c\nh\nf"

    class Link(val x1: Int, val y1: Int, val x2: Int, val y2: Int, val url: String)

    class Writer(val reg: PageFont, val bld: PageFont) {
        val ops = StringBuilder()
        val links = ArrayList<Link>()

        fun op(s: String) { ops.append(s).append('\n') }
        fun font(id: Int) = if (id == 2) bld else reg

        fun gids(id: Int, s: String): List<Int> {
            val f = font(id)
            val out = ArrayList<Int>()
            var i = 0
            while (i < s.length) {
                val r = s.codePointAt(i)
                i += Character.charCount(r)
                out += f.gid[r] ?: f.gid['?'.code]!!
            }
            return out
        }

        fun width1000(id: Int, size: Int, s: String): Int {
            if (id == 3) return 600 * s.codePointCount(0, s.length) * size
            return gids(id, s).sumOf { font(id).width1000(it) } * size
        }

        fun text(id: Int, size: Int, x: Int, y: Int, color: String, s: String) {
            val str = if (id == 3) {
                "(" + s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)") + ")"
            } else {
                glyphHex(id, s)
            }
            op("$color rg")
            op("BT /F$id $size Tf $x $y Td $str Tj ET")
        }

        /** F1/F2 text `<GGGG…>` (PAGE_SPEC.md §2). */
        fun glyphHex(id: Int, s: String): String = gids(id, s).joinToString("", "<", ">") { String.format(Locale.ROOT, "%04X", it) }

        fun link(id: Int, size: Int, x: Int, y: Int, s: String) {
            val wd = (width1000(id, size, s) + 999) / 1000
            links += Link(x, y - 3, x + wd, y + size, s)
        }

        fun hline(y: Int) {
            op("$LINE RG")
            op("0.75 w $LEFT $y m ${LEFT + WIDTH} $y l S")
        }

        fun wrap(id: Int, size: Int, s: String, maxW: Int, maxLines: Int): List<String> = wrapLimit(id, size, s, maxW * 1000, maxLines)

        /** [wrap] with the width limit in 1/1000 pt (visible signature: 1/100 pt × 10). */
        fun wrapLimit(id: Int, size: Int, s: String, limit: Int, maxLines: Int): List<String> {
            fun fits(t: String) = width1000(id, size, t) <= limit
            val lines = ArrayList<String>()
            var cur = ""
            for (w0 in s.split(" ")) {
                var word = w0
                if (word.isEmpty()) continue
                val cand = if (cur.isEmpty()) word else "$cur $word"
                if (fits(cand)) { cur = cand; continue }
                if (cur.isNotEmpty()) { lines += cur; cur = "" }
                while (!fits(word)) {
                    val r = word.codePoints().toArray()
                    var n = 1
                    while (n < r.size && fits(String(r, 0, n + 1))) n++
                    lines += String(r, 0, n)
                    word = String(r, n, r.size - n)
                }
                cur = word
            }
            if (cur.isNotEmpty()) lines += cur
            if (lines.size > maxLines) {
                var last = lines[maxLines - 1].codePoints().toArray()
                while (last.isNotEmpty() && !fits(String(last, 0, last.size) + "…")) last = last.copyOf(last.size - 1)
                return lines.subList(0, maxLines - 1) + (String(last, 0, last.size) + "…")
            }
            return lines
        }
    }

    fun humanSize(b: Long): String = when {
        b < (1L shl 10) -> "$b B"
        b < (1L shl 20) -> tenths(b, 1L shl 10) + " KB"
        b < (1L shl 30) -> tenths(b, 1L shl 20) + " MB"
        else -> tenths(b, 1L shl 30) + " GB"
    }

    private fun tenths(b: Long, unit: Long): String {
        val t = (b * 10 + unit / 2) / unit
        return "${t / 10}.${t % 10}"
    }

    fun urlHost(u: String): String {
        val s = u.removePrefix("https://").removePrefix("http://")
        val i = s.indexOf('/')
        if (i > 0) {
            val next = s.indexOf('/', i + 1) - (i + 1)
            if (next > 0) return s.substring(0, i + 1 + next)
        }
        return s
    }

    fun asciiUrl(u: String) = u.isNotEmpty() && u.all { it.code in 0x21..0x7e && it != '(' && it != ')' && it != '\\' }

    private fun content(p: Data, w: Writer): ByteArray {
        require(asciiUrl(p.verifyUrl) && (p.trustUrl.isEmpty() || asciiUrl(p.trustUrl))) { "URL is not ASCII" }
        val m = Qr.encode(p.verifyUrl.toByteArray(Charsets.US_ASCII))
        val tx = texts[p.lang?.takeIf { it.isNotEmpty() } ?: "mn"] ?: throw IllegalArgumentException("page language ${p.lang}")
        w.op("$BANNER rg")
        w.op(BANNER_PATH)
        w.text(2, 13, 56, 778, OK, p.brand + tx.title)
        w.text(1, 9, 56, 760, OK, tx.subtitle)
        var y = 724
        w.hline(y)
        w.text(2, 11, LEFT, y - 17, TEXT, tx.document)
        y -= 34
        w.text(1, 8, LEFT, y, MUTED, tx.fileName)
        y -= 14
        for ((i, line) in w.wrap(2, 10, p.fileName, WIDTH, FILE_NAME_MAX).withIndex()) {
            if (i > 0) y -= 14
            w.text(2, 10, LEFT, y, TEXT, line)
        }
        y -= 20
        w.text(1, 8, LEFT, y, MUTED, tx.hashAlg)
        w.text(1, 8, COL2, y, MUTED, tx.size)
        w.text(2, 10, LEFT, y - 14, TEXT, "SHA256")
        w.text(2, 10, COL2, y - 14, TEXT, humanSize(p.fileSize))
        y -= 34
        w.text(1, 8, LEFT, y, MUTED, tx.docHash)
        w.text(3, 9, LEFT, y - 13, TEXT, p.documentHash)
        y -= 31
        w.text(1, 8, LEFT, y, MUTED, tx.docId)
        w.text(3, 9, LEFT, y - 13, TEXT, p.docId)
        y -= 35
        w.hline(y)
        w.text(2, 11, LEFT, y - 17, TEXT, tx.verification)
        y -= 35
        w.text(1, 9, LEFT, y, LINK, p.verifyUrl)
        w.link(1, 9, LEFT, y, p.verifyUrl)
        y -= 14
        w.op("0 0 0 rg")
        val n = m.size
        for (r in 0 until n) {
            var c = 0
            while (c < n) {
                if (!m[r][c]) { c++; continue }
                val s = c
                while (c < n && m[r][c]) c++
                w.op("${LEFT + QR_MODULE * s} ${y - QR_MODULE * (r + 1)} ${QR_MODULE * (c - s)} $QR_MODULE re")
            }
        }
        w.op("f")
        w.text(2, 11, QR_TEXT_X, y - 14, TEXT, tx.scan)
        w.text(1, 9, QR_TEXT_X, y - 29, MUTED, tx.scanHint)
        w.text(2, 9, QR_TEXT_X, y - 43, LINK, urlHost(p.verifyUrl))
        if (p.trustUrl.isNotEmpty()) {
            w.text(1, 9, QR_TEXT_X, y - 60, MUTED, tx.trust)
            w.text(2, 9, QR_TEXT_X, y - 74, LINK, p.trustUrl)
            w.link(2, 9, QR_TEXT_X, y - 74, p.trustUrl)
        }
        w.hline(71)
        w.text(1, 8, LEFT, 58, MUTED, "CA: " + p.caName + "  |  TSA: " + p.tsaName + "  |  " + tx.provider + ": " + p.provider)
        return w.ops.toString().toByteArray(Charsets.UTF_8)
    }

    /** Appends the page as its own incremental revision (PAGE_SPEC §8); the Catalog is unchanged. */
    fun append(base: ByteArray, p: Data): ByteArray {
        val reg = PageFont.regular
        val bld = PageFont.bold
        val w = Writer(reg, bld)
        val content = content(p, w)
        val inc = Incremental(base)
        val rd = inc.reader
        val rootRef = rd.trailer["Root"].ref ?: throw PdfException("Catalog is not an indirect object")
        val pagesRaw = inc.root["Pages"]
        val pp = pagesRaw.ref
        val pages = rd.resolve(pagesRaw).dict
        if (pages == null || pp == null || rd.get(pages, "Type").name != "Pages" || pp == rootRef || pp.id == 0) {
            throw PdfException("/Pages root missing")
        }
        val count = rd.get(pages, "Count").long ?: 0
        val kidsRaw = pages["Kids"]
        val kids = rd.resolve(kidsRaw) as? PdfObj.Arr
        if (count < 0 || kids == null) throw PdfException("/Pages /Kids /Count invalid")
        if (rootRef.gen != 0) throw PdfException("Catalog generation is not 0")
        val pageId = inc.reserve()
        val contentId = inc.reserve()
        val fontIds = Array(2) { IntArray(5) { inc.reserve() } }
        val courierId = inc.reserve()
        val linkIds = IntArray(w.links.size) { inc.reserve() }

        val pg = StringBuilder("<< /Type /Page /Parent ${pp.id} ${pp.gen} R /MediaBox $MEDIA_BOX /CropBox $MEDIA_BOX /Rotate 0 ")
        pg.append("/Resources << /Font << /F1 ${fontIds[0][0]} 0 R /F2 ${fontIds[1][0]} 0 R /F3 $courierId 0 R >> >> /Contents $contentId 0 R")
        if (linkIds.isNotEmpty()) pg.append(" /Annots [").append(linkIds.joinToString(" ") { "$it 0 R" }).append(']')
        pg.append(" >>")
        inc.writeObject(pageId, pg.toString().toByteArray(Charsets.ISO_8859_1))
        inc.writeObject(contentId, streamObj("", content))
        writeFont(inc, fontIds[0], reg)
        writeFont(inc, fontIds[1], bld)
        inc.writeObject(courierId, "<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>".toByteArray())
        for ((i, l) in w.links.withIndex()) {
            inc.writeObject(
                linkIds[i],
                "<< /Type /Annot /Subtype /Link /Rect [${l.x1} ${l.y1} ${l.x2} ${l.y2}] /Border [0 0 0] /A << /S /URI /URI (${l.url}) >> >>"
                    .toByteArray(Charsets.ISO_8859_1),
            )
        }
        val pn = StringBuilder("<<")
        for (key in pages.sortedKeys) {
            if (key == "Kids" || key == "Count") continue
            pn.append(" /").append(Incremental.escapeName(key)).append(' ').append(inc.serialize(pages[key]))
        }
        pn.append(" /Kids [")
        for (k in kids.items) pn.append(inc.serialize(k)).append(' ')
        pn.append("$pageId 0 R] /Count ${count + 1} >>")
        inc.writeObject(pp.id, pn.toString().toByteArray(Charsets.ISO_8859_1), pp.gen)
        return inc.finish(rootRef.id)
    }

    fun streamObj(extra: String, data: ByteArray) =
        Der.concat("<< /Length ${data.size}$extra >>\nstream\n".toByteArray(), data, "\nendstream".toByteArray())

    private fun writeFont(inc: Incremental, ids: IntArray, f: PageFont) {
        fontBodies(ids, f).forEachIndexed { i, b -> inc.writeObject(ids[i], b) }
    }

    /** [writeFont]'s 5 object bodies (in [ids] order) — shared by the verify page and the visible signature. */
    fun fontBodies(ids: IntArray, f: PageFont): List<ByteArray> {
        val wa = f.widths.indices.joinToString(" ") { f.width1000(it).toString() }
        return listOf(
            "<< /Type /Font /Subtype /Type0 /BaseFont /${f.psName} /Encoding /Identity-H /DescendantFonts [${ids[1]} 0 R] /ToUnicode ${ids[4]} 0 R >>".toByteArray(),
            ("<< /Type /Font /Subtype /CIDFontType2 /BaseFont /${f.psName} /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) " +
                "/Supplement 0 >> /FontDescriptor ${ids[2]} 0 R /CIDToGIDMap /Identity /W [0 [$wa]] >>").toByteArray(),
            ("<< /Type /FontDescriptor /FontName /${f.psName} /Flags 32 /FontBBox [${f.bbox[0]} ${f.bbox[1]} ${f.bbox[2]} ${f.bbox[3]}] " +
                "/ItalicAngle 0 /Ascent ${f.ascent} /Descent ${f.descent} /CapHeight ${f.capHeight} /StemV 80 /FontFile2 ${ids[3]} 0 R >>").toByteArray(),
            streamObj(" /Length1 ${f.length1} /Filter /FlateDecode", f.stream),
            streamObj("", toUnicode(f)),
        )
    }

    private fun toUnicode(f: PageFont): ByteArray {
        val uni = HashMap<Int, Int>()
        for ((r, g) in f.gid) {
            val old = uni[g]
            if (old == null || r < old) uni[g] = r
        }
        val pairs = (0 until f.widths.size).mapNotNull { g -> uni[g]?.let { g to it } }
        val b = StringBuilder(
            "/CIDInit /ProcSet findresource begin\n12 dict begin\nbegincmap\n" +
                "/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def\n/CMapName /Adobe-Identity-UCS def\n/CMapType 2 def\n" +
                "1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange\n",
        )
        for (chunk in pairs.chunked(100)) {
            b.append("${chunk.size} beginbfchar\n")
            for ((g, r) in chunk) b.append(String.format(Locale.ROOT, "<%04X> <%04X>\n", g, r))
            b.append("endbfchar\n")
        }
        b.append("endcmap\nCMapName currentdict /CMap defineresource pop\nend\nend")
        return b.toString().toByteArray(Charsets.US_ASCII)
    }
}
