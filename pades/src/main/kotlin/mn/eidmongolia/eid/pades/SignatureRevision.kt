package mn.eidmongolia.eid.pades

import java.security.MessageDigest
import java.util.Calendar
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/** Go reference `pades/internal/core/signature.go`: the signature revision (R_sig), CMS embedding, text strings. */
internal object SignatureRevision {
    /** /Contents capacity in CMS bytes (2 × measured max 14 KiB); file holds 2× hex chars. */
    const val PLACEHOLDER_BYTES = 2 * (14 shl 10)
    const val SUB_FILTER = "ETSI.CAdES.detached"
    private const val BYTE_RANGE_WIDTH = 40
    const val REASON_MAX_UNITS = 127

    /** [placement] — the visible stamp's final position (null for an invisible signature), PLACEMENT_SPEC.md. */
    class Prepared(
        val pdf: ByteArray, val byteRange: LongArray, val digest: ByteArray, val fieldName: String,
        val placement: StampPlacement.Result? = null,
    )

    class PlaceholderOverflow(msg: String) : Exception(msg)

    /**
     * Approval signature revision: Sig dict + placeholder, widget, new Catalog/AcroForm. Without [vis] the widget is
     * invisible on the first page; with [vis] (APPEARANCE_SPEC.md) it has a /Rect on page [Appearance.Visible.page], /F 4
     * and an /AP /N form XObject (+ 2 fonts), appended to that page's /Annots. [Appearance.Visible.name] must equal the
     * written /Name, else [AppearanceException].
     */
    fun prepare(base: ByteArray, signingTime: Date, signerName: String, reason: String?, vis: Appearance.Visible? = null): Prepared {
        val inc = Incremental(base)
        val rd = inc.reader
        val root = inc.root
        val acroObj = rd.get(root, "AcroForm")
        val acro = acroObj.dict
        val fieldsObj = if (acro != null) rd.get(acro, "Fields") else PdfObj.Null
        val fields = (fieldsObj as? PdfObj.Arr)?.items ?: emptyList()
        val names = HashSet<String>()
        var sigFields = 0
        for (f in fields) {
            val fd = rd.resolve(f).dict ?: continue
            names += text(rd.get(fd, "T"))
            if (rd.get(fd, "FT").name == "Sig") sigFields++
        }
        var k = sigFields + 1
        while (names.contains("Signature $k")) k++
        val fieldName = "Signature $k"

        val sigId = inc.reserve()
        val fieldId = inc.reserve()
        val catId = inc.reserve()
        val apIds = if (vis != null) IntArray(11) { inc.reserve() } else IntArray(0) // form, F1 ×5, F2 ×5

        // ── Sig dict (placeholder) ──
        val sig = StringBuilder("<<\n /Type /Sig\n /Filter /Adobe.PPKLite\n /SubFilter /$SUB_FILTER\n /ByteRange ")
        val brAt = sig.length
        repeat(BYTE_RANGE_WIDTH) { sig.append(' ') }
        sig.append("\n /Contents <")
        val contentsAt = sig.length - 1
        repeat(2 * PLACEHOLDER_BYTES) { sig.append('0') }
        sig.append(">\n /M ").append(pdfDate(signingTime))
        sigText(signerName, 120)?.let { sig.append("\n /Name ").append(it) }
        sigText(reason ?: "", REASON_MAX_UNITS)?.let { sig.append("\n /Reason ").append(it) }
        sig.append("\n>>")
        val sigStart = inc.writeObject(sigId, sig.toString().toByteArray(Charsets.ISO_8859_1))

        // ── field + widget ──
        val page: Pair<PdfDict, PdfRef>?
        var placement: StampPlacement.Result? = null
        if (vis == null) {
            // Invisible (digitorus createVisualSignature, invisible): first page.
            val fld = StringBuilder("<<\n  /Type /Annot\n  /Subtype /Widget\n  /Rect [0 0 0 0]\n")
            page = firstPage(rd, root["Pages"], rd.trailer["Root"].ref, 0)
            page?.let { fld.append("  /P ${it.second.id} ${it.second.gen} R\n") }
            fld.append("  /F 132\n  /FT /Sig\n  /T ($fieldName)\n  /V $sigId 0 R\n>>")
            inc.writeObject(fieldId, fld.toString().toByteArray(Charsets.ISO_8859_1))
        } else {
            if (sigText(signerName, 120) == null || GoText.trimSpace(signerName) != vis.name) throw AppearanceException("name cannot be written to /Name")
            page = Appearance.nthPage(rd, root["Pages"], rd.trailer["Root"].ref, vis.page) ?: throw AppearanceException("page ${vis.page} missing")
            val g = Appearance.geometry(rd, page.first)
            var rect = Appearance.rect(g.box, g.rot, vis.x, vis.y, vis.w, vis.h)
            // PLACEMENT_SPEC.md: move off existing page content; the requested rect stays when nothing is free.
            val placed = StampPlacement.choose(rd, page.first, page.second.id, g.box, g.rot, vis.x, vis.y, vis.w, vis.h)
            if (placed.status == StampPlacement.Status.MOVED) rect = Appearance.rect(g.box, g.rot, placed.x, placed.y, vis.w, vis.h)
            placement = placed
            val bodies = Appearance.objects(
                Appearance.Params(vis.w.toInt(), vis.h.toInt(), g.rot, vis.name, vis.role, vis.lang, vis.date, vis.url), apIds,
            )
            inc.writeObject(fieldId, Appearance.widget(fieldName, rect, page.second, sigId, apIds[0]))
            bodies.forEachIndexed { i, b -> inc.writeObject(apIds[i], b) }
        }
        page?.let { addWidgetToPage(inc, it.first, it.second, fieldId) }

        // ── new Catalog ──
        val cat = StringBuilder("<<\n  /Type /Catalog\n")
        if (rd.get(root, "Version").isNull) {
            val v = rd.version.toDoubleOrNull()
            if (v != null && v < 1.5) cat.append("  /Version /1.5\n")
        }
        cat.append(inc.catalogCopy(setOf("AcroForm")))
        cat.append("  /AcroForm <<")
        if (acro != null && acroObj is PdfObj.Dict) {
            for (key in acro.sortedKeys) {
                if (key == "Fields" || key == "SigFlags") continue
                cat.append(" /").append(Incremental.escapeName(key)).append(' ').append(inc.serialize(acro[key]))
            }
        }
        cat.append(" /Fields [")
        val rawFields = (acro?.get("Fields")?.let { if (it is PdfObj.Ref) rd.resolve(it) else it } as? PdfObj.Arr)?.items ?: emptyList()
        for (f in rawFields) cat.append(inc.serialize(f)).append(' ')
        cat.append("$fieldId 0 R] /SigFlags 3 >>\n>>")
        inc.writeObject(catId, cat.toString().toByteArray(Charsets.ISO_8859_1))

        val doc = inc.finish(catId)
        val a = sigStart.toLong() + contentsAt
        val b = a + 2L * PLACEHOLDER_BYTES + 2
        if (doc[a.toInt()] != '<'.code.toByte() || doc[(b - 1).toInt()] != '>'.code.toByte()) {
            throw PdfException("placeholder position mismatch")
        }
        val br = longArrayOf(0, a, b, doc.size - b)
        val field = "[${br[0]} ${br[1]} ${br[2]} ${br[3]}]"
        if (field.length > BYTE_RANGE_WIDTH) throw PdfException("ByteRange does not fit")
        val fb = field.toByteArray(Charsets.ISO_8859_1)
        System.arraycopy(fb, 0, doc, sigStart + brAt, fb.size)
        val h = MessageDigest.getInstance("SHA-256")
        h.update(doc, 0, a.toInt())
        h.update(doc, b.toInt(), doc.size - b.toInt())
        return Prepared(doc, br, h.digest(), fieldName, placement)
    }

    /** CMS → hex into the placeholder (other bytes untouched); never truncates. */
    fun embedCms(prepared: ByteArray, br: LongArray, cms: ByteArray): ByteArray {
        if (cms.isEmpty()) throw IllegalArgumentException("CMS empty")
        if (cms.size > PLACEHOLDER_BYTES) throw PlaceholderOverflow("${cms.size} > $PLACEHOLDER_BYTES bytes")
        val a = br[1].toInt()
        val b = br[2].toInt()
        if (br[0] != 0L || a <= 0 || b.toLong() != a + 2L * PLACEHOLDER_BYTES + 2 || b + br[3] != prepared.size.toLong() ||
            prepared[a] != '<'.code.toByte() || prepared[b - 1] != '>'.code.toByte()
        ) throw IllegalArgumentException("ByteRange does not match the prepared document")
        for (i in a + 1 until b - 1) if (prepared[i] != '0'.code.toByte()) throw IllegalArgumentException("placeholder already filled")
        val out = prepared.copyOf()
        val hex = "0123456789abcdef"
        for ((i, v) in cms.withIndex()) {
            out[a + 1 + 2 * i] = hex[(v.toInt() shr 4) and 0xf].code.toByte()
            out[a + 2 + 2 * i] = hex[v.toInt() and 0xf].code.toByte()
        }
        return out
    }

    /** /Contents value as viewers read it: hex-decoded, including the placeholder's zero padding (VRI key). */
    fun signatureContents(signed: ByteArray, br: LongArray): ByteArray {
        val a = br[1].toInt()
        val b = br[2].toInt()
        if (br[0] != 0L || a <= 0 || b <= a + 2 || b > signed.size || signed[a] != '<'.code.toByte() || signed[b - 1] != '>'.code.toByte()) {
            throw IllegalArgumentException("ByteRange does not point at /Contents")
        }
        return Hex.decode(signed, a + 1, b - 1) ?: throw IllegalArgumentException("/Contents hex")
    }

    private fun addWidgetToPage(inc: Incremental, page: PdfDict, pageRef: PdfRef, widget: Int) {
        val rd = inc.reader
        val annotsRaw = page["Annots"]
        val annots = rd.resolve(annotsRaw)
        if (!annots.isNull && annots !is PdfObj.Arr) throw PdfException("page /Annots is not an array")
        val arr = StringBuilder("[")
        for (e in (annots as? PdfObj.Arr)?.items ?: emptyList()) arr.append(inc.serialize(e)).append(' ')
        arr.append("$widget 0 R]")
        val annotsRef = annotsRaw.ref
        if (!annots.isNull && annotsRef != null) {
            inc.writeObject(annotsRef.id, arr.toString().toByteArray(Charsets.ISO_8859_1), annotsRef.gen)
            return
        }
        val b = StringBuilder("<<")
        for (key in page.sortedKeys) {
            if (key == "Annots") continue
            b.append(" /").append(Incremental.escapeName(key)).append(' ').append(inc.serialize(page[key]))
        }
        b.append(" /Annots ").append(arr).append(" >>")
        inc.writeObject(pageRef.id, b.toString().toByteArray(Charsets.ISO_8859_1), pageRef.gen)
    }

    /** First /Page of the /Pages tree (digitorus findFirstPage; bounded depth) + the reference it was reached by. */
    private fun firstPage(rd: PdfReader, v: PdfObj, owner: PdfRef?, depth: Int): Pair<PdfDict, PdfRef>? {
        if (depth > 32) return null
        val ref = v.ref ?: owner ?: return null
        val d = rd.resolve(v).dict ?: return null
        when (rd.get(d, "Type").name) {
            "Page" -> return d to ref
            "Pages" -> {
                val kids = (rd.get(d, "Kids") as? PdfObj.Arr)?.items ?: return null
                for (kid in kids) firstPage(rd, kid, ref, depth + 1)?.let { return it }
            }
        }
        return null
    }

    /** PDF text string → String (UTF-16BE with BOM, else PDFDocEncoding ≈ Latin-1) — digitorus `Text()`. */
    fun text(o: PdfObj): String {
        val b = (o as? PdfObj.Str)?.bytes ?: return ""
        if (b.size >= 2 && b[0] == 0xFE.toByte() && b[1] == 0xFF.toByte()) return String(b, 2, b.size - 2, Charsets.UTF_16BE)
        return String(b, Charsets.ISO_8859_1)
    }

    /** "(D:YYYYMMDDHHmmSS+08'00')" — always +08:00 (Go reference normalises to FixedZone +08). */
    fun pdfDate(t: Date): String {
        val c = Calendar.getInstance(TimeZone.getTimeZone("GMT+08:00"), Locale.ROOT)
        c.time = t
        return String.format(
            Locale.ROOT, "(D:%04d%02d%02d%02d%02d%02d+08'00')",
            c.get(Calendar.YEAR), c.get(Calendar.MONTH) + 1, c.get(Calendar.DAY_OF_MONTH),
            c.get(Calendar.HOUR_OF_DAY), c.get(Calendar.MINUTE), c.get(Calendar.SECOND),
        )
    }

    /**
     * Go sigText: hex PDF text string — ASCII as is, else BOM + UTF-16BE. Null (not written) when empty after
     * TrimSpace, longer than [maxUnits] UTF-16 units, containing control chars or PDF keywords.
     */
    fun sigText(input: String, maxUnits: Int): String? {
        val s = GoText.trimSpace(input)
        if (s.isEmpty() || s.length > maxUnits) return null
        var ascii = true
        var i = 0
        while (i < s.length) {
            val r = s.codePointAt(i)
            if (r < 0x20 || r == 0x7f || Character.getType(r) == Character.CONTROL.toInt()) return null
            if (r in 0xD800..0xDFFF) return null // lone surrogate (Go: invalid UTF-8)
            if (r > 0x7e) ascii = false
            i += Character.charCount(r)
        }
        for (kw in listOf(" obj", "endobj", "stream", "xref", "trailer", "%%EOF")) if (s.contains(kw)) return null
        if (ascii) return Incremental.hexString(s.toByteArray(Charsets.ISO_8859_1))
        val raw = byteArrayOf(0xfe.toByte(), 0xff.toByte()) + s.toByteArray(Charsets.UTF_16BE)
        return Incremental.hexString(raw)
    }
}

internal object Hex {
    fun encode(b: ByteArray): String = Incremental.hexString(b).let { it.substring(1, it.length - 1) }

    /** Strict even-length hex decode of b[from, to); null on any non-hex char. */
    fun decode(b: ByteArray, from: Int, to: Int): ByteArray? {
        if ((to - from) % 2 != 0) return null
        val out = ByteArray((to - from) / 2)
        for (i in out.indices) {
            val hi = PdfLexer.hexVal(b[from + 2 * i].toInt() and 0xff) ?: return null
            val lo = PdfLexer.hexVal(b[from + 2 * i + 1].toInt() and 0xff) ?: return null
            out[i] = ((hi shl 4) or lo).toByte()
        }
        return out
    }

    fun decode(s: String): ByteArray = s.toByteArray(Charsets.ISO_8859_1).let { decode(it, 0, it.size) ?: throw IllegalArgumentException("hex") }
}
