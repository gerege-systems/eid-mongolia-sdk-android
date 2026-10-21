package mn.eidmongolia.eid.pades

import java.io.ByteArrayOutputStream
import java.util.zip.DataFormatException
import java.util.zip.Inflater

/**
 * Visible stamp placement — PLACEMENT_SPEC.md (pades-client/1), 1:1 port of the Go reference
 * `pades/internal/core/occupancy.go` (`Occupancy`) and `placement.go` (`PlaceCandidates`, `PlaceVisible`); iOS
 * `Placement.swift` is the same port. The requested rect is the preferred spot; the page is scanned (content stream,
 * form XObjects, images, annotations — never rendered) into conservative h100 boxes and the stamp moves to the first
 * free candidate.
 *
 * Arithmetic (§2): IEEE-754 binary64, `+ − × ÷` only, each product rounded on its own and the terms summed left to
 * right as written. JVM/ART double arithmetic is strict (no contraction into FMA); `Math.fma` is never used.
 */
internal object StampPlacement {
    enum class Status(val wire: String) { REQUESTED("requested"), MOVED("moved"), OVERLAP("overlap"), UNSCANNED("unscanned") }

    /** The stamp's lower-left corner in visible page space (h100) and how it was chosen. */
    class Result(val x: Long, val y: Long, val status: Status)

    const val PAD = 400L      // h100: clearance kept around the stamp
    const val STEP = 1200L    // h100: vertical step between candidates
    const val MAX_STEPS = 100 // at most this many steps up per column

    /**
     * Candidate positions (visible space, h100) in trial order (§6): requested (x, y); mirrored (vw − x − w, y); then up
     * the requested column y + k·step (k = 1…, while y + k·step + h ≤ vh − y, k ≤ 100); then up the mirrored column.
     * The mirrored column is left out when it equals the requested one.
     */
    fun candidates(vw: Long, vh: Long, x: Long, y: Long, w: Long, h: Long): List<Pair<Long, Long>> {
        val xl = vw - x - w
        val out = mutableListOf(x to y)
        if (xl != x) out += xl to y
        val cols = if (xl != x) listOf(x, xl) else listOf(x)
        for (cx in cols) {
            var k = 1
            while (k <= MAX_STEPS && y + k * STEP + h <= vh - y) {
                out += cx to y + k * STEP
                k++
            }
        }
        return out
    }

    /**
     * The first candidate whose /Rect, grown by [PAD] on every side, overlaps no occupied box (strict overlap: touching
     * edges are free). null → none is free (the caller keeps the requested rect).
     */
    fun place(box: LongArray, rot: Int, x: Long, y: Long, w: Long, h: Long, occ: List<LongArray>): Pair<Long, Long>? {
        var vw = box[2] - box[0]
        var vh = box[3] - box[1]
        if (rot == 90 || rot == 270) vw = vh.also { vh = vw }
        for ((cx, cy) in candidates(vw, vh, x, y, w, h)) {
            val r = try { Appearance.rect(box, rot, cx, cy, w, h) } catch (_: AppearanceException) { continue }
            if (free(r, occ)) return cx to cy
        }
        return null
    }

    /** [r] (user space, h100) grown by [PAD] on every side overlaps no occupied box (strict overlap: touching edges are free) — Go `placeFree`. */
    fun free(r: LongArray, occ: List<LongArray>): Boolean {
        val e = longArrayOf(r[0] - PAD, r[1] - PAD, r[2] + PAD, r[3] + PAD)
        return occ.none { b -> b[0] < e[2] && e[0] < b[2] && b[1] < e[3] && e[1] < b[3] }
    }

    /**
     * Scan + choice for a visible stamp at (x, y, w, h) on [page] (reached as object [pageId]) — Go `PlaceOnPage`.
     * [exact] (§6a): the requested rect is the only candidate (never moved) — REQUESTED when free, OVERLAP when not.
     */
    fun choose(rd: PdfReader, page: PdfDict, pageId: Int, box: LongArray, rot: Int, x: Long, y: Long, w: Long, h: Long, exact: Boolean = false): Result {
        val occ = try { Occupancy.scan(rd, page, pageId, box) } catch (_: Exception) { return Result(x, y, Status.UNSCANNED) }
        if (exact) {
            val r = try { Appearance.rect(box, rot, x, y, w, h) } catch (_: AppearanceException) { return Result(x, y, Status.OVERLAP) }
            return Result(x, y, if (free(r, occ)) Status.REQUESTED else Status.OVERLAP)
        }
        val (px, py) = place(box, rot, x, y, w, h, occ) ?: return Result(x, y, Status.OVERLAP)
        return if (px == x && py == y) Result(x, y, Status.REQUESTED) else Result(px, py, Status.MOVED)
    }

    /** [locate]'s result: the page (dict + reference), its /Rotate, the final /Rect (user space, h100) and the choice. */
    class Located(val page: Pair<PdfDict, PdfRef>, val rot: Int, val rect: LongArray, val result: Result)

    /**
     * Where the stamp goes on page [page] (1-based, resolved) of the /Pages tree [pages] — the one path shared by
     * [SignatureRevision.prepare] and [Pades.suggestPlacement] (PLACEMENT_SPEC §6b): page → geometry → the requested
     * rect must lie inside the page ([AppearanceException]) → scan + choice.
     */
    fun locate(rd: PdfReader, pages: PdfObj, owner: PdfRef?, page: Int, x: Long, y: Long, w: Long, h: Long, exact: Boolean): Located {
        val p = Appearance.nthPage(rd, pages, owner, page) ?: throw AppearanceException("page $page missing")
        val g = Appearance.geometry(rd, p.first)
        var rect = Appearance.rect(g.box, g.rot, x, y, w, h)
        // PLACEMENT_SPEC.md: move off existing page content (exact: only report it); the requested rect stays when
        // nothing is free.
        val placed = choose(rd, p.first, p.second.id, g.box, g.rot, x, y, w, h, exact)
        if (placed.status == Status.MOVED) rect = Appearance.rect(g.box, g.rot, placed.x, placed.y, w, h)
        return Located(p, g.rot, rect, placed)
    }
}

/**
 * Occupancy scanner — PLACEMENT_SPEC.md §3–§5. A pure function of the page objects. Any failure (limit, unsupported
 * filter, broken stream, unparsable object) is [Unscannable] (or a reader exception) — the stamp then stays where it
 * was requested.
 */
internal object Occupancy {
    class Unscannable(msg: String) : Exception(msg)

    // Limits (§5).
    const val MAX_BYTES = 4 shl 20        // decoded content bytes, page + every form execution
    const val MAX_OPS = 100_000           // operators executed, page + forms
    const val MAX_DEPTH = 8               // form XObject nesting (page content = 0)
    const val MAX_SAVE = 64               // q nesting per content stream
    const val MAX_OPERANDS = 65_536       // operand objects pending at one operator (nested array elements count)
    const val MAX_NESTING = 32            // array / dictionary nesting in an operand
    const val MAX_ANNOTS = 10_000         // /Annots entries
    const val MAX_W_ENTRIES = 65_536      // CIDFont /W: elements read (outer array, and each inner array)
    const val MAX_W_ASSIGN = 262_144      // CIDFont /W: CID assignments attempted before reading stops
    const val MAX_NUM_LEN = 32            // a longer numeric token is not a number
    const val CLAMP = 1e7                 // box coordinates are clamped to ±CLAMP pt before quantising

    /**
     * Occupied boxes of a page in default user space, h100, outward-rounded, in emission order (content stream, then
     * /Annots). [box] = the page's normalised CropBox/MediaBox (h100), used only for the background-fill rule.
     */
    fun scan(rd: PdfReader, page: PdfDict, pageId: Int, box: LongArray): List<LongArray> {
        val s = Scanner(rd, box)
        val pg = Val(PdfObj.Dict(page), pageId)
        val content = s.pageContent(s.key(pg, "Contents"))
        val res = s.inherited(pg, "Resources")
        s.run(content, res, GState(), 0)
        s.annots(s.key(pg, "Annots"))
        return s.boxes
    }

    // ── Values (digitorus/pdf `Value` semantics) ──

    /** A resolved object and the id of the indirect object it lives in (digitorus `Value.GetPtr()` — the font cache key). */
    class Val(val o: PdfObj, val ptr: Int) {
        val isNull get() = o.isNull
        val name: String get() = o.name ?: ""
        val count: Int get() = o.array?.size ?: 0
        val isDict get() = o is PdfObj.Dict
        val isStream get() = o is PdfObj.Stream
        val isArray get() = o is PdfObj.Arr

        /** Integer or real (digitorus Kind Integer | Real). */
        val number: Double?
            get() = when (o) {
                is PdfObj.Int -> o.v.toDouble()
                is PdfObj.Real -> o.v
                else -> null
            }

        companion object {
            val NULL = Val(PdfObj.Null, 0)
        }
    }

    // ── Arithmetic (§2) ──

    val IDENTITY = doubleArrayOf(1.0, 0.0, 0.0, 1.0, 0.0, 0.0)

    /** m × n (row-vector convention), each product rounded on its own, summed left to right. Never mutated in place. */
    fun mul(m: DoubleArray, n: DoubleArray): DoubleArray = doubleArrayOf(
        m[0] * n[0] + m[1] * n[2],
        m[0] * n[1] + m[1] * n[3],
        m[2] * n[0] + m[3] * n[2],
        m[2] * n[1] + m[3] * n[3],
        m[4] * n[0] + m[5] * n[2] + n[4],
        m[4] * n[1] + m[5] * n[3] + n[5],
    )

    /** (x, y) × m = (a·x + c·y + e, b·x + d·y + f). */
    fun apply(m: DoubleArray, x: Double, y: Double): DoubleArray =
        doubleArrayOf(m[0] * x + m[2] * y + m[4], m[1] * x + m[3] * y + m[5])

    fun finite(m: DoubleArray) = m.all { it.isFinite() }

    /** Go `int(f)`: truncation toward zero; saturating (as Kotlin `toLong`), NaN → 0. */
    fun toLong(v: Double): Long = v.toLong()

    /** A float bounding box being accumulated (Math.min/max = Go min/max: NaN wins, −0 < +0). */
    class Rect(var x0: Double, var y0: Double, var x1: Double, var y1: Double) {
        constructor(x: Double, y: Double) : this(x, y, x, y)

        fun add(x: Double, y: Double) {
            x0 = Math.min(x0, x); y0 = Math.min(y0, y); x1 = Math.max(x1, x); y1 = Math.max(y1, y)
        }
    }

    /** Outward to h100 after clamping to ±CLAMP pt: floor(min·100), ceil(max·100). NaN → unscannable. */
    fun quantise(r: Rect): LongArray {
        val v = doubleArrayOf(r.x0, r.y0, r.x1, r.y1)
        for (i in 0 until 4) {
            if (v[i].isNaN()) throw Unscannable("NaN")
            v[i] = Math.min(Math.max(v[i], -CLAMP), CLAMP)
        }
        return longArrayOf(
            Math.floor(v[0] * 100).toLong(), Math.floor(v[1] * 100).toLong(),
            Math.ceil(v[2] * 100).toLong(), Math.ceil(v[3] * 100).toLong(),
        )
    }

    // ── Fonts (§3.4) ──

    enum class FontKind { SIMPLE, IDENTITY, COMPOSITE, FALLBACK }

    class Font(val kind: FontKind) {
        var first = 0L
        val widths = ArrayList<Double?>()
        var missing = 1000.0
        var dw = 1000.0
        val w = HashMap<Long, Double>()

        /** Each code's width (glyph space, 1/1000 em) and whether it is the 1-byte code 32 (word spacing). */
        inline fun glyphs(b: ByteArray, fn: (Double, Boolean) -> Unit) {
            if (kind == FontKind.IDENTITY) {
                var i = 0
                while (i + 1 < b.size) {
                    val cid = ((b[i].toLong() and 0xff) shl 8) or (b[i + 1].toLong() and 0xff)
                    fn(w[cid] ?: dw, false)
                    i += 2
                }
                return
            }
            for (cb in b) {
                val c = cb.toInt() and 0xff
                var w0 = 1000.0
                if (kind == FontKind.SIMPLE) {
                    w0 = missing
                    val i = c.toLong() - first
                    if (i >= 0 && i < widths.size) widths[i.toInt()]?.let { w0 = it }
                }
                fn(w0, kind != FontKind.COMPOSITE && c == 0x20)
            }
        }

        companion object {
            val FALLBACK = Font(FontKind.FALLBACK)
        }
    }

    // ── Content lexer (§3.1) ──

    sealed class Operand {
        class Num(val v: Double) : Operand()
        class Str(val b: ByteArray) : Operand()
        class Name(val v: String) : Operand()
        class Arr(val items: List<Operand>) : Operand()
        object Dict : Operand()
        /** true/false/null, or a keyword inside an array/dictionary. */
        object Other : Operand()
    }

    sealed class Token {
        object Eof : Token()
        /** [open] = "[" | "<<" for a container to complete, else "". */
        class Obj(val o: Operand, val open: String) : Token()
        class Keyword(val kw: String) : Token()
        object ArrEnd : Token()
        object DictEnd : Token()
    }

    class Lexer(val b: ByteArray) {
        var i = 0

        private fun at(p: Int) = b[p].toInt() and 0xff

        companion object {
            fun isSpace(c: Int) = c == 0 || c == 9 || c == 10 || c == 12 || c == 13 || c == 32
            fun isDelim(c: Int) = when (c) {
                0x28, 0x29, 0x3C, 0x3E, 0x5B, 0x5D, 0x7B, 0x7D, 0x2F, 0x25 -> true
                else -> false
            }

            /** [+-]?(\d+(\.\d*)?|\.\d+), at most MAX_NUM_LEN bytes. */
            fun isNumber(t: ByteArray): Boolean {
                if (t.isEmpty() || t.size > MAX_NUM_LEN) return false
                var i = 0
                if (t[0] == '+'.code.toByte() || t[0] == '-'.code.toByte()) i++
                var digits = 0
                var dot = false
                while (i < t.size) {
                    val c = t[i].toInt() and 0xff
                    when {
                        c in 0x30..0x39 -> digits++
                        c == 0x2E && !dot -> dot = true
                        else -> return false
                    }
                    i++
                }
                return digits > 0
            }

            fun unhex(c: Int): Int? = when (c) {
                in 0x30..0x39 -> c - 0x30
                in 0x61..0x66 -> c - 0x61 + 10
                in 0x41..0x46 -> c - 0x41 + 10
                else -> null
            }
        }

        fun skipSpace() {
            while (i < b.size) {
                val c = at(i)
                if (isSpace(c)) {
                    i++
                } else if (c == 0x25) {
                    while (i < b.size && at(i) != 0x0D && at(i) != 0x0A) i++
                } else {
                    return
                }
            }
        }

        fun regular(): ByteArray {
            val s = i
            while (i < b.size && !isSpace(at(i)) && !isDelim(at(i))) i++
            return b.copyOfRange(s, i)
        }

        /** After '(' : balanced parentheses, escapes; EOF ends the string. */
        fun literal(): ByteArray {
            val out = ByteArrayOutputStream()
            var depth = 1
            while (i < b.size) {
                var c = at(i)
                i++
                when (c) {
                    0x28 -> depth++
                    0x29 -> {
                        depth--
                        if (depth == 0) return out.toByteArray()
                    }
                    0x5C -> {
                        if (i >= b.size) return out.toByteArray()
                        val e = at(i)
                        i++
                        when (e) {
                            0x6E -> c = 0x0A
                            0x72 -> c = 0x0D
                            0x74 -> c = 0x09
                            0x62 -> c = 0x08
                            0x66 -> c = 0x0C
                            0x0D -> {
                                if (i < b.size && at(i) == 0x0A) i++
                                continue
                            }
                            0x0A -> continue
                            in 0x30..0x37 -> {
                                var v = e - 0x30
                                var k = 0
                                while (k < 2 && i < b.size && at(i) in 0x30..0x37) {
                                    v = v * 8 + (at(i) - 0x30)
                                    i++
                                    k++
                                }
                                c = v and 0xff
                            }
                            else -> c = e
                        }
                    }
                }
                out.write(c)
            }
            return out.toByteArray()
        }

        /** After '<' : hex digits, other bytes skipped, odd final nibble padded with 0; '>' or EOF ends it. */
        fun hexString(): ByteArray {
            val out = ByteArrayOutputStream()
            var hi = 0
            var half = false
            while (i < b.size) {
                val c = at(i)
                i++
                if (c == 0x3E) break
                val v = unhex(c) ?: continue
                if (half) out.write((hi shl 4) or v) else hi = v
                half = !half
            }
            if (half) out.write(hi shl 4)
            return out.toByteArray()
        }

        /** After '/' : regular bytes, #xx decoded (one char per byte, as PdfObj names). */
        fun name(): String {
            val t = regular()
            val sb = StringBuilder()
            var k = 0
            while (k < t.size) {
                val c = t[k].toInt() and 0xff
                if (c == 0x23 && k + 2 < t.size) {
                    val h = unhex(t[k + 1].toInt() and 0xff)
                    val lo = unhex(t[k + 2].toInt() and 0xff)
                    if (h != null && lo != null) {
                        sb.append(((h shl 4) or lo).toChar())
                        k += 3
                        continue
                    }
                }
                sb.append(c.toChar())
                k++
            }
            return sb.toString()
        }

        /** One token; '{' '}' and stray ')' / '>' are skipped. */
        fun next(): Token {
            while (true) {
                skipSpace()
                if (i >= b.size) return Token.Eof
                when (at(i)) {
                    0x28 -> {
                        i++
                        return Token.Obj(Operand.Str(literal()), "")
                    }
                    0x3C -> {
                        if (i + 1 < b.size && at(i + 1) == 0x3C) {
                            i += 2
                            return Token.Obj(Operand.Dict, "<<")
                        }
                        i++
                        return Token.Obj(Operand.Str(hexString()), "")
                    }
                    0x3E -> {
                        if (i + 1 < b.size && at(i + 1) == 0x3E) {
                            i += 2
                            return Token.DictEnd
                        }
                        i++
                        continue
                    }
                    0x5B -> {
                        i++
                        return Token.Obj(Operand.Arr(emptyList()), "[")
                    }
                    0x5D -> {
                        i++
                        return Token.ArrEnd
                    }
                    0x2F -> {
                        i++
                        return Token.Obj(Operand.Name(name()), "")
                    }
                    0x29, 0x7B, 0x7D -> {
                        i++
                        continue
                    }
                }
                val t = regular()
                val s = String(t, Charsets.ISO_8859_1)
                if (isNumber(t)) {
                    val v = s.toDoubleOrNull() ?: return Token.Obj(Operand.Other, "")
                    return Token.Obj(Operand.Num(v), "")
                }
                return when (s) {
                    "true", "false", "null" -> Token.Obj(Operand.Other, "")
                    else -> Token.Keyword(s)
                }
            }
        }

        /** Result of [obj]: the completed operand and whether EOF ended the content. */
        class Completed(val o: Operand, val eof: Boolean)

        /**
         * Completes an array or dictionary opened by [next] (open = "[" or "<<"). Inside, every token is an element;
         * EOF ends the content (eof = true). Nesting > MAX_NESTING or too many elements → unscannable.
         */
        fun obj(o: Operand, open: String, depth: Int, count: IntArray): Completed {
            if (open.isEmpty()) return Completed(o, false)
            if (depth >= MAX_NESTING) throw Unscannable("nesting")
            val elems = ArrayList<Operand>()
            fun done(): Operand = if (open == "[") Operand.Arr(elems) else o
            while (true) {
                val e: Operand = when (val t = next()) {
                    Token.Eof -> return Completed(done(), true)
                    Token.ArrEnd -> if (open == "[") return Completed(done(), false) else continue
                    Token.DictEnd -> if (open == "<<") return Completed(done(), false) else continue
                    is Token.Keyword -> Operand.Other
                    is Token.Obj -> {
                        val y = obj(t.o, t.open, depth + 1, count)
                        if (y.eof) return Completed(done(), true)
                        y.o
                    }
                }
                count[0]++
                if (count[0] > MAX_OPERANDS) throw Unscannable("operands")
                if (open == "[") elems += e
            }
        }
    }

    // ── Interpreter (§3.2–§3.6) ──

    /** Graphics + text state; saved by `q` as a copy (arrays are never mutated in place). */
    data class GState(
        var ctm: DoubleArray = IDENTITY,
        var lw: Double = 1.0,
        var fillWhite: Boolean = false,
        var strokeWhite: Boolean = false,
        var tc: Double = 0.0,
        var tw: Double = 0.0,
        var th: Double = 1.0,
        var tl: Double = 0.0,
        var tfs: Double = 0.0,
        var trise: Double = 0.0,
        var font: Font = Font.FALLBACK,
    )

    class Subpath(var sx: Double, var sy: Double) {
        var cx = sx
        var cy = sy
        val bbox = Rect(sx, sy)
        val segs = ArrayList<Rect>()

        fun close() {
            val seg = Rect(cx, cy)
            seg.add(sx, sy)
            segs += seg
            cx = sx; cy = sy
        }
    }

    class Scanner(private val rd: PdfReader, private val page: LongArray) {
        private var bytes = 0
        private var ops = 0
        val boxes = ArrayList<LongArray>()
        private val fonts = HashMap<Int, Font>()

        // digitorus resolve: a reference becomes the object it names (ptr = its id); a missing object is null; a
        // reference to a reference is a reader failure.
        private fun res(x: PdfObj, parent: Int): Val {
            if (x !is PdfObj.Ref) return Val(x, parent)
            val y = rd.obj(x.r)
            if (y is PdfObj.Ref) throw Unscannable("reference to a reference")
            if (y.isNull) return Val.NULL
            return Val(y, x.r.id)
        }

        fun key(v: Val, k: String): Val {
            val d = v.o.dict ?: return Val.NULL
            return res(d[k], v.ptr)
        }

        fun index(v: Val, i: Int): Val {
            val a = v.o.array ?: return Val.NULL
            if (i < 0 || i >= a.size) return Val.NULL
            return res(a[i], v.ptr)
        }

        /** A page attribute, following /Parent (depth ≤ 32). */
        fun inherited(page: Val, k: String): Val {
            var v = page
            repeat(32) {
                val x = key(v, k)
                if (!x.isNull) return x
                v = key(v, "Parent")
                if (!v.isDict) return Val.NULL
            }
            return Val.NULL
        }

        private fun emit(r: Rect) {
            boxes += quantise(r)
        }

        /** Decoded bytes of a content/form stream: no filter, or exactly FlateDecode without parameters (§3.1). */
        fun stream(v: Val): ByteArray {
            val s = v.o as? PdfObj.Stream ?: throw Unscannable("not a stream")
            val f = key(v, "Filter")
            val p = key(v, "DecodeParms")
            val flate = when {
                f.isNull && p.isNull -> false
                f.o is PdfObj.Name && f.name == "FlateDecode" && p.isNull -> true
                f.isArray && f.count == 1 && index(f, 0).let { it.o is PdfObj.Name && it.name == "FlateDecode" } &&
                    (p.isNull || (p.isArray && p.count == 1 && index(p, 0).isNull)) -> true
                else -> throw Unscannable("filter")
            }
            if (s.start < 0 || s.end > rd.bytes.size || s.start > s.end) throw Unscannable("stream range")
            val raw = rd.bytes.copyOfRange(s.start, s.end)
            val left = MAX_BYTES - bytes
            val out = if (flate) inflate(raw, left) else raw
            if (out.size > left) throw Unscannable("content bytes")
            bytes += out.size
            return out
        }

        /** /Contents: absent → empty; a stream; or an array of streams joined with LF. */
        fun pageContent(c: Val): ByteArray = when (c.o) {
            PdfObj.Null -> ByteArray(0)
            is PdfObj.Stream -> stream(c)
            is PdfObj.Arr -> {
                val out = ByteArrayOutputStream()
                for (i in 0 until c.count) {
                    val b = stream(index(c, i))
                    if (i > 0) out.write(0x0A)
                    out.write(b)
                }
                out.toByteArray()
            }
            else -> throw Unscannable("/Contents")
        }

        private fun font(v: Val): Font {
            if (!v.isDict) return Font.FALLBACK
            if (v.ptr != 0) fonts[v.ptr]?.let { return it }
            val f = loadFont(v)
            if (v.ptr != 0) fonts[v.ptr] = f
            return f
        }

        private fun loadFont(v: Val): Font {
            when (key(v, "Subtype").name) {
                "Type3" -> return Font.FALLBACK
                "Type0" -> {
                    val enc = key(v, "Encoding")
                    if (enc.o !is PdfObj.Name || (enc.name != "Identity-H" && enc.name != "Identity-V")) return Font(FontKind.COMPOSITE)
                    val f = Font(FontKind.IDENTITY)
                    val d = index(key(v, "DescendantFonts"), 0)
                    key(d, "DW").number?.let { f.dw = it }
                    val w = key(d, "W")
                    val n = minOf(w.count, MAX_W_ENTRIES)
                    var budget = MAX_W_ASSIGN
                    fun set(cid: Long, value: Double): Boolean {
                        budget--
                        if (budget < 0) return false
                        if (cid in 0..0xFFFF && !f.w.containsKey(cid)) f.w[cid] = value
                        return true
                    }
                    var i = 0
                    read@ while (i < n) {
                        val c0 = index(w, i).number
                        if (c0 == null || i + 1 >= n) break
                        val arr = index(w, i + 1)
                        if (arr.isArray) {
                            for (j in 0 until minOf(arr.count, MAX_W_ENTRIES)) {
                                val x = index(arr, j).number ?: continue
                                if (!set(toLong(c0) + j, x)) break@read
                            }
                            i += 2
                            continue
                        }
                        val c1 = index(w, i + 1).number
                        val x = index(w, i + 2).number
                        if (c1 == null || x == null || i + 2 >= n) break
                        var c = maxOf(toLong(c0), 0L)
                        val hi = toLong(c1)
                        while (c <= hi && c <= 0xFFFF) {
                            if (!set(c, x)) break@read
                            c++
                        }
                        i += 3
                    }
                    return f
                }
            }
            val f = Font(FontKind.SIMPLE)
            key(v, "FirstChar").number?.let { f.first = toLong(it) }
            val ws = key(v, "Widths")
            for (i in 0 until minOf(ws.count, 256)) f.widths += index(ws, i).number
            key(key(v, "FontDescriptor"), "MissingWidth").number?.let { if (it > 0) f.missing = it }
            return f
        }

        private fun nums(ops: List<Operand>, n: Int): DoubleArray? {
            if (ops.size != n) return null
            val out = DoubleArray(n)
            for (i in 0 until n) out[i] = (ops[i] as? Operand.Num)?.v ?: return null
            return out
        }

        private fun textMatrix(m: DoubleArray): DoubleArray {
            if (!finite(m)) throw Unscannable("text matrix")
            return m
        }

        /**
         * Executes one content stream (page content or a form) from graphics state [g0], with its own operand stack,
         * q stack, path and text matrices.
         */
        fun run(content: ByteArray, res: Val, g0: GState, depth: Int) {
            val l = Lexer(content)
            var g = g0.copy()
            val stack = ArrayList<GState>()
            var path = ArrayList<Subpath>()
            var tm = IDENTITY
            var tlm = IDENTITY
            val opnds = ArrayList<Operand>()
            val count = intArrayOf(0)
            while (true) {
                val kw = when (val t = l.next()) {
                    Token.Eof -> return
                    Token.ArrEnd, Token.DictEnd -> continue
                    is Token.Obj -> {
                        val x = l.obj(t.o, t.open, 0, count)
                        if (x.eof) return
                        count[0]++
                        if (count[0] > MAX_OPERANDS) throw Unscannable("operands")
                        opnds += x.o
                        continue
                    }
                    is Token.Keyword -> t.kw
                }
                ops++
                if (ops > MAX_OPS) throw Unscannable("operators")
                val args = ArrayList(opnds)
                opnds.clear()
                count[0] = 0
                when (kw) {
                    "q", "Q", "BT" -> {
                        if (args.isNotEmpty()) continue
                        when (kw) {
                            "BT" -> { tm = IDENTITY; tlm = IDENTITY }
                            "Q" -> if (stack.isNotEmpty()) g = stack.removeAt(stack.size - 1)
                            else -> {
                                if (stack.size >= MAX_SAVE) throw Unscannable("q nesting")
                                stack += g.copy()
                            }
                        }
                    }
                    "cm" -> nums(args, 6)?.let {
                        g.ctm = mul(it, g.ctm)
                        if (!finite(g.ctm)) throw Unscannable("CTM")
                    }
                    "w" -> nums(args, 1)?.let { g.lw = it[0] }
                    "g" -> nums(args, 1)?.let { g.fillWhite = it[0] >= 1 }
                    "G" -> nums(args, 1)?.let { g.strokeWhite = it[0] >= 1 }
                    "rg" -> nums(args, 3)?.let { g.fillWhite = it[0] >= 1 && it[1] >= 1 && it[2] >= 1 }
                    "RG" -> nums(args, 3)?.let { g.strokeWhite = it[0] >= 1 && it[1] >= 1 && it[2] >= 1 }
                    "k" -> nums(args, 4)?.let { g.fillWhite = it[0] <= 0 && it[1] <= 0 && it[2] <= 0 && it[3] <= 0 }
                    "K" -> nums(args, 4)?.let { g.strokeWhite = it[0] <= 0 && it[1] <= 0 && it[2] <= 0 && it[3] <= 0 }
                    "cs", "sc", "scn" -> g.fillWhite = false
                    "CS", "SC", "SCN" -> g.strokeWhite = false

                    // ── Path construction (points transformed by the CTM when given) ──
                    "m" -> nums(args, 2)?.let {
                        val p = apply(g.ctm, it[0], it[1])
                        path.add(Subpath(p[0], p[1]))
                    }
                    "l", "c", "v", "y" -> {
                        val n = when (kw) { "l" -> 2; "c" -> 6; else -> 4 }
                        val v = nums(args, n) ?: continue
                        val sp = path.lastOrNull() ?: continue
                        val seg = Rect(sp.cx, sp.cy)
                        var i = 0
                        while (i < n) {
                            val p = apply(g.ctm, v[i], v[i + 1])
                            seg.add(p[0], p[1])
                            sp.bbox.add(p[0], p[1])
                            sp.cx = p[0]; sp.cy = p[1]
                            i += 2
                        }
                        sp.segs += seg
                    }
                    "h" -> if (args.isEmpty()) path.lastOrNull()?.close()
                    "re" -> nums(args, 4)?.let { v ->
                        val p0 = apply(g.ctm, v[0], v[1])
                        val p1 = apply(g.ctm, v[0] + v[2], v[1])
                        val p2 = apply(g.ctm, v[0] + v[2], v[1] + v[3])
                        val p3 = apply(g.ctm, v[0], v[1] + v[3])
                        val sp = Subpath(p0[0], p0[1])
                        for (p in listOf(p1, p2, p3)) {
                            val seg = Rect(sp.cx, sp.cy)
                            seg.add(p[0], p[1])
                            sp.segs += seg
                            sp.bbox.add(p[0], p[1])
                            sp.cx = p[0]; sp.cy = p[1]
                        }
                        sp.close()
                        path.add(sp)
                    }
                    "S", "s", "f", "F", "f*", "B", "B*", "b", "b*", "n" -> {
                        if (args.isNotEmpty()) continue
                        if (kw == "s" || kw == "b" || kw == "b*") path.lastOrNull()?.close()
                        val fill = kw != "S" && kw != "s" && kw != "n"
                        val stroke = kw == "S" || kw == "s" || kw == "B" || kw == "B*" || kw == "b" || kw == "b*"
                        if (fill && !g.fillWhite) fill(path)
                        if (stroke && !g.strokeWhite) stroke(path, g)
                        path = ArrayList()
                    }

                    // ── Text ──
                    "Tc" -> nums(args, 1)?.let { g.tc = it[0] }
                    "Tw" -> nums(args, 1)?.let { g.tw = it[0] }
                    "Tz" -> nums(args, 1)?.let { g.th = it[0] / 100 }
                    "TL" -> nums(args, 1)?.let { g.tl = it[0] }
                    "Ts" -> nums(args, 1)?.let { g.trise = it[0] }
                    "Tf" -> {
                        val fname = args.getOrNull(0) as? Operand.Name
                        val size = args.getOrNull(1) as? Operand.Num
                        if (args.size == 2 && fname != null && size != null) {
                            g.font = font(key(key(res, "Font"), fname.v))
                            g.tfs = size.v
                        }
                    }
                    "Td", "TD" -> nums(args, 2)?.let { v ->
                        if (kw == "TD") g.tl = -v[1]
                        tlm = textMatrix(mul(doubleArrayOf(1.0, 0.0, 0.0, 1.0, v[0], v[1]), tlm))
                        tm = tlm
                    }
                    "T*" -> if (args.isEmpty()) {
                        tlm = textMatrix(mul(doubleArrayOf(1.0, 0.0, 0.0, 1.0, 0.0, -g.tl), tlm))
                        tm = tlm
                    }
                    "Tm" -> nums(args, 6)?.let { tm = it; tlm = it }
                    "Tj", "'", "\"", "TJ" -> {
                        val items: List<Operand> = when {
                            (kw == "Tj" || kw == "'") && args.size == 1 && args[0] is Operand.Str -> args
                            kw == "\"" && args.size == 3 && args[0] is Operand.Num && args[1] is Operand.Num && args[2] is Operand.Str -> {
                                g.tw = (args[0] as Operand.Num).v
                                g.tc = (args[1] as Operand.Num).v
                                listOf(args[2])
                            }
                            kw == "TJ" && args.size == 1 && args[0] is Operand.Arr -> (args[0] as Operand.Arr).items
                            else -> continue
                        }
                        if (kw == "'" || kw == "\"") {
                            tlm = textMatrix(mul(doubleArrayOf(1.0, 0.0, 0.0, 1.0, 0.0, -g.tl), tlm))
                            tm = tlm
                        }
                        tm = show(items, g, tm)
                    }
                    "Do" -> {
                        val xname = (args.singleOrNull() as? Operand.Name)?.v ?: continue
                        val x = key(key(res, "XObject"), xname)
                        when (key(x, "Subtype").name) {
                            "Image" -> unitSquare(g.ctm)
                            "Form" -> {
                                if (!x.isStream) continue
                                if (depth + 1 > MAX_DEPTH) throw Unscannable("form depth")
                                var fm = IDENTITY
                                val m = key(x, "Matrix")
                                if (m.isArray && m.count == 6) {
                                    val v = DoubleArray(6)
                                    var ok = true
                                    for (i in 0 until 6) {
                                        val n = index(m, i).number
                                        if (n == null) { ok = false; break }
                                        v[i] = n
                                    }
                                    if (ok) fm = v
                                }
                                val ctm = mul(fm, g.ctm)
                                if (!finite(ctm)) throw Unscannable("form matrix")
                                var fres = key(x, "Resources")
                                if (!fres.isDict) fres = res
                                val b = stream(x)
                                val fg = g.copy()
                                fg.ctm = ctm
                                run(b, fres, fg, depth + 1)
                            }
                        }
                    }
                    "BI" -> inlineImage(l, g.ctm)
                }
            }
        }

        /** One box per subpath; a subpath box covering ≥ half of the page box is a background and is skipped. */
        private fun fill(path: List<Subpath>) {
            for (sp in path) {
                val q = quantise(sp.bbox)
                val w = minOf(q[2], page[2]) - maxOf(q[0], page[0])
                val h = minOf(q[3], page[3]) - maxOf(q[1], page[1])
                if (w > 0 && h > 0 && 2 * w * h >= (page[2] - page[0]) * (page[3] - page[1])) continue
                boxes += q
            }
        }

        /** One box per segment, widened by half the line width mapped through the CTM (|a|+|c|, |b|+|d|). */
        private fun stroke(path: List<Subpath>, g: GState) {
            val hw = Math.abs(g.lw) / 2
            val ex = hw * Math.abs(g.ctm[0]) + hw * Math.abs(g.ctm[2])
            val ey = hw * Math.abs(g.ctm[1]) + hw * Math.abs(g.ctm[3])
            for (sp in path) for (r in sp.segs) emit(Rect(r.x0 - ex, r.y0 - ey, r.x1 + ex, r.y1 + ey))
        }

        private fun unitSquare(ctm: DoubleArray) {
            val p = apply(ctm, 0.0, 0.0)
            val r = Rect(p[0], p[1])
            for ((px, py) in listOf(1.0 to 0.0, 0.0 to 1.0, 1.0 to 1.0)) {
                val t = apply(ctm, px, py)
                r.add(t[0], t[1])
            }
            emit(r)
        }

        /**
         * One box per string/array operand: [min, max] of glyph extents in text space × [rise − 0.3·Tfs, rise + Tfs],
         * through Tm then the CTM. Returns the advanced Tm.
         */
        private fun show(items: List<Operand>, g: GState, tm: DoubleArray): DoubleArray {
            var x = 0.0
            var ext: DoubleArray? = null
            for (it in items) {
                when (it) {
                    is Operand.Num -> x -= it.v / 1000 * g.tfs * g.th
                    is Operand.Str -> g.font.glyphs(it.b) { w0, space ->
                        val gwa = w0 / 1000 * g.tfs
                        val gw = gwa * g.th
                        val xe = x + gw
                        val lo = Math.min(x, xe)
                        val hi = Math.max(x, xe)
                        val e = ext
                        if (e == null) ext = doubleArrayOf(lo, hi) else { e[0] = Math.min(e[0], lo); e[1] = Math.max(e[1], hi) }
                        var adv = gwa + g.tc
                        if (space) adv += g.tw
                        x += adv * g.th
                    }
                    else -> {}
                }
            }
            ext?.let { e ->
                val ya = g.trise + g.tfs * -0.3
                val yb = g.trise + g.tfs
                var r: Rect? = null
                for ((px, py) in listOf(e[0] to ya, e[1] to ya, e[0] to yb, e[1] to yb)) {
                    val t = apply(tm, px, py)
                    val d = apply(g.ctm, t[0], t[1])
                    val rr = r
                    if (rr == null) r = Rect(d[0], d[1]) else rr.add(d[0], d[1])
                }
                emit(r!!)
            }
            val out = mul(doubleArrayOf(1.0, 0.0, 0.0, 1.0, x, 0.0), tm)
            if (!finite(out)) throw Unscannable("text matrix")
            return out
        }

        /**
         * BI <key value>… ID <data> EI: data ends at the first "EI" preceded by a whitespace byte and followed by a
         * whitespace byte or the end of the content. No EI → the content ends (no box).
         */
        private fun inlineImage(l: Lexer, ctm: DoubleArray) {
            val count = intArrayOf(0)
            scan@ while (true) {
                when (val t = l.next()) {
                    Token.Eof -> return
                    is Token.Obj -> if (l.obj(t.o, t.open, 0, count).eof) return
                    is Token.Keyword -> if (t.kw == "ID") break@scan
                    else -> {}
                }
            }
            val b = l.b
            fun sp(p: Int) = Lexer.isSpace(b[p].toInt() and 0xff)
            if (l.i < b.size && sp(l.i)) l.i++
            var p = l.i
            while (p + 1 < b.size) {
                if (b[p] == 'E'.code.toByte() && b[p + 1] == 'I'.code.toByte() && p > 0 && sp(p - 1) && (p + 2 == b.size || sp(p + 2))) {
                    l.i = p + 2
                    unitSquare(ctm)
                    return
                }
                p++
            }
            l.i = b.size
        }

        /** /Rect of every annotation except /Popup, hidden (/F bit 2) or NoView (/F bit 6) and zero-area rects. */
        fun annots(a: Val) {
            if (!a.isArray) return
            if (a.count > MAX_ANNOTS) throw Unscannable("annotations")
            for (i in 0 until a.count) {
                val an = index(a, i)
                if (!an.isDict || key(an, "Subtype").name == "Popup") continue
                val f = key(an, "F").o
                if (f is PdfObj.Int && (f.v and (2L or 32L)) != 0L) continue
                val rc = key(an, "Rect")
                if (!rc.isArray || rc.count != 4) continue
                val v = DoubleArray(4)
                var ok = true
                for (j in 0 until 4) {
                    val n = index(rc, j).number
                    if (n == null) { ok = false; break }
                    v[j] = n
                }
                if (!ok || v[0] == v[2] || v[1] == v[3]) continue
                emit(Rect(Math.min(v[0], v[2]), Math.min(v[1], v[3]), Math.max(v[0], v[2]), Math.max(v[1], v[3])))
            }
        }
    }

    /**
     * zlib (RFC 1950) inflate, strict: valid header, raw deflate to its final block, Adler-32 must match ([Inflater] with
     * the zlib wrapper checks the header — CM 8, CINFO ≤ 7, FCHECK — and the trailer); FDICT only with DICTID 1 (Go);
     * truncation or any error → unscannable; bytes after the checksum are ignored; output over [limit] → unscannable.
     */
    fun inflate(input: ByteArray, limit: Int): ByteArray {
        val inf = Inflater()
        try {
            inf.setInput(input)
            val out = ByteArrayOutputStream()
            val buf = ByteArray(64 shl 10)
            while (!inf.finished()) {
                val n = inf.inflate(buf)
                if (n == 0 && inf.needsDictionary()) {
                    // FDICT: Go compress/zlib accepts a preset dictionary only when DICTID = Adler-32 of its nil
                    // dictionary (1) and inflates on; any other DICTID → ErrDictionary.
                    if (inf.adler != 1) throw Unscannable("FlateDecode: preset dictionary")
                    inf.setDictionary(ByteArray(0))
                    continue
                }
                if (n == 0 && inf.needsInput()) throw Unscannable("FlateDecode truncated")
                out.write(buf, 0, n)
                if (out.size() > limit) throw Unscannable("content bytes")
            }
            return out.toByteArray()
        } catch (e: DataFormatException) {
            throw Unscannable("FlateDecode: ${e.message}")
        } finally {
            inf.end()
        }
    }
}
