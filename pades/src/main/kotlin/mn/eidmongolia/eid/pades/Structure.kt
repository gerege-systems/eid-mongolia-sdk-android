package mn.eidmongolia.eid.pades

import java.util.zip.Inflater

/**
 * PRECHECKS #2a / #2b — Go reference `validate.CheckStructure` (nesting.go + objstm.go), run before any PDF parsing:
 * array/dictionary nesting > 256 from every point where a reader may start an object (after the `obj` / `trailer`
 * keywords, at every offset of a /Type /ObjStm header), a read/inflate budget, top-level /Size > 2 097 152, and the
 * object-stream graph (a container that is itself in an object stream, header references into object streams,
 * /Extends cycles or chains > 64). Same rules on every SDK (golden validate/v4 `deep-nesting*`); iOS `Structure` 1:1.
 * One layer of defence — it does not make untrusted PDF parsing safe on its own.
 */
internal object Structure {
    class Failure : Exception("PDF structure nested too deep or too complex")

    const val MAX_NESTING = 256
    private const val SCAN_FACTOR = 16 // read budget = 16 × len(doc) + 1 MiB
    private const val MAX_OBJSTM_BYTES = 32 shl 20 // all inflated object streams together (zip bomb)
    const val MAX_XREF_SIZE = 1L shl 21
    private const val MAX_OBJSTM_CHAIN = 64

    fun check(doc: ByteArray) {
        val s = Scan(SCAN_FACTOR * doc.size + (1 shl 20), MAX_OBJSTM_BYTES, hasEncryptRef(doc))
        for (kw in listOf("obj".toByteArray(), "trailer".toByteArray())) {
            var k = 0
            while (true) {
                val at = PdfReader.indexOf(doc, kw, k)
                if (at < 0) break
                val end = at + kw.size
                k = end
                // The keyword stands alone (`endobj`, `objx` are other keywords).
                if (at > 0 && !isSpace(doc[at - 1]) && !isDelim(doc[at - 1])) continue
                if (end < doc.size && !isSpace(doc[end]) && !isDelim(doc[end])) continue
                s.obj(doc, 0, doc.size, end, true)
            }
        }
        if (s.bigSize) throw Failure()
        checkObjStmGraph(doc)
    }

    /**
     * `/Encrypt` followed by an indirect reference (`N G R`) or a direct dictionary (`<<`) — Go regexp
     * `/Encrypt(?:\s+\d+\s+\d+\s+R|\s*<<)` (`\s` = [\t\n\f\r ]); `/EncryptMetadata` does not count.
     */
    fun hasEncryptRef(b: ByteArray): Boolean {
        val key = "/Encrypt".toByteArray()
        fun ws(i: Int) = i < b.size && b[i].toInt().let { it == 9 || it == 10 || it == 12 || it == 13 || it == 32 }
        fun digit(i: Int) = i < b.size && b[i] in '0'.code.toByte()..'9'.code.toByte()
        var from = 0
        while (true) {
            val k = PdfReader.indexOf(b, key, from)
            if (k < 0) return false
            from = k + 1
            var q = k + key.size
            while (ws(q)) q++
            if (q + 1 < b.size && b[q] == '<'.code.toByte() && b[q + 1] == '<'.code.toByte()) return true
            var p = k + key.size
            var ok = true
            repeat(2) {
                if (!ok) return@repeat
                val w = p
                while (ws(p)) p++
                val d = p
                while (digit(p)) p++
                if (p == d || d == w) ok = false
            }
            if (ok) {
                val w = p
                while (ws(p)) p++
                if (p > w && p < b.size && b[p] == 'R'.code.toByte()) return true
            }
        }
    }

    private fun isSpace(c: Byte) = c.toInt().let { it == 0 || it == 9 || it == 10 || it == 12 || it == 13 || it == 32 }

    // ()<>[]{}/%
    private fun isDelim(c: Byte) = c.toInt().let {
        it == 0x28 || it == 0x29 || it == 0x3C || it == 0x3E || it == 0x5B || it == 0x5D || it == 0x7B || it == 0x7D || it == 0x2F || it == 0x25
    }

    private enum class Tok { EOF, ERR, ARR, ARR_END, DICT, DICT_END, NAME, WORD, STR }

    /** digitorus buffer.readToken (structure only) over b[0 until end]. */
    private class Lex(val b: ByteArray, val end: Int, var pos: Int) {
        var v = ""

        fun next(): Tok {
            while (true) {
                while (pos < end && isSpace(b[pos])) pos++
                if (pos < end && b[pos] == '%'.code.toByte()) {
                    while (pos < end && b[pos] != '\r'.code.toByte() && b[pos] != '\n'.code.toByte()) pos++
                    continue
                }
                break
            }
            if (pos >= end) return Tok.EOF
            val c = b[pos].toInt() and 0xff
            pos++
            when (c) {
                0x3C -> {
                    if (pos < end && b[pos] == '<'.code.toByte()) { pos++; return Tok.DICT }
                    while (pos < end && b[pos] != '>'.code.toByte()) pos++
                    pos++
                    return Tok.STR
                }
                0x28 -> {
                    var depth = 1
                    while (pos < end && depth > 0) {
                        when (b[pos].toInt()) {
                            0x28 -> depth++
                            0x29 -> depth--
                            0x5C -> pos++
                        }
                        pos++
                    }
                    return Tok.STR
                }
                0x5B -> return Tok.ARR
                0x5D -> return Tok.ARR_END
                0x7B, 0x7D -> { v = c.toChar().toString(); return Tok.WORD }
                0x2F -> {
                    val sb = StringBuilder()
                    while (pos < end && !isDelim(b[pos]) && !isSpace(b[pos])) {
                        if (b[pos] == '#'.code.toByte() && pos + 2 < end) {
                            val hi = PdfLexer.hexVal(b[pos + 1].toInt() and 0xff)
                            val lo = PdfLexer.hexVal(b[pos + 2].toInt() and 0xff)
                            if (hi != null && lo != null) {
                                sb.append(((hi shl 4) or lo).toChar())
                                pos += 3
                                continue
                            }
                        }
                        sb.append((b[pos].toInt() and 0xff).toChar())
                        pos++
                    }
                    v = sb.toString()
                    return Tok.NAME
                }
                0x3E -> {
                    if (pos < end && b[pos] == '>'.code.toByte()) { pos++; return Tok.DICT_END }
                    return Tok.ERR
                }
                0x29 -> return Tok.ERR
            }
            val start = pos - 1
            while (pos < end && !isDelim(b[pos]) && !isSpace(b[pos])) pos++
            v = String(b, start, pos - start, Charsets.ISO_8859_1)
            return Tok.WORD
        }
    }

    private val INT_RE = Regex("^[+-]?[0-9]+$")

    /** Go `strconv.ParseInt(s, 10, 64)` succeeds. */
    private fun isInt(s: String) = INT_RE.matches(s) && s.toLongOrNull() != null

    /** Go `v, _ := strconv.ParseInt(s, 10, 64)`: syntax error → 0, out of range → ±MaxInt64. */
    private fun parseInt64(s: String): Long {
        if (!INT_RE.matches(s)) return 0
        return s.toLongOrNull() ?: if (s.startsWith("-")) Long.MIN_VALUE else Long.MAX_VALUE
    }

    private class Frame(val dict: Boolean, var expectKey: Boolean, var key: String = "")

    private class Info {
        var typ = ""
        var filter = ""
        var filters = 0
        var parms = false
        var indirect = false
        var first = 0L
        var nCount = 0L
    }

    private class Scan(var budget: Int, var inflateLeft: Int, val encrypted: Boolean) {
        var bigSize = false

        /**
         * One reader object at [start] (a doubled `N G obj` included) in b[base until end], depth-checked; with
         * [allowStream] a top-level /Type /ObjStm dictionary's stream is inflated and its objects checked.
         */
        fun obj(b: ByteArray, base: Int, end: Int, start: Int, allowStream: Boolean) {
            val l = Lex(b, end, start)
            try {
                body(l, b, base, end, start, allowStream)
            } finally {
                budget -= l.pos - start
            }
        }

        private fun body(l: Lex, b: ByteArray, base: Int, end: Int, start: Int, allowStream: Boolean) {
            val stack = ArrayList<Frame>()
            val info = Info()
            while (true) {
                if (budget - (l.pos - start) < 0) throw Failure()
                val tok = l.next()
                val top = stack.lastOrNull()
                if (top != null && top.dict && top.expectKey) {
                    when (tok) {
                        Tok.DICT_END -> {
                            stack.removeAt(stack.size - 1)
                            if (stack.isEmpty()) {
                                if (allowStream && (info.typ == "ObjStm" || info.indirect)) objStm(b, end, l, info)
                                return
                            }
                            stack.last().expectKey = stack.last().dict
                            continue
                        }
                        Tok.NAME -> {
                            top.key = l.v
                            top.expectKey = false
                            continue
                        }
                        else -> return // non-name key — the reader fails here
                    }
                }
                when (tok) {
                    Tok.EOF, Tok.ERR, Tok.DICT_END -> return
                    Tok.ARR, Tok.DICT -> {
                        if (stack.size >= MAX_NESTING) throw Failure()
                        if (stack.size == 1 && stack[0].dict && stack[0].key == "DecodeParms") info.parms = true
                        stack += Frame(tok == Tok.DICT, tok == Tok.DICT)
                        continue
                    }
                    Tok.ARR_END -> {
                        if (top == null || top.dict) return
                        stack.removeAt(stack.size - 1)
                    }
                    Tok.WORD -> {
                        var done = false
                        if (isInt(l.v)) {
                            val save = l.pos
                            val saveV = l.v
                            if (l.next() == Tok.WORD && isInt(l.v)) {
                                val t3 = l.next()
                                if (t3 == Tok.WORD && l.v == "R") {
                                    if (stack.size == 1 && stack[0].dict && stack[0].key in setOf("Type", "Filter", "DecodeParms", "N", "First")) {
                                        info.indirect = true
                                    }
                                    done = true // a reference = one value
                                } else if (t3 == Tok.WORD && l.v == "obj") {
                                    continue // doubled `N G obj` — the next value continues this object
                                }
                            }
                            if (!done) {
                                l.pos = save
                                l.v = saveV
                            }
                        }
                        if (!done) noteScalar(stack, info, tok, l.v)
                    }
                    Tok.NAME, Tok.STR -> noteScalar(stack, info, tok, l.v)
                }
                if (stack.isEmpty()) return
                stack.last().let { if (it.dict) it.expectKey = true }
            }
        }

        private fun noteScalar(stack: List<Frame>, info: Info, tok: Tok, v: String) {
            if (stack.size == 1 && stack[0].dict) {
                when (stack[0].key) {
                    "Type" -> if (tok == Tok.NAME) info.typ = v
                    "Filter" -> if (tok == Tok.NAME) { info.filter = v; info.filters = 1 }
                    "DecodeParms" -> if (!(tok == Tok.WORD && v == "null")) info.parms = true
                    "N" -> info.nCount = parseInt64(v)
                    "Size" -> if (tok == Tok.WORD && isInt(v) && v.toLong() > MAX_XREF_SIZE) bigSize = true
                    "First" -> info.first = parseInt64(v)
                }
            } else if (stack.size == 2 && stack[0].dict && stack[0].key == "Filter" && !stack[1].dict && tok == Tok.NAME) {
                info.filter = v
                info.filters++
            }
        }

        /** The data after `stream` (FlateDecode ends on its own, whatever /Length says), objects at every header offset. */
        private fun objStm(b: ByteArray, end: Int, l: Lex, info: Info) {
            if (l.next() != Tok.WORD || l.v != "stream" || encrypted) return
            if (info.indirect) throw Failure() // /Type /Filter /N /First by reference — never in a legitimate file
            if (info.typ != "ObjStm") return
            var p = l.pos
            if (p < end && b[p] == '\r'.code.toByte()) p++
            if (p < end && b[p] == '\n'.code.toByte()) p++
            p = minOf(p, end)
            if (info.filters == 0) {
                objStmData(b, p, end, info) // unfiltered — the rest of the data
                return
            }
            if (info.filters != 1 || info.filter != "FlateDecode") return // the reader does not decode it
            if (info.parms) throw Failure() // predictor object streams are not replayed — fail closed
            val (data, over) = inflatePrefix(b, p, end, inflateLeft)
            if (over) throw Failure()
            inflateLeft -= data.size
            budget -= data.size
            objStmData(data, 0, data.size, info)
        }

        private fun objStmData(b: ByteArray, base: Int, end: Int, info: Info) {
            val l = Lex(b, end, base)
            var i = 0L
            while (i < info.nCount) {
                i++
                if (l.next() == Tok.EOF) break
                if (l.next() != Tok.WORD) continue
                val off = l.v.toLongOrNull() ?: continue
                if (!isInt(l.v) || info.first < 0 || off < 0 || info.first > end - base || off >= (end - base) - info.first) continue
                if (budget < 0) throw Failure()
                obj(b, base, end, base + (info.first + off).toInt(), false)
            }
            if (budget < 0) throw Failure()
        }
    }

    /**
     * zlib-inflates the prefix of b[from until to] (stops at the end of the zlib stream or at the first error, keeping
     * what was produced — Go `io.ReadAll(zlib.NewReader)`); second = more than [limit] bytes came out.
     */
    private fun inflatePrefix(b: ByteArray, from: Int, to: Int, limit: Int): Pair<ByteArray, Boolean> {
        val inf = Inflater()
        val out = java.io.ByteArrayOutputStream()
        try {
            inf.setInput(b, from, to - from)
            val buf = ByteArray(64 shl 10)
            while (!inf.finished()) {
                val n = try { inf.inflate(buf) } catch (_: java.util.zip.DataFormatException) { break }
                if (n == 0 && (inf.needsInput() || inf.needsDictionary())) break
                out.write(buf, 0, n)
                if (out.size() > limit) return ByteArray(0) to true
            }
        } finally {
            inf.end()
        }
        return out.toByteArray() to false
    }

    /**
     * Go `checkObjStmGraph`: an object's container stream must not itself be in an object stream; the container's (and
     * its /Extends chain's) header must not reference objects inside object streams; /Extends must not cycle or exceed
     * 64. A reader that cannot open or parse the document is not judged here (the caller reports PDF_INVALID).
     */
    private fun checkObjStmGraph(doc: ByteArray) {
        val r = try { PdfReader.open(doc) } catch (_: Exception) { return }
        val xr = r.xref
        fun registered(p: PdfRef) = when (val e = xr[p.id]) {
            is PdfReader.XrefEntry.Offset -> e.gen == p.gen
            is PdfReader.XrefEntry.Compressed -> p.gen == 0
            null -> false
        }
        fun inStream(p: PdfRef) = xr[p.id] is PdfReader.XrefEntry.Compressed && registered(p)
        val containers = java.util.TreeSet<Int>()
        for (e in xr.values) {
            if (e !is PdfReader.XrefEntry.Compressed) continue
            if (inStream(PdfRef(e.stream, 0))) throw Failure()
            containers += e.stream
        }
        for (c in containers) {
            val seen = HashSet<PdfRef>()
            var p = PdfRef(c, 0)
            while (registered(p)) {
                if (p in seen || seen.size > MAX_OBJSTM_CHAIN) throw Failure()
                seen += p
                val e = xr[p.id] as? PdfReader.XrefEntry.Offset ?: break
                val (hdr, isStream) = r.rawHeader(e.off, p.id) ?: return
                if (!isStream) break
                var bad = false
                walkRefs(PdfObj.Dict(hdr), 0) { if (inStream(it)) bad = true }
                if (bad) throw Failure()
                p = (hdr["Extends"] as? PdfObj.Ref)?.r ?: break
            }
        }
    }

    private fun walkRefs(v: PdfObj, depth: Int, fn: (PdfRef) -> Unit) {
        if (depth > MAX_NESTING) return
        when (v) {
            is PdfObj.Ref -> fn(v.r)
            is PdfObj.Dict -> for (x in v.d.entries.values) walkRefs(x, depth + 1, fn)
            is PdfObj.Stream -> for (x in v.d.entries.values) walkRefs(x, depth + 1, fn)
            is PdfObj.Arr -> for (x in v.items) walkRefs(x, depth + 1, fn)
            else -> {}
        }
    }
}
