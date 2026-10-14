package mn.eidmongolia.eid.pades

/**
 * Minimal PDF object model + lexer (ISO 32000-1 §7.3) for the incremental signature writer — reads only what a
 * signature revision needs (trailer, Catalog, AcroForm, first page, DSS); content streams are never interpreted.
 * Port of the eid-desktop Swift `PdfObject.swift` (byte-identical to the Go reference on the golden vectors), which
 * mirrors the subset of digitorus/pdf the Go writer uses.
 */
internal class PdfException(msg: String) : Exception(msg)

internal data class PdfRef(val id: Int, val gen: Int)

/** Names are kept one byte per char (Latin-1, `#xx` decoded); keys serialise sorted by byte (Go `sort.Strings`). */
internal class PdfDict(val entries: LinkedHashMap<String, PdfObj> = LinkedHashMap()) {
    operator fun get(key: String): PdfObj = entries[key] ?: PdfObj.Null
    val sortedKeys: List<String> get() = entries.keys.sorted()
}

internal sealed class PdfObj {
    object Null : PdfObj()
    data class Bool(val v: Boolean) : PdfObj()
    data class Int(val v: Long) : PdfObj()
    data class Real(val v: Double) : PdfObj()
    /** Raw string bytes (literal escapes resolved / hex decoded). */
    class Str(val bytes: ByteArray) : PdfObj()
    data class Name(val v: String) : PdfObj()
    class Arr(val items: List<PdfObj>) : PdfObj()
    class Dict(val d: PdfDict) : PdfObj()
    data class Ref(val r: PdfRef) : PdfObj()
    /** Stream dictionary + raw (still encoded) data range [start, end) in the reader's bytes. */
    class Stream(val d: PdfDict, val start: kotlin.Int, val end: kotlin.Int) : PdfObj()

    val dict: PdfDict? get() = when (this) { is Dict -> d; is Stream -> d; else -> null }
    val array: List<PdfObj>? get() = (this as? Arr)?.items
    val name: String? get() = (this as? Name)?.v
    val isNull get() = this === Null
    val ref: PdfRef? get() = (this as? Ref)?.r
    val long: Long?
        get() = when (this) {
            is Int -> v
            is Real -> if (v == Math.rint(v) && Math.abs(v) < 1e15) v.toLong() else null
            else -> null
        }
}

internal class PdfLexer(val b: ByteArray, var pos: kotlin.Int = 0) {
    companion object {
        fun isWhite(c: kotlin.Int) = c == 0 || c == 9 || c == 10 || c == 12 || c == 13 || c == 32
        fun isDelim(c: kotlin.Int) = c == 0x28 || c == 0x29 || c == 0x3C || c == 0x3E || c == 0x5B || c == 0x5D ||
            c == 0x7B || c == 0x7D || c == 0x2F || c == 0x25
        fun isRegular(c: kotlin.Int) = !isWhite(c) && !isDelim(c)
        fun hexVal(c: kotlin.Int): kotlin.Int? = when (c) {
            in 0x30..0x39 -> c - 0x30
            in 0x41..0x46 -> c - 0x41 + 10
            in 0x61..0x66 -> c - 0x61 + 10
            else -> null
        }

        fun real(w: String): Double? {
            if (!w.contains('.') || !w.all { it.isDigit() || it == '.' || it == '-' || it == '+' }) return null
            var s = w
            if (s.startsWith(".") || s.startsWith("-.") || s.startsWith("+.")) s = s.replace(".", "0.")
            return s.toDoubleOrNull()
        }
    }

    private fun at(i: kotlin.Int) = b[i].toInt() and 0xff

    fun skipWhite() {
        while (pos < b.size) {
            val c = at(pos)
            if (isWhite(c)) { pos++; continue }
            if (c == 0x25) {
                while (pos < b.size && at(pos) != 10 && at(pos) != 13) pos++
                continue
            }
            break
        }
    }

    fun peekWord(p: kotlin.Int): Pair<String, kotlin.Int>? {
        var i = p
        while (i < b.size && isWhite(at(i))) i++
        val s = i
        while (i < b.size && isRegular(at(i))) i++
        if (i <= s) return null
        return String(b, s, i - s, Charsets.ISO_8859_1) to i
    }

    fun word(): String? {
        skipWhite()
        val (w, end) = peekWord(pos) ?: return null
        pos = end
        return w
    }

    fun expect(keyword: String) {
        if (word() != keyword) throw PdfException("expected $keyword at $pos")
    }

    fun parseObject(depth: kotlin.Int = 0): PdfObj {
        if (depth >= 64) throw PdfException("nesting too deep")
        skipWhite()
        if (pos >= b.size) throw PdfException("unexpected end of file")
        when (at(pos)) {
            0x2F -> {
                pos++
                val sb = StringBuilder()
                while (pos < b.size && isRegular(at(pos))) {
                    var ch = at(pos)
                    if (ch == 0x23 && pos + 2 < b.size) {
                        val hi = hexVal(at(pos + 1))
                        val lo = hexVal(at(pos + 2))
                        if (hi != null && lo != null) {
                            ch = (hi shl 4) or lo
                            pos += 2
                        }
                    }
                    sb.append(ch.toChar())
                    pos++
                }
                return PdfObj.Name(sb.toString())
            }
            0x28 -> return PdfObj.Str(literalString())
            0x3C -> {
                if (pos + 1 < b.size && at(pos + 1) == 0x3C) {
                    pos += 2
                    val d = PdfDict()
                    while (true) {
                        skipWhite()
                        if (pos >= b.size) throw PdfException("unterminated dictionary")
                        if (at(pos) == 0x3E && pos + 1 < b.size && at(pos + 1) == 0x3E) { pos += 2; break }
                        val key = parseObject(depth + 1) as? PdfObj.Name ?: throw PdfException("dictionary key is not a name at $pos")
                        val value = parseObject(depth + 1)
                        if (!value.isNull) d.entries[key.v] = value // null value = absent key (§7.3.7)
                    }
                    return PdfObj.Dict(d)
                }
                return PdfObj.Str(hexString())
            }
            0x5B -> {
                pos++
                val a = ArrayList<PdfObj>()
                while (true) {
                    skipWhite()
                    if (pos >= b.size) throw PdfException("unterminated array")
                    if (at(pos) == 0x5D) { pos++; break }
                    a += parseObject(depth + 1)
                }
                return PdfObj.Arr(a)
            }
        }
        val c = at(pos)
        val w = word() ?: throw PdfException("unexpected byte $c at $pos")
        when (w) {
            "true" -> return PdfObj.Bool(true)
            "false" -> return PdfObj.Bool(false)
            "null" -> return PdfObj.Null
        }
        w.toLongOrNull()?.let { i ->
            val save = pos
            if (i >= 0) {
                val g = peekWord(pos)
                val gen = g?.first?.toIntOrNull()
                if (g != null && gen != null && gen >= 0) {
                    val r = peekWord(g.second)
                    if (r != null && r.first == "R") {
                        pos = r.second
                        return PdfObj.Ref(PdfRef(i.toInt(), gen))
                    }
                }
            }
            pos = save
            return PdfObj.Int(i)
        }
        real(w)?.let { return PdfObj.Real(it) }
        throw PdfException("unexpected token $w at $pos")
    }

    private fun hexString(): ByteArray {
        pos++
        val out = java.io.ByteArrayOutputStream()
        var hi: kotlin.Int? = null
        while (pos < b.size) {
            val c = at(pos++)
            if (c == 0x3E) {
                hi?.let { out.write(it shl 4) }
                return out.toByteArray()
            }
            if (isWhite(c)) continue
            val v = hexVal(c) ?: throw PdfException("bad hex string")
            if (hi != null) { out.write((hi shl 4) or v); hi = null } else hi = v
        }
        throw PdfException("unterminated hex string")
    }

    private fun literalString(): ByteArray {
        pos++
        val out = java.io.ByteArrayOutputStream()
        var depth = 1
        while (pos < b.size) {
            val c = at(pos++)
            when (c) {
                0x5C -> {
                    if (pos >= b.size) continue
                    val e = at(pos++)
                    when (e) {
                        0x6E -> out.write(10)
                        0x72 -> out.write(13)
                        0x74 -> out.write(9)
                        0x62 -> out.write(8)
                        0x66 -> out.write(12)
                        0x0D -> if (pos < b.size && at(pos) == 0x0A) pos++
                        0x0A -> {}
                        in 0x30..0x37 -> {
                            var v = e - 0x30
                            var k = 0
                            while (k < 2 && pos < b.size && at(pos) in 0x30..0x37) {
                                v = v * 8 + (at(pos) - 0x30)
                                pos++
                                k++
                            }
                            out.write(v and 0xff)
                        }
                        else -> out.write(e)
                    }
                }
                0x28 -> { depth++; out.write(c) }
                0x29 -> {
                    depth--
                    if (depth == 0) return out.toByteArray()
                    out.write(c)
                }
                0x0D -> {
                    if (pos < b.size && at(pos) == 0x0A) pos++
                    out.write(0x0A)
                }
                else -> out.write(c)
            }
        }
        throw PdfException("unterminated literal string")
    }
}
