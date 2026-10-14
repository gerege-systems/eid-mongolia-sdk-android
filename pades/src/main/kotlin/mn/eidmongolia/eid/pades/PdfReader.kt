package mn.eidmongolia.eid.pades

import java.io.ByteArrayOutputStream
import java.util.zip.Inflater

/**
 * Cross-reference structure of a PDF (classic tables, xref streams, hybrid files, object streams) + indirect object
 * resolution. Port of eid-desktop `PdfReader.swift` (the digitorus/pdf subset the Go writer uses). Reading compressed
 * input streams uses [Inflater] — only WRITING is uncompressed (cross-SDK byte identity).
 */
internal class PdfReader private constructor(
    val bytes: ByteArray,
    /** Header version, e.g. "1.3". */
    val version: String,
    /** Latest trailer (for an xref stream: its dictionary). */
    val trailer: PdfDict,
    /** `startxref` of the file — the new revision's /Prev. */
    val startXref: Int,
    /** The latest xref section is a stream (the new revision writes the same kind). */
    val xrefIsStream: Boolean,
    xref: Map<Int, XrefEntry>,
) {
    sealed class XrefEntry {
        data class Offset(val off: Int, val gen: Int) : XrefEntry()
        data class Compressed(val stream: Int, val index: Int) : XrefEntry()
    }

    val xref: Map<Int, XrefEntry> = xref
    private val cache = HashMap<PdfRef, PdfObj>()
    private val objStmCache = HashMap<Int, Triple<Int, List<Pair<Int, Int>>, ByteArray>>()

    val maxObjectId: Int get() = xref.keys.maxOrNull() ?: 0

    /** Object numbers in ascending order (Go digitorus `Xref()` iteration order). */
    val objectIds: List<Int> get() = xref.keys.sorted()

    companion object {
        fun open(data: ByteArray): PdfReader {
            val version = headerVersion(data)
            val sx = findStartXref(data) ?: throw PdfException("startxref not found")
            val seen = HashSet<Int>()
            var offset: Int? = sx
            var first: Pair<PdfDict, Boolean>? = null
            val entries = HashMap<Int, XrefEntry>()
            while (offset != null) {
                val off = offset
                if (seen.contains(off)) break
                if (seen.size >= 512 || off < 0 || off >= data.size) throw PdfException("bad xref offset")
                seen += off
                val (dict, isStream, section) = readSection(data, off)
                if (first == null) first = dict to isStream
                val merged = HashMap(section)
                if (!isStream) {
                    dict["XRefStm"].long?.toInt()?.let { stm ->
                        if (!seen.contains(stm)) {
                            seen += stm
                            try {
                                val extra = readSection(data, stm).third
                                for ((k, v) in extra) if (!merged.containsKey(k)) merged[k] = v
                            } catch (_: Exception) {
                            }
                        }
                    }
                }
                for ((k, v) in merged) if (!entries.containsKey(k)) entries[k] = v
                offset = dict["Prev"].long?.toInt()
            }
            val (tr, isStream) = first ?: throw PdfException("no xref")
            return PdfReader(data, version, tr, sx, isStream, entries)
        }

        fun headerVersion(b: ByteArray): String {
            val limit = minOf(b.size, 1024)
            val at = indexOf(b, "%PDF-".toByteArray(), 0, limit)
            if (at < 0) return ""
            var i = at + 5
            val sb = StringBuilder()
            while (i < limit && (b[i] in '0'.code.toByte()..'9'.code.toByte() || b[i] == '.'.code.toByte())) sb.append(b[i++].toInt().toChar())
            return sb.toString()
        }

        fun findStartXref(b: ByteArray): Int? {
            val key = "startxref".toByteArray()
            val from = maxOf(0, b.size - 2048)
            var i = b.size - key.size
            while (i >= from) {
                if (regionEquals(b, i, key)) return PdfLexer(b, i + key.size).word()?.toIntOrNull()
                i--
            }
            return null
        }

        fun indexOf(b: ByteArray, key: ByteArray, from: Int, to: Int = b.size): Int {
            var i = from
            while (i + key.size <= to) {
                if (regionEquals(b, i, key)) return i
                i++
            }
            return -1
        }

        private fun regionEquals(b: ByteArray, at: Int, key: ByteArray): Boolean {
            if (at < 0 || at + key.size > b.size) return false
            for (k in key.indices) if (b[at + k] != key[k]) return false
            return true
        }

        private fun readSection(b: ByteArray, off: Int): Triple<PdfDict, Boolean, Map<Int, XrefEntry>> {
            val lx = PdfLexer(b, off)
            lx.skipWhite()
            val pw = lx.peekWord(lx.pos)
            if (pw != null && pw.first == "xref") {
                lx.pos = pw.second
                val out = HashMap<Int, XrefEntry>()
                while (true) {
                    lx.skipWhite()
                    val w2 = lx.peekWord(lx.pos) ?: throw PdfException("bad xref table")
                    if (w2.first == "trailer") { lx.word(); break }
                    val start = lx.word()?.toIntOrNull()
                    val count = lx.word()?.toIntOrNull()
                    if (start == null || count == null || count < 0 || count >= (1 shl 23)) throw PdfException("bad xref subsection")
                    for (k in 0 until count) {
                        val o = lx.word()?.toIntOrNull()
                        val g = lx.word()?.toIntOrNull()
                        val t = lx.word()
                        if (o == null || g == null || t == null) throw PdfException("bad xref entry")
                        val id = start + k
                        if (t == "n" && !out.containsKey(id) && o > 0) out[id] = XrefEntry.Offset(o, g)
                    }
                }
                val tr = lx.parseObject() as? PdfObj.Dict ?: throw PdfException("bad trailer")
                return Triple(tr.d, false, out)
            }
            val bare = PdfReader(b, "", PdfDict(), 0, false, emptyMap())
            val obj = bare.parseIndirect(off, null)
            if (obj !is PdfObj.Stream || obj.d["Type"].name != "XRef") throw PdfException("xref stream expected")
            val d = obj.d
            val raw = bare.decodedStream(obj)
            val w = d["W"].array?.mapNotNull { it.long?.toInt() }
            val size = d["Size"].long
            if (w == null || w.size != 3 || w.any { it < 0 || it > 8 } || size == null) throw PdfException("bad xref stream")
            val index = (d["Index"].array?.mapNotNull { it.long?.toInt() } ?: listOf(0, size.toInt())).toMutableList()
            if (index.size % 2 != 0) index.removeAt(index.size - 1)
            val rowLen = w.sum()
            if (rowLen <= 0) throw PdfException("bad xref stream /W")
            val out = HashMap<Int, XrefEntry>()
            var p = 0
            fun field(n: Int, def: Int): Int {
                if (n <= 0) return def
                var v = 0
                repeat(n) { v = (v shl 8) or (raw[p++].toInt() and 0xff) }
                return v
            }
            var pair = 0
            while (pair < index.size) {
                val start = index[pair]
                val count = index[pair + 1]
                for (k in 0 until count) {
                    if (p + rowLen > raw.size) break
                    val type = field(w[0], 1)
                    val f2 = field(w[1], 0)
                    val f3 = field(w[2], 0)
                    val id = start + k
                    if (out.containsKey(id)) continue
                    when (type) {
                        1 -> if (f2 > 0) out[id] = XrefEntry.Offset(f2, f3)
                        2 -> out[id] = XrefEntry.Compressed(f2, f3)
                    }
                }
                pair += 2
            }
            return Triple(d, true, out)
        }

        private fun endstreamFollows(b: ByteArray, p: Int) = PdfLexer(b, p).word() == "endstream"

        fun inflate(input: ByteArray, limit: Int = 64 shl 20): ByteArray {
            val inf = Inflater()
            try {
                inf.setInput(input)
                val out = ByteArrayOutputStream(input.size * 2)
                val buf = ByteArray(64 shl 10)
                while (!inf.finished()) {
                    val n = inf.inflate(buf)
                    if (n == 0) {
                        if (inf.needsInput() || inf.needsDictionary()) break // truncated: keep what we have
                    }
                    out.write(buf, 0, n)
                    if (out.size() > limit) throw PdfException("FlateDecode output too large")
                }
                return out.toByteArray()
            } catch (e: java.util.zip.DataFormatException) {
                throw PdfException("FlateDecode failed")
            } finally {
                inf.end()
            }
        }

        private fun unpredict(data: ByteArray, p: PdfDict): ByteArray {
            val predictor = (p["Predictor"].long ?: 1).toInt()
            if (predictor < 10) {
                if (predictor == 1) return data
                throw PdfException("unsupported predictor $predictor")
            }
            val colors = (p["Colors"].long ?: 1).toInt()
            val bpc = (p["BitsPerComponent"].long ?: 8).toInt()
            val columns = (p["Columns"].long ?: 1).toInt()
            val bpp = maxOf(1, colors * bpc / 8)
            val rowLen = (colors * bpc * columns + 7) / 8
            if (rowLen <= 0) throw PdfException("bad predictor parameters")
            val out = ByteArrayOutputStream(data.size)
            var prev = IntArray(rowLen)
            var i = 0
            while (i + 1 + rowLen <= data.size) {
                val type = data[i].toInt() and 0xff
                val row = IntArray(rowLen) { data[i + 1 + it].toInt() and 0xff }
                for (x in 0 until rowLen) {
                    val a = if (x >= bpp) row[x - bpp] else 0
                    val b = prev[x]
                    val c = if (x >= bpp) prev[x - bpp] else 0
                    val add = when (type) {
                        0 -> 0
                        1 -> a
                        2 -> b
                        3 -> (a + b) / 2
                        4 -> {
                            val pp = a + b - c
                            val pa = Math.abs(pp - a)
                            val pb = Math.abs(pp - b)
                            val pc = Math.abs(pp - c)
                            if (pa <= pb && pa <= pc) a else if (pb <= pc) b else c
                        }
                        else -> throw PdfException("bad PNG predictor row")
                    }
                    row[x] = (row[x] + add) and 0xff
                }
                for (v in row) out.write(v)
                prev = row
                i += 1 + rowLen
            }
            return out.toByteArray()
        }
    }

    /** The object a reference points to; [PdfObj.Null] when it does not exist (§7.3.10). */
    fun obj(ref: PdfRef): PdfObj {
        cache[ref]?.let { return it }
        val entry = xref[ref.id] ?: return PdfObj.Null
        val o = when (entry) {
            is XrefEntry.Offset -> {
                if (entry.gen != ref.gen) return PdfObj.Null
                parseIndirect(entry.off, ref.id)
            }
            is XrefEntry.Compressed -> {
                if (ref.gen != 0) return PdfObj.Null
                objectFromStream(entry.stream, entry.index, ref.id)
            }
        }
        cache[ref] = o
        return o
    }

    /** Follows references (bounded). */
    fun resolve(o: PdfObj): PdfObj {
        var cur = o
        var n = 0
        while (cur is PdfObj.Ref) {
            if (++n >= 16) throw PdfException("reference loop")
            cur = obj(cur.r)
        }
        return cur
    }

    fun get(d: PdfDict, key: String): PdfObj = resolve(d[key])

    fun parseIndirect(off: Int, id: Int?): PdfObj {
        if (off < 0 || off >= bytes.size) throw PdfException("object offset out of range")
        val lx = PdfLexer(bytes, off)
        val n = lx.word()?.toIntOrNull()
        if (n == null || lx.word()?.toIntOrNull() == null) throw PdfException("bad object header at $off")
        if (id != null && n != id) throw PdfException("object $id not at its xref offset")
        lx.expect("obj")
        val o = lx.parseObject()
        if (o !is PdfObj.Dict) return o
        lx.skipWhite()
        val pw = lx.peekWord(lx.pos)
        if (pw == null || pw.first != "stream") return o
        var start = pw.second
        if (start < bytes.size && bytes[start] == 0x0D.toByte()) start++
        if (start < bytes.size && bytes[start] == 0x0A.toByte()) start++
        var length = -1
        val lenObj = o.d["Length"]
        if (lenObj.long != null) {
            length = lenObj.long!!.toInt()
        } else if (lenObj is PdfObj.Ref) {
            try { resolve(lenObj).long?.let { length = it.toInt() } } catch (_: Exception) {}
        }
        if (length >= 0 && start + length <= bytes.size && endstreamFollows(bytes, start + length)) {
            return PdfObj.Stream(o.d, start, start + length)
        }
        val r = indexOf(bytes, "endstream".toByteArray(), start)
        if (r < 0) throw PdfException("endstream not found")
        var e = r
        if (e > start && bytes[e - 1] == 0x0A.toByte()) e--
        if (e > start && bytes[e - 1] == 0x0D.toByte()) e--
        return PdfObj.Stream(o.d, start, e)
    }

    private fun objectFromStream(stm: Int, index: Int, id: Int): PdfObj {
        val entry = objStmCache.getOrPut(stm) {
            val s = obj(PdfRef(stm, 0))
            val n = s.dict?.get("N")?.long
            val first = s.dict?.get("First")?.long
            if (s !is PdfObj.Stream || s.d["Type"].name != "ObjStm" || n == null || first == null || n < 0 || n >= (1 shl 20)) {
                throw PdfException("bad object stream $stm")
            }
            val data = decodedStream(s)
            val lx = PdfLexer(data)
            val offsets = ArrayList<Pair<Int, Int>>()
            repeat(n.toInt()) {
                val oid = lx.word()?.toIntOrNull()
                val o = lx.word()?.toIntOrNull()
                if (oid == null || o == null) throw PdfException("bad object stream header")
                offsets += oid to o
            }
            Triple(first.toInt(), offsets, data)
        }
        if (index < 0 || index >= entry.second.size || entry.second[index].first != id) {
            throw PdfException("object $id not in object stream $stm")
        }
        return PdfLexer(entry.third, entry.first + entry.second[index].second).parseObject()
    }

    /** Decoded data of a stream (FlateDecode with PNG predictors, or unfiltered). */
    fun decodedStream(s: PdfObj): ByteArray {
        if (s !is PdfObj.Stream) throw PdfException("not a stream")
        var data = bytes.copyOfRange(s.start, s.end)
        val filters: List<PdfObj> = when (val f = resolve(s.d["Filter"])) {
            PdfObj.Null -> emptyList()
            is PdfObj.Name -> listOf(f)
            is PdfObj.Arr -> f.items
            else -> throw PdfException("bad /Filter")
        }
        val parms: List<PdfObj> = when (val p = resolve(s.d["DecodeParms"])) {
            is PdfObj.Arr -> p.items
            is PdfObj.Dict -> listOf(p)
            else -> emptyList()
        }
        for ((i, f) in filters.withIndex()) {
            if (f.name != "FlateDecode" && f.name != "Fl") throw PdfException("unsupported filter ${f.name}")
            data = inflate(data)
            if (i < parms.size) resolve(parms[i]).dict?.let { data = unpredict(data, it) }
        }
        return data
    }
}
