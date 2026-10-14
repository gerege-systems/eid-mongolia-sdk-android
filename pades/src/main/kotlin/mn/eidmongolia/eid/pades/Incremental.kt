package mn.eidmongolia.eid.pades

import java.io.ByteArrayOutputStream
import java.math.BigDecimal

/**
 * One incremental update (revision): output = base + "\n" + new objects + xref + trailer; base bytes never change.
 * 1:1 port of the Go reference `pades/internal/core/incremental.go` + `serialize.go` (digitorus fork). New xref
 * streams are written UNCOMPRESSED (no /Filter) — cross-SDK byte identity (decision 2026-10-14).
 */
internal class Incremental(base: ByteArray) {
    private class Entry(val id: Int, val gen: Int, val offset: Int)

    val reader: PdfReader = try {
        PdfReader.open(base)
    } catch (e: PdfException) {
        throw e
    } catch (e: Exception) {
        throw PdfException("PDF: ${e.message}")
    }
    private val out = ByteArrayOutputStream(base.size + (64 shl 10))
    var nextId: Int
        private set
    private val entries = ArrayList<Entry>()

    init {
        if (!reader.get(reader.trailer, "Encrypt").isNull) throw PdfException("encrypted PDF")
        if (reader.get(reader.trailer, "Root") !is PdfObj.Dict) throw PdfException("Catalog missing")
        val size = reader.trailer["Size"].long
        if (size == null || size <= 0 || size > (1 shl 23)) throw PdfException("bad /Size")
        nextId = maxOf(size.toInt(), reader.maxObjectId + 1)
        out.write(base)
        out.write('\n'.code) // empty line after %%EOF (digitorus)
    }

    val root: PdfDict get() = (reader.get(reader.trailer, "Root") as PdfObj.Dict).d
    val rootRef: PdfRef? get() = reader.trailer["Root"].ref
    val size get() = out.size()

    fun reserve(): Int = nextId++

    /** Writes object `id gen`; returns the offset where its body starts. */
    fun writeObject(id: Int, body: ByteArray, gen: Int = 0): Int {
        out.write('\n'.code)
        entries += Entry(id, gen, out.size())
        out.write("$id $gen obj\n".toByteArray())
        val start = out.size()
        out.write(trimSpace(body))
        out.write("\nendobj\n".toByteArray())
        return start
    }

    fun addObject(body: ByteArray): Pair<Int, Int> {
        val id = reserve()
        return id to writeObject(id, body)
    }

    /** xref (same kind as the base's latest section) + trailer; [rootId] = the new Catalog. */
    fun finish(rootId: Int): ByteArray {
        if (entries.isEmpty()) throw PdfException("no new objects")
        out.write('\n'.code)
        val xrefStart = out.size()
        var xid = 0
        if (reader.xrefIsStream) {
            xid = reserve()
            entries += Entry(xid, 0, xrefStart)
        }
        entries.sortBy { it.id }
        val runs = ArrayList<IntArray>() // [start index, count]
        for ((i, e) in entries.withIndex()) {
            if (i > 0 && e.id == entries[i - 1].id) throw PdfException("duplicate object number")
            if (i > 0 && e.id == entries[i - 1].id + 1) { runs.last()[1]++; continue }
            runs += intArrayOf(i, 1)
        }
        val prev = reader.startXref
        val extra = StringBuilder()
        val tr = reader.trailer
        val infoRaw = tr["Info"]
        val info = reader.resolve(infoRaw)
        if (!info.isNull) {
            val r = infoRaw.ref
            if (r == null) extra.append(" /Info ").append(serialize(info)) // direct /Info (profile pades-client/1, P3)
            else extra.append(" /Info ${r.id} ${r.gen} R")
        }
        val id = reader.resolve(tr["ID"])
        if (id is PdfObj.Arr && id.items.size == 2) {
            val a = (reader.resolve(id.items[0]) as? PdfObj.Str)?.bytes ?: ByteArray(0)
            val b = (reader.resolve(id.items[1]) as? PdfObj.Str)?.bytes ?: ByteArray(0)
            extra.append(" /ID [${hexString(a)} ${hexString(b)}]")
        }
        if (!reader.xrefIsStream) {
            val sb = StringBuilder("xref\n")
            for (r in runs) {
                sb.append("${entries[r[0]].id} ${r[1]}\n")
                for (k in r[0] until r[0] + r[1]) {
                    val e = entries[k]
                    sb.append(String.format(java.util.Locale.ROOT, "%010d %05d n\r\n", e.offset, e.gen))
                }
            }
            sb.append("trailer\n<< /Size $nextId /Root $rootId 0 R$extra /Prev $prev >>\nstartxref\n$xrefStart\n%%EOF\n")
            out.write(sb.toString().toByteArray(Charsets.ISO_8859_1))
            return out.toByteArray()
        }
        val rows = ByteArrayOutputStream(entries.size * 6)
        for (e in entries) {
            if (e.gen > 0xff) throw PdfException("generation does not fit 1 byte")
            rows.write(1)
            rows.write(e.offset ushr 24); rows.write((e.offset shr 16) and 0xff)
            rows.write((e.offset shr 8) and 0xff); rows.write(e.offset and 0xff)
            rows.write(e.gen)
        }
        val index = runs.joinToString(" ") { "${entries[it[0]].id} ${it[1]}" }
        out.write(
            ("$xid 0 obj\n<< /Type /XRef /Length ${rows.size()} /W [1 4 1] /Prev $prev /Size $nextId " +
                "/Index [$index] /Root $rootId 0 R$extra >>\nstream\n").toByteArray(Charsets.ISO_8859_1),
        )
        rows.writeTo(out)
        out.write("\nendstream\nendobj\nstartxref\n$xrefStart\n%%EOF\n".toByteArray())
        return out.toByteArray()
    }

    /** Catalog keys except /Type and [skip], as "  /Key value\n" (digitorus createCatalog). */
    fun catalogCopy(skip: Set<String>): String {
        val sb = StringBuilder()
        val r = root
        for (key in r.sortedKeys) {
            if (key == "Type" || key in skip) continue
            sb.append("  /").append(escapeName(key)).append(' ').append(serialize(r[key])).append('\n')
        }
        return sb.toString()
    }

    /**
     * Go serialize.go: direct values are rewritten; references stay "N G R" (a reference to a missing object →
     * "null"). Strings as hex, names #xx-escaped, reals without exponent.
     */
    fun serialize(v: PdfObj, depth: Int = 0): String {
        if (depth > 32) throw PdfException("value nested too deep")
        return when (v) {
            PdfObj.Null -> "null"
            is PdfObj.Ref -> if (reader.obj(v.r).isNull) "null" else "${v.r.id} ${v.r.gen} R"
            is PdfObj.Str -> hexString(v.bytes)
            is PdfObj.Bool -> if (v.v) "true" else "false"
            is PdfObj.Int -> v.v.toString()
            is PdfObj.Real -> formatReal(v.v)
            is PdfObj.Name -> "/" + escapeName(v.v)
            is PdfObj.Dict -> buildString {
                append("<<")
                for (key in v.d.sortedKeys) append(" /").append(escapeName(key)).append(' ').append(serialize(v.d[key], depth + 1))
                append(" >>")
            }
            is PdfObj.Arr -> v.items.joinToString(" ", "[", "]") { serialize(it, depth + 1) }
            is PdfObj.Stream -> throw PdfException("cannot copy a direct stream")
        }
    }

    companion object {
        private val HEX = "0123456789abcdef".toCharArray()

        fun hexString(raw: ByteArray): String {
            val sb = StringBuilder(raw.size * 2 + 2).append('<')
            for (b in raw) sb.append(HEX[(b.toInt() shr 4) and 0xf]).append(HEX[b.toInt() and 0xf])
            return sb.append('>').toString()
        }

        fun escapeName(n: String): String {
            val sb = StringBuilder()
            for (ch in n) {
                val c = ch.code and 0xff
                if (c < 0x21 || c > 0x7e || "#()<>[]{}/%".indexOf(ch) >= 0) sb.append(String.format(java.util.Locale.ROOT, "#%02X", c))
                else sb.append(ch)
            }
            return sb.toString()
        }

        /** Go strconv.FormatFloat(f, 'f', -1, 64): shortest round-trip digits, never an exponent. */
        fun formatReal(d: Double): String {
            if (d == Math.rint(d) && Math.abs(d) < 1e15) return d.toLong().toString()
            return BigDecimal(d.toString()).stripTrailingZeros().toPlainString()
        }

        /** Go bytes.TrimSpace (ASCII whitespace). */
        fun trimSpace(b: ByteArray): ByteArray {
            fun ws(c: Byte) = c == 9.toByte() || c == 10.toByte() || c == 11.toByte() || c == 12.toByte() || c == 13.toByte() || c == 32.toByte()
            var lo = 0
            var hi = b.size
            while (lo < hi && ws(b[lo])) lo++
            while (hi > lo && ws(b[hi - 1])) hi--
            return if (lo == 0 && hi == b.size) b else b.copyOfRange(lo, hi)
        }
    }
}
