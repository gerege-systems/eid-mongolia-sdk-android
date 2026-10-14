package mn.eidmongolia.eid.pades

import java.io.ByteArrayOutputStream
import java.math.BigInteger

/** Minimal DER (X.690) reader/writer — only what CMS/TSP/OCSP/X.509 parsing in this module needs. */
internal object Der {
    const val BOOLEAN = 0x01
    const val INTEGER = 0x02
    const val BIT_STRING = 0x03
    const val OCTET_STRING = 0x04
    const val NULL = 0x05
    const val OID = 0x06
    const val ENUMERATED = 0x0a
    const val UTF8_STRING = 0x0c
    const val PRINTABLE_STRING = 0x13
    const val T61_STRING = 0x14
    const val IA5_STRING = 0x16
    const val UTC_TIME = 0x17
    const val GENERALIZED_TIME = 0x18
    const val BMP_STRING = 0x1e
    const val SEQUENCE = 0x30
    const val SET = 0x31

    fun ctx(n: Int, constructed: Boolean = true) = 0x80 or (if (constructed) 0x20 else 0) or n

    /** One TLV element (single-byte tags only — enough for every structure parsed here). */
    class Tlv(val buf: ByteArray, val tag: Int, val start: Int, val valueStart: Int, val end: Int) {
        val length get() = end - valueStart
        fun value(): ByteArray = buf.copyOfRange(valueStart, end)
        fun encoded(): ByteArray = buf.copyOfRange(start, end)
        fun children(): List<Tlv> = parseAll(buf, valueStart, end)
        fun child(i: Int): Tlv = children()[i]
        fun bigInt(): BigInteger = BigInteger(value())
        fun oid(): String = decodeOid(buf, valueStart, end)
    }

    fun parse(b: ByteArray, off: Int = 0, limit: Int = b.size): Tlv {
        require(off + 2 <= limit) { "DER truncated" }
        val tag = b[off].toInt() and 0xff
        require(tag and 0x1f != 0x1f) { "DER multi-byte tag" }
        var p = off + 1
        val first = b[p++].toInt() and 0xff
        val len: Int
        if (first < 0x80) {
            len = first
        } else {
            val n = first and 0x7f
            require(n in 1..4) { "DER length" }
            var l = 0L
            repeat(n) { l = (l shl 8) or (b[p++].toLong() and 0xff) }
            require(l <= Int.MAX_VALUE) { "DER length" }
            len = l.toInt()
        }
        require(len >= 0 && p + len <= limit) { "DER truncated" }
        return Tlv(b, tag, off, p, p + len)
    }

    fun parseAll(b: ByteArray, off: Int, end: Int): List<Tlv> {
        val out = ArrayList<Tlv>()
        var p = off
        while (p < end) {
            val t = parse(b, p, end)
            out += t
            p = t.end
        }
        return out
    }

    private fun decodeOid(b: ByteArray, s: Int, e: Int): String {
        val parts = ArrayList<Long>()
        var v = 0L
        for (i in s until e) {
            val c = b[i].toInt() and 0xff
            v = (v shl 7) or (c and 0x7f).toLong()
            if (c and 0x80 == 0) {
                parts += v
                v = 0
            }
        }
        require(parts.isNotEmpty()) { "OID empty" }
        val first = parts[0]
        val (a, bb) = when {
            first < 40 -> 0L to first
            first < 80 -> 1L to first - 40
            else -> 2L to first - 80
        }
        return (listOf(a, bb) + parts.drop(1)).joinToString(".")
    }

    // ── writer ──

    fun tlv(tag: Int, value: ByteArray): ByteArray {
        val out = ByteArrayOutputStream(value.size + 6)
        out.write(tag)
        writeLen(out, value.size)
        out.write(value)
        return out.toByteArray()
    }

    fun seq(vararg parts: ByteArray) = tlv(SEQUENCE, concat(*parts))
    fun set(vararg parts: ByteArray) = tlv(SET, concat(*parts))
    fun octets(v: ByteArray) = tlv(OCTET_STRING, v)
    fun nullValue() = byteArrayOf(NULL.toByte(), 0)
    fun bool(v: Boolean) = byteArrayOf(BOOLEAN.toByte(), 1, if (v) 0xff.toByte() else 0)
    fun int(v: Long) = tlv(INTEGER, BigInteger.valueOf(v).toByteArray())
    /** Go `encoding/asn1` / cryptobyte big.Int: minimal two's complement (Java's toByteArray is the same). */
    fun int(v: BigInteger) = tlv(INTEGER, v.toByteArray())

    fun oid(dotted: String): ByteArray {
        val p = dotted.split('.').map { it.toLong() }
        val out = ByteArrayOutputStream()
        writeBase128(out, p[0] * 40 + p[1])
        for (x in p.drop(2)) writeBase128(out, x)
        return tlv(OID, out.toByteArray())
    }

    private fun writeBase128(out: ByteArrayOutputStream, v: Long) {
        val tmp = ArrayList<Int>()
        var x = v
        tmp += (x and 0x7f).toInt()
        x = x shr 7
        while (x > 0) {
            tmp += ((x and 0x7f) or 0x80).toInt()
            x = x shr 7
        }
        for (i in tmp.indices.reversed()) out.write(tmp[i])
    }

    private fun writeLen(out: ByteArrayOutputStream, n: Int) {
        when {
            n < 0x80 -> out.write(n)
            n < 0x100 -> { out.write(0x81); out.write(n) }
            n < 0x10000 -> { out.write(0x82); out.write(n shr 8); out.write(n and 0xff) }
            n < 0x1000000 -> { out.write(0x83); out.write(n shr 16); out.write((n shr 8) and 0xff); out.write(n and 0xff) }
            else -> { out.write(0x84); out.write(n ushr 24); out.write((n shr 16) and 0xff); out.write((n shr 8) and 0xff); out.write(n and 0xff) }
        }
    }

    fun concat(vararg parts: ByteArray): ByteArray {
        val out = ByteArrayOutputStream(parts.sumOf { it.size })
        for (p in parts) out.write(p)
        return out.toByteArray()
    }

    /** Unsigned byte-wise compare (Go `bytes.Compare`) — DER SET OF ordering. */
    val BYTES_ORDER = Comparator<ByteArray> { a, b ->
        val n = minOf(a.size, b.size)
        for (i in 0 until n) {
            val d = (a[i].toInt() and 0xff) - (b[i].toInt() and 0xff)
            if (d != 0) return@Comparator d
        }
        a.size - b.size
    }
}
