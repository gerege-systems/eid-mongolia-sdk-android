package mn.eidmongolia.eid.pades

import org.json.JSONArray
import org.json.JSONObject

/**
 * Opaque prepare → complete state. Same layout as the Go reference (`pades/state.go`): "EIDPADES1" ‖ uint32 BE header
 * length ‖ JSON header ‖ prepared PDF. Kotlin adds `priorCmsSha256` (Go ignores unknown keys when decoding).
 */
internal class PrepState(
    val docId: String,
    val signerCert: ByteArray,
    val chain: List<ByteArray>,
    val signedAttrs: ByteArray,
    val byteRange: LongArray,
    val revIndex: Int,
    val inSha256: String,
    val hasPage: Boolean,
    val pageSha256: String?,
    val claimedRole: String?,
    val priorCmsSha256: List<String>,
    val pdf: ByteArray,
) {
    fun encode(): ByteArray {
        val h = JSONObject()
        h.put("docId", docId)
        h.put("signerCert", Base64Std.encode(signerCert))
        h.put("chain", JSONArray(chain.map(Base64Std::encode)))
        h.put("signedAttrs", Base64Std.encode(signedAttrs))
        h.put("byteRange", JSONArray(byteRange.toList()))
        h.put("revIndex", revIndex)
        h.put("inSha256", inSha256)
        h.put("hasPage", hasPage)
        pageSha256?.takeIf { it.isNotEmpty() }?.let { h.put("pageSha256", it) }
        claimedRole?.takeIf { it.isNotEmpty() }?.let { h.put("claimedRole", it) }
        h.put("preparedSha256", Hex.encode(Cms.sha256(pdf)))
        h.put("priorCmsSha256", JSONArray(priorCmsSha256))
        val head = h.toString().toByteArray(Charsets.UTF_8)
        val out = ByteArray(MAGIC.size + 4 + head.size + pdf.size)
        System.arraycopy(MAGIC, 0, out, 0, MAGIC.size)
        val n = head.size
        out[MAGIC.size] = (n ushr 24).toByte(); out[MAGIC.size + 1] = (n shr 16).toByte()
        out[MAGIC.size + 2] = (n shr 8).toByte(); out[MAGIC.size + 3] = n.toByte()
        System.arraycopy(head, 0, out, MAGIC.size + 4, n)
        System.arraycopy(pdf, 0, out, MAGIC.size + 4 + n, pdf.size)
        return out
    }

    companion object {
        private val MAGIC = "EIDPADES1".toByteArray()

        fun decode(b: ByteArray): PrepState {
            require(b.size >= MAGIC.size + 4 && b.copyOf(MAGIC.size).contentEquals(MAGIC)) { "state header" }
            var p = MAGIC.size
            val n = ((b[p].toLong() and 0xff) shl 24) or ((b[p + 1].toLong() and 0xff) shl 16) or
                ((b[p + 2].toLong() and 0xff) shl 8) or (b[p + 3].toLong() and 0xff)
            p += 4
            require(n <= b.size - p) { "state truncated" }
            val h = JSONObject(String(b, p, n.toInt(), Charsets.UTF_8))
            val pdf = b.copyOfRange(p + n.toInt(), b.size)
            require(Hex.encode(Cms.sha256(pdf)) == h.getString("preparedSha256")) { "prepared PDF hash mismatch" }
            val br = h.getJSONArray("byteRange")
            val chain = h.optJSONArray("chain") ?: JSONArray()
            val prior = h.optJSONArray("priorCmsSha256") ?: JSONArray()
            val s = PrepState(
                docId = h.getString("docId"),
                signerCert = Base64Std.decode(h.getString("signerCert")),
                chain = (0 until chain.length()).map { Base64Std.decode(chain.getString(it)) },
                signedAttrs = Base64Std.decode(h.getString("signedAttrs")),
                byteRange = LongArray(4) { br.getLong(it) },
                revIndex = h.getInt("revIndex"),
                inSha256 = h.getString("inSha256"),
                hasPage = h.optBoolean("hasPage", false),
                pageSha256 = h.optString("pageSha256").ifEmpty { null },
                claimedRole = h.optString("claimedRole").ifEmpty { null },
                priorCmsSha256 = (0 until prior.length()).map { prior.getString(it) },
                pdf = pdf,
            )
            require(s.signedAttrs.isNotEmpty() && s.signerCert.isNotEmpty() && s.pdf.isNotEmpty() && s.revIndex >= 1) { "state incomplete" }
            return s
        }
    }
}

/** RFC 4648 standard base64 with padding (Go encoding/json []byte). java.util.Base64 is API 26+. */
internal object Base64Std {
    private const val A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    fun encode(b: ByteArray): String {
        val sb = StringBuilder((b.size + 2) / 3 * 4)
        var i = 0
        while (i < b.size) {
            val n = minOf(3, b.size - i)
            var v = 0
            for (k in 0 until 3) v = (v shl 8) or (if (k < n) b[i + k].toInt() and 0xff else 0)
            for (k in 0 until 4) sb.append(if (k <= n) A[(v shr (18 - 6 * k)) and 0x3f] else '=')
            i += 3
        }
        return sb.toString()
    }

    /** Decodes, ignoring whitespace (PEM bodies). */
    fun decode(s: String): ByteArray {
        val out = java.io.ByteArrayOutputStream(s.length * 3 / 4)
        var v = 0
        var bits = 0
        for (ch in s) {
            if (ch == '=' ) break
            if (ch.isWhitespace()) continue
            val x = A.indexOf(ch)
            require(x >= 0) { "base64" }
            v = (v shl 6) or x
            bits += 6
            if (bits >= 8) {
                bits -= 8
                out.write((v shr bits) and 0xff)
            }
        }
        return out.toByteArray()
    }
}
