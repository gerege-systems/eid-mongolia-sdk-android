package mn.eidmongolia.eid.pades

import java.security.MessageDigest

/**
 * /DSS revision (R_dss) — Go reference `pades/internal/core/dss.go`. Keeps every old DSS entry, reuses byte-identical
 * old streams by reference, writes new streams UNCOMPRESSED, VRI key = SHA1(/Contents) upper hex.
 */
internal object Dss {
    private const val MAX_DSS_STREAM = 4 shl 20

    fun append(signed: ByteArray, d: DssData): ByteArray {
        require(d.certs.size + d.ocsps.size + d.crls.size > 0) { "DSS empty" }
        val inc = Incremental(signed)
        val rd = inc.reader
        val root = inc.root
        val oldObj = rd.get(root, "DSS")
        if (!oldObj.isNull && oldObj !is PdfObj.Dict) throw PdfException("/DSS is not a dictionary")
        val old = (oldObj as? PdfObj.Dict)?.d
        val known = HashMap<String, String>() // sha256 hex of stream data → reference
        val lists = HashMap<String, MutableList<String>>()
        for (key in listOf("Certs", "OCSPs", "CRLs")) {
            val arr = old?.let { rd.get(it, key) as? PdfObj.Arr }?.items ?: continue
            for (e in arr) {
                val ref = inc.serialize(e)
                lists.getOrPut(key) { ArrayList() } += ref
                val v = try { rd.resolve(e) } catch (_: Exception) { null }
                if (v is PdfObj.Stream) {
                    try {
                        val data = rd.decodedStream(v)
                        known[Hex.encode(Cms.sha256(if (data.size > MAX_DSS_STREAM) data.copyOf(MAX_DSS_STREAM) else data))] = ref
                    } catch (_: Exception) {
                    }
                }
            }
        }
        val vriEntry = arrayOf(ArrayList<String>(), ArrayList<String>(), ArrayList<String>())
        fun add(slot: Int, key: String, items: List<ByteArray>) {
            for (der in items) {
                val sum = Hex.encode(Cms.sha256(der))
                var ref = known[sum]
                if (ref == null) {
                    val s = Der.concat("<< /Length ${der.size} >>\nstream\n".toByteArray(), der, "\nendstream".toByteArray())
                    val (id, _) = inc.addObject(s)
                    ref = "$id 0 R"
                    known[sum] = ref
                    lists.getOrPut(key) { ArrayList() } += ref
                }
                if (ref !in vriEntry[slot]) vriEntry[slot] += ref
            }
        }
        add(0, "Certs", d.certs)
        add(1, "OCSPs", d.ocsps)
        add(2, "CRLs", d.crls)

        val dss = StringBuilder("<<")
        for (key in listOf("Certs", "OCSPs", "CRLs")) {
            val l = lists[key]
            if (!l.isNullOrEmpty()) dss.append(" /").append(key).append(" [").append(l.joinToString(" ")).append(']')
        }
        val vri = old?.let { rd.get(it, "VRI") }
        val contents = d.contents
        if ((contents != null && contents.isNotEmpty()) || vri is PdfObj.Dict) {
            dss.append(" /VRI <<")
            val newKey = if (contents != null && contents.isNotEmpty()) {
                Hex.encode(MessageDigest.getInstance("SHA-1").digest(contents)).uppercase()
            } else null
            if (vri is PdfObj.Dict) {
                for (key in vri.d.sortedKeys) {
                    if (key == newKey) continue
                    dss.append(" /").append(Incremental.escapeName(key)).append(' ').append(inc.serialize(vri.d[key]))
                }
            }
            if (newKey != null) {
                dss.append(" /").append(newKey).append(" <<")
                for ((i, k) in listOf("Cert", "OCSP", "CRL").withIndex()) {
                    if (vriEntry[i].isNotEmpty()) dss.append(" /").append(k).append(" [").append(vriEntry[i].joinToString(" ")).append(']')
                }
                dss.append(" >>")
            }
            dss.append(" >>")
        }
        dss.append(" >>")
        val (dssId, _) = inc.addObject(dss.toString().toByteArray(Charsets.ISO_8859_1))
        val cat = StringBuilder("<<\n  /Type /Catalog\n")
        cat.append(inc.catalogCopy(setOf("DSS")))
        cat.append("  /DSS $dssId 0 R\n>>")
        val (catId, _) = inc.addObject(cat.toString().toByteArray(Charsets.ISO_8859_1))
        return inc.finish(catId)
    }
}
