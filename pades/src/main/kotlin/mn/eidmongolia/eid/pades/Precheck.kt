package mn.eidmongolia.eid.pades

/** Embedded eID chain (same PEMs as Go `pades/internal/eidcrypto/chain`). */
internal object EidChain {
    private fun load(name: String): Cert {
        val s = EidChain::class.java.getResourceAsStream("/mn/eidmongolia/eid/pades/chain/$name")
            ?: throw IllegalStateException("eID chain resource $name missing")
        return Cert.parse(Cert.pemBlocks(s.use { String(it.readBytes(), Charsets.US_ASCII) }).single())
    }

    val nationalRoot by lazy { load("01-mongolian-national-root-ca.pem") }
    val intermediates by lazy {
        listOf(
            load("02-mongolian-national-issuing-ca-mddc.pem"), load("03-gerege-issuing-ca.pem"),
            load("04-eid-mongolia-issuing-ca.pem"), load("05-eid-mongolia-org-issuing-ca.pem"),
        )
    }
    /** eID issuing CAs (04 natural persons, 05 organisations). */
    val issuers by lazy { intermediates.subList(2, 4) }
}

/**
 * Light prepare checks — exactly `pades/PRECHECKS.md` of the Go reference (no revision validator in native SDKs).
 * Steps 1–3 (size, `%PDF-`, signer cert) run in [Pades.prepare]; this covers 4–10.
 */
internal object Precheck {
    const val MAX_SIGNATURES = 16
    const val VERIFY_URL = "https://ca.eidmongolia.mn/verify/"
    val UUID_RE = Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

    class Result(val newDoc: Boolean, val revIndex: Int, val priorCmsSha256: List<String>)

    private class SigDict(val obj: Int, val byteRange: List<Long>?, val subFilter: String?, val type: String? = null)

    fun run(doc: ByteArray, issuers: List<Cert>): Result {
        if (encrypted(doc)) throw EidPadesException.PdfEncrypted("encrypted PDF is not supported")
        val (sigs, flags) = try {
            scan(doc)
        } catch (e: EidPadesException) {
            throw e
        } catch (e: Exception) {
            throw EidPadesException.PdfInvalid("not a PDF or damaged: ${e.message}")
        }
        if (sigs.isEmpty()) return Result(true, 1, emptyList())
        if (sigs.size >= MAX_SIGNATURES) throw EidPadesException.PdfTooManySignatures("too many signatures")
        val (locked, hasDss) = flags
        val checked = sigs.map { s ->
            try {
                checkPriorSignature(doc, s)
            } catch (e: Exception) {
                throw EidPadesException.PdfPriorSignatureInvalid("prior signature invalid: ${e.message}")
            }
        }
        if (locked) throw EidPadesException.PdfLocked("document is certified with DocMDP P=1")
        for ((i, s) in sigs.withIndex()) {
            val c = checked[i]
            if (s.subFilter != SignatureRevision.SUB_FILTER || issuers.none { c.leaf.issuedBy(it) } || !c.stamped || !hasDss) {
                throw EidPadesException.PdfForeignSignature("document has a non-eID signature")
            }
        }
        return Result(false, sigs.size + 1, checked.map { it.cmsSha256 })
    }

    /**
     * Light self-check of `complete`'s output (no full validator — Go runs the CA validator here): the document parses,
     * its signature count (/Type /Sig or none) is [revIndex], the final Catalog has /DSS, and the signature whose
     * ByteRange is [own] has exactly [cms] as /Contents and passes step 8 (covers its revision up to %%EOF,
     * messageDigest and signature verify). Returns the prior signatures' (CMS sha256, revision sha256), object order —
     * each revision hash = that signature's own sigRevSha256 (Go Completed.PriorRevisionSHA256).
     */
    fun selfCheck(out: ByteArray, own: LongArray, cms: ByteArray, revIndex: Int): List<Pair<String, String>> {
        val (sigs, flags) = scan(out)
        require(flags.second) { "no /DSS" }
        val ownList = own.toList()
        val cmsHex = Hex.encode(Cms.sha256(cms))
        var found = false
        var count = 0
        val prior = ArrayList<Pair<String, String>>()
        for (s in sigs) {
            if (s.type != null && s.type != "Sig") continue
            count++
            val c = checkPriorSignature(out, s)
            if (s.byteRange == ownList) {
                require(!found && c.cmsSha256 == cmsHex) { "the new signature is not the prepared one" }
                found = true
            } else {
                val br = s.byteRange!!
                val h = java.security.MessageDigest.getInstance("SHA-256")
                h.update(out, 0, (br[2] + br[3]).toInt())
                prior += c.cmsSha256 to Hex.encode(h.digest())
            }
        }
        require(found && count == revIndex) { "signature count " + count + ", want " + revIndex }
        return prior
    }

    /** Step 4: /Encrypt in the trailer; when the parser cannot open the file, `/Encrypt n g R` or `/Encrypt <<` in the bytes. */
    private fun encrypted(doc: ByteArray): Boolean = try {
        val r = PdfReader.open(doc)
        !r.trailer["Encrypt"].isNull
    } catch (_: Exception) {
        Structure.hasEncryptRef(doc)
    }

    private class Checked(val leaf: Cert, val stamped: Boolean, val cmsSha256: String)

    /** Signature dicts (object order) + (DocMDP P=1 lock, final Catalog has a /DSS dict). */
    private fun scan(doc: ByteArray): Pair<List<SigDict>, Pair<Boolean, Boolean>> {
        val r = PdfReader.open(doc)
        val root = r.get(r.trailer, "Root") as? PdfObj.Dict ?: throw PdfException("Catalog missing")
        var locked = false
        val hasDss = r.get(root.d, "DSS") is PdfObj.Dict
        val perms = r.get(root.d, "Perms").dict
        if (perms != null) r.get(perms, "DocMDP").dict?.let { if (docMdpP1(r, it)) locked = true }
        val sigs = ArrayList<SigDict>()
        for (id in r.objectIds) {
            val gen = (r.xref[id] as? PdfReader.XrefEntry.Offset)?.gen ?: 0
            val v = r.obj(PdfRef(id, gen)) as? PdfObj.Dict ?: continue
            if (r.get(v.d, "ByteRange").isNull || r.get(v.d, "Contents").isNull) continue
            val brItems = (r.get(v.d, "ByteRange") as? PdfObj.Arr)?.items?.map { r.resolve(it) }
            val br = if (brItems != null && brItems.all { it is PdfObj.Int }) brItems.map { (it as PdfObj.Int).v } else null
            if (docMdpP1(r, v.d)) locked = true
            sigs += SigDict(id, br, r.get(v.d, "SubFilter").name, r.get(v.d, "Type").name)
        }
        sigs.sortBy { it.obj }
        return sigs to (locked to hasDss)
    }

    /** /Reference row with /TransformMethod /DocMDP (or none) and /TransformParams /P 1. */
    private fun docMdpP1(r: PdfReader, sig: PdfDict): Boolean {
        val ref = (r.get(sig, "Reference") as? PdfObj.Arr)?.items ?: return false
        for (e in ref) {
            val d = r.resolve(e).dict ?: continue
            val m = r.get(d, "TransformMethod")
            val p = r.get(d, "TransformParams").dict?.let { r.get(it, "P") }
            if ((m.isNull || m.name == "DocMDP") && p is PdfObj.Int && p.v == 1L) return true
        }
        return false
    }

    /** Step 8: structural ByteRange checks + CMS signature over the ByteRange bytes (no chain/revocation/time). */
    private fun checkPriorSignature(doc: ByteArray, s: SigDict): Checked {
        val br = s.byteRange
        require(br != null && br.size == 4 && br[0] == 0L && br[1] > 0 && br[2] > br[1] + 1 && br[3] >= 0 && br[2] + br[3] <= doc.size) { "ByteRange" }
        val a = br[1].toInt()
        val b = br[2].toInt()
        require(doc[a] == '<'.code.toByte() && doc[b - 1] == '>'.code.toByte()) { "ByteRange does not point at /Contents" }
        // The signature covers its revision up to %%EOF (trailing CR/LF trimmed).
        var end = (br[2] + br[3]).toInt()
        while (end > 0 && (doc[end - 1] == '\r'.code.toByte() || doc[end - 1] == '\n'.code.toByte())) end--
        require(end >= 5 && String(doc, end - 5, 5, Charsets.ISO_8859_1) == "%%EOF") { "ByteRange does not end at %%EOF" }
        val raw = Hex.decode(doc, a + 1, b - 1) ?: throw IllegalArgumentException("/Contents hex")
        val first = Der.parse(raw)
        require(first.tag == Der.SEQUENCE) { "CMS is not DER" }
        val der = first.encoded()
        val p = Cms.parse(der)
        require(p.signerCount == 1 && p.signer != null) { "CMS signer" }
        val signed = ByteArray(a + br[3].toInt())
        System.arraycopy(doc, 0, signed, 0, a)
        System.arraycopy(doc, b, signed, a, br[3].toInt())
        require(Cms.verify(p, signed)) { "signature" }
        return Checked(p.signer!!, Cms.OID_TIMESTAMP_TOKEN in p.unsignedAttrOids, Hex.encode(Cms.sha256(der)))
    }

    /** docId from the first eID verify-page link (`/Subtype /Link`, `/A /URI` = VERIFY_URL + lowercase UUID). */
    fun docIdFromPage(doc: ByteArray): String? = try {
        val r = PdfReader.open(doc)
        var found: String? = null
        for (id in r.objectIds) {
            val gen = (r.xref[id] as? PdfReader.XrefEntry.Offset)?.gen ?: 0
            val v = (r.obj(PdfRef(id, gen)) as? PdfObj.Dict)?.d ?: continue
            if (r.get(v, "Subtype").name != "Link") continue
            val uri = r.get(v, "A").dict?.let { r.get(it, "URI") } as? PdfObj.Str ?: continue
            val u = String(uri.bytes, Charsets.ISO_8859_1)
            if (u.startsWith(VERIFY_URL) && UUID_RE.matches(u.removePrefix(VERIFY_URL))) {
                found = u.removePrefix(VERIFY_URL)
                break
            }
        }
        found
    } catch (_: Exception) {
        null
    }
}
