package mn.eidmongolia.eid.pades

import java.security.SecureRandom
import java.util.Date

/**
 * Native signing path — Go reference `pades/prepare.go` + `pades/complete.go` (profile pades-client/1) without the
 * revision validator (native SDKs do light prechecks only; full verification is the Go backend SDK).
 */
internal object Pades {
    const val PROFILE = "pades-client/1"
    const val MAX_INPUT_BYTES = (10 shl 20) - (256 shl 10)
    const val MAX_OUTPUT_BYTES = 10 shl 20
    private const val MAX_FILE_NAME = 120
    const val DEFAULT_TSA_URL = "https://tsa.timeserver.mn/"
    private const val PAGE_BRAND = "eID Mongolia"
    private const val PAGE_PROVIDER = "ca.eidmongolia.mn"
    private const val PAGE_TRUST_URL = "https://eidmongolia.mn/trust"
    private const val PAGE_TSA_NAME = "eID Mongolia TSA (tsa.timeserver.mn)"

    /** Clock / sleep / nonce — fixed in conformance tests (Go: Now, sleepFn, nonceReader). */
    class Env(
        val now: () -> Date = { Date() },
        val sleep: (Long) -> Unit = { if (it > 0) Thread.sleep(it) },
        val nonce: () -> ByteArray = { ByteArray(8).also { SecureRandom().nextBytes(it) } },
    )

    fun prepare(doc: ByteArray, o: PrepareOptions): Prepared {
        if (doc.size > MAX_INPUT_BYTES) throw EidPadesException.PdfTooLarge("PDF larger than 9.75 MiB")
        if (doc.size < 5 || String(doc, 0, 5, Charsets.ISO_8859_1) != "%PDF-") throw EidPadesException.PdfInvalid("not a PDF or damaged")
        val cert = try { Cert.parse(o.signerCert) } catch (e: Exception) { throw EidPadesException.SignerInvalid("signerCert: ${e.message}") }
        if (!cert.isRsa && !cert.isEc) throw EidPadesException.SignerInvalid("unsupported signer key type")
        val chain = signerChain(cert, o.chain)
        if (o.docId != null && o.docId.isNotEmpty() && !Precheck.UUID_RE.matches(o.docId)) {
            throw EidPadesException.RequestInvalid("docId must be a lowercase UUID")
        }
        if (o.lang != null && o.lang.isNotEmpty() && o.lang != "mn" && o.lang != "en") throw EidPadesException.RequestInvalid("lang: mn | en")
        val now = o.signingTime ?: Date()
        val inHex = Hex.encode(Cms.sha256(doc))
        val pre = Precheck.run(doc, EidChain.issuers + chain[0])
        var docId = o.docId?.takeIf { it.isNotEmpty() }
        val hasPage = pre.newDoc && o.verifyPage
        if (!pre.newDoc) {
            Precheck.docIdFromPage(doc)?.let { fromPage ->
                if (docId != null && docId != fromPage) throw EidPadesException.RequestInvalid("docId does not match the document's verify page")
                docId = fromPage
            }
        }
        if (pre.newDoc && docId == null) docId = randomUuid()
        var base = doc
        var pageHex: String? = null
        if (hasPage) {
            val fileName = cleanFileName(o.fileName) ?: throw EidPadesException.RequestInvalid("fileName required, ≤ 120 characters")
            val id = docId ?: throw EidPadesException.Internal("docId")
            base = try {
                VerifyPage.append(
                    doc,
                    VerifyPage.Data(
                        brand = PAGE_BRAND, fileName = fileName, documentHash = inHex, fileSize = doc.size.toLong(), docId = id,
                        verifyUrl = Precheck.VERIFY_URL + id, trustUrl = PAGE_TRUST_URL, caName = cert.issuerCommonName,
                        tsaName = PAGE_TSA_NAME, provider = PAGE_PROVIDER, lang = o.lang,
                    ),
                )
            } catch (e: Exception) {
                throw EidPadesException.PdfInvalid("cannot append the verify page: ${e.message}")
            }
            pageHex = Hex.encode(Cms.sha256(base))
        }
        val name = o.signerName?.takeIf { GoText.trimSpace(it).isNotEmpty() } ?: cert.displayName
        val prep = try {
            SignatureRevision.prepare(base, now, name, o.reason)
        } catch (e: Exception) {
            throw EidPadesException.PdfInvalid("cannot write the signature revision: ${e.message}")
        }
        if (prep.pdf.size + (256 shl 10) > MAX_OUTPUT_BYTES) throw EidPadesException.PdfTooLarge("signed output would exceed 10 MiB")
        val attrs = try {
            Cms.signedAttributes(prep.digest, cert, o.claimedRole)
        } catch (e: Exception) {
            throw EidPadesException.RequestInvalid("claimedRole")
        }
        val st = PrepState(
            docId = docId ?: "", signerCert = cert.raw, chain = chain.map { it.raw }, signedAttrs = attrs, byteRange = prep.byteRange,
            revIndex = pre.revIndex, inSha256 = inHex, hasPage = hasPage, pageSha256 = pageHex, claimedRole = o.claimedRole,
            priorCmsSha256 = pre.priorCmsSha256, pdf = prep.pdf,
        )
        return Prepared(dtbs = Cms.dtbs(attrs), digest = prep.digest, docId = docId ?: "", state = st.encode())
    }

    fun complete(state: ByteArray, signature: ByteArray, o: CompleteOptions, env: Env = Env()): Completed {
        val st = try { PrepState.decode(state) } catch (e: Exception) { throw EidPadesException.StateInvalid("state: ${e.message}") }
        val cert = try { Cert.parse(st.signerCert) } catch (e: Exception) { throw EidPadesException.StateInvalid("state signerCert") }
        val chain = try { st.chain.map(Cert::parse) } catch (e: Exception) { throw EidPadesException.StateInvalid("state chain") }
        val roots = try {
            if (o.roots.isEmpty()) listOf(EidChain.nationalRoot) else o.roots.map(Cert::parse)
        } catch (e: Exception) {
            throw EidPadesException.RequestInvalid("roots")
        }
        val sig = Cms.citizenSignature(cert, Cms.dtbs(st.signedAttrs), signature)
            ?: throw EidPadesException.SignatureInvalid("signature does not verify over the DTBS")
        val f = Fetcher(o.transport ?: DefaultHttp)
        val ts = try {
            Tsa.timestamp(f, o.tsaUrl ?: DEFAULT_TSA_URL, sig, roots, chain, env.now(), env.nonce())
        } catch (e: Exception) {
            throw EidPadesException.TsaUnavailable("TSA timestamp: ${e.message}")
        }
        val cms = try {
            Cms.assemble(st.signedAttrs, cert, chain, sig, ts.raw)
        } catch (e: Exception) {
            throw EidPadesException.SelfValidationFailed("CMS assembly: ${e.message}")
        }
        val signed = try {
            SignatureRevision.embedCms(st.pdf, st.byteRange, cms)
        } catch (e: SignatureRevision.PlaceholderOverflow) {
            throw EidPadesException.PlaceholderOverflow("CMS does not fit the placeholder: ${e.message}")
        } catch (e: Exception) {
            throw EidPadesException.StateInvalid("cannot embed the CMS: ${e.message}")
        }
        val dss = try {
            Ltv.collectWithWait(f, env.now, env.sleep, ts.genTime, roots, listOf(cert) + chain, ts.certificates)
        } catch (e: Exception) {
            throw EidPadesException.LtvUnavailable("OCSP/CRL: ${e.message}")
        }
        val out = try {
            dss.contents = SignatureRevision.signatureContents(signed, st.byteRange)
            Dss.append(signed, dss)
        } catch (e: Exception) {
            throw EidPadesException.SelfValidationFailed("DSS revision: ${e.message}")
        }
        if (out.size > MAX_OUTPUT_BYTES) throw EidPadesException.PdfTooLarge("output larger than 10 MiB")
        return Completed(
            pdf = out, cms = cms, docId = st.docId, outSha256 = Hex.encode(Cms.sha256(out)), inSha256 = st.inSha256,
            hasPage = st.hasPage, pageSha256 = st.pageSha256, signerCert = cert.raw, revIndex = st.revIndex,
            sigRevSha256 = Hex.encode(Cms.sha256(signed)), priorCmsSha256 = st.priorCmsSha256,
        )
    }

    /** Given chain (DER 04/03/02) or the embedded eID chain followed from the signer's issuer (root excluded). */
    private fun signerChain(signer: Cert, ders: List<ByteArray>): List<Cert> {
        if (ders.isNotEmpty()) {
            return try { ders.map(Cert::parse) } catch (e: Exception) { throw EidPadesException.SignerInvalid("chain: ${e.message}") }
        }
        val pool = EidChain.intermediates
        val chain = ArrayList<Cert>()
        var cur = signer
        repeat(pool.size + 1) {
            val next = pool.firstOrNull { it.rawSubject.contentEquals(cur.rawIssuer) && cur.signedBy(it) } ?: return@repeat
            chain += next
            cur = next
        }
        if (chain.isEmpty()) throw EidPadesException.SignerInvalid("signer's issuer is not in the embedded eID chain — pass chain")
        return chain
    }

    /** CA/Go: drop Cc/Cf/Zl/Zp, NFC, TrimSpace; 1…120 characters. */
    fun cleanFileName(s: String?): String? {
        if (s == null) return null
        val sb = StringBuilder()
        var i = 0
        while (i < s.length) {
            val r = s.codePointAt(i)
            i += Character.charCount(r)
            val t = Character.getType(r)
            if (t == Character.CONTROL.toInt() || t == Character.FORMAT.toInt() || t == Character.LINE_SEPARATOR.toInt() ||
                t == Character.PARAGRAPH_SEPARATOR.toInt() || t == Character.SURROGATE.toInt() || r == 0xFFFD
            ) continue
            sb.appendCodePoint(r)
        }
        val out = GoText.trimSpace(java.text.Normalizer.normalize(sb, java.text.Normalizer.Form.NFC))
        if (out.isEmpty() || out.codePointCount(0, out.length) > MAX_FILE_NAME) return null
        return out
    }

    private fun randomUuid(): String {
        val b = ByteArray(16).also { SecureRandom().nextBytes(it) }
        b[6] = ((b[6].toInt() and 0x0f) or 0x40).toByte()
        b[8] = ((b[8].toInt() and 0x3f) or 0x80).toByte()
        val h = Hex.encode(b)
        return "${h.substring(0, 8)}-${h.substring(8, 12)}-${h.substring(12, 16)}-${h.substring(16, 20)}-${h.substring(20)}"
    }
}
