package mn.eidmongolia.eid.pades

import java.util.Date

/**
 * [EidPades.prepare] input — Go reference `pades.PrepareOptions` (iOS `EidPades.PrepareOptions` 1:1).
 *
 * @param signerCert citizen SIGN certificate DER (signingCertificateV2)
 * @param chain issuer chain DER (04, 03, 02); empty → built from the embedded eID chain
 * @param signerName `/Name`; null/blank → certificate GIVENNAME SURNAME (else CN)
 * @param reason `/Reason` (≤ 127 UTF-16 units, else omitted)
 * @param claimedRole CA representation response `claimedRole` (onBehalfOf) → signer-attributes-v2 in signedAttrs
 * @param signingTime `/M`; null → now. Always written at +08:00 (same instant → same DTBS on every platform)
 * @param docId verify page / QR UUID (lowercase); null → generated for a new document, read from the page otherwise
 * @param verifyPage append the verification (QR) page — only for a document without signatures
 * @param fileName name shown on the page (required with [verifyPage]; NFC, ≤ 120 characters)
 * @param lang page language "mn" | "en"; null/empty → "mn"
 * @param appearance visible signature (APPEARANCE_SPEC.md); null → invisible (default, byte-identical to before)
 * @param verifyPagePosition where the verification page goes when it is added ([verifyPage] on an unsigned document):
 *   "last" (default; also null/empty) or "first" (it becomes page 1). [SignatureAppearance.page], `suggestPlacement` and
 *   [Placement.page] always count the pages of the input PDF as given — never the added page (PAGE_SPEC §8a,
 *   PLACEMENT_SPEC §1b). Other values → REQUEST_INVALID.
 */
class PrepareOptions(
    val signerCert: ByteArray,
    val chain: List<ByteArray> = emptyList(),
    val signerName: String? = null,
    val reason: String? = null,
    val claimedRole: String? = null,
    val signingTime: Date? = null,
    val docId: String? = null,
    val verifyPage: Boolean = false,
    val fileName: String? = null,
    val lang: String? = null,
    val appearance: SignatureAppearance? = null,
    val verifyPagePosition: String? = null,
)

/**
 * Visible signature placement — Go reference `pades.Appearance` (APPEARANCE_SPEC.md §1; iOS `SignatureAppearance` 1:1).
 * Coordinates in pt from the bottom-left corner of the page's CropBox (else MediaBox) AFTER /Rotate (as displayed);
 * x to the right, y up. Each value is rounded to 0.01 pt; height ≥ 45 pt (QR), else REQUEST_INVALID.
 *
 * @param page input document page, 1-based (an explicit number is kept as is); 0 → the input's last page that is not an
 *   eID verify page — neither this prepare's verify page nor earlier revisions' ones count (PLACEMENT_SPEC §1a)
 * @param lang "mn" | "en"; null → [PrepareOptions.lang] (else mn)
 * @param exact draw the stamp exactly at page/x/y/width/height (a position the signer chose, e.g. dragged on a page
 *   preview): never moved off page content. [Placement.status] is then REQUESTED, or OVERLAP when content is under the
 *   rect (UNSCANNED when the page cannot be scanned) — never MOVED. false (default) = x/y is only the preferred spot
 *   (PLACEMENT_SPEC.md §6, §6a). The rect must lie inside the page (else REQUEST_INVALID).
 * @param width, height the whole widget rect — with [stampImage] the box plus the stamp's overflow above it. Both 0 →
 *   the default size (APPEARANCE_SPEC §6.3, PLACEMENT_SPEC §6c): 220 × 64, with [signatureImage] 220 × 110, with
 *   [stampImage] 240 × 147.5
 * @param signatureImage the signer's handwritten-signature image (CA signature-image) drawn inside the stamp
 *   (APPEARANCE_SPEC §6); null = none (byte-identical to golden v9)
 * @param stampImage the organization's stamp image (CA representations[].stampImage); only with
 *   [PrepareOptions.claimedRole] (onBehalfOf), else REQUEST_INVALID
 */
class SignatureAppearance(
    val page: Int = 0,
    val x: Double,
    val y: Double,
    val width: Double = 0.0,
    val height: Double = 0.0,
    val lang: String? = null,
    val exact: Boolean = false,
    val signatureImage: PdfImage? = null,
    val stampImage: PdfImage? = null,
) {
    companion object {
        /** Default sizes (pt) when width and height are both 0 (Go `pades.Default*Stamp*`, APPEARANCE_SPEC §6.3). */
        const val DEFAULT_WIDTH = 220.0
        const val DEFAULT_HEIGHT = 64.0
        const val DEFAULT_SIGNATURE_WIDTH = 220.0
        const val DEFAULT_SIGNATURE_HEIGHT = 110.0
        const val DEFAULT_ORG_WIDTH = 240.0
        const val DEFAULT_ORG_HEIGHT = 147.5
    }

    /** Go `appearanceSize`: (width, height), or the default for the images when both are 0. */
    internal fun size(): Pair<Double, Double> = when {
        width != 0.0 || height != 0.0 -> width to height
        stampImage != null -> DEFAULT_ORG_WIDTH to DEFAULT_ORG_HEIGHT
        signatureImage != null -> DEFAULT_SIGNATURE_WIDTH to DEFAULT_SIGNATURE_HEIGHT
        else -> DEFAULT_WIDTH to DEFAULT_HEIGHT
    }
}

/**
 * A "PDF image" as the CA serves it (Go `pades.PDFImage`, APPEARANCE_SPEC §6.1): one ink colour + an 8-bit alpha channel.
 * [alpha] is written into the PDF verbatim (/SMask, /FlateDecode) — nothing is compressed at runtime.
 *
 * @param width, height px, 1…1600
 * @param color [r, g, b], 0…255 each
 * @param alpha zlib stream (RFC 1950, nothing after the Adler-32) inflating to exactly width·height bytes, rows
 *   top-down, no PNG filter bytes; ≤ 300 KiB (CA JSON: base64-decoded `alpha`)
 * @param sha256 lowercase hex SHA-256 of the PNG the CA stores; not written into the PDF, carried to the registration
 *   ([Completed.images] → `images`)
 */
class PdfImage(
    val width: Int,
    val height: Int,
    val color: IntArray,
    val alpha: ByteArray,
    val sha256: String,
)

/** [SignatureImage.kind]; [wire] = the CA/Go string. */
enum class SignatureImageKind(val wire: String) {
    /** The citizen's handwritten-signature image. */
    SIGNATURE("signature"),
    /** The organization's stamp image. */
    STAMP("stamp"),
}

/** One image drawn in a signature's stamp (Go `eid.PDFSignatureImage`): registration `images` row. */
data class SignatureImage(val kind: SignatureImageKind, val sha256: String)

/**
 * [EidPades.prepare] output.
 * @property dtbs the 32 bytes the phone/token signs — SHA-256(signedAttrs) (RP-API `RAW_DIGEST_SIGNATURE` hash)
 * @property digest messageDigest = SHA-256(ByteRange)
 * @property state opaque, serialisable — the app may persist it while waiting for the signature
 * @property placement where the visible stamp was drawn; null without [PrepareOptions.appearance] (PLACEMENT_SPEC.md)
 */
class Prepared(
    val dtbs: ByteArray,
    val digest: ByteArray,
    val docId: String,
    val state: ByteArray,
    val placement: Placement? = null,
)

/**
 * The visible stamp's final rect ([SignatureAppearance] coordinates, pt) and how it was chosen — Go `pades.Placement`
 * (iOS `EidPades.Placement` 1:1). The stamp avoids existing page content (PLACEMENT_SPEC.md); surface
 * [PlacementStatus.OVERLAP] / [PlacementStatus.UNSCANNED] to the signer — the signature is valid either way.
 *
 * @property page 1-based page the stamp is on
 */
data class Placement(
    val page: Int,
    val x: Double,
    val y: Double,
    val width: Double,
    val height: Double,
    val status: PlacementStatus,
)

/** [Placement.status]; [wire] = the Go/iOS string. */
enum class PlacementStatus(val wire: String) {
    /** Drawn at the requested spot (it was free). */
    REQUESTED("requested"),
    /** The requested spot was occupied; the stamp moved to free space. */
    MOVED("moved"),
    /** No free spot: drawn at the requested spot over content. */
    OVERLAP("overlap"),
    /** The page could not be scanned within the limits: drawn at the requested spot. */
    UNSCANNED("unscanned"),
}

/**
 * [EidPades.suggestPlacement] result — Go `pades.Suggestion` (iOS `EidPades.PlacementSuggestion` 1:1, PLACEMENT_SPEC.md
 * §6b), pt. [page], [x], [y], [width], [height], [status] are what [EidPades.prepare] returns in [Prepared.placement]
 * for the same PDF and appearance. Coordinates: origin at the visible lower-left corner, x right, y up — a UI that
 * renders the page at `s` px/pt with a top-left origin maps `left = x·s`, `top = (pageHeight − y − height)·s`; back:
 * `x = left/s`, `y = pageHeight − top/s − height`, then prepare with `exact = true`.
 *
 * @property page 1-based, resolved (appearance page 0 → PLACEMENT_SPEC §1a)
 * @property pageWidth visible size of [page] (CropBox, else MediaBox, after /Rotate)
 * @property pageCount pages in /Pages tree order
 * @property pages visible size of every page; index 0 = page 1; (0, 0) = geometry unreadable
 */
data class PlacementSuggestion(
    val page: Int,
    val x: Double,
    val y: Double,
    val width: Double,
    val height: Double,
    val status: PlacementStatus,
    val pageWidth: Double,
    val pageHeight: Double,
    val pageCount: Int,
    val pages: List<PageSize>,
)

/** A page's visible size in pt ([PlacementSuggestion.pages]). */
data class PageSize(val width: Double, val height: Double)

/**
 * [EidPades.complete] input.
 * @param tsaUrl RFC 3161 TSA; null → `https://tsa.timeserver.mn/`
 * @param roots trust anchors DER (TSA chain); empty → Mongolian National Root CA (other values: sandbox/tests)
 * @param transport HTTP for TSA / OCSP / CRL; null → HttpURLConnection, 10 s total deadline per request (Go), no redirects
 */
class CompleteOptions(
    val tsaUrl: String? = null,
    val roots: List<ByteArray> = emptyList(),
    val transport: EidPadesTransport? = null,
)

/**
 * [EidPades.complete] output. [registration] builds the CA `POST /pdf/signatures` body the RP backend posts as is (Go
 * `pades.Registration` → `Client.PDF.RegisterSignature`, TS `registrationFromCompleted` → `registerSignature`).
 * Hashes are lowercase hex.
 * @property pdf signed PAdES-BASELINE-LT document
 * @property cms the embedded CMS SignedData (DER)
 * @property pageSha256 document after the verify page, before the signature revision ([hasPage] only)
 * @property sigRevSha256 the signature revision (before DSS) — doc[:ByteRange end]
 * @property priorCmsSha256 earlier signatures' CMS DER sha256, document order
 * @property priorRevisionSha256 earlier signatures' revision sha256 (doc[:ByteRange end]), same order as [priorCmsSha256]
 *   — informational; do not send both lists for the same signatures (the CA answers 400), use [registration]
 * @property fileName [PrepareOptions.fileName] as cleaned by prepare (CA `cleanFileName`); null when not given or invalid
 * @property claimedRole [PrepareOptions.claimedRole] carried through the state; null for a personal signature —
 *   [registration] then requires `onBehalfOf` (the CA rejects a claimed role without an organisation)
 */
class Completed(
    val pdf: ByteArray,
    val cms: ByteArray,
    val docId: String,
    val outSha256: String,
    val inSha256: String,
    val hasPage: Boolean,
    val pageSha256: String?,
    val signerCert: ByteArray,
    val revIndex: Int,
    val sigRevSha256: String,
    val priorCmsSha256: List<String>,
    val priorRevisionSha256: List<String>,
    val fileName: String? = null,
    val claimedRole: String? = null,
    /** Images drawn in this signature's stamp (signatureImage, then stampImage — those given); sent as `images`. */
    val images: List<SignatureImage> = emptyList(),
) {
    /**
     * The CA registration body for this signature (Go `pades.Registration`). Prior signatures go as `priorCmsSha256`
     * only; [Registration.priorSignatures] keeps both keys for the 409 `PRIOR_MISMATCH` retry.
     * @param medium null = inferred the way the CA pairs them: [sessionId] given → [Medium.PHONE], else [Medium.TOKEN]
     * @param sessionId the RAW_DIGEST_SIGNATURE session (required for [Medium.PHONE], absent for [Medium.TOKEN])
     * @param onBehalfOf NTRMN-… (required when prepare had a [claimedRole])
     * @throws EidPadesException.RequestInvalid revIndex 1 without a verification page, no valid fileName in prepare,
     *   [Medium.PHONE] without [sessionId], [Medium.TOKEN] with [sessionId], or [claimedRole] without [onBehalfOf]
     */
    fun registration(medium: Medium? = null, sessionId: String? = null, onBehalfOf: String? = null): Registration {
        if (revIndex == 1 && !hasPage) {
            throw EidPadesException.RequestInvalid("the CA registers a first signature only with the verification page (PrepareOptions.verifyPage)")
        }
        val name = fileName?.takeIf { it.isNotEmpty() } ?: throw EidPadesException.RequestInvalid("fileName empty (PrepareOptions.fileName)")
        val session = sessionId?.takeIf { it.isNotEmpty() }
        val m = medium ?: if (session != null) Medium.PHONE else Medium.TOKEN
        if (m == Medium.PHONE && session == null) {
            throw EidPadesException.RequestInvalid("medium phone requires sessionId (the RAW_DIGEST_SIGNATURE session)")
        }
        if (m == Medium.TOKEN && session != null) throw EidPadesException.RequestInvalid("medium token takes no sessionId")
        val obo = onBehalfOf?.takeIf { it.isNotEmpty() }
        if (!claimedRole.isNullOrEmpty() && obo == null) {
            throw EidPadesException.RequestInvalid("claimedRole was prepared: onBehalfOf (NTRMN-…) is required")
        }
        val etsi = try {
            Cert.parse(signerCert).subjectAttr(Cert.OID_SERIAL_NUMBER)
        } catch (_: Exception) {
            null
        }
        return Registration(
            docID = docId, revIndex = revIndex, medium = m, sessionID = session,
            cms = Base64Std.encode(cms), fileName = name, inSha256 = inSha256,
            pageSha256 = if (revIndex == 1) pageSha256 else null, sigRevSha256 = sigRevSha256, outSha256 = outSha256,
            priorCmsSha256 = priorCmsSha256.takeIf { it.isNotEmpty() },
            onBehalfOf = obo, signerEtsi = etsi, images = images.takeIf { it.isNotEmpty() },
            priorSignatures = if (priorRevisionSha256.size == priorCmsSha256.size) {
                priorCmsSha256.zip(priorRevisionSha256) { c, r -> PriorSignature(c, r) }
            } else {
                emptyList()
            },
        )
    }
}

/** `phone` (RP-API RAW_DIGEST_SIGNATURE session) | `token` (USB token). */
enum class Medium(val wire: String) { PHONE("phone"), TOKEN("token") }

/**
 * One prior signature's two keys (Go `eid.PDFPriorSignature`): the CA knows a client-side row by its CMS hash and a
 * CA-assembled (mode A) row by its revision hash — which one a prior signature is cannot be told from the file.
 */
class PriorSignature(val cmsSha256: String, val revisionSha256: String)

/**
 * Body of CA `POST /pdf/signatures` (CA `dto.PDFSignatureRegisterRequest`, Go `eid.PDFSignatureRegistration`, TS
 * `RegisterSignatureInput`) — [toJson] gives the exact field names (the CA rejects unknown fields).
 * @property cms CMS DER, standard base64
 * @property pageSha256 only for revIndex 1
 * @property priorRevisionSha256 prior CA-assembled (mode A) signatures by revision hash — null by default; on 409
 *   `PRIOR_MISMATCH` move the matching [priorSignatures] from [priorCmsSha256] to here
 * @property priorSignatures SDK-only (not in [toJson]): every prior signature's CMS and revision hash, document order
 */
data class Registration(
    val docID: String,
    val revIndex: Int,
    val medium: Medium,
    val sessionID: String?,
    val cms: String,
    val fileName: String,
    val inSha256: String,
    val pageSha256: String?,
    val sigRevSha256: String,
    val outSha256: String,
    val priorCmsSha256: List<String>?,
    val priorRevisionSha256: List<String>? = null,
    val onBehalfOf: String?,
    val signerEtsi: String?,
    val priorSignatures: List<PriorSignature> = emptyList(),
    /** APPEARANCE_SPEC §6.6: each image in the stamp as {kind, sha256}; null/empty = not sent. */
    val images: List<SignatureImage>? = null,
) {
    /** JSON object; null / absent optional fields are omitted (Go `omitempty`). */
    fun toJson(): String {
        val sb = StringBuilder("{")
        fun key(k: String) {
            if (sb.length > 1) sb.append(',')
            sb.append('"').append(k).append("\":")
        }
        fun str(k: String, v: String?) {
            if (v == null) return
            key(k)
            jsonString(sb, v)
        }
        fun list(k: String, v: List<String>?) {
            if (v.isNullOrEmpty()) return
            key(k)
            sb.append('[')
            v.forEachIndexed { i, s -> if (i > 0) sb.append(','); jsonString(sb, s) }
            sb.append(']')
        }
        str("docID", docID)
        key("revIndex"); sb.append(revIndex)
        str("medium", medium.wire)
        str("sessionID", sessionID)
        str("cms", cms)
        str("fileName", fileName)
        str("inSha256", inSha256)
        str("pageSha256", pageSha256)
        str("sigRevSha256", sigRevSha256)
        str("outSha256", outSha256)
        list("priorCmsSha256", priorCmsSha256)
        list("priorRevisionSha256", priorRevisionSha256)
        str("onBehalfOf", onBehalfOf)
        str("signerEtsi", signerEtsi)
        if (!images.isNullOrEmpty()) {
            key("images")
            sb.append('[')
            images.forEachIndexed { i, im ->
                if (i > 0) sb.append(',')
                sb.append("{\"kind\":")
                jsonString(sb, im.kind.wire)
                sb.append(",\"sha256\":")
                jsonString(sb, im.sha256)
                sb.append('}')
            }
            sb.append(']')
        }
        return sb.append('}').toString()
    }

    private fun jsonString(sb: StringBuilder, s: String) {
        sb.append('"')
        for (c in s) {
            when {
                c == '"' -> sb.append("\\\"")
                c == '\\' -> sb.append("\\\\")
                c < ' ' || c == ' ' || c == ' ' -> sb.append(String.format(java.util.Locale.ROOT, "\\u%04x", c.code))
                else -> sb.append(c)
            }
        }
        sb.append('"')
    }
}
