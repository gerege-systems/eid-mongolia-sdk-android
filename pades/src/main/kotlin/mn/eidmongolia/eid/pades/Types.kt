package mn.eidmongolia.eid.pades

import java.util.Date

/**
 * [EidPades.prepare] input — Go reference `pades.PrepareOptions` (iOS `GeregeEIDPDF.PrepareOptions` 1:1).
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
 * @param lang page language "mn" | "en"; null → reference default
 * @param appearance visible signature (APPEARANCE_SPEC.md); null → invisible (default, byte-identical to before)
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
)

/**
 * Visible signature placement — Go reference `pades.Appearance` (APPEARANCE_SPEC.md §1; iOS `SignatureAppearance` 1:1).
 * Coordinates in pt from the bottom-left corner of the page's CropBox (else MediaBox) AFTER /Rotate (as displayed);
 * x to the right, y up. Each value is rounded to 0.01 pt; height ≥ 45 pt (QR), else REQUEST_INVALID.
 *
 * @param page input document page, 1-based (an explicit number is kept as is); 0 → the input's last page that is not an
 *   eID verify page — neither this prepare's verify page nor earlier revisions' ones count (PLACEMENT_SPEC §1a)
 * @param lang "mn" | "en"; null → [PrepareOptions.lang] (else mn)
 */
class SignatureAppearance(
    val page: Int = 0,
    val x: Double,
    val y: Double,
    val width: Double,
    val height: Double,
    val lang: String? = null,
)

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
 * [EidPades.complete] input.
 * @param tsaUrl RFC 3161 TSA; null → `https://tsa.timeserver.mn/`
 * @param roots trust anchors DER (TSA chain); empty → Mongolian National Root CA (other values: sandbox/tests)
 * @param transport HTTP for TSA / OCSP / CRL; null → HttpURLConnection, 10 s timeout, no redirects
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
) {
    /**
     * The CA registration body for this signature (Go `pades.Registration`). Prior signatures go as `priorCmsSha256`
     * only; [Registration.priorSignatures] keeps both keys for the 409 `PRIOR_MISMATCH` retry.
     * @param sessionId the RAW_DIGEST_SIGNATURE session (required for [Medium.PHONE])
     * @param onBehalfOf NTRMN-… (required when prepare had a claimedRole)
     * @throws EidPadesException.RequestInvalid revIndex 1 without a verification page, or no valid fileName in prepare
     */
    fun registration(medium: Medium, sessionId: String? = null, onBehalfOf: String? = null): Registration {
        if (revIndex == 1 && !hasPage) {
            throw EidPadesException.RequestInvalid("the CA registers a first signature only with the verification page (PrepareOptions.verifyPage)")
        }
        val name = fileName?.takeIf { it.isNotEmpty() } ?: throw EidPadesException.RequestInvalid("fileName empty (PrepareOptions.fileName)")
        val etsi = try {
            Cert.parse(signerCert).subjectAttr(Cert.OID_SERIAL_NUMBER)
        } catch (_: Exception) {
            null
        }
        return Registration(
            docID = docId, revIndex = revIndex, medium = medium, sessionID = sessionId?.takeIf { it.isNotEmpty() },
            cms = Base64Std.encode(cms), fileName = name, inSha256 = inSha256,
            pageSha256 = if (revIndex == 1) pageSha256 else null, sigRevSha256 = sigRevSha256, outSha256 = outSha256,
            priorCmsSha256 = priorCmsSha256.takeIf { it.isNotEmpty() },
            onBehalfOf = onBehalfOf?.takeIf { it.isNotEmpty() }, signerEtsi = etsi,
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
