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
 * @param page input document page, 1-based; 0 → the input's last page (a verify page added by this prepare is not counted)
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
 */
class Prepared(
    val dtbs: ByteArray,
    val digest: ByteArray,
    val docId: String,
    val state: ByteArray,
)

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
 * [EidPades.complete] output — everything the RP backend needs for `RegisterSignature` → CA `POST /pdf/signatures`
 * without re-parsing the PDF. Hashes are lowercase hex.
 * @property pdf signed PAdES-BASELINE-LT document
 * @property cms the embedded CMS SignedData (DER)
 * @property pageSha256 document after the verify page, before the signature revision ([hasPage] only)
 * @property sigRevSha256 the signature revision (before DSS) — doc[:ByteRange end]
 * @property priorCmsSha256 earlier signatures' CMS DER sha256, document order
 * @property priorRevisionSha256 earlier signatures' revision sha256 (doc[:ByteRange end]), same order as [priorCmsSha256]
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
)
