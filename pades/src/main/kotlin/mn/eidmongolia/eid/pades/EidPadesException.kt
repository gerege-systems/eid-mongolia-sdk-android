package mn.eidmongolia.eid.pades

/**
 * Core-ийн тогтвортой алдааны кодууд (Go `pades/errors.go`). [code] нь Go/WASM/.NET/Swift-тэй ИЖИЛ мөр —
 * апп логик/телеметрийг үүгээр салаалуулна, [message]-ээр биш. iOS `GeregeEIDPDF.PadesError`-тэй 1:1.
 */
sealed class EidPadesException(val code: String, message: String) : Exception(message) {
    class PdfInvalid(message: String) : EidPadesException("PDF_INVALID", message)
    class PdfEncrypted(message: String) : EidPadesException("PDF_ENCRYPTED", message)
    /** DocMDP P=1 — баримт цааш гарын үсэг зөвшөөрөхгүй. */
    class PdfLocked(message: String) : EidPadesException("PDF_LOCKED", message)
    class PdfTooLarge(message: String) : EidPadesException("PDF_TOO_LARGE", message)
    /** Гарын үсгийн дээд тоо (16) хүрсэн. */
    class PdfTooManySignatures(message: String) : EidPadesException("PDF_TOO_MANY_SIGNATURES", message)
    /** Өмнөх гарын үсэг хүчингүй — дээр нь зурахгүй. */
    class PdfPriorSignatureInvalid(message: String) : EidPadesException("PDF_PRIOR_SIGNATURE_INVALID", message)
    /** Өмнөх гарын үсэг eID-ийн хүчинтэй B-LT биш. */
    class PdfForeignSignature(message: String) : EidPadesException("PDF_FOREIGN_SIGNATURE", message)
    /** signerCert задрахгүй / түлхүүрийн төрөл дэмжигдэхгүй. */
    class SignerInvalid(message: String) : EidPadesException("SIGNER_INVALID", message)
    /** Options буруу (үл мэдэгдэх түлхүүр, lang, fileName …) — wrapper/апп-ын алдаа. */
    class RequestInvalid(message: String) : EidPadesException("REQUEST_INVALID", message)
    /** Гарын үсэг DTBS дээр SignerCert-ээр шалгагдсангүй (буруу түлхүүр/хэлбэр). */
    class SignatureInvalid(message: String) : EidPadesException("SIGNATURE_INVALID", message)
    /** TSA хүрэхгүй — ижил state-ээр дахин оролдож болно. */
    class TsaUnavailable(message: String) : EidPadesException("TSA_UNAVAILABLE", message)
    /** OCSP/CRL авч чадсангүй — ижил state-ээр дахин оролдож болно. */
    class LtvUnavailable(message: String) : EidPadesException("LTV_UNAVAILABLE", message)
    class SelfValidationFailed(message: String) : EidPadesException("SELF_VALIDATION_FAILED", message)
    class PlaceholderOverflow(message: String) : EidPadesException("PLACEHOLDER_OVERFLOW", message)
    class StateInvalid(message: String) : EidPadesException("STATE_INVALID", message)
    /** Core-ийн дотоод алдаа (pades.Error биш). */
    class Internal(message: String) : EidPadesException("INTERNAL", message)
    /** Энэ wrapper-т үл мэдэгдэх код (шинэ core) — [code]-ийг хэвээр хадгална. */
    class Unknown(code: String, message: String) : EidPadesException(code, message)

    companion object {
        /** Кодоос төрөл. */
        fun of(code: String, message: String): EidPadesException = when (code) {
            "PDF_INVALID" -> PdfInvalid(message)
            "PDF_ENCRYPTED" -> PdfEncrypted(message)
            "PDF_LOCKED" -> PdfLocked(message)
            "PDF_TOO_LARGE" -> PdfTooLarge(message)
            "PDF_TOO_MANY_SIGNATURES" -> PdfTooManySignatures(message)
            "PDF_PRIOR_SIGNATURE_INVALID" -> PdfPriorSignatureInvalid(message)
            "PDF_FOREIGN_SIGNATURE" -> PdfForeignSignature(message)
            "SIGNER_INVALID" -> SignerInvalid(message)
            "REQUEST_INVALID" -> RequestInvalid(message)
            "SIGNATURE_INVALID" -> SignatureInvalid(message)
            "TSA_UNAVAILABLE" -> TsaUnavailable(message)
            "LTV_UNAVAILABLE" -> LtvUnavailable(message)
            "SELF_VALIDATION_FAILED" -> SelfValidationFailed(message)
            "PLACEHOLDER_OVERFLOW" -> PlaceholderOverflow(message)
            "STATE_INVALID" -> StateInvalid(message)
            "INTERNAL" -> Internal(message)
            else -> Unknown(code, message)
        }
    }
}
