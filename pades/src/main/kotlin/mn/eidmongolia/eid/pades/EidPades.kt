package mn.eidmongolia.eid.pades

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * eID client-side PAdES — the PDF never reaches an eID server (docs/PADES_CLIENT_SIDE.md). Native Kotlin
 * implementation of the signing path, byte-identical to the Go reference (`eid-mongolia-sdk-go/pades`, profile
 * `pades-client/1`) on the shared golden vectors; iOS `GeregeEIDPades.EidPades` 1:1.
 *
 * Flow: [prepare] → have `Prepared.dtbs` signed via an RP-API signature session (RAW_DIGEST_SIGNATURE) on the phone or
 * token → [complete] (RFC 3161 TSA + OCSP/CRL over the network, DSS) → register [Completed] through the RP backend
 * (`POST /pdf/signatures`). No full validator here — verification is the Go backend SDK / CA registry lookup.
 *
 * Thread-safe, no global state. [prepare] is CPU work — do not call it on the UI thread.
 */
object EidPades {
    /** PDF/CMS profile implemented by this SDK (Go `pades.ProfileVersion`). */
    const val version = Pades.PROFILE

    fun prepare(pdf: ByteArray, options: PrepareOptions): Prepared = guard { Pades.prepare(pdf, options) }

    /**
     * Runs [prepare]'s placement (page 0 resolution, page scan, candidate search; [SignatureAppearance.exact]) on [pdf]
     * without signing — no certificate, no network — so a UI can show the default stamp position, the page sizes, and
     * whether a chosen rect lies over content (Go `pades.SuggestPlacement`, PLACEMENT_SPEC.md §6b). CPU work — not on
     * the UI thread.
     *
     * Errors, in order: PDF_TOO_LARGE, PDF_INVALID (header/structure), REQUEST_INVALID (appearance values), PDF_ENCRYPTED,
     * REQUEST_INVALID (page > page count, page geometry, rect outside the page). Not checked here ([prepare] does): prior
     * signatures, the signer certificate, whether the signer's name fits the stamp. Page 0 skips this document's eID
     * verify pages using the docId read from its verify page — for an unsigned document no page is skipped.
     */
    fun suggestPlacement(pdf: ByteArray, appearance: SignatureAppearance): PlacementSuggestion =
        guard { Pades.suggestPlacement(pdf, appearance) }

    /**
     * @param state [Prepared.state]
     * @param signature RSA PKCS#1 v1.5, ECDSA r‖s or DER — selected by the certificate's key
     * Network work, runs on [Dispatchers.IO].
     */
    suspend fun complete(state: ByteArray, signature: ByteArray, options: CompleteOptions = CompleteOptions()): Completed =
        withContext(Dispatchers.IO) { guard { Pades.complete(state, signature, options) } }

    private inline fun <T> guard(f: () -> T): T = try {
        f()
    } catch (e: EidPadesException) {
        throw e
    } catch (e: Exception) {
        throw EidPadesException.Internal(e.message ?: e.javaClass.simpleName)
    }
}
