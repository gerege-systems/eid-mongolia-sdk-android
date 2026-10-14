package mn.eidmongolia.eid.pades

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * eID client-side PAdES — the PDF never reaches an eID server (docs/PADES_CLIENT_SIDE.md). Native Kotlin
 * implementation of the signing path, byte-identical to the Go reference (`eid-mongolia-sdk-go/pades`, profile
 * `pades-client/1`) on the shared golden vectors; iOS `GeregeEIDPDF.EidPades` 1:1.
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
