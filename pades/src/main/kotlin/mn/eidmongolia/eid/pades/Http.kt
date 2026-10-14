package mn.eidmongolia.eid.pades

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

/**
 * HTTP for TSA / OCSP / CRL (complete). Injectable (sandbox, proxy, tests) — Go `CompleteOptions.HTTPClient`,
 * iOS `EidPadesTransport`.
 * Must return the body of a 200 response and throw otherwise.
 */
fun interface EidPadesTransport {
    @Throws(IOException::class)
    fun send(method: String, url: String, contentType: String?, body: ByteArray?): ByteArray
}

/** Go fetch.go defaultHTTPClient: 10 s timeout, no redirects, 200 only, ≤ 4 MiB. */
internal object DefaultHttp : EidPadesTransport {
    private const val TIMEOUT_MS = 10_000
    const val MAX_RESPONSE = 4 shl 20

    override fun send(method: String, url: String, contentType: String?, body: ByteArray?): ByteArray {
        val c = URL(url).openConnection() as HttpURLConnection
        try {
            c.instanceFollowRedirects = false
            c.connectTimeout = TIMEOUT_MS
            c.readTimeout = TIMEOUT_MS
            c.requestMethod = method
            contentType?.let { c.setRequestProperty("Content-Type", it) }
            if (body != null) {
                c.doOutput = true
                c.setFixedLengthStreamingMode(body.size)
                c.outputStream.use { it.write(body) }
            }
            val code = c.responseCode
            if (code != 200) throw IOException("$url: HTTP $code")
            val out = ByteArrayOutputStream()
            c.inputStream.use { inp ->
                val buf = ByteArray(16 shl 10)
                while (true) {
                    val n = inp.read(buf)
                    if (n < 0) break
                    out.write(buf, 0, n)
                    if (out.size() > MAX_RESPONSE) throw IOException("$url: response larger than 4 MiB")
                }
            }
            return out.toByteArray()
        } finally {
            c.disconnect()
        }
    }
}

/** Go fetcher: http/https only, national CRLs via the eID mirror (WIRE.md §3), GET responses cached per complete(). */
internal class Fetcher(private val client: EidPadesTransport) {
    private val cache = HashMap<String, ByteArray>()

    fun get(raw: String): ByteArray {
        val url = target(raw)
        cache[url]?.let { return it }
        return client.send("GET", url, null, null).also { checkSize(it); cache[url] = it }
    }

    fun post(raw: String, contentType: String, body: ByteArray): ByteArray {
        val url = target(raw)
        return client.send("POST", url, contentType, body).also(::checkSize)
    }

    private fun target(raw: String): String {
        CRL_MIRROR[raw]?.let { return it }
        checkScheme(raw)
        return raw
    }

    companion object {
        /** National CRLs (http-only, not ours) → eID https mirror; the CRL signature is checked against its issuer. */
        val CRL_MIRROR = mapOf(
            "http://esign.gov.mn/MNICA-2022.crl" to "https://crl.eidmongolia.mn/MNICA-2022.crl",
            "http://esign.gov.mn/MNRCA-2021.crl" to "https://crl.eidmongolia.mn/MNRCA-2021.crl",
        )
    }

    private fun checkScheme(url: String) {
        val scheme = url.substringBefore(':', "").lowercase()
        if (scheme != "http" && scheme != "https") throw IOException("URL scheme \"$scheme\" not supported")
    }

    private fun checkSize(b: ByteArray) {
        if (b.size > DefaultHttp.MAX_RESPONSE) throw IOException("response larger than 4 MiB")
    }
}
