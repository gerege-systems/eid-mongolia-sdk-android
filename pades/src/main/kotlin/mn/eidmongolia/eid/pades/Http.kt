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

/**
 * Go fetch.go defaultHTTPClient: 10 s TOTAL per request (connect + send + headers + body — Go `http.Client.Timeout`,
 * not a per-read idle timeout), no redirects, 200 only, ≤ 4 MiB. The exchange runs on a daemon worker and the caller
 * waits at most the deadline: a server trickling bytes cannot hold `complete` past it (`HttpURLConnection.disconnect`
 * alone does not reliably abort a blocked read, so the caller does not wait on it; the worker still ends at its own
 * read timeout).
 */
internal object DefaultHttp : EidPadesTransport {
    private const val TIMEOUT_MS = 10_000L
    const val MAX_RESPONSE = 4 shl 20

    private val workers = java.util.concurrent.Executors.newCachedThreadPool { r ->
        Thread(r, "eid-pades-http").apply { isDaemon = true }
    }

    override fun send(method: String, url: String, contentType: String?, body: ByteArray?): ByteArray =
        send(method, url, contentType, body, TIMEOUT_MS)

    /** [timeoutMs] — the whole request's deadline (tests use a short one). */
    internal fun send(method: String, url: String, contentType: String?, body: ByteArray?, timeoutMs: Long): ByteArray {
        val c = URL(url).openConnection() as HttpURLConnection
        val job = workers.submit(java.util.concurrent.Callable { exchange(c, method, url, contentType, body, timeoutMs) })
        try {
            return job.get(timeoutMs, java.util.concurrent.TimeUnit.MILLISECONDS)
        } catch (_: java.util.concurrent.TimeoutException) {
            job.cancel(true)
            c.disconnect()
            throw java.net.SocketTimeoutException("$url: timeout after $timeoutMs ms")
        } catch (e: java.util.concurrent.ExecutionException) {
            throw e.cause as? IOException ?: IOException("$url: ${e.cause}", e.cause)
        } catch (e: InterruptedException) {
            job.cancel(true)
            c.disconnect()
            Thread.currentThread().interrupt()
            throw java.io.InterruptedIOException("$url: interrupted").apply { initCause(e) }
        }
    }

    private fun exchange(c: HttpURLConnection, method: String, url: String, contentType: String?, body: ByteArray?, timeoutMs: Long): ByteArray {
        try {
            val t = timeoutMs.coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
            c.instanceFollowRedirects = false
            c.connectTimeout = t
            c.readTimeout = t
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
                    if (Thread.currentThread().isInterrupted) throw java.io.InterruptedIOException("$url: cancelled")
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
