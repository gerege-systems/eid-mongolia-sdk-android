package mn.eidmongolia.eid.pades

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.net.ServerSocket
import java.net.SocketTimeoutException
import kotlin.concurrent.thread

/** DefaultHttp: the timeout is a total deadline (Go `http.Client.Timeout`), not a per-read idle timeout. */
class HttpDeadlineTest {
    /** Serves one connection: headers, then [body] one byte every [gapMs]. */
    private fun trickle(body: ByteArray, gapMs: Long): ServerSocket {
        val ss = ServerSocket(0)
        thread(isDaemon = true) {
            try {
                ss.accept().use { s ->
                    val inp = s.getInputStream().bufferedReader()
                    while (inp.readLine()?.isNotEmpty() == true) Unit
                    val out = s.getOutputStream()
                    out.write("HTTP/1.1 200 OK\r\nContent-Length: ${body.size}\r\nConnection: close\r\n\r\n".toByteArray())
                    out.flush()
                    for (b in body) {
                        Thread.sleep(gapMs)
                        out.write(b.toInt())
                        out.flush()
                    }
                }
            } catch (_: Exception) {
            }
        }
        return ss
    }

    @Test
    fun tricklingServerHitsTotalDeadline() {
        // Each byte arrives well inside the read timeout, but the whole body takes ~4 s > 1 s deadline.
        trickle(ByteArray(20) { 'x'.code.toByte() }, 200).use { ss ->
            val t0 = System.nanoTime()
            try {
                DefaultHttp.send("GET", "http://127.0.0.1:${ss.localPort}/", null, null, 1_000)
                fail("expected a timeout")
            } catch (_: SocketTimeoutException) {
            }
            val ms = (System.nanoTime() - t0) / 1_000_000
            assertTrue("took $ms ms", ms in 900L..2_500L)
        }
    }

    @Test
    fun fastServerWithinDeadline() {
        val body = "ok".toByteArray()
        trickle(body, 1).use { ss ->
            assertArrayEquals(body, DefaultHttp.send("GET", "http://127.0.0.1:${ss.localPort}/", null, null, 5_000))
        }
    }
}
