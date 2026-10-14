package mn.eidmongolia.eid.pades

/** Vendored golden vectors (classpath `/golden/…`) — works for JVM unit tests and on-device instrumented runs. */
internal object Golden {
    fun file(name: String): ByteArray =
        Golden::class.java.getResourceAsStream("/golden/$name")?.use { it.readBytes() } ?: error("golden/$name missing")

    fun pem(name: String): ByteArray = Cert.pemBlocks(String(file(name), Charsets.US_ASCII)).single()
}
