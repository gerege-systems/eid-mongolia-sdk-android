package mn.eidmongolia.eid.pades

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * APPEARANCE_SPEC §6 input checks (REQUEST_INVALID before the PDF is parsed), the default sizes (§6.3) and the
 * registration images (§6.6) — Go `TestAppearanceImageInput`. Byte identity is in [GoldenTest] (golden v10 img-*).
 */
class AppearanceImageTest {
    private val cases = JSONObject(String(Golden.file("manifest.json"), Charsets.UTF_8)).getJSONArray("cases")
    private fun appearance(case: String): JSONObject =
        (0 until cases.length()).map { cases.getJSONObject(it) }.single { it.getString("name") == case }
            .getJSONObject("prepare").getJSONObject("appearance")

    private fun image(o: JSONObject): PdfImage {
        val c = o.getJSONArray("color")
        return PdfImage(o.getInt("width"), o.getInt("height"), IntArray(3) { c.getInt(it) }, Base64Std.decode(o.getString("alpha")), o.getString("sha256"))
    }

    private fun sig() = image(appearance("img-signature-stamp").getJSONObject("signatureImage"))
    private fun stamp() = image(appearance("img-signature-stamp").getJSONObject("stampImage"))
    private fun mod(width: Int? = null, height: Int? = null, color: IntArray? = null, alpha: ByteArray? = null, sha256: String? = null): PdfImage {
        val s = sig()
        return PdfImage(width ?: s.width, height ?: s.height, color ?: s.color, alpha ?: s.alpha, sha256 ?: s.sha256)
    }

    /** Go `fdictAlpha`: the same stream with FDICT set and DICTID 1 (empty dictionary) — §6.1 rejects it. */
    private fun fdictAlpha(z: ByteArray): ByteArray {
        val cmf = z[0].toInt() and 0xFF
        var flg = 0xC0 or 0x20
        flg = flg or ((31 - (cmf * 256 + flg) % 31) % 31)
        return byteArrayOf(cmf.toByte(), flg.toByte(), 0, 0, 0, 1) + z.copyOfRange(2, z.size)
    }

    @Test
    fun inputErrors() {
        val doc = Golden.file("input/quartz-pdf13.pdf")
        val s = sig()
        val bad = mapOf(
            "sha256 upper" to mod(sha256 = s.sha256.uppercase()),
            "sha256 short" to mod(sha256 = s.sha256.substring(0, 63)),
            "colour 256" to mod(color = intArrayOf(18, 256, 110)),
            "colour negative" to mod(color = intArrayOf(-1, 32, 110)),
            "width 1601" to mod(width = 1601),
            "height 0" to mod(height = 0),
            "alpha empty" to mod(alpha = ByteArray(0)),
            "alpha not zlib" to mod(alpha = "not zlib".toByteArray()),
            "alpha extra bytes" to mod(height = s.height - 1),
            "alpha short" to image(appearance("img-bad-alpha").getJSONObject("signatureImage")),
            "alpha trailing" to mod(alpha = s.alpha + byteArrayOf(0)),
            "alpha > 300 KiB" to mod(alpha = ByteArray((300 shl 10) + 1)),
            "alpha FDICT 1" to mod(alpha = fdictAlpha(s.alpha)),
        )
        for ((name, im) in bad) {
            try {
                EidPades.suggestPlacement(doc, SignatureAppearance(x = 36.0, y = 36.0, signatureImage = im))
                fail("$name: expected REQUEST_INVALID")
            } catch (x: EidPadesException) {
                assertEquals(name, "REQUEST_INVALID", x.code)
            }
        }
        for ((a, wh) in listOf(
            SignatureAppearance(x = 36.0, y = 36.0) to (220.0 to 64.0),
            SignatureAppearance(x = 36.0, y = 36.0, signatureImage = sig()) to (220.0 to 110.0),
            SignatureAppearance(x = 36.0, y = 36.0, stampImage = stamp()) to (240.0 to 147.5),
            SignatureAppearance(x = 36.0, y = 36.0, signatureImage = sig(), stampImage = stamp()) to (240.0 to 147.5),
            SignatureAppearance(x = 36.0, y = 36.0, width = 300.0, height = 180.0, stampImage = stamp()) to (300.0 to 180.0),
        )) {
            val r = EidPades.suggestPlacement(doc, a)
            assertEquals(wh, r.width to r.height)
        }
    }

    @Test
    fun registrationImages() {
        val s = sig()
        val t = stamp()
        fun completed(images: List<SignatureImage>, role: String?) = Completed(
            pdf = ByteArray(0), cms = byteArrayOf(1), docId = "d", outSha256 = "", inSha256 = "", hasPage = false, pageSha256 = null,
            signerCert = ByteArray(0), revIndex = 2, sigRevSha256 = "", priorCmsSha256 = emptyList(), priorRevisionSha256 = emptyList(),
            fileName = "a.pdf", claimedRole = role, images = images,
        )
        val j = completed(
            listOf(SignatureImage(SignatureImageKind.SIGNATURE, s.sha256), SignatureImage(SignatureImageKind.STAMP, t.sha256)), "x",
        ).registration(onBehalfOf = "NTRMN-1234567").toJson()
        assertTrue(j, j.contains("\"images\":[{\"kind\":\"signature\",\"sha256\":\"${s.sha256}\"},{\"kind\":\"stamp\",\"sha256\":\"${t.sha256}\"}]"))
        assertFalse(completed(emptyList(), null).registration().toJson().contains("\"images\""))
    }
}
