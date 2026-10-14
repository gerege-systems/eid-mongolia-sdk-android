package mn.eidmongolia.eid.pades

/**
 * PAGE_SPEC.md §7 QR — ISO/IEC 18004, byte mode, ECC M, versions 1–6 (smallest that fits), FIXED mask 0 (no penalty
 * selection, so every language produces the same matrix). Port of the Go reference `pades/internal/qr`.
 */
internal object Qr {
    private class Version(val ecPerBlock: Int, val blocks: Int, val dataPerBlock: Int, val align: IntArray)

    private val versions = arrayOf(
        Version(0, 0, 0, intArrayOf()),
        Version(10, 1, 16, intArrayOf()),
        Version(16, 1, 28, intArrayOf(6, 18)),
        Version(26, 1, 44, intArrayOf(6, 22)),
        Version(18, 2, 32, intArrayOf(6, 26)),
        Version(24, 2, 43, intArrayOf(6, 30)),
        Version(16, 4, 27, intArrayOf(6, 34)),
    )

    /** Matrix [row][col], true = dark; no quiet zone. */
    fun encode(data: ByteArray): Array<BooleanArray> {
        var ver = 0
        for (v in 1..6) {
            if (4 + 8 + 8 * data.size <= versions[v].blocks * versions[v].dataPerBlock * 8) { ver = v; break }
        }
        require(ver != 0) { "QR data too long (≤ 106 bytes)" }
        val vi = versions[ver]
        val total = vi.blocks * vi.dataPerBlock
        val bits = ArrayList<Boolean>()
        fun put(v: Int, n: Int) { for (i in n - 1 downTo 0) bits += (v shr i) and 1 == 1 }
        put(0b0100, 4)
        put(data.size, 8)
        for (b in data) put(b.toInt() and 0xff, 8)
        put(0, minOf(4, total * 8 - bits.size))
        while (bits.size % 8 != 0) bits += false
        val cw = ArrayList<Int>()
        for (i in bits.indices step 8) {
            var b = 0
            for (j in 0 until 8) if (bits[i + j]) b = b or (1 shl (7 - j))
            cw += b
        }
        var i = 0
        while (cw.size < total) { cw += if (i % 2 == 0) 0xEC else 0x11; i++ }
        val gen = rsGenerator(vi.ecPerBlock)
        val dataBlocks = (0 until vi.blocks).map { b -> cw.subList(b * vi.dataPerBlock, (b + 1) * vi.dataPerBlock).toIntArray() }
        val ecBlocks = dataBlocks.map { rsRemainder(it, gen) }
        val final = ArrayList<Int>()
        for (k in 0 until vi.dataPerBlock) for (b in 0 until vi.blocks) final += dataBlocks[b][k]
        for (k in 0 until vi.ecPerBlock) for (b in 0 until vi.blocks) final += ecBlocks[b][k]
        return place(ver, vi, final.toIntArray())
    }

    private fun place(ver: Int, vi: Version, final: IntArray): Array<BooleanArray> {
        val n = 17 + 4 * ver
        val m = Array(n) { BooleanArray(n) }
        val fn = Array(n) { BooleanArray(n) }
        fun set(r: Int, c: Int, dark: Boolean) { m[r][c] = dark; fn[r][c] = true }
        fun finder(r0: Int, c0: Int) {
            for (r in -1..7) for (c in -1..7) {
                val rr = r0 + r
                val cc = c0 + c
                if (rr < 0 || cc < 0 || rr >= n || cc >= n) continue
                val dark = r in 0..6 && c in 0..6 && (r == 0 || r == 6 || c == 0 || c == 6 || (r in 2..4 && c in 2..4))
                set(rr, cc, dark)
            }
        }
        finder(0, 0)
        finder(0, n - 7)
        finder(n - 7, 0)
        for (k in 8 until n - 8) {
            set(6, k, k % 2 == 0)
            set(k, 6, k % 2 == 0)
        }
        for (r in vi.align) for (c in vi.align) {
            if ((r < 9 && c < 9) || (r < 9 && c > n - 9) || (r > n - 9 && c < 9)) continue
            for (dr in -2..2) for (dc in -2..2) set(r + dr, c + dc, maxOf(Math.abs(dr), Math.abs(dc)) != 1)
        }
        val f = formatBits(0)
        fun fb(k: Int) = (f shr k) and 1 == 1
        for (k in 0..5) set(k, 8, fb(k))
        set(7, 8, fb(6))
        set(8, 8, fb(7))
        set(8, 7, fb(8))
        for (k in 9 until 15) set(8, 14 - k, fb(k))
        for (k in 0 until 8) set(8, n - 1 - k, fb(k))
        for (k in 8 until 15) set(n - 15 + k, 8, fb(k))
        set(n - 8, 8, true)
        var bit = 0
        var up = true
        var col = n - 1
        while (col > 0) {
            if (col == 6) col--
            for (k in 0 until n) {
                val r = if (up) n - 1 - k else k
                for (c in intArrayOf(col, col - 1)) {
                    if (fn[r][c]) continue
                    var dark = bit < final.size * 8 && (final[bit / 8] shr (7 - bit % 8)) and 1 == 1
                    bit++
                    if ((r + c) % 2 == 0) dark = !dark
                    m[r][c] = dark
                }
            }
            up = !up
            col -= 2
        }
        return m
    }

    private fun formatBits(data: Int): Int {
        var v = data shl 10
        for (k in 14 downTo 10) if ((v shr k) and 1 == 1) v = v xor (0x537 shl (k - 10))
        return ((data shl 10) or v) xor 0x5412
    }

    private val gfExp = IntArray(512)
    private val gfLog = IntArray(256)

    init {
        var x = 1
        for (k in 0 until 255) {
            gfExp[k] = x
            gfLog[x] = k
            x = x shl 1
            if (x and 0x100 != 0) x = x xor 0x11D
        }
        for (k in 255 until 512) gfExp[k] = gfExp[k - 255]
    }

    private fun gfMul(a: Int, b: Int) = if (a == 0 || b == 0) 0 else gfExp[gfLog[a] + gfLog[b]]

    private fun rsGenerator(n: Int): IntArray {
        var g = intArrayOf(1)
        for (k in 0 until n) {
            val next = IntArray(g.size + 1)
            for ((j, c) in g.withIndex()) {
                next[j] = next[j] xor c
                next[j + 1] = next[j + 1] xor gfMul(c, gfExp[k])
            }
            g = next
        }
        return g.copyOfRange(1, g.size)
    }

    private fun rsRemainder(data: IntArray, gen: IntArray): IntArray {
        val rem = IntArray(gen.size)
        for (d in data) {
            val f = d xor rem[0]
            System.arraycopy(rem, 1, rem, 0, rem.size - 1)
            rem[rem.size - 1] = 0
            for ((k, g) in gen.withIndex()) rem[k] = rem[k] xor gfMul(g, f)
        }
        return rem
    }
}
