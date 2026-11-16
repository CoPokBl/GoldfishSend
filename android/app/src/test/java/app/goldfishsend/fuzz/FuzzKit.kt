package app.goldfishsend.fuzz

import app.goldfishsend.proto.Content
import com.code_intelligence.jazzer.api.FuzzedDataProvider
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.IdentityKeyPair
import org.signal.libsignal.protocol.ecc.ECPrivateKey

/** Helpers shared by the fuzz harnesses. */
object FuzzKit {
    /** A deterministic identity, so runs (and roster hashes, which decide ties) reproduce. */
    fun identity(seed: Long): IdentityKeyPair {
        val bytes = ByteArray(32)
        java.util.Random(seed xor 0x5DEECE66DL).nextBytes(bytes)
        val priv = ECPrivateKey(bytes)
        return IdentityKeyPair(IdentityKey(priv.getPublicKey()), priv)
    }

    /** A string that survives a UTF-8 round trip unchanged (no lone surrogates). */
    fun FuzzedDataProvider.str(max: Int): String = String(consumeString(max).toByteArray(Charsets.UTF_8), Charsets.UTF_8)

    fun FuzzedDataProvider.strings(maxCount: Int, maxLen: Int): List<String> = List(consumeInt(0, maxCount)) { str(maxLen) }

    fun FuzzedDataProvider.optLong(): Long? = if (consumeBoolean()) consumeLong() else null

    fun FuzzedDataProvider.optBool(): Boolean? = if (consumeBoolean()) consumeBoolean() else null

    fun FuzzedDataProvider.optInt(): Int? = if (consumeBoolean()) consumeInt() else null

    /** Any [Content] value, with fuzzed fields. */
    fun FuzzedDataProvider.content(): Content = when (consumeInt(0, 15)) {
        0 -> Content.Hello(str(80), str(60), if (consumeBoolean()) str(80) else null, if (consumeBoolean()) str(60) else null)
        1 -> Content.Text(str(40), str(300), consumeLong(), optLong(), optBool(), optInt(), optInt())
        2 -> Content.Receipt(strings(8, 30), str(12))
        3 -> Content.Timer(consumeLong())
        4 -> Content.Delete(strings(8, 30))
        5 -> Content.Mailbox(str(80), str(60), if (consumeBoolean()) str(60) else null)
        6 -> Content.Chunk(str(30), consumeInt(), consumeInt(), str(300))
        7 -> Content.GText(str(50), str(40), str(300), consumeLong(), optLong(), optBool())
        8 -> Content.GReceipt(str(50), strings(8, 30), str(12))
        9 -> Content.GDelete(str(50), strings(8, 30))
        10 -> Content.GRoster(str(50), str(300), str(100))
        11 -> Content.GCard(str(50), str(300), str(100))
        12 -> Content.GSync(str(50), consumeLong())
        13 -> Content.GLeave(str(50))
        else -> Content.Text(str(20), str(20), consumeLong())
    }
}
