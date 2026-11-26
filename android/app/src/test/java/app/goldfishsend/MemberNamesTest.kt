package app.goldfishsend

import app.goldfishsend.proto.B64
import app.goldfishsend.proto.MemberNames
import app.goldfishsend.proto.MemberNames.Member
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.signal.libsignal.protocol.IdentityKeyPair

/** Self-chosen member names that could pass for someone else's are told apart (MemberNames). */
class MemberNamesTest {
    private fun id() = B64.enc(IdentityKeyPair.generate().publicKey.serialize())

    private val taken = listOf("Alice", "You", "Someone new")

    @Test
    fun lookalikesShareASkeleton() {
        val alice = MemberNames.skeleton("Alice")
        for (n in listOf("alice", "ALICE", "A lice", "Alicé", "Аlice", "Αlice", "AIice", "A1ice", "Ａｌｉｃｅ", "𝐀𝐥𝐢𝐜𝐞", "Alice!")) {
            assertEquals(n, alice, MemberNames.skeleton(n))
        }
        assertEquals(MemberNames.skeleton("You"), MemberNames.skeleton("Yоu"))
        assertEquals(MemberNames.skeleton("Martin"), MemberNames.skeleton("rnartin"))
        assertEquals(MemberNames.skeleton("Bob"), MemberNames.skeleton("B0b"))
        for (n in listOf("Alicia", "Bob", "Al", "Ilse")) {
            assertNotEquals(n, alice, MemberNames.skeleton(n))
        }
        // Names of symbols only are compared as they are.
        assertNotEquals(MemberNames.skeleton("🐟"), MemberNames.skeleton("🐠"))
    }

    @Test
    fun aNameLikeAContactsOrYouGetsASuffix() {
        val (m1, m2, m3, m4) = List(4) { id() }
        val shown = MemberNames.distinct(
            listOf(Member(m1, "Аlice", own = true), Member(m2, "YOU", own = true), Member(m3, "Sam", own = true), Member(m4, "Alice", own = false)),
            taken,
        )
        assertEquals("Аlice (${MemberNames.suffix(m1)})", shown[m1])
        assertEquals("YOU (${MemberNames.suffix(m2)})", shown[m2])
        assertEquals("Sam", shown[m3])
        // Your own name for a contact is yours: it never changes.
        assertEquals("Alice", shown[m4])
    }

    @Test
    fun membersWhoChoseTheSameNameAreBothToldApart() {
        val (a, b, c) = List(3) { id() }
        val shown = MemberNames.distinct(listOf(Member(a, "Sam", true), Member(b, "sam ", true), Member(c, "Dee", true)), taken)
        assertEquals("Sam (${MemberNames.suffix(a)})", shown[a])
        assertEquals("sam  (${MemberNames.suffix(b)})", shown[b])
        assertNotEquals(shown[a], shown[b])
        assertEquals("Dee", shown[c])
    }

    /** A name chosen to look like someone else's suffixed one is suffixed too. */
    @Test
    fun aNameLikeASuffixedOneIsSuffixedToo() {
        val (sam1, sam2, mal) = List(3) { id() }
        val fake = "Sam (${MemberNames.suffix(sam1)})"
        val shown = MemberNames.distinct(listOf(Member(sam1, "Sam", true), Member(sam2, "Sam", true), Member(mal, fake, true)), taken)
        assertEquals(fake, shown[sam1])
        assertEquals("$fake (${MemberNames.suffix(mal)})", shown[mal])
        assertEquals(3, shown.values.toSet().size)
    }

    @Test
    fun theSuffixIsShortAndStable() {
        val k = id()
        val s = MemberNames.suffix(k)
        assertEquals(6, s.length)
        assertEquals(s, MemberNames.suffix(k))
        assertTrue(s.all { it in "0123456789ABCDEFGHJKMNPQRSTVWXYZ" })
        assertNotEquals(s, MemberNames.suffix(id()))
    }
}
