package app.goldfishsend.proto

import java.text.Normalizer

/**
 * How group members are named where messages are read (docs/groups.md, "Names"). A member who isn't your contact shows
 * the name they chose themselves, so nothing stops them choosing a contact's name, another member's, or "You", or one
 * that only looks the same ("Аlice" with a Cyrillic А). Such a name gets a short suffix from the member's identity key,
 * so the two can be told apart. Android-free, so the JVM tests use exactly this code.
 */
object MemberNames {
    /**
     * One member to name: [name] is your own name for them (a contact, or "You") unless [own], when it's the name they
     * chose themselves.
     */
    class Member(val id: String, val name: String, val own: Boolean)

    /**
     * What to call each of [members] (by id). A self-chosen name that looks like one in [taken] (your contacts' names,
     * "You", the app's own placeholders) or like another member's, as chosen or as shown, gets [suffix]. Names that
     * aren't self-chosen are yours, and stay as they are.
     */
    fun distinct(members: List<Member>, taken: Collection<String>): Map<String, String> {
        val fixed = (taken + members.filter { !it.own }.map { it.name }).map(::skeleton).toSet()
        val base = members.associate { it.id to skeleton(it.name) }
        val shown = members.associate { it.id to it.name }.toMutableMap()
        val shownSk = base.toMutableMap()
        // Each round only adds suffixes (a suffixed name can look like someone's chosen one: "Bob (K7Q2XM)"), so it ends.
        var changed = true
        while (changed) {
            changed = false
            for (m in members) {
                if (!m.own || shown[m.id] != m.name) {
                    continue
                }
                val sk = base.getValue(m.id)
                val clash = sk in fixed || members.any { o -> o.id != m.id && (base[o.id] == sk || shownSk[o.id] == sk) }
                if (clash) {
                    shown[m.id] = "${m.name} (${suffix(m.id)})"
                    shownSk[m.id] = skeleton(shown.getValue(m.id))
                    changed = true
                }
            }
        }
        return shown
    }

    /** Six characters (30 bits) of SHA-256 over the member's identity key, in Crockford's base32 (no I, L, O or U). */
    fun suffix(id: String): String {
        val raw = runCatching { B64.dec(id) }.getOrNull() ?: id.toByteArray(Charsets.UTF_8)
        val h = Hash.sha256(raw)
        var bits = 0L
        for (i in 0 until 4) {
            bits = (bits shl 8) or (h[i].toLong() and 0xff)
        }
        return (0 until 6).map { i -> CROCKFORD[((bits shr (32 - 5 * (i + 1))) and 31).toInt()] }.joinToString("")
    }

    private const val CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

    /**
     * What a name looks like, for telling whether two names could be taken for each other: compatibility forms folded
     * (fullwidth, mathematical letters), accents dropped, case ignored, common look-alikes from other scripts mapped to the
     * Latin letter they pass for (Cyrillic and Greek), "I", "l", "1" and "|" taken as one letter, "0" as "o", "rn" as "m",
     * and spaces and punctuation ignored. Not the full Unicode confusables table: it covers what a name is likely to use.
     */
    fun skeleton(name: String): String {
        val decomposed = Normalizer.normalize(name, Normalizer.Form.NFKD)
        val sb = StringBuilder()
        var i = 0
        while (i < decomposed.length) {
            val cp = decomposed.codePointAt(i)
            i += Character.charCount(cp)
            val type = Character.getType(cp)
            if (type == Character.NON_SPACING_MARK.toInt() || type == Character.ENCLOSING_MARK.toInt() || type == Character.COMBINING_SPACING_MARK.toInt()) {
                continue
            }
            val mapped = LOOKALIKES[cp] ?: String(Character.toChars(Character.toLowerCase(cp)))
            for (c in mapped) {
                when {
                    c == 'i' || c == '1' || c == '|' -> sb.append('l')
                    c == '0' -> sb.append('o')
                    Character.isLetterOrDigit(c) -> sb.append(c)
                }
            }
        }
        val out = sb.toString().replace("rn", "m").replace("vv", "w")
        // A name of symbols only (emoji, say) is compared as it is.
        return out.ifEmpty { name.lowercase().filterNot { it.isWhitespace() } }
    }

    /** Letters from other scripts that pass for Latin ones, upper and lower case, as they look. */
    private val LOOKALIKES: Map<Int, String> = buildMap {
        fun add(from: String, to: String) {
            require(from.length == to.length)
            for (k in from.indices) {
                put(from[k].code, to[k].toString())
            }
        }
        // Cyrillic.
        add("АВЕКМНОРСТУХЅІЈԚԜҮӀ", "abekmhopctyxsljqwyl")
        add("авекмнорстухѕіјһԁԛԝӏүьпг", "abekmhopctyxsljhdqwlybnr")
        // Greek.
        add("ΑΒΕΖΗΙΚΜΝΟΡΤΥΧ", "abezhlkmnoptyx")
        add("αβγεηικμνοπρτυχω", "abyenlkuvonptuxw")
        // Latin letters that pass for others.
        add("ıɩłøđħɡʏɑ", "lllodhgya")
    }
}
