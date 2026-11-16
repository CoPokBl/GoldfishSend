package app.goldfishsend.fuzz

import org.junit.Assert.fail
import org.junit.Test

/**
 * Random group scenarios ([GroupScenario]), seeded so a failure reproduces. CI runs a few seeds; for a longer run:
 * `-Pgf.groupFuzz.minutes=10` (or `.seeds=N`, `.start=S`), see README.md, "Fuzzing". A failing seed is shrunk and printed
 * as a step list to paste into a regression test below.
 */
class GroupStatefulTest {
    private fun prop(name: String): String? = System.getProperty("gf.groupFuzz.$name")?.takeIf { it.isNotBlank() }

    @Test
    fun randomScenarios() {
        val start = prop("start")?.toLong() ?: 1L
        val minutes = prop("minutes")?.toDouble()
        val seeds = prop("seeds")?.toLong() ?: if (minutes != null) Long.MAX_VALUE else 150L
        val deadline = minutes?.let { System.currentTimeMillis() + (it * 60_000).toLong() } ?: Long.MAX_VALUE
        var seed = start
        while (seed - start < seeds && System.currentTimeMillis() < deadline) {
            val ops = GroupScenario.generate(seed, length(seed))
            val t0 = System.currentTimeMillis()
            val f = GroupScenario(seed).run(ops)
            if (System.currentTimeMillis() - t0 > 5000) {
                println("group scenarios: seed $seed took ${System.currentTimeMillis() - t0} ms")
            }
            if ((seed - start) % 100 == 99L) {
                println("group scenarios: ${seed - start + 1} seeds from $start passed")
            }
            if (f != null) {
                if (prop("noshrink") != null) {
                    fail("seed $seed: $f")
                }
                val small = GroupScenario.shrink(seed, ops, f)
                val again = GroupScenario(seed).run(small) ?: f
                fail("seed $seed: $again\nshrunk to: scenario(${seed}L, ${small.joinToString(", ", "listOf(", ")")})")
            }
            seed++
        }
        println("group scenarios: ${seed - start} seeds from $start passed")
    }

    /** `-Dgf.groupFuzz.replay="5; Op(8, 51, 72, 0), Op(9, 0, 0, 0)"` runs one scenario with the engine's decisions printed. */
    @Test
    fun replay() {
        val spec = prop("replay") ?: return
        val ops = Regex("""Op\((-?\d+), (-?\d+), (-?\d+), (-?\d+)\)""").findAll(spec).map { m ->
            m.groupValues.drop(1).map { it.toInt() }.let { Op(it[0], it[1], it[2], it[3]) }
        }.toList()
        val seed = spec.substringBefore(';').trim().toLong()
        GroupScenario.debug = true
        app.goldfishsend.group.GroupEngine.debugLog = { println("    $it") }
        try {
            // Just a seed: the scenario randomScenarios generates for it.
            scenario(seed, ops.ifEmpty { GroupScenario.generate(seed, length(seed)).also { println("ops: ${it.joinToString(", ")}") } })
        } finally {
            GroupScenario.debug = false
            app.goldfishsend.group.GroupEngine.debugLog = null
        }
    }

    // ---------- found by randomScenarios, shrunk (see GroupFindingsTest for some of them written out) ----------
    //
    // Most of these were found under the earlier design, with admins and a fork rule (docs/groups-redesign.md), and say
    // what went wrong then. The steps mean the same under the owner design (role changes are ownership transfers now),
    // so each still runs, as a scenario its fix has to keep working.

    /** Bob joined before Alice's card reached him: his card went to no one, so nobody could write to him. */
    @Test
    fun joinBeforeTheInvitersCard() = scenario(5L, listOf(Op(8, 0, 0, 0), Op(9, 0, 0, 0), Op(8, 121, 90, 0), Op(0, 41, 0, 0)))

    /** Alice moved inbox while Bob had no card yet: Bob kept her old card (its inbox is deleted after 15 days). */
    @Test
    fun rotatedCardNeverReachesANewcomer() = scenario(5L, listOf(Op(8, 51, 72, 0), Op(9, 0, 0, 0), Op(6, 0, 0, 0), Op(2, 0, 8, 0), Op(0, 41, 0, 0), Op(8, 0, 166, 0)))

    /** Bob and Mallory joined at about the same time; Alice passed Bob's card on before Mallory's arrived. */
    @Test
    fun concurrentJoinersNeverGetEachOthersCards() =
        scenario(86L, listOf(Op(8, 0, 0, 0), Op(8, 119, 242, 0), Op(0, 159, 0, 0), Op(10, 0, 41, 0), Op(0, 6, 0, 0), Op(8, 69, 179, 249), Op(7, 169, 0, 0)))

    /** Dave's acceptance was relayed before Alice had Bob's card, so Bob never got it and stayed a version behind. */
    @Test
    fun rosterRelayedBeforeANewcomersCard() = scenario(
        86L,
        listOf(Op(8, 0, 0, 0), Op(8, 119, 242, 0), Op(0, 6, 0, 0), Op(8, 69, 179, 0), Op(8, 52, 0, 0), Op(8, 0, 0, 0), Op(2, 0, 153, 0), Op(8, 223, 48, 55), Op(0, 73, 0, 0), Op(8, 163, 0, 0)),
    )

    /** Bob's acceptance was taken in, then that roster lost to a concurrent one without it: Bob was "in" but still invited. */
    @Test
    fun lostAcceptanceAfterItsRosterLost() = scenario(
        140L,
        listOf(
            Op(8, 76, 153, 0), Op(0, 0, 0, 0), Op(8, 0, 0, 0), Op(0, 0, 0, 0), Op(10, 0, 0, 0), Op(8, 0, 0, 0), Op(2, 0, 0, 0), Op(10, 0, 0, 0),
            Op(8, 0, 0, 0), Op(3, 0, 0, 0), Op(10, 0, 0, 0), Op(9, 0, 0, 0), Op(3, 0, 79, 0), Op(8, 0, 0, 0), Op(10, 0, 0, 0), Op(3, 0, 0, 0),
            Op(8, 0, 0, 0), Op(8, 0, 0, 0), Op(0, 0, 0, 0), Op(0, 56, 0, 0), Op(2, 0, 9, 0), Op(8, 54, 42, 0), Op(0, 54, 0, 0),
        ),
    )

    /** Dave missed Carol's acceptance; her later departure, passed on by Alice, skipped a version and was dropped for good. */
    @Test
    fun skippedNonAdminRosterFromAnAdmin() = scenario(
        149L,
        listOf(
            Op(8, 111, 172, 65), Op(2, 0, 133, 0), Op(8, 222, 0, 0), Op(0, 203, 0, 0), Op(8, 33, 54, 0), Op(8, 0, 37, 0), Op(8, 161, 131, 195),
            Op(8, 0, 0, 0), Op(8, 118, 0, 0), Op(5, 0, 0, 0), Op(8, 49, 241, 0), Op(10, 0, 0, 0), Op(1, 169, 0, 0), Op(7, 253, 0, 0),
            Op(8, 122, 152, 59), Op(10, 0, 0, 0), Op(8, 252, 114, 179), Op(2, 0, 87, 0), Op(8, 203, 154, 0), Op(8, 177, 22, 0), Op(8, 25, 49, 164),
            Op(0, 57, 0, 0), Op(7, 253, 0, 0), Op(8, 140, 227, 0), Op(9, 0, 0, 0), Op(1, 182, 0, 0), Op(10, 0, 0, 0), Op(10, 0, 0, 0),
            Op(8, 1, 254, 0), Op(8, 137, 20, 0),
        ),
    )

    /** Alice dropped Carol's roster as too old; Bob built on it, so Alice couldn't check his and the group split for good. */
    @Test
    fun childOfAnIgnoredOldRoster() = scenario(
        225L,
        listOf(
            Op(2, 0, 252, 0), Op(2, 0, 0, 0), Op(6, 0, 0, 0), Op(8, 0, 0, 0), Op(6, 0, 0, 0), Op(10, 0, 0, 0), Op(7, 0, 0, 0), Op(8, 0, 0, 0),
            Op(8, 0, 0, 0), Op(3, 0, 0, 0), Op(8, 0, 0, 0), Op(5, 248, 0, 0), Op(2, 7, 0, 0), Op(4, 0, 0, 0), Op(8, 0, 0, 0), Op(8, 110, 0, 0),
            Op(10, 2, 0, 0), Op(0, 134, 0, 0), Op(8, 0, 0, 0), Op(6, 0, 0, 0), Op(9, 0, 0, 0), Op(3, 36, 0, 0), Op(3, 21, 0, 0), Op(0, 0, 0, 0),
            Op(5, 0, 0, 159), Op(8, 0, 0, 0), Op(6, 0, 0, 0), Op(6, 0, 0, 0), Op(10, 0, 0, 0), Op(3, 48, 0, 0), Op(0, 7, 0, 0), Op(10, 0, 0, 0),
            Op(1, 0, 0, 0), Op(3, 0, 0, 0), Op(0, 201, 0, 0), Op(6, 0, 0, 0),
        ),
    )

    /**
     * Found by GroupScenarioFuzzTest: Alice added Carol, then admitted Bob (his acceptance had lost a tie), which replaced
     * her pending change. Bob's departure then won a tie against both, and Carol's invitation was lost for good.
     */
    @Test
    fun ownChangeReplacedByAnAdmit() =
        scenario(6L, listOf(Op(11, 0, 0, 0), Op(0, 81, 0, 0), Op(4, 0, 0, 0), Op(1, 181, 0, 0), Op(0, 0, 0, 0), Op(8, 0, 10, 0), Op(8, 0, 16, 0), Op(2, 0, 2, 0)))

    /** Found by GroupScenarioFuzzTest: Bob's departure was taken, then lost a tie to Mallory's acceptance, and Bob stayed in. */
    @Test
    fun departureReplacedByAConcurrentAcceptance() =
        scenario(3L, listOf(Op(11, 0, 0, 0), Op(0, 81, 0, 0), Op(11, 0, 0, 0), Op(1, 181, 0, 0), Op(0, 179, 0, 0)))

    /**
     * Found by GroupScenarioFuzzTest: Alice withdrew Dave's invitation, but at Dave it lost a tie to Mallory's concurrent
     * acceptance. Alice had moved on, and nothing after it reaches someone who's out: Dave stayed invited for good.
     */
    @Test
    fun removalLostATieAtTheRemoved() = scenario(
        2L,
        listOf(Op(2, 0, 148, 0), Op(7, 0, 0, 0), Op(8, 0, 0, 0), Op(8, 0, 0, 0), Op(3, 0, 0, 0), Op(0, 94, 0, 0), Op(8, 0, 20, 0), Op(3, 0, 8, 0), Op(5, 0, 0, 0)),
    )

    /** Found by GroupScenarioFuzzTest: Carol took her removal, then Bob's concurrent departure (which still listed her) beat it. */
    @Test
    fun removalReplacedByASiblingThatListsTheRemoved() =
        scenario(2L, listOf(Op(2, 0, 212, 0), Op(4, 0, 0, 0), Op(8, 2, 0, 0), Op(3, 0, 67, 0), Op(0, 0, 0, 0), Op(1, 91, 0, 0), Op(5, 0, 0, 0)))

    /** Found by GroupScenarioFuzzTest: Dave declined; a concurrent roster that still listed him invited won, and re-invited him. */
    @Test
    fun declineReplacedByASiblingThatStillInvites() = scenario(
        5L,
        listOf(Op(2, 0, 0, 0), Op(2, 0, 0, 0), Op(2, 0, 13, 0), Op(1, 0, 0, 0), Op(8, 100, 200, 0), Op(0, 0, 0, 0), Op(2, 0, 17, 0), Op(1, 13, 0, 0), Op(1, 64, 0, 0)),
    )

    /** Found by GroupScenarioFuzzTest: Bob's decline was under the roster that lost a tie, one version down, and was lost. */
    @Test
    fun declineDeeperInALostBranch() = scenario(5L, listOf(Op(11, 0, 0, 0), Op(0, 94, 0, 0), Op(1, 101, 0, 0), Op(1, 94, 0, 0)))

    /** Found by GroupScenarioFuzzTest: Bob joined a withdrawn invitation, was invited again, and stayed "joined" but invited. */
    @Test
    fun joinedButStillInvited() =
        scenario(7L, listOf(Op(11, 0, 0, 0), Op(3, 0, 81, 0), Op(5, 0, 0, 0), Op(8, 0, 118, 51), Op(2, 0, 11, 0), Op(0, 71, 0, 0)))

    /** A roster a sync answer couldn't place made Mallory ask again, forever (a message storm). Seed 1341's steps. */
    @Test
    fun syncRequestLoop() = scenario(
        1341L,
        listOf(
            Op(0, 64, 94, 20), Op(8, 224, 7, 250), Op(8, 91, 162, 133), Op(10, 53, 35, 69), Op(11, 167, 158, 33),
            Op(6, 84, 94, 21), Op(10, 198, 43, 223), Op(8, 114, 98, 211), Op(7, 106, 79, 121), Op(4, 108, 114, 82),
            Op(3, 253, 237, 49), Op(7, 105, 89, 234), Op(8, 178, 111, 18), Op(2, 94, 35, 215), Op(1, 92, 50, 98),
            Op(6, 82, 55, 219), Op(8, 155, 89, 167), Op(8, 63, 32, 17), Op(1, 238, 67, 234), Op(4, 63, 97, 217),
            Op(2, 110, 177, 30), Op(7, 220, 18, 95), Op(7, 2, 0, 117), Op(0, 94, 245, 215), Op(10, 33, 120, 35),
            Op(8, 228, 242, 133), Op(7, 94, 232, 172), Op(10, 104, 145, 0), Op(7, 72, 34, 239), Op(8, 179, 34, 144),
            Op(4, 82, 2, 101), Op(8, 163, 190, 124), Op(0, 242, 199, 187), Op(10, 55, 63, 15), Op(5, 67, 114, 172),
            Op(7, 28, 120, 172), Op(10, 21, 212, 85), Op(10, 183, 220, 210), Op(8, 121, 168, 105), Op(6, 243, 175, 2),
            Op(2, 135, 211, 200), Op(8, 107, 139, 145), Op(8, 78, 123, 135), Op(11, 222, 203, 32), Op(3, 173, 42, 37),
            Op(8, 68, 232, 35), Op(3, 252, 148, 244), Op(0, 71, 115, 238), Op(2, 87, 235, 198), Op(8, 70, 140, 61),
            Op(3, 171, 246, 215), Op(8, 156, 61, 182), Op(6, 113, 21, 167), Op(10, 73, 31, 199), Op(1, 140, 163, 190),
            Op(7, 191, 250, 159), Op(2, 134, 224, 180), Op(7, 27, 236, 76), Op(7, 7, 138, 200), Op(7, 170, 188, 246),
            Op(6, 56, 250, 17), Op(0, 70, 166, 27), Op(0, 99, 78, 243), Op(9, 181, 218, 31), Op(9, 47, 189, 208),
            Op(1, 247, 85, 9), Op(2, 96, 146, 20), Op(8, 18, 139, 56), Op(8, 34, 216, 152), Op(6, 205, 136, 2),
            Op(9, 168, 218, 37),
        ),
    )

    /**
     * Bob renamed on top of his v5, which lost a tie to Alice's v5 that hadn't reached him yet. Alice couldn't take Bob's
     * v6 (it builds on the loser), and Bob found Alice's v5 too old: split until an admin's next change. (Also the
     * committed input built-on-a-sibling-that-lost.)
     */
    @Test
    fun builtOnASiblingThatLost() = scenario(
        0L,
        listOf(
            Op(5, 0, 254, 59), Op(8, 0, 0, 0), Op(8, 229, 229, 229), Op(0, 0, 0, 0), Op(5, 0, 0, 254), Op(0, 1, 0, 0), Op(2, 0, 0, 0),
            Op(8, 0, 136, 229), Op(1, 229, 0, 0), Op(1, 0, 0, 0), Op(0, 0, 0, 0), Op(10, 0, 0, 0), Op(5, 6, 0, 0),
        ),
    )

    /** The same split, the other way round (the committed input open-sibling-branch-2). */
    @Test
    fun openSiblingBranch2() = scenario(
        3L,
        listOf(Op(5, 0, 254, 59), Op(8, 0, 0, 0), Op(8, 229, 0, 0), Op(5, 0, 0, 0), Op(0, 1, 0, 0), Op(5, 6, 0, 0), Op(3, 0, 0, 0), Op(5, 236, 0, 118)),
    )

    /**
     * Seed 1226's steps. Bob, not an admin yet, saw Carol's departure before he could place it (he hadn't got what it
     * built on) and dropped it. Once he was an admin he admitted her from an older acceptance, and her departure was
     * never applied: Carol had left, but was a member for everyone else.
     */
    @Test
    fun seed1226LostDeparture() = scenario(
        1226L,
        listOf(
            Op(5, 183, 5, 118), Op(7, 197, 59, 141), Op(1, 100, 90, 157), Op(9, 146, 137, 208), Op(8, 180, 234, 181),
            Op(2, 231, 81, 211), Op(8, 246, 214, 187), Op(7, 5, 155, 69), Op(7, 211, 38, 225), Op(7, 90, 222, 218),
            Op(10, 195, 171, 96), Op(5, 170, 219, 137), Op(8, 174, 170, 227), Op(8, 115, 46, 158), Op(2, 115, 202, 69),
            Op(8, 154, 90, 170), Op(8, 67, 92, 33), Op(8, 74, 177, 195), Op(8, 105, 219, 225), Op(0, 171, 236, 251),
            Op(8, 36, 200, 233), Op(8, 182, 76, 153), Op(7, 179, 81, 34), Op(8, 230, 58, 95), Op(8, 128, 247, 89),
            Op(0, 21, 233, 47), Op(7, 180, 103, 214), Op(7, 14, 27, 121), Op(5, 24, 245, 24), Op(10, 179, 105, 253),
            Op(0, 59, 172, 218), Op(2, 179, 115, 24), Op(7, 112, 221, 118), Op(6, 238, 79, 36), Op(0, 237, 3, 32),
            Op(5, 130, 16, 85), Op(4, 200, 96, 196), Op(6, 125, 190, 98), Op(1, 60, 76, 28), Op(10, 224, 61, 46),
            Op(9, 163, 35, 255), Op(0, 101, 155, 23), Op(8, 73, 19, 67), Op(8, 251, 254, 164), Op(2, 243, 105, 26),
            Op(8, 140, 245, 12), Op(7, 109, 241, 139), Op(1, 227, 58, 156), Op(10, 50, 234, 138), Op(0, 0, 16, 210),
            Op(5, 66, 143, 47), Op(8, 78, 72, 18), Op(0, 247, 198, 216), Op(9, 67, 156, 241), Op(8, 115, 106, 30),
            Op(0, 33, 137, 87),
        ),
    )

    /**
     * Found by GroupScenarioFuzzTest.forks: Bob left, then moved to the branch that won (which still listed him invited)
     * and took a roster on it as an invitation. Only a branch on which he was out can invite him again.
     */
    @Test
    fun leftThenInvitedByAStaleBranch() = scenario(
        5L,
        listOf(Op(11, 0, 0, 0), Op(2, 0, 252, 0), Op(12, 0, 0, 0), Op(0, 1, 0, 0), Op(5, 0, 0, 0), Op(8, 0, 85, 0), Op(1, 222, 0, 0), Op(1, 181, 0, 0), Op(8, 255, 255, 0)),
    )

    /**
     * Found by GroupScenarioFuzzTest.forks: Dave declined; Mallory's fork from before that, which still listed him invited,
     * won the tie at Dave, and the original invitation further down its line looked like a new one.
     */
    @Test
    fun declinedThenInvitedByAFork() =
        scenario(7L, listOf(Op(2, 0, 28, 0), Op(8, 45, 0, 0), Op(1, 28, 0, 0), Op(8, 0, 79, 0), Op(8, 0, 0, 0), Op(12, 51, 0, 0), Op(12, 0, 0, 0)))

    /**
     * Bob declined, was added again, and the roster re-adding him reached him with a gap before it: whether it was an
     * invitation couldn't be told then, and wasn't looked at again once the gap filled.
     */
    @Test
    fun reinvitationBehindAGap() = scenario(
        122L,
        listOf(Op(11, 0, 0, 0), Op(1, 151, 0, 0), Op(8, 29, 0, 0), Op(1, 184, 0, 0), Op(12, 0, 0, 0), Op(2, 0, 146, 0), Op(10, 13, 0, 25), Op(8, 230, 109, 0)),
    )

    /** Carol left; Mallory's fork from before won at Carol, and her original invitation down its line counted as a new one. */
    @Test
    fun leftThenInvitedByTheOriginalInvitation() = scenario(
        2740L,
        listOf(
            Op(8, 108, 41, 117), Op(2, 0, 47, 0), Op(8, 172, 0, 0), Op(0, 12, 0, 0), Op(10, 0, 0, 0), Op(7, 147, 0, 0), Op(12, 0, 0, 0),
            Op(1, 37, 0, 0), Op(12, 0, 36, 0), Op(8, 246, 10, 0),
        ),
    )

    /**
     * Found by GroupScenarioFuzzTest: Bob, removed, took his re-invitation past a gap and asked for the history, but the
     * answer went to his group inbox, which a member who's out doesn't read. (Also the input reinvited-while-out-past-a-gap.)
     */
    @Test
    fun reinvitedWhileOutPastAGap() =
        scenario(7L, listOf(Op(11, 0, 0, 0), Op(3, 0, 81, 0), Op(5, 0, 0, 0), Op(2, 0, 11, 0), Op(0, 71, 0, 0)))

    /** Found by GroupScenarioFuzzTest.forks (the input fork-split-2): Alice and Bob on different branches for good. */
    @Test
    fun forkSplit2() = scenario(
        7L,
        listOf(Op(3, 0, 44, 0), Op(5, 0, 44, 185), Op(8, 0, 63, 0), Op(2, 0, 42, 0), Op(5, 0, 0, 0), Op(0, 21, 0, 0), Op(5, 96, 0, 0), Op(5, 96, 0, 96), Op(5, 71, 0, 0)),
    )

    /**
     * Found by GroupScenarioFuzzTest.forks (input decline-after-the-inviter-left): Dave's decline reached only Alice, his
     * one contact in the group, after she had left; nobody else ever heard it.
     */
    @Test
    fun declineAfterTheInviterLeft() =
        scenario(7L, listOf(Op(2, 0, 28, 0), Op(8, 255, 0, 0), Op(0, 121, 0, 0), Op(11, 0, 0, 0), Op(4, 0, 186, 0), Op(1, 0, 0, 0), Op(1, 48, 0, 0)))

    /**
     * Found by GroupScenarioFuzzTest (input card-after-the-inviter-left): Mallory's first card reached only Alice, who had
     * left by then, so Bob and Mallory never got each other's cards.
     */
    @Test
    fun cardAfterTheInviterLeft() = scenario(
        0L,
        listOf(Op(11, 0, 0, 0), Op(0, 76, 0, 0), Op(11, 0, 0, 0), Op(0, 24, 0, 0), Op(8, 0, 0, 0), Op(4, 0, 11, 0), Op(1, 0, 0, 0), Op(7, 119, 0, 0)),
    )

    /**
     * Seed 2447's steps: Alice's stored session with Bob had no current state left to send with, so it counted as there
     * but every encryption to him failed (in the app: every outbox row to him, for good).
     */
    @Test
    fun sessionWithoutASendingState() = scenario(
        2447L,
        listOf(
            Op(10, 129, 198, 40), Op(0, 203, 166, 69), Op(7, 45, 62, 115), Op(8, 111, 223, 250), Op(9, 126, 7, 250),
            Op(7, 58, 217, 121), Op(12, 147, 21, 126), Op(8, 203, 133, 42), Op(10, 20, 158, 114),
            Op(10, 132, 220, 221), Op(8, 236, 159, 197), Op(9, 139, 47, 237), Op(2, 48, 244, 139),
            Op(12, 80, 210, 163), Op(8, 213, 20, 242), Op(8, 195, 95, 51), Op(10, 218, 254, 169), Op(8, 243, 144, 171),
            Op(9, 190, 178, 206), Op(12, 130, 139, 245), Op(5, 132, 93, 42), Op(10, 82, 184, 83), Op(7, 129, 100, 148),
            Op(8, 61, 22, 113), Op(7, 251, 158, 23), Op(2, 18, 225, 131), Op(2, 72, 118, 120), Op(10, 17, 89, 186),
            Op(5, 109, 22, 184), Op(8, 52, 164, 177), Op(3, 104, 89, 46), Op(8, 2, 61, 103), Op(2, 73, 49, 205),
            Op(7, 87, 167, 194), Op(8, 246, 240, 101), Op(0, 161, 14, 125), Op(10, 222, 41, 153), Op(2, 40, 248, 11),
            Op(7, 77, 6, 131), Op(8, 193, 128, 210), Op(5, 7, 108, 43), Op(0, 215, 76, 202), Op(8, 184, 203, 19),
            Op(0, 37, 33, 150), Op(7, 82, 65, 109), Op(2, 137, 254, 223), Op(2, 0, 139, 187), Op(7, 79, 165, 182),
            Op(8, 88, 98, 247), Op(8, 28, 214, 170), Op(7, 150, 243, 169), Op(0, 219, 195, 60), Op(8, 75, 160, 171),
            Op(3, 195, 252, 66), Op(7, 139, 157, 193), Op(6, 9, 157, 250), Op(7, 229, 196, 146), Op(8, 63, 158, 113),
            Op(10, 153, 177, 10), Op(0, 106, 226, 14), Op(8, 62, 68, 144), Op(1, 195, 44, 52), Op(1, 238, 211, 32),
            Op(10, 206, 32, 11), Op(8, 54, 127, 199), Op(0, 201, 51, 160), Op(1, 124, 189, 157), Op(8, 226, 254, 236),
            Op(10, 115, 155, 233), Op(7, 100, 47, 97), Op(10, 241, 37, 214), Op(3, 38, 84, 5), Op(3, 49, 48, 173),
            Op(8, 208, 239, 83), Op(10, 182, 217, 73), Op(4, 34, 75, 155), Op(8, 79, 93, 53),
        ),
    )

    /**
     * Found by GroupScenarioFuzzTest (input admins-remove-each-other): Alice and Bob, both admins, removed each other at
     * once. Each then dropped the other's roster unread (the sender wasn't in their roster any more), so neither learnt
     * which removal won.
     */
    @Test
    fun adminsRemoveEachOther() =
        scenario(0L, listOf(Op(11, 0, 0, 0), Op(0, 76, 0, 0), Op(8, 0, 0, 0), Op(4, 0, 11, 0), Op(11, 0, 0, 0), Op(3, 211, 0, 0), Op(3, 0, 16, 0)))

    /**
     * Seed 2549 (and the forks fuzzer, inputs last-admin-departure-lost*): Bob left before he heard Alice had made him an
     * admin, then Alice left. Bob's departure lost the fork, and the only admin who could apply it was Bob, whose inbox
     * was gone. The case that showed the fork rule couldn't be patched; now Bob's departure is a fact, and the next member
     * takes over.
     */
    @Test
    fun departureOfTheLastAdminLostAFork() = scenario(
        7L,
        listOf(Op(2, 0, 28, 0), Op(8, 255, 0, 0), Op(0, 121, 0, 0), Op(11, 0, 0, 0), Op(4, 0, 186, 0), Op(1, 0, 0, 0), Op(0, 98, 0, 0), Op(1, 106, 0, 0)),
    )

    /**
     * Bob removed Alice while she invited Dave. The removal won, and Dave, who only knows Alice, waited on an invitation
     * nobody else knew of: Alice tells him it's off.
     */
    @Test
    fun invitationLostToTheInvitersRemoval() =
        scenario(0L, listOf(Op(11, 0, 0, 0), Op(0, 76, 0, 0), Op(8, 0, 0, 0), Op(4, 0, 11, 0), Op(11, 0, 0, 0), Op(3, 56, 0, 0), Op(2, 0, 98, 0)))

    /** Seed 2549 itself, shrunk under the fork rule (Mallory's forks around the same departures). */
    @Test
    fun seed2549() = scenario(
        2549L,
        listOf(
            Op(2, 0, 138, 0), Op(11, 0, 0, 0), Op(12, 0, 0, 0), Op(8, 5, 0, 0), Op(12, 0, 0, 0), Op(8, 0, 0, 0), Op(12, 0, 0, 0),
            Op(0, 101, 0, 0), Op(12, 0, 0, 0), Op(8, 0, 18, 248), Op(8, 84, 230, 185), Op(4, 0, 201, 0), Op(0, 178, 0, 0),
            Op(1, 46, 0, 0), Op(1, 0, 0, 0),
        ),
    )

    /** The scenario fuzzer's last finding under the fork rule (input removed-but-still-a-member): Carol out, yet a member. */
    @Test
    fun removedButStillAMember() = scenario(
        1L,
        listOf(
            Op(2, 0, 98, 0), Op(8, 21, 94, 196), Op(0, 71, 0, 0), Op(3, 83, 0, 0), Op(0, 54, 0, 0), Op(0, 83, 0, 0), Op(2, 0, 102, 0),
            Op(5, 0, 0, 0), Op(8, 0, 200, 0), Op(8, 229, 229, 229), Op(5, 0, 0, 254), Op(10, 29, 0, 1), Op(9, 0, 0, 0),
            Op(8, 41, 125, 0), Op(8, 0, 136, 229), Op(11, 0, 0, 0), Op(0, 82, 0, 0), Op(4, 0, 38, 0),
        ),
    )

    // ---------- found under the owner design ----------

    /**
     * Found by GroupScenarioFuzzTest (input acceptance-the-new-owner-never-heard): Alice made Bob the owner while
     * Mallory joined; Mallory's acceptance reached only Alice. First-hand recipients now pass facts on to the owner.
     */
    @Test
    fun acceptanceTheNewOwnerNeverHeard() =
        scenario(0L, listOf(Op(11, 0, 0, 0), Op(0, 76, 0, 0), Op(8, 0, 75, 0), Op(4, 0, 11, 0), Op(0, 94, 0, 0)))

    /**
     * Found by GroupScenarioFuzzTest.forks (input newcomer-card-only-the-old-owner-had): Carol joined after Alice, the
     * owner, left; her card reached nobody who could pass it on. An acceptance now carries the newcomer's card.
     */
    @Test
    fun newcomerCardOnlyTheOldOwnerHad() =
        scenario(7L, listOf(Op(8, 255, 0, 0), Op(5, 0, 0, 0), Op(2, 0, 42, 0), Op(0, 166, 0, 0), Op(8, 255, 0, 0), Op(1, 0, 0, 0), Op(0, 42, 0, 0)))

    /** Seed 1108: Alice left right after inviting; her departure overtook the invitation (1:1 isn't ordered) and was dropped. */
    @Test
    fun departureThatOvertookTheInvitation() = scenario(1108L, listOf(Op(1, 0, 0, 0), Op(8, 169, 160, 0), Op(11, 0, 0, 0), Op(0, 101, 0, 0)))

    /**
     * Found by GroupScenarioFuzzTest (input reinvited-past-a-gap-after-the-owner-left): Carol, removed, was invited again
     * past a gap; she asked for what she'd missed, but the owner had left. A re-invitation is taken on its owner's word.
     */
    @Test
    fun reinvitedPastAGapAfterTheOwnerLeft() = scenario(
        0L,
        listOf(Op(8, 0, 0, 0), Op(2, 0, 212, 0), Op(8, 0, 255, 0), Op(3, 0, 67, 0), Op(0, 36, 0, 0), Op(8, 0, 83, 0), Op(2, 0, 102, 0), Op(1, 0, 0, 0)),
    )

    /**
     * Found by GroupScenarioFuzzTest.forks (input departure-held-only-by-the-old-owner): Dave passed Mallory's departure on
     * to Alice, the owner, who left; Bob took over without it. A new owner now gets the facts its members hold.
     */
    @Test
    fun departureHeldOnlyByTheOldOwner() = scenario(
        7L,
        listOf(Op(2, 0, 223, 0), Op(8, 71, 109, 0), Op(0, 31, 0, 0), Op(0, 78, 0, 0), Op(0, 74, 0, 0), Op(8, 138, 185, 0), Op(12, 0, 0, 0), Op(1, 0, 0, 0)),
    )

    /**
     * Seed 1236: Mallory, next in line, sent her departure only to some, and signed rosters as owner for the rest. An
     * invitee who heard it decided the group had nobody left to own it, and for good.
     */
    @Test
    fun selectiveDepartureOfTheNextOwner() = scenario(
        1236L,
        listOf(
            Op(8, 188, 0, 0), Op(0, 184, 0, 0), Op(8, 158, 149, 0), Op(8, 12, 0, 0), Op(8, 251, 163, 96), Op(12, 0, 0, 0), Op(9, 0, 0, 0),
            Op(1, 0, 0, 0), Op(8, 122, 181, 0), Op(2, 114, 43, 0), Op(0, 1, 0, 0),
        ),
    )

    /**
     * Found by GroupScenarioFuzzTest (input reinvitation-kept-from-a-departure): Carol kept Alice's re-invitation as a
     * roster beyond a gap (it came inside Alice's departure), and so ignored it when it came again as her invitation.
     */
    @Test
    fun reinvitationKeptFromADeparture() = scenario(
        2L,
        listOf(
            Op(2, 0, 238, 0), Op(2, 0, 212, 0), Op(8, 91, 128, 0), Op(8, 2, 49, 212), Op(3, 0, 67, 0), Op(0, 94, 0, 0), Op(8, 13, 13, 0),
            Op(8, 100, 0, 0), Op(2, 0, 22, 0), Op(1, 13, 0, 0), Op(1, 0, 0, 0), Op(9, 0, 0, 0), Op(8, 0, 31, 0), Op(0, 1, 0, 0),
        ),
    )

    /**
     * Seed 1367: Mallory, next in line once Alice left, sent a departure carrying an old roster and went on signing as the
     * owner: an owner equivocating. Members can't prevent that; the harness checks only safety then. (Before, a sync
     * request was also suppressed for a gap whose first ask had gone to someone else.)
     */
    @Test
    fun nextOwnerEquivocates() = scenario(
        1367L,
        listOf(
            Op(8, 43, 0, 0), Op(0, 204, 0, 0), Op(8, 59, 38, 0), Op(8, 27, 30, 70), Op(2, 0, 113, 0), Op(12, 0, 0, 0), Op(1, 0, 0, 0),
            Op(9, 0, 0, 0), Op(8, 209, 0, 0), Op(8, 0, 88, 0), Op(0, 253, 0, 0), Op(0, 11, 0, 0),
        ),
    )

    /** Found by GroupScenarioFuzzTest.forks (input departures-in-a-group-nobody-owns): members of a dead group disagreed. */
    @Test
    fun departuresInAGroupNobodyOwns() =
        scenario(7L, listOf(Op(2, 0, 223, 0), Op(8, 71, 109, 0), Op(0, 8, 0, 0), Op(0, 1, 0, 0), Op(12, 0, 0, 0), Op(1, 0, 0, 0)))

    /**
     * Found by GroupScenarioFuzzTest (input old-stints-card-kept): Carol joined an invitation already withdrawn, then
     * joined again when re-invited; Alice kept the first card (same `seq`) and wrote to its deleted inbox.
     */
    @Test
    fun oldStintsCardKept() =
        scenario(0L, listOf(Op(2, 0, 98, 0), Op(2, 0, 212, 0), Op(8, 2, 125, 0), Op(3, 0, 67, 0), Op(2, 0, 102, 0), Op(0, 82, 0, 0), Op(11, 0, 0, 0), Op(0, 82, 0, 0)))

    /**
     * Found by GroupScenarioFuzzTest.forks (input owner-whose-rosters-reached-nobody): Bob took over, signed two rosters
     * nobody could receive (he had no one's card yet), and left. His departure carried only the newest, so Dave could
     * never place it. A departure now carries the run of rosters its author signed.
     */
    @Test
    fun ownerWhoseRostersReachedNobody() = scenario(
        7L,
        listOf(
            Op(2, 0, 28, 0), Op(2, 0, 202, 0), Op(8, 255, 164, 0), Op(0, 16, 0, 0), Op(11, 0, 0, 0), Op(12, 0, 0, 109), Op(1, 0, 0, 0),
            Op(0, 138, 0, 0), Op(8, 138, 199, 0), Op(5, 66, 0, 0), Op(1, 31, 0, 0),
        ),
    )

    private fun length(seed: Long) = 30 + (seed % 50).toInt()

    private fun scenario(seed: Long, ops: List<Op>) {
        GroupScenario(seed).run(ops)?.let { fail(it.toString()) }
    }
}
