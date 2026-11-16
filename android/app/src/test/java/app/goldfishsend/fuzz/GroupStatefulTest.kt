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
            scenario(seed, ops.ifEmpty { GroupScenario.generate(seed, length(seed)) })
        } finally {
            GroupScenario.debug = false
            app.goldfishsend.group.GroupEngine.debugLog = null
        }
    }

    // ---------- found by randomScenarios, shrunk (see GroupFindingsTest for some of them written out) ----------

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

    private fun length(seed: Long) = 30 + (seed % 50).toInt()

    private fun scenario(seed: Long, ops: List<Op>) {
        GroupScenario(seed).run(ops)?.let { fail(it.toString()) }
    }
}
