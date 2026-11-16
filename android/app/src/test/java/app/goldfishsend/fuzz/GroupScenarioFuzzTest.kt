package app.goldfishsend.fuzz

import com.code_intelligence.jazzer.api.FuzzedDataProvider
import com.code_intelligence.jazzer.junit.FuzzTest

/** [GroupScenario] driven by coverage-guided input instead of a seed (`-Pgf.fuzz`, see README.md, "Fuzzing"). */
class GroupScenarioFuzzTest {
    @FuzzTest(maxDuration = "60s")
    fun scenario(data: FuzzedDataProvider) = run(data, kinds = 11)

    /** The same, with Mallory's forks on older rosters (step kind 12) too. */
    @FuzzTest(maxDuration = "60s")
    fun forks(data: FuzzedDataProvider) = run(data, kinds = 12)

    private fun run(data: FuzzedDataProvider, kinds: Int) {
        val seed = data.consumeInt(0, 7).toLong()
        val ops = List(data.consumeInt(1, 60)) {
            Op(data.consumeInt(0, kinds), data.consumeInt(0, 255), data.consumeInt(0, 255), data.consumeInt(0, 255))
        }
        val f = GroupScenario(seed).run(ops) ?: return
        // Shrunk and printed like GroupStatefulTest's, to replay or paste into a regression test there.
        val small = GroupScenario.shrink(seed, ops, f, millis = 60_000)
        throw AssertionError("$f\nshrunk to: scenario(${seed}L, ${small.joinToString(", ", "listOf(", ")")})", f.cause)
    }
}
