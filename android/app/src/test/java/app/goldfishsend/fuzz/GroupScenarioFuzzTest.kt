package app.goldfishsend.fuzz

import com.code_intelligence.jazzer.api.FuzzedDataProvider
import com.code_intelligence.jazzer.junit.FuzzTest

/** [GroupScenario] driven by coverage-guided input instead of a seed (`-Pgf.fuzz`, see README.md, "Fuzzing"). */
class GroupScenarioFuzzTest {
    @FuzzTest(maxDuration = "60s")
    fun scenario(data: FuzzedDataProvider) {
        val seed = data.consumeInt(0, 7).toLong()
        val ops = List(data.consumeInt(1, 60)) {
            Op(data.consumeInt(0, 11), data.consumeInt(0, 255), data.consumeInt(0, 255), data.consumeInt(0, 255))
        }
        val f = GroupScenario(seed).run(ops) ?: return
        // Shrunk and printed like GroupStatefulTest's, to replay or paste into a regression test there.
        val small = GroupScenario.shrink(seed, ops, f, millis = 60_000)
        throw AssertionError("$f\nshrunk to: scenario(${seed}L, ${small.joinToString(", ", "listOf(", ")")})", f.cause)
    }
}
