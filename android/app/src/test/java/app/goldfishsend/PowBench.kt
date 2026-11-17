package app.goldfishsend

import app.goldfishsend.proto.Pow
import app.goldfishsend.proto.Rand
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking

/**
 * Argon2id (t = 1, p = 1) timings with the solver's own code path: per call on one thread, and throughput on as many
 * threads as [Pow.threadsFor] allows. The same code is in androidTest (PowBenchmarkDeviceTest).
 */
object PowBench {
    fun run(sizesMiB: List<Int> = listOf(8, 16, 32), calls: Int = 20): List<String> {
        val ch = Rand.bytes(32)
        return sizesMiB.map { mib ->
            val m = mib * 1024
            // 256 leading zero bits never happen, so the search runs until stopped.
            val never = Pow.Params(256, m, 1)
            var n = 0
            Pow.solveRange(ch, never, 0, 1, { n++ }) { n >= 3 }
            val times = LongArray(calls)
            n = 0
            var last = System.nanoTime()
            Pow.solveRange(ch, never, 0, 1, {
                val now = System.nanoTime()
                times[n] = now - last
                last = now
                n++
            }) { n >= calls }
            times.sort()
            val median = times[calls / 2] / 1e6

            val threads = Pow.threadsFor(m)
            val done = AtomicLong()
            val total = calls * threads
            val t0 = System.nanoTime()
            runBlocking {
                coroutineScope {
                    (0 until threads).map { w ->
                        async(Dispatchers.IO) {
                            Pow.solveRange(ch, never, w.toLong(), threads.toLong(), { done.incrementAndGet() }) { done.get() >= total }
                        }
                    }.awaitAll()
                }
            }
            val perCall = (System.nanoTime() - t0) / 1e6 / done.get()
            "m=$mib MiB: ${"%.1f".format(median)} ms per call on one thread (median of $calls), " +
                "${"%.1f".format(perCall)} ms per call on $threads threads " +
                "(cores ${Runtime.getRuntime().availableProcessors()}, heap ${Runtime.getRuntime().maxMemory() shr 20} MiB)"
        }
    }
}
