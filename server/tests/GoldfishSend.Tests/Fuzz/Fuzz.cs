using System.Collections.Immutable;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using CsCheck;

namespace GoldfishSend.Tests.Fuzz;

/// <summary>
/// Runs property checks over generated inputs. By default every run replays the same cases (case i of a property uses
/// PCG stream hash(property name), seed i), so CI is deterministic. For a longer local run, set <c>GF_FUZZ_SECONDS</c>:
/// each property then runs that long on random seeds (CsCheck, with shrinking), on <c>GF_FUZZ_THREADS</c> threads
/// (default 4). A failure prints the case's seed; <c>GF_FUZZ_SEED=&lt;seed&gt;</c> replays exactly that case.
/// </summary>
public static class Fuzz {
    public static int Seconds => int.TryParse(Environment.GetEnvironmentVariable("GF_FUZZ_SECONDS"), out var s) ? s : 0;
    private static int Threads => int.TryParse(Environment.GetEnvironmentVariable("GF_FUZZ_THREADS"), out var t) ? t : 4;
    private static string? ReplaySeed => Environment.GetEnvironmentVariable("GF_FUZZ_SEED") is { Length: > 0 } s ? s : null;

    public static void Run<T>(Gen<T> gen, Action<T> property, int iterations, Func<T, string>? print = null,
        [CallerMemberName] string name = "") {
        print ??= v => Check.Print(v);
        if (ReplaySeed is { } replay) {
            gen.Sample(property, seed: replay, iter: 1, threads: 1, print: print);
            return;
        }
        if (Seconds > 0) {
            gen.Sample(property, time: Seconds, threads: Threads, print: print, writeLine: Console.WriteLine);
            return;
        }
        var stream = Stream(name);
        for (var i = 0; i < iterations; i++) {
            var pcg = new PCG(stream, (ulong)i);
            var seed = pcg.ToString();
            var value = gen.Generate(pcg, null!, out _);
            try {
                property(value);
            } catch (Exception e) {
                throw new FuzzFailure(name, seed, Describe(print, value), e);
            }
        }
    }

    public static async Task RunAsync<T>(Gen<T> gen, Func<T, Task> property, int iterations, Func<T, string>? print = null,
        [CallerMemberName] string name = "") {
        print ??= v => Check.Print(v);
        var deadline = Seconds > 0 ? DateTime.UtcNow.AddSeconds(Seconds) : (DateTime?)null;
        var stream = Stream(name);
        var rng = PCG.ThreadPCG;
        for (var i = 0; deadline is null ? i < iterations : DateTime.UtcNow < deadline; i++) {
            var pcg = ReplaySeed is { } replay ? PCG.Parse(replay) : deadline is null ? new PCG(stream, (ulong)i) : new PCG(rng.Next(), rng.Next64());
            var seed = pcg.ToString();
            var value = gen.Generate(pcg, null!, out _);
            try {
                await property(value);
            } catch (Exception e) {
                throw new FuzzFailure(name, seed, Describe(print, value), e);
            }
            if (ReplaySeed is not null) {
                return;
            }
        }
    }

    /// <summary>A differential check is only worth something if the generator reaches both verdicts often.</summary>
    public static void AssertMix(int accepted, int iterations) {
        if (Seconds == 0 && ReplaySeed is null) {
            Assert.InRange(accepted, iterations / 10, iterations - iterations / 10);
        }
    }

    private static uint Stream(string name) => BitConverter.ToUInt32(SHA256.HashData(Encoding.UTF8.GetBytes(name)));

    private static string Describe<T>(Func<T, string> print, T value) {
        try {
            var text = print(value);
            return text.Length > 4000 ? text[..4000] + "…" : text;
        } catch (Exception e) {
            return $"<print failed: {e.GetType().Name}>";
        }
    }

    // --- shared generators ---

    public static Gen<byte[]> Bytes(int min, int max) => Gen.Byte.Array[min, max];

    public static Gen<T[]> Sequence<T>(IReadOnlyList<Gen<T>> gens) =>
        gens.Aggregate(Gen.Const(ImmutableList<T>.Empty), (acc, g) => acc.SelectMany(list => g.Select(list.Add))).Select(l => l.ToArray());

    /// <summary>Applies 1 to 4 random edits (bit flips, byte sets, truncation, extension, splices) to <paramref name="input"/>.</summary>
    public static Gen<byte[]> Mutate(byte[] input, int maxLength = 1 << 16) =>
        Gen.Int[1, 4].SelectMany(n => Gen.Int[0, int.MaxValue].Array[n * 3]).Select(r => {
            var data = input.ToList();
            for (var i = 0; i < r.Length; i += 3) {
                var (op, a, b) = (r[i] % 7, r[i + 1], r[i + 2]);
                var at = data.Count == 0 ? 0 : a % data.Count;
                switch (op) {
                    case 0 when data.Count > 0:
                        data[at] ^= (byte)(1 << (b % 8));
                        break;
                    case 1 when data.Count > 0:
                        data[at] = Interesting[b % Interesting.Length];
                        break;
                    case 2:
                        data.RemoveRange(at, data.Count - at);
                        break;
                    case 3 when data.Count < maxLength:
                        data.InsertRange(at, Enumerable.Repeat(Interesting[b % Interesting.Length], 1 + b % 8));
                        break;
                    case 4 when data.Count > 0:
                        data.RemoveRange(at, Math.Min(1 + b % 8, data.Count - at));
                        break;
                    case 5 when data.Count > 1:
                        (data[at], data[b % data.Count]) = (data[b % data.Count], data[at]);
                        break;
                    default:
                        if (data.Count < maxLength) {
                            data.Add((byte)b);
                        }
                        break;
                }
            }
            return data.ToArray();
        });

    private static readonly byte[] Interesting = [0x00, 0x01, 0x02, 0x04, 0x7f, 0x80, 0xfe, 0xff, 0x20, 0x2f, 0x2e, 0x25, 0x3f, 0x23, 0x5c, 0x41];

    public static string Hex(byte[] data) => data.Length > 256 ? Convert.ToHexStringLower(data[..256]) + $"…({data.Length} B)" : Convert.ToHexStringLower(data);
}

public sealed class FuzzFailure(string property, string seed, string input, Exception inner)
    : Exception($"{property} failed on case seed {seed} (replay with GF_FUZZ_SEED={seed})\ninput: {input}\n{inner.Message}", inner);
