using System.Buffers.Text;
using System.Text;
using CsCheck;

namespace GoldfishSend.Tests.Fuzz;

/// <summary>Hostile JSON request bodies for the JSON endpoints: malformed text, wrong types, huge values, deep nesting.</summary>
public static class JsonGen {
    public static readonly Gen<string> B64Value = Gen.OneOf(
        Gen.Int[0, 100].Select(n => Base64Url.EncodeToString(new byte[n])),
        Gen.Const(Base64Url.EncodeToString(new byte[32])),
        Gen.Const(Base64Url.EncodeToString(new byte[65])),
        Gen.Const(Base64Url.EncodeToString(new byte[16])),
        Gen.Const(Base64Url.EncodeToString(new byte[32]) + "="),
        Gen.Const(Convert.ToBase64String(new byte[32]).Replace('A', '+')),
        Gen.Const("AAAA AAAA AAAA AAAA AAAA AAAA AAAA AAAA AAAA AA"),
        Gen.Const("A"),
        Gen.Const(""),
        Gen.Const("====="),
        Gen.Const("\u00e9\u00e9\u00e9\u00e9"),
        Gen.Const("\\u0000AAAA"),
        Gen.Int[8000, 9000].Select(n => new string('A', n)),
        Gen.Const(new string('A', 20000)),
        Gen.String[0, 60]);

    private static readonly Gen<string> UrlValue = Gen.OneOf(
        Gen.Const("https://push.example.org/x"),
        Gen.Const("https://127.0.0.1/"),
        Gen.Const("http://[::1]/"),
        Gen.Const("https://push.example.org:99999/"),
        Gen.Const("https://" + new string('a', 3000) + ".com/"),
        Gen.Const("javascript:alert(1)"),
        Gen.String[0, 80]);

    /// <summary>A JSON scalar or container of the wrong kind, as JSON text.</summary>
    public static readonly Gen<string> WrongValue = Gen.OneOf(
        Gen.Const("null"), Gen.Const("true"), Gen.Const("false"), Gen.Const("0"), Gen.Const("-1"),
        Gen.Const("1e400"), Gen.Const("-1e400"), Gen.Const("123456789012345678901234567890"), Gen.Const("1.5"),
        Gen.Const("{}"), Gen.Const("[]"), Gen.Const("[null]"), Gen.Const("{\"a\":1}"), Gen.Const("\"\""),
        Gen.Const("NaN"), Gen.Const("Infinity"), Gen.Const("'x'"), Gen.Const("\"\\ud800\""), Gen.Const("\"\\u0000\""),
        Gen.Int[1, 2000].Select(depth => new string('[', depth) + new string(']', depth)),
        Gen.Int[1, 2000].Select(depth => string.Concat(Enumerable.Repeat("{\"a\":", depth)) + "1" + new string('}', depth)));

    private static Gen<string> Value(Gen<string> valid) => Gen.Frequency(
        (6, valid.Select(Quote)),
        (2, WrongValue));

    private static Gen<string> Credential => Gen.Frequency(
        (6, Gen.Select(Value(B64Value), Value(B64Value), Gen.Bool,
            (s, o, swap) => swap ? $"{{\"ownerSecret\":{o},\"sendSecret\":{s}}}" : $"{{\"sendSecret\":{s},\"ownerSecret\":{o}}}")),
        (1, WrongValue));

    private static Gen<string> Items => Gen.Frequency(
        (6, Gen.Int[0, 3].SelectMany(n => Credential.Array[n]).Select(a => "[" + string.Join(",", a) + "]")),
        (1, Gen.Int[99, 102].Select(n => "[" + string.Join(",", Enumerable.Repeat(
            $"{{\"sendSecret\":\"{Base64Url.EncodeToString(new byte[32])}\",\"ownerSecret\":\"{Base64Url.EncodeToString(new byte[32])}\"}}", n)) + "]")),
        (1, WrongValue));

    private static Gen<string> Object(params (string Name, Gen<string> Value)[] fields) {
        var members = fields.Select(f => Gen.Frequency(
                (8, f.Value.Select(v => $"\"{f.Name}\":{v}")),
                (1, Gen.Const("")),
                (1, Gen.Select(f.Value, f.Value, (a, b) => $"\"{f.Name}\":{a},\"{f.Name}\":{b}")),
                (1, f.Value.Select(v => $"\"{f.Name.ToUpperInvariant()}\":{v}"))))
            .ToArray();
        return Gen.Select(Fuzz.Sequence(members), Gen.Frequency((5, Gen.Const("")), (1, Gen.Const("\"extra\":[1,{\"x\":null}]"))),
            (parts, extra) => "{" + string.Join(",", parts.Append(extra).Where(p => p.Length > 0)) + "}");
    }

    private static Gen<string> Pow => Gen.Frequency(
        (5, Object(("challenge", Value(B64Value)), ("nonce", Value(B64Value)))),
        (1, WrongValue));

    public static Gen<string> CreateMailbox => Object(
        ("pow", Pow), ("sendSecret", Value(B64Value)), ("ownerHash", Value(B64Value)), ("endpoint", Value(UrlValue)),
        ("p256dh", Value(B64Value)), ("auth", Value(B64Value)));

    public static Gen<string> Verify => Object(("items", Items), ("code", Value(B64Value)));

    public static Gen<string> Rotate => Object(
        ("items", Items), ("endpoint", Value(UrlValue)), ("p256dh", Value(B64Value)), ("auth", Value(B64Value)));

    public static Gen<string> Batch => Object(("items", Items));

    /// <summary>Breaks a document: truncation, byte mutations (possibly invalid UTF-8), junk around it, or another top-level value.</summary>
    public static Gen<byte[]> Malformed(Gen<string> document) => Gen.Frequency(
        (4, document.Select(Encoding.UTF8.GetBytes)),
        (2, document.SelectMany(d => Gen.Int[0, d.Length].Select(n => Encoding.UTF8.GetBytes(d[..n])))),
        (2, document.SelectMany(d => Fuzz.Mutate(Encoding.UTF8.GetBytes(d)))),
        (1, document.Select(d => Encoding.UTF8.GetBytes("\uFEFF" + d))),
        (1, document.Select(d => Encoding.UTF8.GetBytes(d + "{}"))),
        (1, document.Select(d => Encoding.UTF8.GetBytes("/* c */" + d))),
        (1, document.Select(d => Encoding.Unicode.GetBytes(d))),
        (1, WrongValue.Select(Encoding.UTF8.GetBytes)),
        (1, Gen.Const(Array.Empty<byte>())),
        (1, Gen.Int[5000, 20000].Select(n => Encoding.UTF8.GetBytes("{\"items\":" + new string('[', n)))));

    public static string Quote(string value) {
        var sb = new StringBuilder("\"");
        foreach (var c in value) {
            sb.Append(c switch {
                '"' => "\\\"",
                '\\' => "\\\\",
                < ' ' => $"\\u{(int)c:x4}",
                _ => c.ToString(),
            });
        }
        return sb.Append('"').ToString();
    }
}
