using System.Reflection;
using Dapper;
using Microsoft.Extensions.Logging;

namespace GoldfishSend.Infrastructure.MySql;

/// <summary>Applies the embedded <c>Migrations/NNNN_name.sql</c> scripts in order. Multiple nodes are safe because a MySQL named lock serialises them.</summary>
public sealed class Migrator {
    private const string LockName = "goldfish_migrations";

    private readonly Db _db;
    private readonly ILogger<Migrator> _logger;

    public Migrator(Db db, ILogger<Migrator> logger) {
        _db = db;
        _logger = logger;
    }

    public async Task MigrateAsync(CancellationToken ct = default) {
        await using var conn = await _db.OpenAsync(ct);
        var locked = await conn.ExecuteScalarAsync<int?>("SELECT GET_LOCK(@name, 60)", new { name = LockName });
        if (locked != 1) {
            throw new InvalidOperationException("Could not acquire the migration lock.");
        }
        try {
            await conn.ExecuteAsync("""
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version VARCHAR(128) NOT NULL PRIMARY KEY
                ) ENGINE = InnoDB
                """);
            var applied = (await conn.QueryAsync<string>("SELECT version FROM schema_migrations")).ToHashSet();

            foreach (var (version, sql) in LoadScripts()) {
                if (applied.Contains(version)) {
                    continue;
                }
                _logger.LogInformation("Applying migration {Version}", version);
                // MySQL DDL auto-commits, so every script must be idempotent or atomic by itself.
                foreach (var statement in SplitStatements(sql)) {
                    await conn.ExecuteAsync(statement);
                }
                await conn.ExecuteAsync("INSERT INTO schema_migrations (version) VALUES (@version)", new { version });
            }
        } finally {
            await conn.ExecuteScalarAsync<int?>("SELECT RELEASE_LOCK(@name)", new { name = LockName });
        }
    }

    private static IEnumerable<(string Version, string Sql)> LoadScripts() {
        var assembly = typeof(Migrator).Assembly;
        const string prefix = "GoldfishSend.Infrastructure.MySql.Migrations.";
        return assembly.GetManifestResourceNames()
            .Where(n => n.StartsWith(prefix, StringComparison.Ordinal) && n.EndsWith(".sql", StringComparison.Ordinal))
            .Order(StringComparer.Ordinal)
            .Select(n => (n[prefix.Length..^4], ReadResource(assembly, n)));
    }

    private static string ReadResource(Assembly assembly, string name) {
        using var stream = assembly.GetManifestResourceStream(name)!;
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    private static IEnumerable<string> SplitStatements(string sql) {
        var lines = sql.Split('\n').Where(l => !l.TrimStart().StartsWith("--", StringComparison.Ordinal));
        return string.Join('\n', lines)
            .Split(';')
            .Select(s => s.Trim())
            .Where(s => s.Length > 0);
    }
}
