using MySqlConnector;

namespace GoldfishSend.Infrastructure.MySql;

public sealed class Db {
    private readonly MySqlDataSource _dataSource;

    public Db(MySqlDataSource dataSource) {
        _dataSource = dataSource;
    }

    public async Task<MySqlConnection> OpenAsync(CancellationToken ct = default) {
        return await _dataSource.OpenConnectionAsync(ct);
    }

    public static bool IsDuplicateKey(MySqlException ex) {
        return ex.ErrorCode == MySqlErrorCode.DuplicateKeyEntry;
    }
}
