namespace GoldfishSend.Infrastructure.Redis;

/// <summary>
/// Per-subject caps on a shared pool (the PoW verification slots): a subject may hold at most its limit at once. Counts
/// live only in process memory, keyed by the caller's subject bytes, and an entry goes away when its count returns to
/// zero.
/// </summary>
public sealed class FairShares {
    private readonly Dictionary<string, int> _held = new();

    /// <summary>Takes one share for every (key, limit), or none if any key is already at its limit.</summary>
    public bool TryEnter(IReadOnlyList<(string Key, int Limit)> keys) {
        lock (_held) {
            foreach (var (key, limit) in keys) {
                if (_held.GetValueOrDefault(key) >= limit) {
                    return false;
                }
            }
            foreach (var (key, _) in keys) {
                _held[key] = _held.GetValueOrDefault(key) + 1;
            }
            return true;
        }
    }

    public void Exit(IReadOnlyList<(string Key, int Limit)> keys) {
        lock (_held) {
            foreach (var (key, _) in keys) {
                var n = _held.GetValueOrDefault(key) - 1;
                if (n <= 0) {
                    _held.Remove(key);
                } else {
                    _held[key] = n;
                }
            }
        }
    }

    public int Held(string key) {
        lock (_held) {
            return _held.GetValueOrDefault(key);
        }
    }

    /// <summary>Subjects holding a share right now (for tests: it shrinks back to empty).</summary>
    public int Count {
        get {
            lock (_held) {
                return _held.Count;
            }
        }
    }
}
