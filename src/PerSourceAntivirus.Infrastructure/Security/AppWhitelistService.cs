using System.Collections.Concurrent;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.Security;

public sealed class AppWhitelistService(IAppWhitelistRepository repo) : IAppWhitelistService
{
    private ConcurrentDictionary<string, AppWhitelistEntry> _cache = new(StringComparer.OrdinalIgnoreCase);
    private bool _cacheLoaded;
    private readonly SemaphoreSlim _cacheLock = new(1, 1);

    public async Task<IReadOnlyList<AppWhitelistEntry>> GetAllAsync(CancellationToken ct = default)
        => await repo.GetAllAsync(ct);

    public async Task AddEntryAsync(AppWhitelistEntry entry, CancellationToken ct = default)
    {
        await repo.AddAsync(entry, ct);
        await RebuildCacheAsync(ct);
    }

    public async Task RemoveEntryAsync(Guid id, CancellationToken ct = default)
    {
        await repo.RemoveAsync(id, ct);
        await RebuildCacheAsync(ct);
    }

    public async Task<bool> IsAllowedAsync(string hash, string path, CancellationToken ct = default)
    {
        await EnsureCacheAsync(ct);
        if (!string.IsNullOrEmpty(hash) && _cache.TryGetValue(hash, out var byHash) && byHash.IsEnabled && byHash.Action == "Allow")
            return true;
        if (!string.IsNullOrEmpty(path) && _cache.TryGetValue(path, out var byPath) && byPath.IsEnabled && byPath.Action == "Allow")
            return true;
        return false;
    }

    public async Task<string> GetActionAsync(string hash, string path, CancellationToken ct = default)
    {
        await EnsureCacheAsync(ct);
        if (!string.IsNullOrEmpty(hash) && _cache.TryGetValue(hash, out var byHash) && byHash.IsEnabled)
            return byHash.Action;
        if (!string.IsNullOrEmpty(path) && _cache.TryGetValue(path, out var byPath) && byPath.IsEnabled)
            return byPath.Action;
        return "Sandbox";
    }

    private async Task EnsureCacheAsync(CancellationToken ct)
    {
        if (_cacheLoaded) return;
        await RebuildCacheAsync(ct);
    }

    private async Task RebuildCacheAsync(CancellationToken ct)
    {
        await _cacheLock.WaitAsync(ct);
        try
        {
            var all = await repo.GetAllAsync(ct);
            var newCache = new ConcurrentDictionary<string, AppWhitelistEntry>(StringComparer.OrdinalIgnoreCase);
            foreach (var entry in all.Where(e => e.IsEnabled))
                newCache[entry.Value] = entry;
            _cache = newCache;
            _cacheLoaded = true;
        }
        finally
        {
            _cacheLock.Release();
        }
    }
}
