using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IAppWhitelistService
{
    Task<bool> IsAllowedAsync(string hash, string path, CancellationToken ct = default);
    Task<string> GetActionAsync(string hash, string path, CancellationToken ct = default); // Allow/Block/Sandbox
    Task AddEntryAsync(AppWhitelistEntry entry, CancellationToken ct = default);
    Task RemoveEntryAsync(Guid id, CancellationToken ct = default);
    Task<IReadOnlyList<AppWhitelistEntry>> GetAllAsync(CancellationToken ct = default);
}
