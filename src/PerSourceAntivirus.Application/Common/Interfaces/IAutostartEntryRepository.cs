using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IAutostartEntryRepository
{
    Task AddRangeAsync(IEnumerable<AutostartEntry> entries, CancellationToken ct = default);
    Task<IReadOnlyList<AutostartEntry>> GetAllAsync(CancellationToken ct = default);
}
