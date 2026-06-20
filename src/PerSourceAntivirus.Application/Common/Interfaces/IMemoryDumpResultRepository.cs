using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IMemoryDumpResultRepository
{
    Task AddAsync(MemoryDumpResult result, CancellationToken ct);
    Task<IReadOnlyList<MemoryDumpResult>> GetAllAsync(CancellationToken ct);
}
