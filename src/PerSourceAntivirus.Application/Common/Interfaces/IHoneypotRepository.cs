using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IHoneypotRepository
{
    Task AddAsync(HoneypotFile file, CancellationToken ct = default);
    Task<IReadOnlyList<HoneypotFile>> GetAllAsync(CancellationToken ct = default);
    Task UpdateAsync(HoneypotFile file, CancellationToken ct = default);
}
