using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IIncidentRepository
{
    Task AddAsync(Incident incident, CancellationToken ct = default);
    Task UpdateAsync(Incident incident, CancellationToken ct = default);
    Task<IReadOnlyList<Incident>> GetAllAsync(CancellationToken ct = default);
    Task<IReadOnlyList<Incident>> GetActiveAsync(CancellationToken ct = default);
}
