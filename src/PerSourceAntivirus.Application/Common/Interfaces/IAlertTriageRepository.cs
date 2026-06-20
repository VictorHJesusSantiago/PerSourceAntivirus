using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IAlertTriageRepository
{
    Task AddAsync(AlertTriage triage, CancellationToken ct = default);
    Task UpdateAsync(AlertTriage triage, CancellationToken ct = default);
    Task<IReadOnlyList<AlertTriage>> GetAllAsync(CancellationToken ct = default);
    Task<IReadOnlyList<AlertTriage>> GetByStatusAsync(string status, CancellationToken ct = default);
}
