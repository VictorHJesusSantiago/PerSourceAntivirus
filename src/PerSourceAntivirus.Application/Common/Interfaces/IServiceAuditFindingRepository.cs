using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IServiceAuditFindingRepository
{
    Task AddAsync(ServiceAuditFinding finding, CancellationToken ct = default);
    Task<IReadOnlyList<ServiceAuditFinding>> GetAllAsync(CancellationToken ct = default);
}
