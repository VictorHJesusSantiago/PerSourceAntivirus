using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IServiceAuditor
{
    Task<IReadOnlyList<ServiceAuditFinding>> AuditAsync(CancellationToken ct);
}
