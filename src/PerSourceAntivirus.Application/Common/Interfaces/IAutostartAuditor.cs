using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IAutostartAuditor
{
    Task<IReadOnlyList<AutostartEntry>> AuditAsync(CancellationToken ct);
}
