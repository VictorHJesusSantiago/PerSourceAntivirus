using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IUserAccountAuditor
{
    Task<IReadOnlyList<UserAccountAuditFinding>> AuditAsync(CancellationToken ct);
}
