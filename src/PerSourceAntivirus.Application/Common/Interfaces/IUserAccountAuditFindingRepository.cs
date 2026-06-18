using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IUserAccountAuditFindingRepository
{
    Task AddAsync(UserAccountAuditFinding finding, CancellationToken ct = default);
    Task<IReadOnlyList<UserAccountAuditFinding>> GetAllAsync(CancellationToken ct = default);
}
