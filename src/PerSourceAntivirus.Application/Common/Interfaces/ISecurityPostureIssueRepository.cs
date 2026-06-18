using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface ISecurityPostureIssueRepository
{
    Task AddRangeAsync(IEnumerable<SecurityPostureIssue> issues, CancellationToken ct = default);
    Task<IReadOnlyList<SecurityPostureIssue>> GetAllAsync(CancellationToken ct = default);
}
