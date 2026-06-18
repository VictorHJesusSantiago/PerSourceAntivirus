using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface ISecurityPostureChecker
{
    Task<IReadOnlyList<SecurityPostureIssue>> RunChecksAsync(CancellationToken ct);
}
