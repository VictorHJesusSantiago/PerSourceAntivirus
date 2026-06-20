using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IBrowserExtensionAuditor
{
    Task<IReadOnlyList<BrowserExtensionFinding>> AuditAsync(CancellationToken ct = default);
}
