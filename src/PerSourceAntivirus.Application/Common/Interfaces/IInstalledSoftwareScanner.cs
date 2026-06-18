using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IInstalledSoftwareScanner
{
    Task<IReadOnlyList<VulnerableSoftwareAlert>> ScanInstalledSoftwareAsync(CancellationToken ct);
}
