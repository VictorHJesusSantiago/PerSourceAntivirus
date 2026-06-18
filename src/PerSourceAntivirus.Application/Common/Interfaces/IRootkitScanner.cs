using PerSourceAntivirus.Domain.Entities;
namespace PerSourceAntivirus.Application.Common.Interfaces;
public interface IRootkitScanner
{
    Task<IReadOnlyList<RootkitFinding>> ScanAsync(CancellationToken ct = default);
}
