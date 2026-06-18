using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IOpenPortScanner
{
    Task<IReadOnlyList<OpenPortInfo>> ScanAsync(CancellationToken ct);
}
