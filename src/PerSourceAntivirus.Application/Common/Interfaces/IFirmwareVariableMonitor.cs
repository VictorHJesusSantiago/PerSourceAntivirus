using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IFirmwareVariableMonitor
{
    Task<IReadOnlyList<FirmwareVariableSnapshot>> ScanAsync(CancellationToken ct = default);
    Task SaveBaselineAsync(CancellationToken ct = default);
    bool IsBaselineEstablished { get; }
}
