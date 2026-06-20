using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IFirmwareVariableSnapshotRepository
{
    Task AddRangeAsync(IEnumerable<FirmwareVariableSnapshot> snapshots, CancellationToken ct);
    Task<IReadOnlyList<FirmwareVariableSnapshot>> GetAllAsync(CancellationToken ct);
    Task<IReadOnlyList<FirmwareVariableSnapshot>> GetBaselineAsync(CancellationToken ct);
}
