using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IVssSnapshotRepository
{
    Task AddAsync(VssSnapshotEvent snapshotEvent, CancellationToken ct = default);
    Task<IReadOnlyList<VssSnapshotEvent>> GetAllAsync(CancellationToken ct = default);
}
