using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IMbrSnapshotRepository
{
    Task<MbrSnapshot?> GetLatestBaselineAsync(int driveIndex, CancellationToken cancellationToken = default);
    Task AddAsync(MbrSnapshot snapshot, CancellationToken cancellationToken = default);
}
