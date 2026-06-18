using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IVssRollbackService
{
    Task<string?> CreateSnapshotAsync(string folderPath, string reason, CancellationToken ct);
    Task<bool> RestoreFromLatestSnapshotAsync(string folderPath, CancellationToken ct);
    Task<IReadOnlyList<VssSnapshotEvent>> ListSnapshotsAsync(CancellationToken ct);
    event EventHandler<VssSnapshotEventArgs> SnapshotCreated;
}

public record VssSnapshotEventArgs(VssSnapshotEvent Event);
