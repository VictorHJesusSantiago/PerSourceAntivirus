namespace PerSourceAntivirus.Application.Common.Interfaces;

public record ShadowCopyInfo(string Id, string Volume, DateTime CreatedAt);

public interface IVssBackupService
{
    Task<string?> CreateSnapshotAsync(string volume, CancellationToken ct = default);
    Task DeleteSnapshotAsync(string shadowId, CancellationToken ct = default);
    Task<IReadOnlyList<ShadowCopyInfo>> ListSnapshotsAsync(CancellationToken ct = default);
}
