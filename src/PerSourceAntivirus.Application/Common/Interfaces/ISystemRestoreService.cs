namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface ISystemRestoreService
{
    Task<bool> CreateRestorePointAsync(string description, CancellationToken ct = default);
    Task<IReadOnlyList<SystemRestorePointInfo>> GetRestorePointsAsync(CancellationToken ct = default);
    Task<bool> RestoreToPointAsync(int sequenceNumber, CancellationToken ct = default);
}

public record SystemRestorePointInfo(int SequenceNumber, string Description, DateTime CreationTime, string RestorePointType);
