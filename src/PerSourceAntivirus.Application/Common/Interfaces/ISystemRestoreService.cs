namespace PerSourceAntivirus.Application.Common.Interfaces;

// Wraps Windows System Restore (via the built-in PowerShell System Restore cmdlets) so the
// GUI can create/list/restore checkpoints without the user needing to open the Control Panel.
public interface ISystemRestoreService
{
    Task<bool> CreateRestorePointAsync(string description, CancellationToken ct = default);
    Task<IReadOnlyList<SystemRestorePointInfo>> GetRestorePointsAsync(CancellationToken ct = default);
    Task<bool> RestoreToPointAsync(int sequenceNumber, CancellationToken ct = default);
}

public record SystemRestorePointInfo(int SequenceNumber, string Description, DateTime CreationTime, string RestorePointType);
