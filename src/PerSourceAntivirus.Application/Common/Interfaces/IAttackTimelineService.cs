using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IAttackTimelineService
{
    Task<AttackTimeline> GetTimelineAsync(int processId, DateTime? from, DateTime? to, CancellationToken ct = default);
    Task<AttackTimeline> GetTimelineByAlertIdAsync(Guid alertId, string alertType, CancellationToken ct = default);
}

public record AttackTimeline(
    int ProcessId,
    string ProcessName,
    string ImagePath,
    IReadOnlyList<ProcessCreationEvent> ChildProcesses,
    IReadOnlyList<FileActivityEvent> FileActivities,
    IReadOnlyList<NetworkConnectionEvent> NetworkConnections,
    IReadOnlyList<RegistryActivityEvent> RegistryActivities,
    DateTime From,
    DateTime To);
