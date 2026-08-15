using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IProcessMitigationService
{
    bool ApplyAcgToCurrentProcess();
    bool ApplyCigToCurrentProcess();
    bool ApplyCfgToCurrentProcess();
    Task<IReadOnlyList<CfgViolationAlert>> MonitorCfgViolationsAsync(int pollIntervalSeconds, CancellationToken ct);
}
