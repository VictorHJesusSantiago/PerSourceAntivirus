using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IProcessMitigationService
{
    bool ApplyAcgToCurrentProcess();  // ACG = no dynamic code
    bool ApplyCigToCurrentProcess();  // CIG = only signed DLLs
    bool ApplyCfgToCurrentProcess();  // CFG enforcement
    Task<IReadOnlyList<CfgViolationAlert>> MonitorCfgViolationsAsync(int pollIntervalSeconds, CancellationToken ct);
}
