using System.Runtime.Versioning;
using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Infrastructure.Persistence;
using SysProcess = System.Diagnostics.Process;

namespace PerSourceAntivirus.Infrastructure.Reporting;

[SupportedOSPlatform("windows")]
public sealed class AlertAggregatorService(AppDbContext db) : IAlertAggregatorService
{
    public async Task<IReadOnlyList<AggregatedAlert>> GetRecentAlertsAsync(int count = 100, CancellationToken ct = default)
    {
        var all = new List<AggregatedAlert>();

        var ransomware = await db.RansomwareAlerts
            .OrderByDescending(a => a.DetectedAtUtc).Take(5).ToListAsync(ct);
        all.AddRange(ransomware.Select(a => new AggregatedAlert(
            "Ransomware", a.Id, a.Detail, (int)a.Severity, a.DetectedAtUtc, a.FilePath)));

        var hollowing = await db.ProcessHollowingAlerts
            .OrderByDescending(a => a.DetectedAtUtc).Take(5).ToListAsync(ct);
        all.AddRange(hollowing.Select(a => new AggregatedAlert(
            "ProcessHollowing", a.Id, a.DetectedSequence, a.Severity, a.DetectedAtUtc, a.TargetProcessName)));

        var networkIntrusion = await db.NetworkIntrusionAlerts
            .OrderByDescending(a => a.DetectedAtUtc).Take(5).ToListAsync(ct);
        all.AddRange(networkIntrusion.Select(a => new AggregatedAlert(
            "NetworkIntrusion", a.Id, a.Description, a.Severity, a.DetectedAtUtc, a.SourceIp)));

        var amsiBypass = await db.AmsiBypassAlerts
            .OrderByDescending(a => a.DetectedAtUtc).Take(5).ToListAsync(ct);
        all.AddRange(amsiBypass.Select(a => new AggregatedAlert(
            "AmsiBypass", a.Id, a.Details, a.Severity, a.DetectedAtUtc, a.ProcessName)));

        var apiCallSeq = await db.Set<Domain.Entities.ApiCallSequenceAlert>()
            .OrderByDescending(a => a.DetectedAtUtc).Take(5).ToListAsync(ct);
        all.AddRange(apiCallSeq.Select(a => new AggregatedAlert(
            "ApiCallSequence", a.Id, a.DetectionReason, a.Severity, a.DetectedAtUtc, a.ProcessName)));

        var parentChild = await db.Set<Domain.Entities.ParentChildAnomalyAlert>()
            .OrderByDescending(a => a.DetectedAtUtc).Take(5).ToListAsync(ct);
        all.AddRange(parentChild.Select(a => new AggregatedAlert(
            "ParentChildAnomaly", a.Id, a.AnomalyReason, a.Severity, a.DetectedAtUtc, a.ChildProcessName)));

        var cmdLine = await db.Set<Domain.Entities.ProcessCommandLineAlert>()
            .OrderByDescending(a => a.DetectedAtUtc).Take(5).ToListAsync(ct);
        all.AddRange(cmdLine.Select(a => new AggregatedAlert(
            "ProcessCommandLine", a.Id, a.Triggers, a.Severity, a.DetectedAtUtc, a.ProcessName)));

        var portScan = await db.PortScanAlerts
            .OrderByDescending(a => a.DetectedAtUtc).Take(5).ToListAsync(ct);
        all.AddRange(portScan.Select(a => new AggregatedAlert(
            "PortScan", a.Id, a.DetectionMethod, a.Severity, a.DetectedAtUtc, a.SourceIp)));

        var pua = await db.PuaAlerts
            .OrderByDescending(a => a.DetectedAtUtc).Take(5).ToListAsync(ct);
        all.AddRange(pua.Select(a => new AggregatedAlert(
            "PUA", a.Id, a.DetectionReason, a.Severity, a.DetectedAtUtc, a.ProcessName)));

        var supplyChain = await db.Set<Domain.Entities.SupplyChainAlert>()
            .OrderByDescending(a => a.DetectedAtUtc).Take(5).ToListAsync(ct);
        all.AddRange(supplyChain.Select(a => new AggregatedAlert(
            "SupplyChain", a.Id, a.Details, a.Severity, a.DetectedAtUtc, a.ProcessName)));

        return all
            .OrderByDescending(a => a.DetectedAt)
            .Take(count)
            .ToList();
    }

    public async Task<IReadOnlyList<AggregatedAlert>> GetAlertsByTypeAsync(string alertType, CancellationToken ct = default)
    {
        var all = await GetRecentAlertsAsync(int.MaxValue, ct);
        return all.Where(a => string.Equals(a.AlertType, alertType, StringComparison.OrdinalIgnoreCase)).ToList();
    }
}
