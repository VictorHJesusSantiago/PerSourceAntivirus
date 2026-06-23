using System.Runtime.Versioning;
using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Infrastructure.Persistence;
using SysProcess = System.Diagnostics.Process;

namespace PerSourceAntivirus.Infrastructure.Reporting;

[SupportedOSPlatform("windows")]
public sealed class ThreatTrendService(AppDbContext db) : IThreatTrendService
{
    public async Task<IReadOnlyList<ThreatTrendPoint>> GetDailyTrendAsync(int daysBack, CancellationToken ct = default)
    {
        var result = new List<ThreatTrendPoint>();
        var now = DateTime.UtcNow.Date;

        for (var i = daysBack; i >= 0; i--)
        {
            var day = now.AddDays(-i);
            var next = day.AddDays(1);

            var total = await db.RansomwareAlerts.CountAsync(a => a.DetectedAtUtc >= day && a.DetectedAtUtc < next, ct)
                + await db.ProcessHollowingAlerts.CountAsync(a => a.DetectedAtUtc >= day && a.DetectedAtUtc < next, ct)
                + await db.NetworkIntrusionAlerts.CountAsync(a => a.DetectedAtUtc >= day && a.DetectedAtUtc < next, ct)
                + await db.LolBinAlerts.CountAsync(a => a.AlertedAtUtc >= day && a.AlertedAtUtc < next, ct)
                + await db.FilelessAlerts.CountAsync(a => a.DetectedAtUtc >= day && a.DetectedAtUtc < next, ct)
                + await db.DgaAlerts.CountAsync(a => a.DetectedAtUtc >= day && a.DetectedAtUtc < next, ct)
                + await db.AmsiBypassAlerts.CountAsync(a => a.DetectedAtUtc >= day && a.DetectedAtUtc < next, ct)
                + await db.PortScanAlerts.CountAsync(a => a.DetectedAtUtc >= day && a.DetectedAtUtc < next, ct)
                + await db.PuaAlerts.CountAsync(a => a.DetectedAtUtc >= day && a.DetectedAtUtc < next, ct)
                + await db.Set<Domain.Entities.SupplyChainAlert>().CountAsync(a => a.DetectedAtUtc >= day && a.DetectedAtUtc < next, ct);

            var critical = await db.RansomwareAlerts.CountAsync(a => a.DetectedAtUtc >= day && a.DetectedAtUtc < next && (int)a.Severity >= 8, ct)
                + await db.ProcessHollowingAlerts.CountAsync(a => a.DetectedAtUtc >= day && a.DetectedAtUtc < next && a.Severity >= 8, ct)
                + await db.AmsiBypassAlerts.CountAsync(a => a.DetectedAtUtc >= day && a.DetectedAtUtc < next && a.Severity >= 8, ct);

            result.Add(new ThreatTrendPoint(day, total, critical));
        }

        return result;
    }

    public async Task<IReadOnlyList<ThreatTypeCount>> GetTopThreatTypesAsync(int topN, CancellationToken ct = default)
    {
        var counts = new List<ThreatTypeCount>
        {
            new("Ransomware", await db.RansomwareAlerts.CountAsync(ct)),
            new("ProcessHollowing", await db.ProcessHollowingAlerts.CountAsync(ct)),
            new("NetworkIntrusion", await db.NetworkIntrusionAlerts.CountAsync(ct)),
            new("LolBin", await db.LolBinAlerts.CountAsync(ct)),
            new("Fileless", await db.FilelessAlerts.CountAsync(ct)),
            new("DGA", await db.DgaAlerts.CountAsync(ct)),
            new("AmsiBypass", await db.AmsiBypassAlerts.CountAsync(ct)),
            new("PortScan", await db.PortScanAlerts.CountAsync(ct)),
            new("PUA", await db.PuaAlerts.CountAsync(ct)),
            new("SupplyChain", await db.Set<Domain.Entities.SupplyChainAlert>().CountAsync(ct)),
            new("Rootkit", await db.RootkitFindings.CountAsync(ct)),
            new("Exploit", await db.ExploitFindings.CountAsync(ct)),
            new("ComHijack", await db.ComHijackAlerts.CountAsync(ct)),
            new("ArpSpoofing", await db.ArpSpoofingAlerts.CountAsync(ct)),
            new("Keylogger", await db.KeyloggerDetectionAlerts.CountAsync(ct)),
        };

        return counts
            .OrderByDescending(x => x.Count)
            .Take(topN)
            .ToList();
    }
}
