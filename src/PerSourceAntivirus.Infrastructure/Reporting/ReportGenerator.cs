using System.Runtime.Versioning;
using System.Text;
using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;
using SysProcess = System.Diagnostics.Process;

namespace PerSourceAntivirus.Infrastructure.Reporting;

[SupportedOSPlatform("windows")]
public sealed class ReportGenerator(AppDbContext db, IThreatReportRepository repo) : IReportGenerator
{
    public async Task<ThreatReport> GenerateAsync(DateTime from, DateTime to, string reportType, string outputDirectory, CancellationToken ct = default)
    {
        var totalFiles = await db.ScannedFiles.CountAsync(f => f.ScannedAtUtc >= from && f.ScannedAtUtc <= to, ct);
        var totalThreats = await db.RansomwareAlerts.CountAsync(a => a.DetectedAtUtc >= from && a.DetectedAtUtc <= to, ct)
            + await db.ProcessHollowingAlerts.CountAsync(a => a.DetectedAtUtc >= from && a.DetectedAtUtc <= to, ct)
            + await db.LolBinAlerts.CountAsync(a => a.AlertedAtUtc >= from && a.AlertedAtUtc <= to, ct)
            + await db.FilelessAlerts.CountAsync(a => a.DetectedAtUtc >= from && a.DetectedAtUtc <= to, ct)
            + await db.RootkitFindings.CountAsync(r => r.DetectedAtUtc >= from && r.DetectedAtUtc <= to, ct);
        var totalSuspicious = await db.PeMlPredictions.CountAsync(p => p.Classification == "Suspicious" && p.PredictedAtUtc >= from && p.PredictedAtUtc <= to, ct)
            + await db.AmsiScanEvents.CountAsync(a => a.WasBlocked && a.ScannedAtUtc >= from && a.ScannedAtUtc <= to, ct);

        var topThreatTypes = await BuildTopThreatTypesAsync(from, to, ct);

        var timestamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
        var sanitized = string.Concat(reportType.Split(Path.GetInvalidFileNameChars()));
        Directory.CreateDirectory(outputDirectory);
        var outputPath = Path.Combine(outputDirectory, $"report_{sanitized}_{timestamp}.html");

        var html = BuildHtmlReport(reportType, from, to, totalFiles, totalThreats, totalSuspicious, topThreatTypes, timestamp);
        await File.WriteAllTextAsync(outputPath, html, Encoding.UTF8, ct);

        var report = new ThreatReport
        {
            Id = Guid.NewGuid(),
            ReportType = reportType,
            PeriodStart = from,
            PeriodEnd = to,
            OutputFilePath = outputPath,
            TotalFilesScanned = totalFiles,
            TotalThreats = totalThreats,
            TotalSuspicious = totalSuspicious,
            TopThreatTypes = string.Join(", ", topThreatTypes),
            GeneratedAtUtc = DateTime.UtcNow
        };

        await repo.AddAsync(report, ct);
        return report;
    }

    public Task<ThreatReport> GenerateWeeklyAsync(string outputDirectory, CancellationToken ct = default)
    {
        var to = DateTime.UtcNow;
        var from = to.AddDays(-7);
        return GenerateAsync(from, to, "Weekly", outputDirectory, ct);
    }

    public Task<ThreatReport> GenerateMonthlyAsync(string outputDirectory, CancellationToken ct = default)
    {
        var to = DateTime.UtcNow;
        var from = to.AddDays(-30);
        return GenerateAsync(from, to, "Monthly", outputDirectory, ct);
    }

    private async Task<List<string>> BuildTopThreatTypesAsync(DateTime from, DateTime to, CancellationToken ct)
    {
        var counts = new List<(string Type, int Count)>
        {
            ("Ransomware", await db.RansomwareAlerts.CountAsync(a => a.DetectedAtUtc >= from && a.DetectedAtUtc <= to, ct)),
            ("ProcessHollowing", await db.ProcessHollowingAlerts.CountAsync(a => a.DetectedAtUtc >= from && a.DetectedAtUtc <= to, ct)),
            ("LolBin", await db.LolBinAlerts.CountAsync(a => a.AlertedAtUtc >= from && a.AlertedAtUtc <= to, ct)),
            ("Fileless", await db.FilelessAlerts.CountAsync(a => a.DetectedAtUtc >= from && a.DetectedAtUtc <= to, ct)),
            ("Rootkit", await db.RootkitFindings.CountAsync(r => r.DetectedAtUtc >= from && r.DetectedAtUtc <= to, ct)),
            ("DGA", await db.DgaAlerts.CountAsync(a => a.DetectedAtUtc >= from && a.DetectedAtUtc <= to, ct)),
            ("NetworkIntrusion", await db.NetworkIntrusionAlerts.CountAsync(a => a.DetectedAtUtc >= from && a.DetectedAtUtc <= to, ct)),
            ("AmsiBypass", await db.AmsiBypassAlerts.CountAsync(a => a.DetectedAtUtc >= from && a.DetectedAtUtc <= to, ct)),
        };

        return counts
            .Where(x => x.Count > 0)
            .OrderByDescending(x => x.Count)
            .Take(5)
            .Select(x => $"{x.Type}({x.Count})")
            .ToList();
    }

    private static string BuildHtmlReport(string reportType, DateTime from, DateTime to,
        int totalFiles, int totalThreats, int totalSuspicious, List<string> topTypes, string timestamp)
    {
        var sb = new StringBuilder();
        sb.Append("""
<!DOCTYPE html><html><head><meta charset="utf-8"><title>PerSource Antivirus Report</title><style>
body{font-family:Arial,sans-serif;background:#1e1e2e;color:#cdd6f4;padding:2rem;margin:0}
.card{background:#2a2a3e;border-radius:8px;padding:1rem;margin:1rem 0;border:1px solid #313244}
h1{color:#4a9eff;margin-bottom:0.5rem}
h2{color:#89b4fa;border-bottom:1px solid #313244;padding-bottom:0.5rem}
.danger{color:#f38ba8}
.warning{color:#fab387}
.safe{color:#a6e3a1}
.meta{color:#9399b2;font-size:0.875rem}
table{width:100%;border-collapse:collapse;margin-top:0.5rem}
th{background:#1a1a2e;padding:8px 12px;text-align:left;color:#89b4fa;font-weight:600}
td{padding:8px 12px;border-bottom:1px solid #313244}
tr:hover td{background:#313244}
.stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1rem;margin:1rem 0}
.stat-card{background:#313244;border-radius:6px;padding:1rem;text-align:center}
.stat-number{font-size:2rem;font-weight:700;line-height:1.2}
.stat-label{font-size:0.8rem;color:#9399b2;margin-top:0.25rem}
</style></head><body>
""");
        sb.Append($"<h1>&#x1F6E1; PerSource Antivirus &mdash; {System.Net.WebUtility.HtmlEncode(reportType)} Report</h1>");
        sb.Append($"<p class=\"meta\">Generated: {timestamp} UTC &nbsp;|&nbsp; Period: {from:yyyy-MM-dd HH:mm} &ndash; {to:yyyy-MM-dd HH:mm} UTC</p>");

        sb.Append("<div class=\"stat-grid\">");
        sb.Append($"<div class=\"stat-card\"><div class=\"stat-number safe\">{totalFiles}</div><div class=\"stat-label\">Files Scanned</div></div>");
        var threatsClass = totalThreats > 0 ? "danger" : "safe";
        sb.Append($"<div class=\"stat-card\"><div class=\"stat-number {threatsClass}\">{totalThreats}</div><div class=\"stat-label\">Threats Detected</div></div>");
        var suspClass = totalSuspicious > 0 ? "warning" : "safe";
        sb.Append($"<div class=\"stat-card\"><div class=\"stat-number {suspClass}\">{totalSuspicious}</div><div class=\"stat-label\">Suspicious Items</div></div>");
        sb.Append("</div>");

        sb.Append("<div class=\"card\"><h2>Top Threat Types</h2>");
        if (topTypes.Count > 0)
        {
            sb.Append("<table><thead><tr><th>#</th><th>Threat Type</th></tr></thead><tbody>");
            for (var i = 0; i < topTypes.Count; i++)
                sb.Append($"<tr><td>{i + 1}</td><td class=\"warning\">{System.Net.WebUtility.HtmlEncode(topTypes[i])}</td></tr>");
            sb.Append("</tbody></table>");
        }
        else
        {
            sb.Append("<p class=\"safe\">No threats detected in this period.</p>");
        }
        sb.Append("</div>");

        sb.Append("<div class=\"card\"><h2>Summary</h2><table><thead><tr><th>Metric</th><th>Value</th></tr></thead><tbody>");
        sb.Append($"<tr><td>Report Type</td><td>{System.Net.WebUtility.HtmlEncode(reportType)}</td></tr>");
        sb.Append($"<tr><td>Period Start</td><td>{from:yyyy-MM-dd HH:mm:ss} UTC</td></tr>");
        sb.Append($"<tr><td>Period End</td><td>{to:yyyy-MM-dd HH:mm:ss} UTC</td></tr>");
        sb.Append($"<tr><td>Total Files Scanned</td><td>{totalFiles}</td></tr>");
        sb.Append($"<tr><td class=\"{threatsClass}\">Total Threats</td><td class=\"{threatsClass}\">{totalThreats}</td></tr>");
        sb.Append($"<tr><td class=\"{suspClass}\">Total Suspicious</td><td class=\"{suspClass}\">{totalSuspicious}</td></tr>");
        sb.Append("</tbody></table></div>");

        sb.Append("</body></html>");
        return sb.ToString();
    }
}
