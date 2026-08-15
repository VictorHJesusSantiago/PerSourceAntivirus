using System.Text;
using System.Text.Json;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Domain.Enums;

namespace PerSourceAntivirus.Cli.Commands;

public static class ScannedFileFormatter
{
    public static string Format(IReadOnlyList<ScannedFile> files, string format) => format switch
    {
        "json" => ToJson(files),
        "csv" => ToCsv(files),
        _ => ToTable(files)
    };

    public static string ToTable(IReadOnlyList<ScannedFile> files)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"{"Status",-12} {"PE",-4} {"Script",-8} {"YARA",-5} {"Quar",-5} {"Rep",-5} {"Hash",-66} {"Entropy",-8} {"Size",-10} Path");
        sb.AppendLine(new string('-', 180));
        foreach (var file in files)
        {
            var status = file.ThreatStatus switch
            {
                ThreatStatus.Malicious => "MALICIOUS",
                ThreatStatus.Suspicious => "SUSPICIOUS",
                ThreatStatus.Clean => "Clean",
                _ => "Unknown"
            };
            var pe = file.PeAnalysis is not null ? "Yes" : "No";
            var script = file.ScriptAnalysis is not null ? file.ScriptAnalysis.ScriptType.ToString()[..2] : "No";
            var yaraHits = file.YaraMatches.Count;
            var quarantined = file.IsQuarantined ? "Yes" : "No";
            var rep = file.HashReputation is not null
                ? $"{file.HashReputation.PositiveDetections}/{file.HashReputation.TotalEngines}"
                : "-";
            sb.AppendLine($"{status,-12} {pe,-4} {script,-8} {yaraHits,-5} {quarantined,-5} {rep,-5} {file.Sha256Hash,-66} {file.Entropy,-8:F3} {file.SizeBytes,-10} {file.FilePath}");
        }
        return sb.ToString();
    }

    public static string ToJson(IReadOnlyList<ScannedFile> files)
    {
        var dtos = files.Select(f => new
        {
            f.Id,
            f.FilePath,
            f.FileName,
            f.SizeBytes,
            f.Sha256Hash,
            f.Entropy,
            ScannedAt = f.ScannedAtUtc,
            ThreatStatus = f.ThreatStatus.ToString(),
            YaraMatches = f.YaraMatches.Select(m => new { m.RuleIdentifier, m.Tags }),
            PeAnalysis = f.PeAnalysis is null ? null : new { f.PeAnalysis.Is64Bit, f.PeAnalysis.IsDll, f.PeAnalysis.IsDotNet, f.PeAnalysis.IsSigned, f.PeAnalysis.Anomalies },
            ScriptAnalysis = f.ScriptAnalysis is null ? null : new { Type = f.ScriptAnalysis.ScriptType.ToString(), f.ScriptAnalysis.HasObfuscation, f.ScriptAnalysis.HasNetworkAccess },
            HashReputation = f.HashReputation is null ? null : new { f.HashReputation.Source, f.HashReputation.PositiveDetections, f.HashReputation.TotalEngines, f.HashReputation.IsMalicious, f.HashReputation.ReportUrl },
            f.IsQuarantined
        });
        return JsonSerializer.Serialize(dtos, new JsonSerializerOptions { WriteIndented = true });
    }

    public static string ToCsv(IReadOnlyList<ScannedFile> files)
    {
        var sb = new StringBuilder();
        sb.AppendLine("Id,FilePath,FileName,SizeBytes,Sha256Hash,Entropy,ScannedAtUtc,ThreatStatus,YaraHits,HasPe,HasScript,IsQuarantined,ReputationSource,PositiveDetections,TotalEngines");
        foreach (var f in files)
        {
            var rep = f.HashReputation;
            sb.AppendLine(string.Join(",",
                f.Id,
                $"\"{f.FilePath.Replace("\"", "\"\"")}\"",
                $"\"{f.FileName}\"",
                f.SizeBytes,
                f.Sha256Hash,
                f.Entropy.ToString("F6"),
                f.ScannedAtUtc.ToString("o"),
                f.ThreatStatus,
                f.YaraMatches.Count,
                f.PeAnalysis is not null,
                f.ScriptAnalysis is not null,
                f.IsQuarantined,
                rep?.Source ?? "",
                rep?.PositiveDetections ?? 0,
                rep?.TotalEngines ?? 0));
        }
        return sb.ToString();
    }
}
