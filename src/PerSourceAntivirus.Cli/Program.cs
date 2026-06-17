using System.Text.Json;
using MediatR;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using PerSourceAntivirus.Application;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Application.Network.Commands.StartDnsMonitor;
using PerSourceAntivirus.Application.Network.Commands.StartNetworkCapture;
using PerSourceAntivirus.Application.Network.Queries.GetDnsEvents;
using PerSourceAntivirus.Application.Network.Queries.GetNetworkConnectionEvents;
using PerSourceAntivirus.Application.Network.Queries.ListCaptureDevices;
using PerSourceAntivirus.Application.Process.Commands.StartProcessMonitor;
using PerSourceAntivirus.Application.Process.Queries.GetProcessEvents;
using PerSourceAntivirus.Application.Scans.Commands.AddScheduledScan;
using PerSourceAntivirus.Application.Scans.Commands.QuarantineFile;
using PerSourceAntivirus.Application.Scans.Commands.RemoveScheduledScan;
using PerSourceAntivirus.Application.Scans.Commands.RestoreFile;
using PerSourceAntivirus.Application.Scans.Commands.ScanDirectory;
using PerSourceAntivirus.Application.Scans.Commands.WatchDirectory;
using PerSourceAntivirus.Application.Scans.Queries.GetScheduledScans;
using PerSourceAntivirus.Application.Scans.Queries.GetScannedFiles;
using PerSourceAntivirus.Domain.Enums;
using PerSourceAntivirus.Infrastructure;
using PerSourceAntivirus.Infrastructure.Persistence;

var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
{
    Args = args,
    ContentRootPath = AppContext.BaseDirectory
});

builder.Services.AddApplicationServices();
builder.Services.AddInfrastructureServices(builder.Configuration);

using var host = builder.Build();

var dbContext = host.Services.GetRequiredService<AppDbContext>();
await dbContext.Database.MigrateAsync();

var mediator = host.Services.GetRequiredService<IMediator>();

if (args.Length == 0)
{
    PrintUsage();
    return 1;
}

switch (args[0])
{
    case "scan":
        if (args.Length < 2)
        {
            Console.Error.WriteLine("Usage: scan <path>");
            return 1;
        }

        var scanResult = await mediator.Send(new ScanDirectoryCommand(args[1]));
        Console.WriteLine($"Scanned {scanResult.FilesScanned} file(s) in {scanResult.Duration.TotalSeconds:F2}s.");
        break;

    case "list":
        var files = await mediator.Send(new GetScannedFilesQuery());
        if (files.Count == 0)
        {
            Console.WriteLine("No scanned files. Run: scan <path>");
            break;
        }

        var format = "table";
        string? outputFile = null;
        for (var i = 1; i < args.Length; i++)
        {
            if (args[i] == "--format" && i + 1 < args.Length) { format = args[++i]; }
            else if (args[i] == "--output" && i + 1 < args.Length) { outputFile = args[++i]; }
        }

        var output = format switch
        {
            "json" => FormatJson(files),
            "csv"  => FormatCsv(files),
            _      => FormatTable(files)
        };

        if (outputFile is not null)
        {
            await File.WriteAllTextAsync(outputFile, output);
            Console.WriteLine($"Exported {files.Count} record(s) to {outputFile}");
        }
        else
        {
            Console.WriteLine(output);
        }
        break;

    case "quarantine":
        if (args.Length < 2 || !Guid.TryParse(args[1], out var quarantineId))
        {
            Console.Error.WriteLine("Usage: quarantine <file-id>");
            return 1;
        }

        try
        {
            var qResult = await mediator.Send(new QuarantineFileCommand(quarantineId));
            Console.WriteLine($"Quarantined: {qResult.OriginalPath}");
            Console.WriteLine($"Stored at:   {qResult.QuarantinePath}");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
            return 1;
        }
        break;

    case "restore":
        if (args.Length < 2 || !Guid.TryParse(args[1], out var restoreId))
        {
            Console.Error.WriteLine("Usage: restore <file-id>");
            return 1;
        }

        try
        {
            var rResult = await mediator.Send(new RestoreFileCommand(restoreId));
            Console.WriteLine($"Restored to: {rResult.RestoredPath}");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
            return 1;
        }
        break;

    case "watch":
        if (args.Length < 2)
        {
            Console.Error.WriteLine("Usage: watch <path>");
            return 1;
        }

        Console.WriteLine($"Watching {args[1]} for new/modified files... (Ctrl+C to stop)");
        using (var cts = new CancellationTokenSource())
        {
            Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
            try
            {
                var watchResult = await mediator.Send(new WatchDirectoryCommand(args[1]), cts.Token);
                Console.WriteLine($"Watch stopped. Scanned {watchResult.FilesScanned} file(s), {watchResult.ThreatsDetected} threat(s) detected.");
            }
            catch (OperationCanceledException)
            {
                Console.WriteLine("Watch stopped.");
            }
        }
        break;

    case "update-blocklist":
        Console.WriteLine("Fetching updated IP blocklist...");
        var updater = host.Services.GetRequiredService<IBlocklistUpdater>();
        var updateResult = await updater.UpdateAsync();
        if (updateResult.Success)
            Console.WriteLine($"Updated blocklist from {updateResult.Source}: {updateResult.IpsTotal} IP(s) loaded.");
        else
        {
            Console.Error.WriteLine($"Update failed: {updateResult.ErrorMessage}");
            return 1;
        }
        break;

    case "update-yara-rules":
        Console.WriteLine("Downloading YARA rules...");
        string? yaraUrl = null;
        for (var i = 1; i < args.Length; i++)
            if (args[i] == "--url" && i + 1 < args.Length) { yaraUrl = args[++i]; }

        var yaraUpdater = host.Services.GetRequiredService<IYaraRulesUpdater>();
        var yaraResult = await yaraUpdater.UpdateAsync(yaraUrl);
        if (yaraResult.Success)
            Console.WriteLine($"Downloaded {yaraResult.FilesDownloaded} rule file(s) from {yaraResult.Source}. Scanner reloaded.");
        else
        {
            Console.Error.WriteLine($"Update failed: {yaraResult.ErrorMessage}");
            return 1;
        }
        break;

    case "devices":
        var devices = await mediator.Send(new ListCaptureDevicesQuery());
        if (devices.Count == 0)
        {
            Console.WriteLine("No capture devices found.");
            Console.WriteLine("Install Npcap (https://npcap.com/) to enable network monitoring.");
            break;
        }

        Console.WriteLine($"{"Name",-40} Description");
        Console.WriteLine(new string('-', 100));
        foreach (var device in devices)
            Console.WriteLine($"{device.Name,-40} {device.Description}");
        break;

    case "monitor":
        int monitorSecs = 30;
        string? monitorDevice = null;
        for (var i = 1; i < args.Length; i++)
        {
            if (args[i] == "--seconds" && i + 1 < args.Length && int.TryParse(args[i + 1], out var s)) { monitorSecs = s; i++; }
            else if (args[i] == "--device" && i + 1 < args.Length) { monitorDevice = args[++i]; }
        }

        Console.WriteLine($"Capturing network traffic for {monitorSecs}s... (Ctrl+C to stop early)");
        using (var cts = new CancellationTokenSource())
        {
            Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
            try
            {
                var monitorResult = await mediator.Send(new StartNetworkCaptureCommand(monitorDevice, monitorSecs), cts.Token);
                Console.WriteLine($"Captured {monitorResult.PacketsCaptured} packet(s) in {monitorResult.Duration.TotalSeconds:F1}s. Blocklisted: {monitorResult.BlocklistedCount}");
            }
            catch (OperationCanceledException) { Console.WriteLine("Monitoring stopped."); }
        }
        break;

    case "connections":
        var onlyBlocklisted = args.Contains("--blocklisted");
        var connectionEvents = await mediator.Send(new GetNetworkConnectionEventsQuery(onlyBlocklisted));

        if (connectionEvents.Count == 0)
        {
            Console.WriteLine(onlyBlocklisted ? "No blocklisted connections recorded." : "No captured connections. Run: monitor");
            break;
        }

        Console.WriteLine($"{"Time",-22} {"Proto",-6} {"Source",-25} {"Destination",-25} {"Bytes",-8} Blocked");
        Console.WriteLine(new string('-', 110));
        foreach (var ev in connectionEvents)
        {
            var src = $"{ev.SourceAddress}:{ev.SourcePort}";
            var dst = $"{ev.DestinationAddress}:{ev.DestinationPort}";
            Console.WriteLine($"{ev.CapturedAtUtc:yyyy-MM-dd HH:mm:ss,-22} {ev.Protocol,-6} {src,-25} {dst,-25} {ev.PacketLength,-8} {(ev.IsBlocklisted ? "YES" : "")}");
        }
        break;

    case "dns-monitor":
        int dnsSecs = 30;
        string? dnsDevice = null;
        for (var i = 1; i < args.Length; i++)
        {
            if (args[i] == "--seconds" && i + 1 < args.Length && int.TryParse(args[i + 1], out var d)) { dnsSecs = d; i++; }
            else if (args[i] == "--device" && i + 1 < args.Length) { dnsDevice = args[++i]; }
        }

        Console.WriteLine($"Capturing DNS queries for {dnsSecs}s... (Ctrl+C to stop early)");
        using (var cts = new CancellationTokenSource())
        {
            Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
            try
            {
                var dnsResult = await mediator.Send(new StartDnsMonitorCommand(dnsDevice, dnsSecs), cts.Token);
                Console.WriteLine($"Captured {dnsResult.QueriesCaptured} DNS query(s) in {dnsResult.Duration.TotalSeconds:F1}s. Suspicious: {dnsResult.SuspiciousCount}");
            }
            catch (OperationCanceledException) { Console.WriteLine("DNS monitoring stopped."); }
        }
        break;

    case "dns-events":
        var onlySuspiciousDns = args.Contains("--suspicious");
        var dnsEvents = await mediator.Send(new GetDnsEventsQuery(onlySuspiciousDns));

        if (dnsEvents.Count == 0)
        {
            Console.WriteLine(onlySuspiciousDns ? "No suspicious DNS queries recorded." : "No DNS events. Run: dns-monitor");
            break;
        }

        Console.WriteLine($"{"Time",-22} {"Type",-6} {"Source",-20} {"Suspicious",-10} Domain");
        Console.WriteLine(new string('-', 110));
        foreach (var ev in dnsEvents)
            Console.WriteLine($"{ev.CapturedAtUtc:yyyy-MM-dd HH:mm:ss,-22} {ev.QueryType,-6} {ev.SourceAddress,-20} {(ev.IsSuspicious ? "YES" : ""),-10} {ev.QueryName}");
        break;

    case "process-monitor":
        int procSecs = 30;
        for (var i = 1; i < args.Length; i++)
            if (args[i] == "--seconds" && i + 1 < args.Length && int.TryParse(args[i + 1], out var p)) { procSecs = p; i++; }

        Console.WriteLine($"Monitoring process creation for {procSecs}s... (Ctrl+C to stop early)");
        using (var cts = new CancellationTokenSource())
        {
            Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
            try
            {
                var procResult = await mediator.Send(new StartProcessMonitorCommand(procSecs), cts.Token);
                Console.WriteLine($"Recorded {procResult.EventsRecorded} process event(s) in {procResult.Duration.TotalSeconds:F1}s. Suspicious: {procResult.SuspiciousCount}");
            }
            catch (OperationCanceledException) { Console.WriteLine("Process monitoring stopped."); }
        }
        break;

    case "process-events":
        var onlySuspiciousProc = args.Contains("--suspicious");
        var procEvents = await mediator.Send(new GetProcessEventsQuery(onlySuspiciousProc));

        if (procEvents.Count == 0)
        {
            Console.WriteLine(onlySuspiciousProc ? "No suspicious process events recorded." : "No process events. Run: process-monitor");
            break;
        }

        Console.WriteLine($"{"Time",-22} {"PID",-7} {"Process",-25} {"Parent",-25} Suspicious");
        Console.WriteLine(new string('-', 110));
        foreach (var ev in procEvents)
            Console.WriteLine($"{ev.DetectedAtUtc:yyyy-MM-dd HH:mm:ss,-22} {ev.ProcessId,-7} {ev.ProcessName,-25} {ev.ParentProcessName,-25} {(ev.IsSuspicious ? $"YES - {ev.SuspicionReason}" : "")}");
        break;

    case "schedule":
        if (args.Length < 2)
        {
            Console.Error.WriteLine("Usage: schedule <add|list|remove>");
            return 1;
        }

        switch (args[1])
        {
            case "add":
                if (args.Length < 3)
                {
                    Console.Error.WriteLine("Usage: schedule add <path> [--every <minutes>]");
                    return 1;
                }
                var schedulePath = args[2];
                var intervalMinutes = 60;
                for (var i = 3; i < args.Length; i++)
                    if (args[i] == "--every" && i + 1 < args.Length && int.TryParse(args[i + 1], out var m)) { intervalMinutes = m; i++; }

                var addResult = await mediator.Send(new AddScheduledScanCommand(schedulePath, intervalMinutes));
                Console.WriteLine($"Scheduled scan added: {addResult.Id}");
                Console.WriteLine($"  Path:     {addResult.Path}");
                Console.WriteLine($"  Interval: every {addResult.IntervalMinutes} minute(s)");
                break;

            case "list":
                var schedules = await mediator.Send(new GetScheduledScansQuery());
                if (schedules.Count == 0)
                {
                    Console.WriteLine("No scheduled scans. Add one with: schedule add <path>");
                    break;
                }

                Console.WriteLine($"{"ID",-38} {"Enabled",-8} {"Interval",-12} {"Last Run",-22} Path");
                Console.WriteLine(new string('-', 120));
                foreach (var s in schedules)
                {
                    var lastRun = s.LastRunAtUtc?.ToString("yyyy-MM-dd HH:mm:ss") ?? "never";
                    Console.WriteLine($"{s.Id,-38} {(s.IsEnabled ? "Yes" : "No"),-8} {s.IntervalMinutes + "m",-12} {lastRun,-22} {s.Path}");
                }
                break;

            case "remove":
                if (args.Length < 3 || !Guid.TryParse(args[2], out var removeId))
                {
                    Console.Error.WriteLine("Usage: schedule remove <id>");
                    return 1;
                }
                await mediator.Send(new RemoveScheduledScanCommand(removeId));
                Console.WriteLine($"Scheduled scan {removeId} removed.");
                break;

            default:
                Console.Error.WriteLine("Usage: schedule <add|list|remove>");
                return 1;
        }
        break;

    default:
        PrintUsage();
        return 1;
}

return 0;

static string FormatTable(IReadOnlyList<PerSourceAntivirus.Domain.Entities.ScannedFile> files)
{
    var sb = new System.Text.StringBuilder();
    sb.AppendLine($"{"Status",-12} {"PE",-4} {"Script",-8} {"YARA",-5} {"Quar",-5} {"Rep",-5} {"Hash",-66} {"Entropy",-8} {"Size",-10} Path");
    sb.AppendLine(new string('-', 180));
    foreach (var file in files)
    {
        var status = file.ThreatStatus switch
        {
            ThreatStatus.Malicious  => "MALICIOUS",
            ThreatStatus.Suspicious => "SUSPICIOUS",
            ThreatStatus.Clean      => "Clean",
            _                       => "Unknown"
        };
        var pe = file.PeAnalysis is not null ? "Yes" : "No";
        var script = file.ScriptAnalysis is not null ? file.ScriptAnalysis.ScriptType.ToString()[..2] : "No";
        var yaraHits = file.YaraMatches.Count;
        var quarantined = file.IsQuarantined ? "Yes" : "No";
        var rep = file.HashReputation is not null ? $"{file.HashReputation.PositiveDetections}/{file.HashReputation.TotalEngines}" : "-";
        sb.AppendLine($"{status,-12} {pe,-4} {script,-8} {yaraHits,-5} {quarantined,-5} {rep,-5} {file.Sha256Hash,-66} {file.Entropy,-8:F3} {file.SizeBytes,-10} {file.FilePath}");
    }
    return sb.ToString();
}

static string FormatJson(IReadOnlyList<PerSourceAntivirus.Domain.Entities.ScannedFile> files)
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
        YaraMatches = f.YaraMatches.Select(m => new { m.RuleIdentifier, Tags = m.Tags }),
        PeAnalysis = f.PeAnalysis is null ? null : new { f.PeAnalysis.Is64Bit, f.PeAnalysis.IsDll, f.PeAnalysis.IsDotNet, f.PeAnalysis.IsSigned, f.PeAnalysis.Anomalies },
        ScriptAnalysis = f.ScriptAnalysis is null ? null : new { Type = f.ScriptAnalysis.ScriptType.ToString(), f.ScriptAnalysis.HasObfuscation, f.ScriptAnalysis.HasNetworkAccess },
        HashReputation = f.HashReputation is null ? null : new { f.HashReputation.Source, f.HashReputation.PositiveDetections, f.HashReputation.TotalEngines, f.HashReputation.IsMalicious, f.HashReputation.ReportUrl },
        f.IsQuarantined
    });
    return JsonSerializer.Serialize(dtos, new JsonSerializerOptions { WriteIndented = true });
}

static string FormatCsv(IReadOnlyList<PerSourceAntivirus.Domain.Entities.ScannedFile> files)
{
    var sb = new System.Text.StringBuilder();
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

static void PrintUsage()
{
    Console.WriteLine("PerSourceAntivirus CLI");
    Console.WriteLine("Usage:");
    Console.WriteLine("  scan <path>                         Scan files: hash, entropy, YARA, PE, script, reputation");
    Console.WriteLine("  list [--format table|json|csv]      List scanned files (default: table)");
    Console.WriteLine("       [--output <file>]              Export to file");
    Console.WriteLine("  quarantine <id>                     Move a file to the quarantine directory");
    Console.WriteLine("  restore <id>                        Restore a quarantined file");
    Console.WriteLine("  watch <path>                        Watch directory and scan new/modified files");
    Console.WriteLine("  update-blocklist                    Fetch latest IP blocklist from configured threat feed");
    Console.WriteLine("  update-yara-rules [--url URL]       Download YARA rules and reload scanner");
    Console.WriteLine("  devices                             List available network capture devices");
    Console.WriteLine("  monitor [--seconds N] [--device D]  Capture network traffic (default: 30s)");
    Console.WriteLine("  connections [--blocklisted]         List captured connection events");
    Console.WriteLine("  dns-monitor [--seconds N]           Capture DNS queries (default: 30s)");
    Console.WriteLine("  dns-events [--suspicious]           List captured DNS query events");
    Console.WriteLine("  process-monitor [--seconds N]       Monitor process creation via WMI (default: 30s)");
    Console.WriteLine("  process-events [--suspicious]       List captured process events");
    Console.WriteLine("  schedule add <path> [--every M]     Add a scheduled scan every M minutes (default: 60)");
    Console.WriteLine("  schedule list                       List all scheduled scans");
    Console.WriteLine("  schedule remove <id>                Remove a scheduled scan");
}
