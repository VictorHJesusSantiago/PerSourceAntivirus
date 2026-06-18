using System.Text.Json;
using MediatR;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using PerSourceAntivirus.Application;
using Microsoft.Extensions.DependencyInjection;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Application.Network.Commands.StartDnsMonitor;
using PerSourceAntivirus.Application.Network.Commands.StartNetworkCapture;
using PerSourceAntivirus.Application.Network.Queries.GetDnsEvents;
using PerSourceAntivirus.Application.Network.Queries.DetectBeaconing;
using PerSourceAntivirus.Application.Network.Queries.GetNetworkConnectionEvents;
using PerSourceAntivirus.Application.Network.Queries.ListCaptureDevices;
using PerSourceAntivirus.Application.Process.Commands.ScanProcessMemory;
using PerSourceAntivirus.Application.Process.Commands.StartProcessMonitor;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Application.Network.Commands.AddWfpBlock;
using PerSourceAntivirus.Application.Network.Commands.RemoveWfpBlock;
using PerSourceAntivirus.Application.Network.Commands.SyncWfpBlocklist;
using PerSourceAntivirus.Application.Network.Queries.GetWfpBlocks;
using PerSourceAntivirus.Application.Pe.Commands.ClassifyPe;
using PerSourceAntivirus.Application.Pe.Queries.GetMlPredictions;
using PerSourceAntivirus.Application.Ransomware.Commands.SetupHoneypot;
using PerSourceAntivirus.Application.Ransomware.Queries.GetHoneypots;
using PerSourceAntivirus.Application.Ransomware.Queries.GetRansomwareAlerts;
using PerSourceAntivirus.Application.Mbr.Commands.SnapshotMbr;
using PerSourceAntivirus.Application.Mbr.Queries.CheckMbr;
using PerSourceAntivirus.Application.Process.Queries.CheckRunningProcesses;
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

    case "update-feeds":
    {
        Console.WriteLine("Updating threat intelligence feeds...");
        var feedUpdaters = host.Services.GetServices<IThreatFeedUpdater>();
        var allOk = true;
        foreach (var feed in feedUpdaters)
        {
            Console.Write($"  [{feed.FeedName}] ");
            var feedResult = await feed.UpdateAsync();
            if (feedResult.Success)
                Console.WriteLine($"OK — {feedResult.RecordsAdded} record(s) added, {feedResult.RecordsTotal} total.");
            else
            {
                Console.WriteLine($"FAILED — {feedResult.ErrorMessage}");
                allOk = false;
            }
        }
        if (!allOk) return 1;
        break;
    }

    case "snapshot-mbr":
    {
        int mbrDrive = 0;
        for (var i = 1; i < args.Length; i++)
            if (args[i] == "--drive" && i + 1 < args.Length && int.TryParse(args[i + 1], out var d)) { mbrDrive = d; i++; }

        Console.WriteLine($"Taking MBR snapshot for PhysicalDrive{mbrDrive}...");
        try
        {
            var snap = await mediator.Send(new SnapshotMbrCommand(mbrDrive));
            Console.WriteLine($"Snapshot saved: {snap.Id}");
            Console.WriteLine($"  Drive:    PhysicalDrive{snap.DriveIndex}");
            Console.WriteLine($"  SHA-256:  {snap.Sha256Hash}");
            Console.WriteLine($"  Taken at: {snap.TakenAtUtc:yyyy-MM-dd HH:mm:ss} UTC");
            Console.WriteLine($"  Baseline: {(snap.IsBaseline ? "Yes (first snapshot)" : "No")}");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
            return 1;
        }
        break;
    }

    case "check-mbr":
    {
        int checkDrive = 0;
        for (var i = 1; i < args.Length; i++)
            if (args[i] == "--drive" && i + 1 < args.Length && int.TryParse(args[i + 1], out var d)) { checkDrive = d; i++; }

        Console.WriteLine($"Checking MBR integrity for PhysicalDrive{checkDrive}...");
        var mbrResult = await mediator.Send(new CheckMbrQuery(checkDrive));

        if (mbrResult.ErrorMessage is not null)
        {
            Console.Error.WriteLine($"Error reading MBR: {mbrResult.ErrorMessage}");
            return 1;
        }

        if (!mbrResult.HasBaseline)
        {
            Console.WriteLine("No baseline snapshot found. Run: snapshot-mbr");
            break;
        }

        if (mbrResult.HashMatched)
        {
            Console.WriteLine($"MBR INTACT — hash matches baseline.");
            Console.WriteLine($"  Current:  {mbrResult.CurrentHash}");
            Console.WriteLine($"  Baseline: {mbrResult.BaselineHash}");
            Console.WriteLine($"  Taken at: {mbrResult.BaselineTakenAtUtc:yyyy-MM-dd HH:mm:ss} UTC");
        }
        else
        {
            Console.Error.WriteLine("!!! MBR TAMPERED — hash mismatch !!!");
            Console.Error.WriteLine($"  Current:  {mbrResult.CurrentHash}");
            Console.Error.WriteLine($"  Baseline: {mbrResult.BaselineHash}");
            Console.Error.WriteLine($"  Baseline taken: {mbrResult.BaselineTakenAtUtc:yyyy-MM-dd HH:mm:ss} UTC");
            return 2;
        }
        break;
    }

    case "etw-monitor":
    {
        int etwSecs = 60;
        bool etwSuspiciousOnly = args.Contains("--suspicious");
        for (var i = 1; i < args.Length; i++)
            if (args[i] == "--seconds" && i + 1 < args.Length && int.TryParse(args[i + 1], out var s)) { etwSecs = s; i++; }

        Console.WriteLine($"ETW monitoring for {etwSecs}s (requires admin)... Ctrl+C to stop early.");
        Console.WriteLine($"{"Time",-22} {"Type",-14} {"PID",-7} {"Process",-25} {"Suspicious",-10} Detail");
        Console.WriteLine(new string('-', 140));

        using var etwCts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; etwCts.Cancel(); };
        etwCts.CancelAfter(TimeSpan.FromSeconds(etwSecs));

        var etwMonitor = host.Services.GetRequiredService<IEtwMonitor>();
        try
        {
            await foreach (var ev in etwMonitor.WatchAsync(etwCts.Token))
            {
                if (etwSuspiciousOnly && !ev.IsSuspicious) continue;
                var suspCol = ev.IsSuspicious ? "YES" : "";
                Console.WriteLine(
                    $"{ev.DetectedAtUtc:yyyy-MM-dd HH:mm:ss,-22} {ev.EventType,-14} " +
                    $"{ev.ProcessId,-7} {ev.ProcessName,-25} {suspCol,-10} {ev.Detail}");
            }
        }
        catch (OperationCanceledException) { /* normal stop */ }

        Console.WriteLine("ETW monitoring stopped.");
        break;
    }

    case "sandbox":
    {
        if (args.Length < 2)
        {
            Console.Error.WriteLine("Usage: sandbox <exe-path> [--timeout N]");
            return 1;
        }

        var sandboxExe = args[1];
        int sandboxTimeout = 30;
        for (var i = 2; i < args.Length; i++)
            if (args[i] == "--timeout" && i + 1 < args.Length && int.TryParse(args[i + 1], out var t)) { sandboxTimeout = t; i++; }

        Console.WriteLine($"Running sandbox: {sandboxExe} (timeout: {sandboxTimeout}s)");
        var runner = host.Services.GetRequiredService<ISandboxRunner>();
        var sandboxResult = await runner.RunAsync(sandboxExe, sandboxTimeout);

        Console.WriteLine($"Duration:        {sandboxResult.Duration.TotalSeconds:F2}s");
        Console.WriteLine($"Exit code:       {(sandboxResult.ExitCode.HasValue ? sandboxResult.ExitCode.ToString() : "N/A")}");
        Console.WriteLine($"Killed/timeout:  {sandboxResult.KilledByTimeout}");
        Console.WriteLine($"Child process:   {sandboxResult.CreatedChildProcess}");
        Console.WriteLine($"Memory limit:    {sandboxResult.MemoryLimitExceeded}");

        if (sandboxResult.ErrorMessage is not null)
        {
            Console.Error.WriteLine($"Error: {sandboxResult.ErrorMessage}");
            return 1;
        }
        break;
    }

    case "check-running":
    {
        Console.WriteLine("Checking running processes against reputation database...");
        var runningResults = await mediator.Send(new CheckRunningProcessesQuery(), CancellationToken.None);

        var checkable  = runningResults.Where(r => r.Sha256Hash is not null).ToList();
        var malicious  = checkable.Where(r => r.IsMalicious).ToList();
        var showAll    = args.Contains("--all");

        Console.WriteLine($"Checked {checkable.Count} process(es) (of {runningResults.Count} total). " +
                          $"Malicious hash matches: {malicious.Count}");
        Console.WriteLine();

        if (malicious.Count > 0)
        {
            Console.WriteLine("MALICIOUS PROCESSES:");
            Console.WriteLine($"{"PID",-7} {"Process",-30} {"Source",-15} Hash");
            Console.WriteLine(new string('-', 120));
            foreach (var p in malicious)
                Console.WriteLine($"{p.ProcessId,-7} {p.ProcessName,-30} {p.ReputationSource,-15} {p.Sha256Hash}");
            Console.WriteLine();
        }
        else
        {
            Console.WriteLine("No malicious hashes detected.");
        }

        if (showAll && checkable.Count > 0)
        {
            Console.WriteLine("ALL CHECKABLE PROCESSES:");
            Console.WriteLine($"{"PID",-7} {"Process",-30} {"Status",-12} Hash");
            Console.WriteLine(new string('-', 120));
            foreach (var p in checkable.OrderByDescending(p => p.IsMalicious).ThenBy(p => p.ProcessName))
                Console.WriteLine($"{p.ProcessId,-7} {p.ProcessName,-30} {(p.IsMalicious ? "MALICIOUS" : "Clean"),-12} {p.Sha256Hash}");
        }
        break;
    }

    case "detect-beaconing":
    {
        int beaconWindow  = 60;
        int beaconMinConn = 5;
        for (var i = 1; i < args.Length; i++)
        {
            if (args[i] == "--window" && i + 1 < args.Length && int.TryParse(args[i + 1], out var w))
                { beaconWindow = w; i++; }
            else if (args[i] == "--min-connections" && i + 1 < args.Length && int.TryParse(args[i + 1], out var m))
                { beaconMinConn = m; i++; }
        }

        var candidates = await mediator.Send(new DetectBeaconingQuery(beaconWindow, beaconMinConn), CancellationToken.None);

        if (candidates.Count == 0)
        {
            Console.WriteLine($"No beaconing patterns detected in the last {beaconWindow} min " +
                              $"(min {beaconMinConn} connections per pair, CV threshold < 10%).");
            break;
        }

        Console.WriteLine($"Beaconing candidates: {candidates.Count}");
        Console.WriteLine($"{"Source",-22} {"Destination",-28} {"Count",-7} {"Avg(s)",-10} {"CV%",-8} First Seen");
        Console.WriteLine(new string('-', 120));
        foreach (var c in candidates)
        {
            var dst = $"{c.DestinationAddress}:{c.DestinationPort}";
            Console.WriteLine(
                $"{c.SourceAddress,-22} {dst,-28} {c.ConnectionCount,-7} " +
                $"{c.AverageIntervalSeconds,-10:F1} {c.CoefficientOfVariationPct,-8:F2} " +
                $"{c.FirstSeen:yyyy-MM-dd HH:mm:ss}");
        }
        break;
    }

    case "scan-memory":
    {
        int targetPid = -1;
        for (var i = 1; i < args.Length; i++)
            if (args[i] == "--pid" && i + 1 < args.Length && int.TryParse(args[i + 1], out var p)) { targetPid = p; i++; }

        if (targetPid <= 0)
        {
            Console.Error.WriteLine("Usage: scan-memory --pid <PID>");
            return 1;
        }

        Console.WriteLine($"Scanning memory of PID {targetPid} with YARA rules...");
        var memResult = await mediator.Send(new ScanProcessMemoryCommand(targetPid));

        Console.WriteLine($"Process:  {memResult.ProcessName} (PID {memResult.ProcessId})");
        Console.WriteLine($"Regions:  {memResult.RegionsScanned} scanned");
        Console.WriteLine($"Matches:  {memResult.Matches.Count}");

        if (!memResult.Success)
        {
            Console.Error.WriteLine($"Error: {memResult.ErrorMessage}");
            return 1;
        }

        if (memResult.Matches.Count > 0)
        {
            Console.WriteLine();
            Console.WriteLine($"{"Address",-20} {"Size",-12} Rule");
            Console.WriteLine(new string('-', 80));
            foreach (var m in memResult.Matches)
                Console.WriteLine($"0x{m.BaseAddress:X16,-18} {m.RegionSize,-12} {m.RuleIdentifier}");
        }
        break;
    }

    case "honeypot":
    {
        if (args.Length < 2)
        {
            Console.Error.WriteLine("Usage: honeypot <setup|status>");
            return 1;
        }

        switch (args[1])
        {
            case "setup":
                Console.WriteLine("Creating honeypot decoy files...");
                var setupResult = await mediator.Send(new SetupHoneypotCommand());
                Console.WriteLine($"Created {setupResult.FilesCreated} decoy file(s):");
                foreach (var path in setupResult.Paths)
                    Console.WriteLine($"  {path}");
                break;

            case "status":
                var honeypots = await mediator.Send(new GetHoneypotsQuery());
                if (honeypots.Count == 0)
                {
                    Console.WriteLine("No honeypot files registered. Run: honeypot setup");
                    break;
                }
                Console.WriteLine($"{"Touched",-8} {"Type",-12} {"Created",-22} Path");
                Console.WriteLine(new string('-', 100));
                foreach (var h in honeypots)
                    Console.WriteLine($"{(h.WasTouched ? "YES" : "No"),-8} {h.DecoyType,-12} {h.CreatedAtUtc:yyyy-MM-dd HH:mm:ss,-22} {h.FilePath}");
                break;

            default:
                Console.Error.WriteLine("Usage: honeypot <setup|status>");
                return 1;
        }
        break;
    }

    case "ransomware-monitor":
    {
        int rnswSecs = 0;
        for (var i = 1; i < args.Length; i++)
            if (args[i] == "--seconds" && i + 1 < args.Length && int.TryParse(args[i + 1], out var s)) { rnswSecs = s; i++; }

        Console.WriteLine("Ransomware monitor active. Watching for honeypot access, mass encryption, suspicious renames, and VSS deletion...");
        Console.WriteLine("(Ctrl+C to stop)");
        Console.WriteLine();
        Console.WriteLine($"{"Time",-22} {"Severity",-10} {"Type",-28} Detail");
        Console.WriteLine(new string('-', 130));

        using var rnswCts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; rnswCts.Cancel(); };
        if (rnswSecs > 0) rnswCts.CancelAfter(TimeSpan.FromSeconds(rnswSecs));

        var rnswMonitor = host.Services.GetRequiredService<IRansomwareMonitor>();
        var rnswRepo = host.Services.GetRequiredService<IRansomwareAlertRepository>();
        try
        {
            await foreach (var alert in rnswMonitor.WatchAsync(rnswCts.Token))
            {
                Console.ForegroundColor = alert.Severity switch
                {
                    PerSourceAntivirus.Domain.Enums.RansomwareSeverity.Critical => ConsoleColor.Red,
                    PerSourceAntivirus.Domain.Enums.RansomwareSeverity.High     => ConsoleColor.Yellow,
                    _                                                            => ConsoleColor.White
                };
                Console.WriteLine(
                    $"{alert.DetectedAtUtc:yyyy-MM-dd HH:mm:ss,-22} " +
                    $"{alert.Severity,-10} {alert.EventType,-28} {alert.Detail}");
                Console.ResetColor();
                try { await rnswRepo.AddAsync(alert); } catch { /* non-fatal persistence error */ }
            }
        }
        catch (OperationCanceledException) { /* normal stop */ }

        Console.WriteLine("Ransomware monitoring stopped.");
        break;
    }

    case "ransomware-alerts":
    {
        var onlyCritical = args.Contains("--critical");
        var alerts = await mediator.Send(new GetRansomwareAlertsQuery(onlyCritical));

        if (alerts.Count == 0)
        {
            Console.WriteLine(onlyCritical ? "No critical ransomware alerts recorded." : "No ransomware alerts recorded. Run: ransomware-monitor");
            break;
        }

        Console.WriteLine($"{"Time",-22} {"Severity",-10} {"Type",-28} {"FilePath",-40} Detail");
        Console.WriteLine(new string('-', 160));
        foreach (var a in alerts)
            Console.WriteLine(
                $"{a.DetectedAtUtc:yyyy-MM-dd HH:mm:ss,-22} {a.Severity,-10} {a.EventType,-28} " +
                $"{(a.FilePath.Length > 38 ? "..." + a.FilePath[^35..] : a.FilePath),-40} {a.Detail}");
        break;
    }

    case "driver-monitor":
    {
        int drvSecs = 0;
        for (var i = 1; i < args.Length; i++)
            if (args[i] == "--seconds" && i + 1 < args.Length && int.TryParse(args[i + 1], out var s)) { drvSecs = s; i++; }

        Console.WriteLine("Connecting to kernel minifilter driver on \\PSAVScanPort...");
        Console.WriteLine("(Ctrl+C to stop)");
        Console.WriteLine();
        Console.WriteLine($"{"Time",-22} {"Blocked",-8} {"FilePath"}");
        Console.WriteLine(new string('-', 120));

        using var drvCts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; drvCts.Cancel(); };
        if (drvSecs > 0) drvCts.CancelAfter(TimeSpan.FromSeconds(drvSecs));

        var drvMonitor = host.Services.GetRequiredService<IMinifilterMonitor>();
        try
        {
            await foreach (var ev in drvMonitor.WatchAsync(drvCts.Token))
            {
                var blockedCol = ev.Blocked ? "BLOCKED" : "allowed";
                Console.ForegroundColor = ev.Blocked ? ConsoleColor.Red : ConsoleColor.Gray;
                Console.WriteLine($"{ev.DetectedAtUtc:yyyy-MM-dd HH:mm:ss,-22} {blockedCol,-8} {ev.FilePath}");
                if (ev.Blocked) Console.WriteLine($"  Reason: {ev.BlockReason}");
                Console.ResetColor();
            }
        }
        catch (OperationCanceledException) { /* normal stop */ }
        catch (InvalidOperationException ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
            Console.Error.WriteLine("To install the driver: run 'driver-install' for instructions.");
            return 1;
        }

        Console.WriteLine("Driver monitoring stopped.");
        break;
    }

    case "classify-pe":
    {
        if (args.Length < 2)
        {
            Console.Error.WriteLine("Usage: classify-pe <file-path>");
            return 1;
        }
        var classResult = await mediator.Send(new ClassifyPeCommand(args[1]));
        if (!classResult.IsPeFile)
        {
            Console.WriteLine($"Not a PE file: {classResult.FilePath}");
            break;
        }
        Console.ForegroundColor = classResult.Classification switch
        {
            "Malicious"  => ConsoleColor.Red,
            "Suspicious" => ConsoleColor.Yellow,
            _            => ConsoleColor.Green
        };
        Console.WriteLine($"Classification: {classResult.Classification}  (score: {classResult.MaliciousProbability:P1})");
        Console.ResetColor();
        Console.WriteLine($"Model:    {classResult.ModelVersion}");
        Console.WriteLine($"File:     {classResult.FilePath}");
        break;
    }

    case "classify-pe-batch":
    {
        if (args.Length < 2)
        {
            Console.Error.WriteLine("Usage: classify-pe-batch <directory>");
            return 1;
        }
        var dir = args[1];
        if (!Directory.Exists(dir)) { Console.Error.WriteLine($"Directory not found: {dir}"); return 1; }

        var exts = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".exe", ".dll", ".sys", ".scr", ".drv", ".ocx" };
        var peFiles = Directory.EnumerateFiles(dir, "*.*", SearchOption.AllDirectories)
            .Where(f => exts.Contains(Path.GetExtension(f)));

        Console.WriteLine($"{"Classification",-14} {"Score",-7} Path");
        Console.WriteLine(new string('-', 100));
        var counts = new Dictionary<string, int>();
        foreach (var f in peFiles)
        {
            var r = await mediator.Send(new ClassifyPeCommand(f));
            if (!r.IsPeFile) continue;
            counts.TryGetValue(r.Classification, out var c);
            counts[r.Classification] = c + 1;
            Console.ForegroundColor = r.Classification == "Malicious" ? ConsoleColor.Red
                : r.Classification == "Suspicious" ? ConsoleColor.Yellow : ConsoleColor.Gray;
            Console.WriteLine($"{r.Classification,-14} {r.MaliciousProbability:P1,-7} {r.FilePath}");
            Console.ResetColor();
        }
        Console.WriteLine();
        foreach (var kv in counts.OrderByDescending(x => x.Value))
            Console.WriteLine($"  {kv.Key}: {kv.Value}");
        break;
    }

    case "ml-predictions":
    {
        string? filterClass = null;
        for (var i = 1; i < args.Length; i++)
            if (args[i] == "--class" && i + 1 < args.Length) { filterClass = args[++i]; }

        var preds = await mediator.Send(new GetMlPredictionsQuery(filterClass));
        if (preds.Count == 0)
        {
            Console.WriteLine("No ML predictions recorded. Run: classify-pe <path>");
            break;
        }
        Console.WriteLine($"{"Classification",-14} {"Score",-7} {"Model",-18} {"Time",-22} Path");
        Console.WriteLine(new string('-', 140));
        foreach (var p in preds)
            Console.WriteLine($"{p.Classification,-14} {p.MaliciousProbability:P1,-7} {p.ModelVersion,-18} {p.PredictedAtUtc:yyyy-MM-dd HH:mm:ss,-22} {p.FilePath}");
        break;
    }

    case "wfp-block":
    {
        if (args.Length < 2)
        {
            Console.Error.WriteLine("Usage: wfp-block <ip> [--reason <text>]");
            return 1;
        }
        var wfpIp = args[1];
        var wfpReason = "manual";
        for (var i = 2; i < args.Length; i++)
            if (args[i] == "--reason" && i + 1 < args.Length) { wfpReason = args[++i]; }

        Console.WriteLine($"Adding WFP block for {wfpIp}...");
        var wfpResult = await mediator.Send(new AddWfpBlockCommand(wfpIp, wfpReason));
        if (wfpResult.Success)
        {
            Console.WriteLine($"Blocked: {wfpIp}");
            Console.WriteLine($"  Outbound filter ID: {wfpResult.FilterIdOutboundV4}");
            Console.WriteLine($"  Inbound  filter ID: {wfpResult.FilterIdInboundV4}");
        }
        else
        {
            Console.Error.WriteLine($"Error: {wfpResult.ErrorMessage}");
            return 1;
        }
        break;
    }

    case "wfp-unblock":
    {
        if (args.Length < 2) { Console.Error.WriteLine("Usage: wfp-unblock <ip>"); return 1; }
        var removed = await mediator.Send(new RemoveWfpBlockCommand(args[1]));
        Console.WriteLine(removed ? $"Removed WFP block for {args[1]}." : $"No active block found for {args[1]}.");
        break;
    }

    case "wfp-list":
    {
        var blocks = await mediator.Send(new GetWfpBlocksQuery());
        if (blocks.Count == 0) { Console.WriteLine("No active WFP blocks. Run: wfp-block <ip>"); break; }
        Console.WriteLine($"{"IP Address",-20} {"Outbound ID",-14} {"Inbound ID",-14} Reason");
        Console.WriteLine(new string('-', 80));
        foreach (var b in blocks)
            Console.WriteLine($"{b.IpAddress,-20} {b.FilterIdOutboundV4,-14} {b.FilterIdInboundV4,-14} {b.Reason}");
        break;
    }

    case "wfp-sync":
    {
        Console.WriteLine("Syncing IP blocklist to WFP...");
        var syncResult = await mediator.Send(new SyncWfpBlocklistCommand());
        Console.WriteLine($"Added: {syncResult.Added}  Already blocked: {syncResult.AlreadyBlocked}  Errors: {syncResult.Errors}");
        break;
    }

    case "kernel-monitor":
    {
        int kernelSecs = 0;
        for (var i = 1; i < args.Length; i++)
            if (args[i] == "--seconds" && i + 1 < args.Length && int.TryParse(args[i + 1], out var s)) { kernelSecs = s; i++; }

        Console.WriteLine("Connecting to kernel event port \\PSAVEventPort (process/image/handle callbacks)...");
        Console.WriteLine("(Ctrl+C to stop)");
        Console.WriteLine();
        Console.WriteLine($"{"Time",-22} {"Event",-20} {"PID",-7} {"Parent",-7} {"ImageBase",-18} Path");
        Console.WriteLine(new string('-', 140));

        using var kCts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; kCts.Cancel(); };
        if (kernelSecs > 0) kCts.CancelAfter(TimeSpan.FromSeconds(kernelSecs));

        var kernelMon = host.Services.GetRequiredService<IKernelEventMonitor>();
        try
        {
            await foreach (var ev in kernelMon.WatchAsync(kCts.Token))
            {
                Console.ForegroundColor = ev.EventType == KernelEventType.HandleStripped ? ConsoleColor.Yellow
                    : ev.EventType == KernelEventType.ProcessCreate ? ConsoleColor.Cyan
                    : ConsoleColor.Gray;
                Console.WriteLine(
                    $"{ev.DetectedAtUtc:yyyy-MM-dd HH:mm:ss,-22} {ev.EventType,-20} " +
                    $"{ev.ProcessId,-7} {ev.ParentProcessId,-7} " +
                    $"0x{ev.ImageBase:X16,-18} {ev.ImagePath}");
                if (ev.CommandLine is not null)
                    Console.WriteLine($"  CmdLine: {ev.CommandLine}");
                Console.ResetColor();
            }
        }
        catch (OperationCanceledException) { }
        catch (InvalidOperationException ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
            Console.Error.WriteLine("Ensure driver is loaded and running as admin.");
            return 1;
        }
        Console.WriteLine("Kernel monitoring stopped.");
        break;
    }

    case "driver-install":
        Console.WriteLine("Minifilter Driver Installation Instructions");
        Console.WriteLine("==========================================");
        Console.WriteLine();
        Console.WriteLine("1. Build the driver:");
        Console.WriteLine("   cd src/PerSourceAntivirus.Driver");
        Console.WriteLine("   cmake -DCMAKE_MODULE_PATH=<FindWDK_path> -G \"Visual Studio 17 2022\" -A x64 .");
        Console.WriteLine("   cmake --build . --config Release -- /p:Platform=x64");
        Console.WriteLine();
        Console.WriteLine("2. Enable test signing (for dev/testing):");
        Console.WriteLine("   bcdedit /set testsigning on   (requires admin, then reboot)");
        Console.WriteLine();
        Console.WriteLine("3. Install the driver INF:");
        Console.WriteLine("   inf2cat /driver:. /os:10_x64");
        Console.WriteLine("   signtool sign /fd sha256 /a PSAVDriver.cat");
        Console.WriteLine("   pnputil /add-driver PerSourceAntivirus.Driver.inf /install");
        Console.WriteLine();
        Console.WriteLine("4. Start the service:");
        Console.WriteLine("   sc start PSAVDriver");
        Console.WriteLine();
        Console.WriteLine("5. Run this tool as admin, then: driver-monitor");
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
    Console.WriteLine("  check-running [--all]               Hash running processes and check against reputation DB");
    Console.WriteLine("  detect-beaconing [--window M]       Detect C2 beaconing in captured connections (default: 60 min)");
    Console.WriteLine("               [--min-connections N]  Minimum connections per pair (default: 5)");
    Console.WriteLine("  update-feeds                        Download Feodo Tracker, MalwareBazaar and URLhaus feeds");
    Console.WriteLine("  snapshot-mbr [--drive N]            Hash MBR sector 0 of PhysicalDriveN and store as baseline");
    Console.WriteLine("  check-mbr [--drive N]               Compare current MBR hash against stored baseline");
    Console.WriteLine("  etw-monitor [--seconds N]           Stream ETW kernel events (DLL load, registry, process)");
    Console.WriteLine("             [--suspicious]           Show only suspicious events");
    Console.WriteLine("  sandbox <exe> [--timeout N]         Run executable in a Job Object sandbox (default: 30s)");
    Console.WriteLine("  schedule add <path> [--every M]     Add a scheduled scan every M minutes (default: 60)");
    Console.WriteLine("  schedule list                       List all scheduled scans");
    Console.WriteLine("  schedule remove <id>                Remove a scheduled scan");
    Console.WriteLine("  classify-pe <file>                  ML/heuristic PE classification (ONNX or built-in scorer)");
    Console.WriteLine("  classify-pe-batch <dir>             Classify all PE files in directory");
    Console.WriteLine("  ml-predictions [--class C]          List stored ML predictions");
    Console.WriteLine("  wfp-block <ip> [--reason R]         Add a WFP firewall block for an IPv4 address (requires admin)");
    Console.WriteLine("  wfp-unblock <ip>                    Remove a WFP block");
    Console.WriteLine("  wfp-list                            List active WFP blocks");
    Console.WriteLine("  wfp-sync                            Sync IP blocklist → WFP blocks");
    Console.WriteLine("  kernel-monitor [--seconds N]        Stream kernel events from \\PSAVEventPort (process/image/handle)");
    Console.WriteLine("  scan-memory --pid <PID>             Scan process memory with YARA rules (fileless/injection)");
    Console.WriteLine("  honeypot setup                      Create hidden decoy files to detect ransomware");
    Console.WriteLine("  honeypot status                     Show honeypot file status");
    Console.WriteLine("  ransomware-monitor [--seconds N]    Monitor for ransomware: honeypot access, mass encryption, VSS deletion");
    Console.WriteLine("  ransomware-alerts [--critical]      List recorded ransomware alerts");
    Console.WriteLine("  driver-monitor [--seconds N]        Connect to kernel minifilter for real-time file open interception");
    Console.WriteLine("  driver-install                      Show instructions for installing the minifilter driver");
}
