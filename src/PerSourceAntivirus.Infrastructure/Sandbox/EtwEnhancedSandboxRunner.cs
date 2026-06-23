using System.Collections.Concurrent;
using System.Diagnostics;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.Sandbox;

public class EtwEnhancedSandboxRunner(ISandboxRunner baseSandbox) : IEnhancedSandboxRunner
{
    public async Task<BehaviorReport> AnalyzeAsync(string filePath, TimeSpan timeout, CancellationToken ct = default)
    {
        if (!File.Exists(filePath))
            return new BehaviorReport(filePath, false, TimeSpan.Zero, [], [], [], [], [], [], "Unknown", "File not found");

        var processes = new ConcurrentBag<string>();
        var filesCreated = new ConcurrentBag<string>();
        var filesDeleted = new ConcurrentBag<string>();
        var registryKeys = new ConcurrentBag<string>();
        var networkConns = new ConcurrentBag<string>();
        var indicators = new ConcurrentBag<string>();

        var sessionName = $"PSAV-Enhanced-{Guid.NewGuid():N}";
        var sw = Stopwatch.StartNew();
        string? errorMessage = null;
        bool success = false;

        // Start ETW session for behavioral monitoring
        TraceEventSession? etwSession = null;
        try
        {
            etwSession = new TraceEventSession(sessionName);
            etwSession.EnableKernelProvider(
                KernelTraceEventParser.Keywords.Process |
                KernelTraceEventParser.Keywords.FileIOInit |
                KernelTraceEventParser.Keywords.Registry |
                KernelTraceEventParser.Keywords.NetworkTCPIP);

            etwSession.Source.Kernel.ProcessStart += data =>
                processes.Add($"{data.ProcessName}({data.ProcessID})");

            etwSession.Source.Kernel.FileIOCreate += data =>
            {
                if (!string.IsNullOrEmpty(data.FileName))
                    filesCreated.Add(data.FileName);
            };

            etwSession.Source.Kernel.FileIODelete += data =>
            {
                if (!string.IsNullOrEmpty(data.FileName))
                    filesDeleted.Add(data.FileName);
            };

            etwSession.Source.Kernel.RegistrySetValue += data =>
            {
                if (!string.IsNullOrEmpty(data.KeyName))
                    registryKeys.Add(data.KeyName);
            };

            etwSession.Source.Kernel.TcpIpConnect += data =>
                networkConns.Add($"{data.daddr}:{data.dport}");

            // Process ETW events in background
            var etwTask = Task.Run(() =>
            {
                try { etwSession.Source.Process(); }
                catch { /* session disposed */ }
            }, ct);

            // Run the sandbox
            var sandboxResult = await baseSandbox.RunAsync(filePath, (int)timeout.TotalSeconds, ct);
            success = sandboxResult.ErrorMessage is null;
            if (!success) errorMessage = sandboxResult.ErrorMessage;

            // Give ETW a moment to flush remaining events
            await Task.Delay(500, CancellationToken.None);
            etwSession.Stop();
        }
        catch (Exception ex)
        {
            errorMessage = ex.Message;
            etwSession?.Stop();
        }
        finally
        {
            etwSession?.Dispose();
        }

        sw.Stop();

        // Analyze collected behavior for suspicious indicators
        AnalyzeBehavior(processes, filesCreated, filesDeleted, registryKeys, networkConns, indicators);

        var verdict = indicators.Count switch
        {
            0 => "Clean",
            <= 2 => "Suspicious",
            _ => "Malicious"
        };

        return new BehaviorReport(
            filePath, success, sw.Elapsed,
            [.. processes],
            [.. filesCreated.Take(50)],
            [.. filesDeleted.Take(50)],
            [.. registryKeys.Take(50)],
            [.. networkConns.Take(50)],
            [.. indicators],
            verdict,
            errorMessage);
    }

    private static void AnalyzeBehavior(
        ConcurrentBag<string> processes,
        ConcurrentBag<string> filesCreated,
        ConcurrentBag<string> filesDeleted,
        ConcurrentBag<string> registryKeys,
        ConcurrentBag<string> networkConns,
        ConcurrentBag<string> indicators)
    {
        // Suspicious process creation
        var suspiciousProcesses = new[] { "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe" };
        foreach (var p in processes)
            if (suspiciousProcesses.Any(s => p.Contains(s, StringComparison.OrdinalIgnoreCase)))
                indicators.Add($"Suspicious process spawned: {p}");

        // Files created in temp/startup locations
        var suspiciousPaths = new[] { @"\Temp\", @"\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\", @"\System32\", @"\SysWOW64\" };
        foreach (var f in filesCreated)
            if (suspiciousPaths.Any(s => f.Contains(s, StringComparison.OrdinalIgnoreCase)))
                indicators.Add($"File created in sensitive path: {f}");

        // Mass file deletion (ransomware indicator)
        if (filesDeleted.Count > 20)
            indicators.Add($"Mass file deletion detected: {filesDeleted.Count} files");

        // Registry persistence locations
        var persistenceKeys = new[] { @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", @"SYSTEM\CurrentControlSet\Services\" };
        foreach (var key in registryKeys)
            if (persistenceKeys.Any(s => key.Contains(s, StringComparison.OrdinalIgnoreCase)))
                indicators.Add($"Registry persistence attempt: {key}");

        // Network connections
        if (networkConns.Count > 0)
            indicators.Add($"Network activity: {networkConns.Count} connections ({string.Join(", ", networkConns.Take(3))})");
    }
}
