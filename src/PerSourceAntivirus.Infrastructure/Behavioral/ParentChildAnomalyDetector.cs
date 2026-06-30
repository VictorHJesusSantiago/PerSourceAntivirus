using System.Collections.Concurrent;
using System.Management;
using System.Runtime.Versioning;
using Microsoft.Extensions.DependencyInjection;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using SysProcess = System.Diagnostics.Process;

namespace PerSourceAntivirus.Infrastructure.Behavioral;

[SupportedOSPlatform("windows")]
public sealed class ParentChildAnomalyDetector : IParentChildAnomalyDetector
{
    private static readonly Dictionary<string, HashSet<string>> AnomalousChildren =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["winword.exe"]  = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe" },
            ["excel.exe"]    = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe" },
            ["outlook.exe"]  = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe" },
            ["powerpnt.exe"] = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe", "mshta.exe" },
            ["iexplore.exe"] = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe", "wscript.exe" },
            ["chrome.exe"]   = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe", "wscript.exe" },
            ["firefox.exe"]  = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe", "wscript.exe" },
            ["svchost.exe"]  = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe" },
            ["explorer.exe"] = new(StringComparer.OrdinalIgnoreCase) { "rundll32.exe" },
        };

    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ConcurrentDictionary<(int ParentPid, int ChildPid), bool> _alerted = new();
    private CancellationTokenSource? _cts;

    public event EventHandler<ParentChildAnomalyAlertEventArgs>? AlertDetected;

    public ParentChildAnomalyDetector(IServiceScopeFactory scopeFactory)
    {
        _scopeFactory = scopeFactory;
    }

    public async Task StartMonitoringAsync(CancellationToken ct)
    {
        _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        await Task.Run(() => PollLoopAsync(_cts.Token), _cts.Token).ConfigureAwait(false);
    }

    public void StopMonitoring() => _cts?.Cancel();

    private async Task PollLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await CheckProcessesAsync(ct).ConfigureAwait(false);
            }
            catch { }

            await Task.Delay(TimeSpan.FromSeconds(5), ct).ConfigureAwait(false);
        }
    }

    private async Task CheckProcessesAsync(CancellationToken ct)
    {
        foreach (var proc in SysProcess.GetProcesses())
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                var childName = proc.ProcessName + ".exe";
                if (!IsAnomalousChildInAnyParent(childName))
                    continue;

                int childPid = proc.Id;
                int parentPid = 0;
                string parentName = string.Empty;
                string cmdLine = string.Empty;

                try
                {
                    using var searcher = new ManagementObjectSearcher(
                        $"SELECT ParentProcessId, CommandLine FROM Win32_Process WHERE ProcessId = {childPid}");
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        parentPid = Convert.ToInt32(obj["ParentProcessId"]);
                        cmdLine = obj["CommandLine"] as string ?? string.Empty;
                    }
                }
                catch { }

                if (parentPid == 0)
                    continue;

                try
                {
                    using var parentProc = SysProcess.GetProcessById(parentPid);
                    parentName = parentProc.ProcessName + ".exe";
                }
                catch { }

                if (string.IsNullOrEmpty(parentName))
                    continue;

                if (!AnomalousChildren.TryGetValue(parentName, out var anomalousSet))
                    continue;

                if (!anomalousSet.Contains(childName))
                    continue;

                if (parentName.Equals("explorer.exe", StringComparison.OrdinalIgnoreCase) &&
                    childName.Equals("rundll32.exe", StringComparison.OrdinalIgnoreCase))
                {
                    if (!cmdLine.Contains("http", StringComparison.OrdinalIgnoreCase))
                        continue;
                }

                var key = (parentPid, childPid);
                if (!_alerted.TryAdd(key, true))
                    continue;

                var alert = new ParentChildAnomalyAlert
                {
                    Id = Guid.NewGuid(),
                    ParentProcessName = parentName,
                    ParentProcessId = parentPid,
                    ChildProcessName = childName,
                    ChildProcessId = childPid,
                    ChildCommandLine = cmdLine.Length > 500 ? cmdLine[..500] : cmdLine,
                    AnomalyReason = $"Suspicious child process: {parentName} spawned {childName}",
                    Severity = 8,
                    DetectedAtUtc = DateTime.UtcNow
                };

                try
                {
                    using var scope = _scopeFactory.CreateScope();
                    var repo = scope.ServiceProvider.GetRequiredService<IParentChildAnomalyAlertRepository>();
                    await repo.AddAsync(alert, CancellationToken.None).ConfigureAwait(false);
                }
                catch { }

                AlertDetected?.Invoke(this, new ParentChildAnomalyAlertEventArgs(alert));
            }
            catch (OperationCanceledException) { throw; }
            catch { }
            finally
            {
                try { proc.Dispose(); } catch { }
            }
        }
    }

    private static bool IsAnomalousChildInAnyParent(string childName)
    {
        foreach (var set in AnomalousChildren.Values)
        {
            if (set.Contains(childName))
                return true;
        }
        return false;
    }
}
